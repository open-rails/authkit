package engine

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Two first-factor enrollments racing for an account: one wins with ten
// backup codes, stored only as SHA-256 digests, and a later additional-factor
// enrollment cannot replace the winner.
func TestFactorEnrollmentConcurrentFirstFactor(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := maintenanceConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorOptional
	svc := newTestEngine(t, cfg, config.Deps{Postgres: pool})
	for _, sameMethod := range []bool{false, true} {
		t.Run(fmt.Sprintf("same_method_%v", sameMethod), func(t *testing.T) {
			username := fmt.Sprintf("firstfactor%d", time.Now().UnixNano())
			user, err := svc.createUser(ctx, username+"@test.example", username)
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, user.ID) })
			start := make(chan struct{})
			var wg sync.WaitGroup
			results := make([][]string, 2)
			errs := make([]error, 2)
			for i := range 2 {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					method := "email"
					phone := "+15551234567"
					if i == 1 && !sameMethod {
						method = "sms"
					}
					results[i], errs[i] = svc.enableFactor(ctx, user.ID, method, &phone, authflow.FirstFactorOnly)
				}(i)
			}
			close(start)
			wg.Wait()
			successes := 0
			var issuedCodes []string
			for i, err := range errs {
				if err == nil {
					successes++
					issuedCodes = results[i]
				} else {
					require.ErrorIs(t, err, errmodel.ErrTwoFAFactorExists)
				}
			}
			require.Equal(t, 1, successes)
			require.Len(t, issuedCodes, 10)
			settings, err := svc.Get2FASettings(ctx, user.ID)
			require.NoError(t, err)
			require.Len(t, settings.Factors, 1)
			require.True(t, settings.Factors[0].IsDefault)
			for i, code := range issuedCodes {
				require.Equal(t, secret.Hash(code), settings.BackupCodes[i])
			}

			// Authenticated management may add another method, but cannot replace the winner.
			phone := "+15559876543"
			_, _, err = svc.enable2FA(ctx, factorEnable{UserID: user.ID, Method: settings.Factors[0].Method, Phone: &phone, Email: user.Email, MakeDefault: true, Mode: authflow.AllowAdditionalFactors})
			require.ErrorIs(t, err, errmodel.ErrTwoFAFactorExists)
			preserved, err := svc.Get2FASettings(ctx, user.ID)
			require.NoError(t, err)
			require.Equal(t, settings, preserved)
		})
	}
}

// A stored step-up code lapses by the database clock: past its TTL even the
// right code is code_expired, until a new one is sent.
func TestTwoFactorCodeExpiresByDatabaseClock(t *testing.T) {
	ctx := t.Context()
	f := newAccountFlow(t, testdb.Pool(t), testConfig(), config.Deps{})
	user := newUser(t, f.engine, "codeexp")
	_, err := f.engine.enableFactor(ctx, user.ID, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	ch := f.expect(200, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword}))
	access := f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.challenge(t),
		"code": sentCode(t, f.email, iam.MessageLoginCode)})).tokens().AccessToken

	stepUp := func(code string) flowResponse {
		return f.request("POST", "/me/step-up/2fa", access, map[string]any{"code": code})
	}
	send := func() string {
		t.Helper()
		f.expect(202, f.request("POST", "/me/step-up/2fa/send", access, map[string]any{}))
		return sentCode(t, f.email, iam.MessageLoginCode)
	}
	code := send()
	wrong := "0" + code[1:]
	if code[0] == '0' {
		wrong = "1" + code[1:]
	}
	require.Equal(t, "invalid_code", f.expect(401, stepUp(wrong)).Error.Code)
	tag, err := f.engine.pg.Exec(ctx, `UPDATE ephemeral_kv SET expires_at = now() - interval '1 second' WHERE key LIKE $1 AND expires_at > now()`,
		keyTwoFactorStepUp+user.ID+":%")
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.Equal(t, "code_expired", f.expect(401, stepUp(code)).Error.Code)
	code = send()
	f.expect(200, stepUp(code))
}
