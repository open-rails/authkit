package engine

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"

	"github.com/stretchr/testify/require"
)

// Real Postgres failures: a store that can hold a challenge but cannot read
// or claim it, and a failing factor write. None should be presented as a
// mistyped OTP.
func TestMFAEnrollmentBackendFailures(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	f := newAccountFlow(t, pg.Pool, testConfig(), config.Deps{})
	for _, method := range []string{"totp", "sms"} {
		for _, failure := range []string{"read", "claim", "persistence"} {
			t.Run(method+"/"+failure, func(t *testing.T) {
				f.t = t
				user := newUser(t, f.engine, "mfaback")
				session := f.expect(200, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})).AccessToken
				body := map[string]any{"method": method}
				if method == "sms" {
					body["phone_number"] = uniquePhone()
				}
				start := f.request("POST", "/user/2fa", session, body)
				if method == "totp" {
					f.expect(200, start)
				} else {
					f.expect(202, start)
				}
				body["code"] = "not-a-code"
				invalid := f.expect(401, f.request("POST", "/user/2fa", session, body))
				require.Equal(t, "invalid_code", invalid.Error.Code)
				proof := func() {
					if method == "totp" {
						code, err := totpCode(start.Secret, time.Now().Unix()/totpPeriod)
						require.NoError(t, err)
						body["code"] = code
					} else {
						body["code"] = sentCode(t, f.sms, iam.MessageVerification)
					}
				}
				proof()
				restore := func() {}
				switch failure {
				case "read":
					restore = takeEphemeralOffline(t, pg.Pool)
				case "claim":
					restore = failEphemeral(t, pg.Pool, "DELETE", "OLD", "")
				case "persistence":
					_, err := pg.Pool.Exec(ctx, `CREATE FUNCTION mfa_backend_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected factor persistence failure'; END $$; CREATE TRIGGER mfa_backend_failure BEFORE INSERT ON mfa_factors FOR EACH ROW EXECUTE FUNCTION mfa_backend_failure()`)
					require.NoError(t, err)
					restore = func() {
						_, err := pg.Pool.Exec(ctx, `DROP TRIGGER mfa_backend_failure ON mfa_factors; DROP FUNCTION mfa_backend_failure()`)
						require.NoError(t, err)
					}
				}
				defer func() { restore() }()
				failed := f.expect(500, f.request("POST", "/user/2fa", session, body))
				require.Equal(t, "internal_error", failed.Error.Code)
				factors, err := f.engine.listUser2FAFactors(ctx, user.ID)
				require.NoError(t, err)
				require.Empty(t, factors)
				restore()
				restore = func() {}
				if failure == "persistence" {
					// A successful claim stays single-use even when the SQL transaction fails.
					delete(body, "code")
					start = f.request("POST", "/user/2fa", session, body)
					if method == "totp" {
						f.expect(200, start)
					} else {
						f.expect(202, start)
					}
				}
				proof()
				f.expect(200, f.request("POST", "/user/2fa", session, body))
				factors, err = f.engine.listUser2FAFactors(ctx, user.ID)
				require.NoError(t, err)
				require.Len(t, factors, 1, fmt.Sprint(method, " must recover after ", failure))
			})
		}
	}
}

// takeEphemeralOffline makes every ephemeral statement fail until restore.
func takeEphemeralOffline(t *testing.T, pool *pgxpool.Pool) (restore func()) {
	t.Helper()
	_, err := pool.Exec(t.Context(), `ALTER TABLE ephemeral_kv RENAME TO ephemeral_kv_offline`)
	require.NoError(t, err)
	var once sync.Once
	restore = func() {
		once.Do(func() {
			_, err := pool.Exec(context.Background(), `ALTER TABLE ephemeral_kv_offline RENAME TO ephemeral_kv`)
			require.NoError(t, err)
		})
	}
	t.Cleanup(restore)
	return restore
}
