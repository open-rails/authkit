package engine

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/secret"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func recoveryKey(t *testing.T, f *accountFlow, user *db.User) (*passkeytest.Authenticator, iam.TokenSet) {
	t.Helper()
	grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	creation := beginMandatoryKey(t, f, grant)
	authn := passkeytest.New(t, "https://app.example")
	done := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, json.RawMessage(authn.Register(t, creation))))
	return authn, done.tokens()
}

func recoverySet(t *testing.T, f *accountFlow, tokens iam.TokenSet) []string {
	t.Helper()
	response := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/backup-codes", tokens.AccessToken, nil))
	var codes struct {
		Codes []string `json:"backup_codes"`
	}
	require.NoError(t, json.Unmarshal([]byte(response.raw), &codes))
	require.Len(t, codes.Codes, 10)
	return codes.Codes
}

func recoveryChallenge(t *testing.T, f *accountFlow, user *db.User) flowResponse {
	t.Helper()
	pending := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword}))
	require.Equal(t, httpapi.AuthSecondFactorRequired, pending.Status, pending.raw)
	require.Equal(t, "backup_code", pending.SecondFactor.Factor.Method)
	require.Empty(t, pending.tokens().AccessToken)
	return pending
}

func TestPasskeyOnlyBackupRecoveryIsPrimaryBoundRotatableAndSingleUse(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	user := newUser(t, f.engine, "keyrecovery")
	_, tokens := recoveryKey(t, f, user)
	original := recoverySet(t, f, tokens)
	settings, err := f.engine.Get2FASettings(t.Context(), user.ID)
	require.NoError(t, err)
	require.False(t, settings.Enabled, "recovery state does not create an OTP factor")
	require.Empty(t, settings.Factors)
	require.Contains(t, settings.BackupCodes, secret.Hash(original[0]))
	require.NotContains(t, settings.BackupCodes, original[0])
	pending := recoveryChallenge(t, f, user)
	other := newUser(t, f.engine, "recoveryother")
	_, err = f.engine.CompleteLoginChallenge(t.Context(), authflow.LoginChallengeInput{UserID: other.ID, Challenge: pending.challenge(t), Code: original[0], BackupCode: true})
	require.Error(t, err, "a primary proof cannot move a recovery code to another account")
	replacement := recoverySet(t, f, tokens)
	body := map[string]any{"user_id": user.ID, "challenge": pending.challenge(t), "code": original[0], "backup_code": true}
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", body))
	body["code"] = replacement[0]
	done := f.expect(http.StatusOK, f.post("/2fa/verify", body))
	f.session(done.tokens(), "pwd", "backup_code", "otp", "mfa")
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "code": replacement[1], "backup_code": true}))
	replay := recoveryChallenge(t, f, user)
	body["challenge"] = replay.challenge(t)
	f.expect(http.StatusUnauthorized, f.post("/2fa/verify", body))
	// One current primary proof and one recovery code commit one session, even
	// when two requests race. A rejected attempt cannot spend another code.
	challenge := replay.challenge(t)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := f.engine.CompleteLoginChallenge(t.Context(), authflow.LoginChallengeInput{UserID: user.ID, Challenge: challenge, Code: replacement[1], BackupCode: true})
			results <- err
		}()
	}
	wg.Wait()
	close(results)
	successes := 0
	for err := range results {
		if err == nil {
			successes++
		}
	}
	require.Equal(t, 1, successes)
	settings, err = f.engine.Get2FASettings(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, settings.BackupCodes, 8)
}

func TestPasskeyRecoveryRequiresStrongSessionAndClearsWithFinalKey(t *testing.T) {
	cfg := testConfig()
	cfg.Passkeys = config.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
	f := newAccountFlow(t, testdb.ScratchPostgres(t).Pool, cfg, config.Deps{})
	user := newUser(t, f.engine, "recoverylifecycle")
	primary := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})).tokens()
	authn := passkeytest.New(t, "https://app.example")
	creation, err := f.engine.BeginPasskeyRegistration(t.Context(), user.ID)
	require.NoError(t, err)
	key, err := f.engine.FinishPasskeyRegistration(t.Context(), user.ID, authn.Register(t, creation))
	require.NoError(t, err)
	refused := f.request(http.MethodPost, "/me/2fa/backup-codes", primary.AccessToken, nil)
	require.Equal(t, http.StatusForbidden, refused.status, refused.raw)
	require.Contains(t, refused.raw, "step_up_required")
	_, err = f.engine.Get2FASettings(t.Context(), user.ID)
	require.ErrorIs(t, err, pgx.ErrNoRows)
	claims, err := f.engine.Verify(t.Context(), primary.AccessToken)
	require.NoError(t, err)
	assertion, err := f.engine.BeginPasskeyStepUp(t.Context(), user.ID, claims.SessionID)
	require.NoError(t, err)
	require.NoError(t, f.engine.StepUpWithPasskey(t.Context(), user.ID, claims.SessionID, authn.Assert(t, assertion, 1)))
	// The same session now has a server-recorded UV proof, so regeneration
	// succeeds without weakening the initial password-only refusal.
	codes := recoverySet(t, f, primary)
	phone := "+15550100087"
	_, err = f.engine.enableFactor(t.Context(), user.ID, "sms", &phone, authflow.FirstFactorOnly)
	require.NoError(t, err)
	require.NoError(t, f.engine.Disable2FA(t.Context(), user.ID))
	settings, err := f.engine.Get2FASettings(t.Context(), user.ID)
	require.NoError(t, err, "removing OTP retains recovery while the passkey remains")
	require.Contains(t, settings.BackupCodes, secret.Hash(codes[0]))
	require.NoError(t, f.engine.DeletePasskey(t.Context(), user.ID, key.ID))
	_, err = f.engine.Get2FASettings(t.Context(), user.ID)
	require.ErrorIs(t, err, pgx.ErrNoRows)
	valid, err := f.engine.VerifyBackupCode(t.Context(), user.ID, codes[0])
	require.NoError(t, err)
	require.False(t, valid)
	// Simulate a stale writer's orphaned set. A later first key scrubs it.
	require.NoError(t, f.engine.q.MFAUpsertSettings(t.Context(), db.MFAUpsertSettingsParams{UserID: user.ID, BackupCodes: []string{secret.Hash(codes[1])}}))
	creation, err = f.engine.BeginPasskeyRegistration(t.Context(), user.ID)
	require.NoError(t, err)
	second := passkeytest.New(t, "https://app.example")
	secondKey, err := f.engine.FinishPasskeyRegistration(t.Context(), user.ID, second.Register(t, creation))
	require.NoError(t, err)
	valid, err = f.engine.VerifyBackupCode(t.Context(), user.ID, codes[1])
	require.NoError(t, err)
	require.False(t, valid, "old codes do not resurrect with a later key")
	start := make(chan struct{})
	finished := make(chan error, 2)
	go func() { <-start; _, err := f.engine.RegenerateBackupCodes(t.Context(), user.ID); finished <- err }()
	go func() { <-start; finished <- f.engine.DeletePasskey(t.Context(), user.ID, secondKey.ID) }()
	close(start)
	<-finished
	<-finished
	_, err = f.engine.Get2FASettings(t.Context(), user.ID)
	require.ErrorIs(t, err, pgx.ErrNoRows, "a racing regeneration cannot leave recovery after final key removal")
}

func TestRequiredPasskeySessionCannotRefreshMFAWithLegacyEmail(t *testing.T) {
	cfg := testConfig()
	cfg.Passkeys = config.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
	f := newAccountFlow(t, testdb.ScratchPostgres(t).Pool, cfg, config.Deps{})
	user := newUser(t, f.engine, "emailstepup")
	authn := passkeytest.New(t, "https://app.example")
	creation, err := f.engine.BeginPasskeyRegistration(t.Context(), user.ID)
	require.NoError(t, err)
	_, err = f.engine.FinishPasskeyRegistration(t.Context(), user.ID, authn.Register(t, creation))
	require.NoError(t, err)
	begun := f.expect(http.StatusOK, f.post("/passkeys/login/begin", nil))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(begun.raw), &assertion))
	tokens := f.expect(http.StatusOK, f.post("/passkeys/login/finish", json.RawMessage(authn.Assert(t, &assertion, 1)))).tokens()
	claims, err := f.engine.Verify(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	_, err = f.engine.enableFactor(t.Context(), user.ID, "email", nil, authflow.FirstFactorOnly)
	require.NoError(t, err)
	require.NoError(t, f.engine.Send2FAStepUpCode(t.Context(), user.ID, claims.SessionID, ""))
	code := sentCode(t, f.email, iam.MessageLoginCode)
	_, err = f.engine.pg.Exec(t.Context(), `UPDATE users SET mfa_required=true WHERE id=$1`, user.ID)
	require.NoError(t, err)
	_, err = f.engine.pg.Exec(t.Context(), `UPDATE refresh_sessions SET mfa_authenticated_at=now()-interval '1 hour' WHERE id=$1`, claims.SessionID)
	require.NoError(t, err)
	var before, after time.Time
	require.NoError(t, f.engine.pg.QueryRow(t.Context(), `SELECT mfa_authenticated_at FROM refresh_sessions WHERE id=$1`, claims.SessionID).Scan(&before))
	require.Error(t, f.engine.CompleteTwoFactorStepUp(t.Context(), user.ID, claims.SessionID, "", code, false))
	require.NoError(t, f.engine.pg.QueryRow(t.Context(), `SELECT mfa_authenticated_at FROM refresh_sessions WHERE id=$1`, claims.SessionID).Scan(&after))
	require.Equal(t, before, after, "an old UV marker cannot make a new email proof into fresh strong MFA")
	methods, err := f.engine.stepUpMethods(t.Context(), user.ID, nil)
	require.NoError(t, err)
	require.Equal(t, []string{"passkey"}, methods)
}
