package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

const enrollPassword = "Correct-horse-battery-1"

// #389: a confirmed enrollment code verifies the enrolling session; other
// sessions still complete 2FA on refresh.
func TestEnrollmentVerifiesEnrollingSession(t *testing.T) {
	pool := testdb.Pool(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin = true
	f := newAccountFlow(t, pool, cfg)
	ctx := t.Context()

	login := func(prefix string) (string, string, flowResponse, flowResponse) {
		t.Helper()
		email := uniqueEmail(prefix)
		user, err := fixtureBackend(f.service.Backend()).createUser(ctx, email, "enr"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(ctx, user.ID, enrollPassword))
		require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(ctx, user.ID))
		body := map[string]any{"identifier": email, "password": enrollPassword}
		return user.ID, email, f.expect(200, f.post("/password/login", body)), f.expect(200, f.post("/password/login", body))
	}
	refresh := func(rt string) flowResponse {
		return f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": rt})
	}
	requireVerified := func(enabled, enrolling flowResponse, method string) {
		t.Helper()
		require.NotEmpty(t, enabled.BackupCodes)
		require.Empty(t, enabled.Tokens.RefreshToken, "step-up style response never rotates the refresh token")
		claims := unverifiedAccessClaims(t, enabled.Tokens.AccessToken)
		require.ElementsMatch(t, []any{"pwd", method, "otp", "mfa"}, claims["amr"])
		require.Equal(t, iam.AssuranceLevelMFA, claims["acr"])
		require.Equal(t, true, claims["mfa_enrolled"])
		require.Contains(t, enabled.raw, `"fresh_auth"`)
		refreshed := f.expect(200, refresh(enrolling.RefreshToken))
		f.session(refreshed.TokenSet, "pwd", method, "otp", "mfa")
		require.Equal(t, true, unverifiedAccessClaims(t, refreshed.AccessToken)["mfa_enrolled"])
	}
	requireChallenged := func(other flowResponse, method string) {
		t.Helper()
		challenged := f.expect(403, refresh(other.RefreshToken))
		require.Equal(t, "2fa_required", challenged.Error.Code)
		require.Equal(t, method, challenged.Error.Metadata.Method)
	}

	t.Run("totp", func(t *testing.T) {
		f.t = t
		_, _, enrolling, other := login("enroll-totp")
		started := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "totp"}))
		enabled := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "totp", "code": flowTOTP(t, started.Secret)}))
		requireVerified(enabled, enrolling, "totp")
		requireChallenged(other, "totp")
	})

	t.Run("email", func(t *testing.T) {
		f.t = t
		_, _, enrolling, other := login("enroll-email")
		f.expect(202, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email"}))
		code := sentCode(t, f.email, testoutbox.Verification)
		wrong := f.expect(401, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email", "code": "000000x"}))
		require.Equal(t, "invalid_code", wrong.Error.Code)
		enabled := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "email", "code": code}))
		requireVerified(enabled, enrolling, "email")
		requireChallenged(other, "email")
	})

	t.Run("sms", func(t *testing.T) {
		f.t = t
		_, _, enrolling, other := login("enroll-sms")
		phone := uniquePhone()
		f.expect(202, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "sms", "phone_number": phone}))
		enabled := f.expect(200, f.request("POST", "/user/2fa", enrolling.AccessToken, map[string]any{"method": "sms", "phone_number": phone, "code": sentCode(t, f.sms, testoutbox.Verification)}))
		requireVerified(enabled, enrolling, "sms")
		requireChallenged(other, "sms")
	})

	t.Run("same channel is not a second factor", func(t *testing.T) {
		f.t = t
		userID, email, _, _ := login("enroll-same-channel")
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "code"}))
		session := f.expect(200, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": sentCode(t, f.email, testoutbox.Verification)}))
		f.session(session.Tokens, "email")
		f.expect(202, f.request("POST", "/user/2fa", session.Tokens.AccessToken, map[string]any{"method": "email"}))
		enabled := f.expect(200, f.request("POST", "/user/2fa", session.Tokens.AccessToken, map[string]any{"method": "email", "code": sentCode(t, f.email, testoutbox.Verification)}))
		require.NotEmpty(t, enabled.BackupCodes)
		require.Empty(t, enabled.Tokens.AccessToken)
		var amr []string
		require.NoError(t, pool.QueryRow(ctx, `SELECT auth_methods FROM refresh_sessions WHERE id=$1`, unverifiedAccessClaims(t, session.Tokens.AccessToken)["sid"]).Scan(&amr))
		require.ElementsMatch(t, []string{"email"}, amr)
		challenged := f.expect(403, refresh(session.Tokens.RefreshToken))
		require.Equal(t, "2fa_required", challenged.Error.Code)
		require.Equal(t, userID, challenged.Error.Metadata.UserID)
		require.Equal(t, "backup_code", challenged.Error.Metadata.Method)
	})
}

// Forced enrollment ends with a 2FA-verified session for every proven method.
func TestForcedEmailEnrollmentIssuesVerifiedSession(t *testing.T) {
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	f := newAccountFlow(t, testdb.Pool(t), cfg)
	ctx := t.Context()
	email := uniqueEmail("forced-email")
	user, err := fixtureBackend(f.service.Backend()).createUser(ctx, email, "forced"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(ctx, user.ID, enrollPassword))
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(ctx, user.ID))

	grant := f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": enrollPassword}))
	require.Equal(t, "2fa_enrollment_required", grant.Error.Code)
	require.Contains(t, grant.Error.Metadata.AllowedMethods, "email")
	restricted := grant.Error.Metadata.TokenSet.AccessToken
	f.expect(202, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "email"}))
	enabled := f.expect(200, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "email", "code": sentCode(t, f.email, testoutbox.Verification)}))
	require.NotEmpty(t, enabled.BackupCodes)
	f.session(enabled.Tokens, "pwd", "email", "otp", "mfa")
	refreshed := f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": enabled.Tokens.RefreshToken}))
	f.session(refreshed.TokenSet, "pwd", "email", "otp", "mfa")
}

func TestAuthenticationContinuationWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	cfg.Registration.Verification = iam.RegistrationVerificationRequired
	cfg.Passkeys = PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
	cfg.Roles = RoleConfig{Roles: []Role{{Persona: "root", Name: "admin", Permissions: []string{"root:*"}}}}
	f := newAccountFlow(t, pg.Pool, cfg)
	ctx := context.Background()
	// Registration proof reaches a restricted enrollment token. Complete an
	// independent TOTP proof, then exercise a fresh first factor and MFA login.
	for _, passwordless := range []bool{false, true} {
		t.Run(fmt.Sprint("passwordless=", passwordless), func(t *testing.T) {
			f.t = t
			email := uniqueEmail("continuation")
			start, confirm := "/register", "/verify/confirm"
			if passwordless {
				start, confirm = "/passwordless/start", "/passwordless/confirm"
			}
			payload := map[string]any{"identifier": email}
			if passwordless {
				payload["mode"] = "both"
			} else {
				payload["username"] = "cont" + uniqueSuffix()
				payload["password"] = "Correct-horse-battery-1"
			}
			f.expect(202, f.post(start, payload))
			path := "/verify"
			if passwordless {
				path = "/login/link"
			}
			link := f.deliveredLink(f.email.Last(t, testoutbox.Verification, "").Link, path, "email")
			first := f.expect(403, f.post(confirm, map[string]any{"token": link}))
			require.Equal(t, "2fa_enrollment_required", first.Error.Code)
			assertWireGolden(t, "mfa-enrollment", json.RawMessage(first.raw))
			grant := first.Error.Metadata.TokenSet
			require.NotEmpty(t, grant.AccessToken)
			require.Empty(t, grant.RefreshToken)
			require.NotContains(t, first.Error.Metadata.AllowedMethods, "email", "two proofs sent to one mailbox are one factor")
			require.Contains(t, first.Error.Metadata.AllowedMethods, "totp")
			require.ElementsMatch(t, []any{"email"}, unverifiedAccessClaims(t, grant.AccessToken)["amr"])
			denied := f.request("GET", "/me", grant.AccessToken, nil)
			require.GreaterOrEqual(t, denied.status, 400, denied.raw)
			totp := f.expect(200, f.request("POST", "/user/2fa", grant.AccessToken, map[string]any{"method": "totp"}))
			enabled := f.expect(200, f.request("POST", "/user/2fa", grant.AccessToken, map[string]any{"method": "totp", "code": flowTOTP(t, totp.Secret)}))
			require.NotEmpty(t, enabled.BackupCodes)
			f.session(enabled.Tokens, "email", "totp", "otp", "mfa")
			replay := f.request("POST", "/user/2fa", grant.AccessToken, map[string]any{"method": "sms", "phone_number": uniquePhone()})
			require.GreaterOrEqual(t, replay.status, 400, replay.raw)
			// Recovery invalidates the captured first factor and its enrollment grant.
			var second flowResponse
			if passwordless {
				f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
				second = f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": sentCode(t, f.email, testoutbox.Verification)}))
			} else {
				second = f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": "Correct-horse-battery-1"}))
			}
			require.Equal(t, "2fa_required", second.Error.Code)
			require.Equal(t, "totp", second.Error.Metadata.Method)
			assertWireGolden(t, "mfa-challenge", json.RawMessage(second.raw))
			methods := make([]string, 0, len(second.Error.Metadata.AvailableFactors))
			for _, factor := range second.Error.Metadata.AvailableFactors {
				methods = append(methods, factor.Method)
			}
			require.Contains(t, methods, "totp")
			wrong := map[string]any{"user_id": second.Error.Metadata.UserID, "challenge": second.Error.Metadata.Challenge + "x", "code": enabled.BackupCodes[0], "backup_code": true}
			f.expect(401, f.post("/2fa/verify", wrong))
			wrong["challenge"] = second.Error.Metadata.Challenge
			done := f.expect(200, f.post("/2fa/verify", wrong))
			method := "pwd"
			if passwordless {
				method = "email"
			}
			f.session(done.TokenSet, method, "backup_code", "otp", "mfa")
			f.expect(401, f.post("/2fa/verify", wrong))
			f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email, "mode": "both"}))
			pending := f.expect(403, f.post("/passwordless/confirm", map[string]any{"token": f.email.Last(t, testoutbox.Verification, "").Token}))
			require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(ctx, pending.Error.Metadata.UserID, "Replacement-password-12345"))
			f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": pending.Error.Metadata.UserID, "challenge": pending.Error.Metadata.Challenge, "code": enabled.BackupCodes[1], "backup_code": true}))
		})
	}
	f.t = t
	phone := uniquePhone()
	f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": phone, "mode": "code"}))
	phoneGrant := f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": phone, "code": sentCode(t, f.sms, testoutbox.Verification)}))
	require.Equal(t, "2fa_enrollment_required", phoneGrant.Error.Code)
	require.NotContains(t, phoneGrant.Error.Metadata.AllowedMethods, "email", "an email-less account cannot enroll a mailbox factor")
	restricted := phoneGrant.Error.Metadata.TokenSet.AccessToken
	f.expect(400, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "email"}))
	phoneTOTP := f.expect(200, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "totp"}))
	phoneSession := f.expect(200, f.request("POST", "/user/2fa", restricted, map[string]any{"method": "totp", "code": flowTOTP(t, phoneTOTP.Secret)}))
	f.session(phoneSession.Tokens, "sms", "totp", "otp", "mfa")

	f.t = t
	// Email-first plus email-only MFA offers a recovery key, never another code
	// to the same mailbox. A password first factor may use that email factor.
	email := uniqueEmail("same-channel")
	user, err := fixtureBackend(f.service.Backend()).createUser(ctx, email, "samechannel"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(ctx, user.ID, "Correct-horse-battery-1"))
	previousCode := sentCode(t, f.email, testoutbox.Verification)
	f.expect(401, f.post("/password/login", map[string]any{"identifier": email, "password": "wrong"}))
	require.Equal(t, previousCode, sentCode(t, f.email, testoutbox.Verification))
	verify := f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": "Correct-horse-battery-1"}))
	require.Equal(t, "verification_required", verify.Error.Code)
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(ctx, user.ID))
	backups, err := fixtureBackend(f.service.Backend()).enableFactor(ctx, user.ID, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": email}))
	ch := f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": email, "code": sentCode(t, f.email, testoutbox.Verification)}))
	require.Equal(t, "backup_code", ch.Error.Metadata.Method)
	f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge, "code": sentCode(t, f.email, testoutbox.Verification)}))
	signed := f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge, "code": backups[0], "backup_code": true}))
	f.session(signed.TokenSet, "email", "backup_code", "otp", "mfa")
	ch = f.expect(403, f.post("/password/login", map[string]any{"identifier": email, "password": "Correct-horse-battery-1"}))
	require.Equal(t, "email", ch.Error.Metadata.Method)
	signed = f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": ch.Error.Metadata.Challenge, "code": lastSent(f.email, testoutbox.LoginCode).Code}))
	f.session(signed.TokenSet, "pwd", "email", "otp", "mfa")
	testPausedPasswordRecovery(f)
	// A fresh UV passkey satisfies Required mode and an MFA-required role without
	// inventing a second traditional factor. The returned JWT passes /me.
	bootstrapCfg := cfg
	bootstrapCfg.TwoFactor.Mode = iam.TwoFactorDisabled
	bootstrap := newServerClient(t, bootstrapCfg, pg.Pool)
	_, err = bootstrap.ensureRootGroup(ctx)
	require.NoError(t, err)
	passkeyUser, err := bootstrap.createUser(ctx, uniqueEmail("uv-role"), "uv"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, bootstrap.markEmailVerified(ctx, passkeyUser.ID))
	grantRole(t, bootstrap, iam.RootGroup(), iam.UserSubject(passkeyUser.ID), "admin")
	authn := passkeytest.New(t, "https://app.example")
	creation, err := f.service.Backend().BeginPasskeyRegistration(ctx, passkeyUser.ID)
	require.NoError(t, err)
	createdPasskey, err := f.service.Backend().FinishPasskeyRegistration(ctx, passkeyUser.ID, authn.Register(t, creation))
	require.NoError(t, err)
	start := f.expect(200, f.post("/passkeys/login/begin", map[string]any{}))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
	require.Empty(t, assertion.Response.AllowedCredentials)
	uv := f.expect(200, f.post("/passkeys/login/finish", json.RawMessage(authn.Assert(t, &assertion, 1))))
	f.session(uv.TokenSet, "swk", "mfa")
	require.Equal(t, true, unverifiedAccessClaims(t, uv.AccessToken)["mfa_enrolled"])
	start = f.expect(200, f.post("/passkeys/login/begin", map[string]any{}))
	require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
	proof := json.RawMessage(authn.Assert(t, &assertion, 2))
	completed := f.completeWhileRevoking(passkeyUser.ID, func() flowResponse { return f.post("/passkeys/login/finish", proof) }, func(ctx context.Context) error {
		return f.service.Backend().DeletePasskey(ctx, passkeyUser.ID, createdPasskey.ID)
	})
	f.expect(200, completed)
	f.session(completed.TokenSet, "swk", "mfa")
	// Revoke-all must see the session committed by refresh-derived MFA, even
	// when revocation began while that completion held the source session.
	optionalCfg := cfg
	optionalCfg.TwoFactor.Mode = iam.TwoFactorOptional
	old := newAccountFlow(t, pg.Pool, optionalCfg)
	refreshUser, err := fixtureBackend(old.service.Backend()).createUser(ctx, uniqueEmail("revoke-all"), "revall"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(old.service.Backend()).adminSetPassword(ctx, refreshUser.ID, "Correct-horse-battery-1"))
	require.NoError(t, fixtureBackend(old.service.Backend()).markEmailVerified(ctx, refreshUser.ID))
	initial := old.expect(200, old.post("/password/login", map[string]any{"identifier": *refreshUser.Email, "password": "Correct-horse-battery-1"}))
	_, err = fixtureBackend(f.service.Backend()).enableFactor(ctx, refreshUser.ID, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	needed := f.expect(403, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": initial.RefreshToken}))
	require.Equal(t, "2fa_required", needed.Error.Code)
	completionBody := map[string]any{"user_id": refreshUser.ID, "challenge": needed.Error.Metadata.Challenge, "code": lastSent(f.email, testoutbox.LoginCode).Code}
	completed = f.completeWhileRevoking(refreshUser.ID, func() flowResponse { return f.post("/2fa/verify", completionBody) }, func(ctx context.Context) error {
		return f.service.Backend().RevokeIssuerSessions(ctx, refreshUser.ID, nil)
	})
	f.expect(200, completed)
	var live int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM refresh_sessions WHERE user_id=$1::uuid AND revoked_at IS NULL`, refreshUser.ID).Scan(&live))
	require.Zero(t, live, "revoke-all cannot miss the derived session")
}

func testPausedPasswordRecovery(f *accountFlow) {
	t, pool, ctx := f.t, fixtureBackend(f.service.Backend()).pg, f.t.Context()
	user, err := fixtureBackend(f.service.Backend()).createUser(ctx, uniqueEmail("paused-password"), "paused"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(ctx, user.ID, "Original-password-12345"))
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(ctx, user.ID))
	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer lock.Rollback(ctx)
	_, err = lock.Exec(ctx, `SELECT id FROM users WHERE id=$1::uuid FOR UPDATE`, user.ID)
	require.NoError(t, err)
	changed := make(chan error, 1)
	go func() {
		changed <- fixtureBackend(f.service.Backend()).adminSetPassword(ctx, user.ID, "Replacement-password-12345")
	}()
	waitLocks := func(want int) {
		require.Eventually(t, func() bool {
			var n int
			err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%UserCredentialVersionForUpdate%'`).Scan(&n)
			return err == nil && n == want
		}, 5*time.Second, 10*time.Millisecond)
	}
	waitLocks(1)
	login := make(chan flowResponse, 1)
	go func() {
		login <- f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Original-password-12345"})
	}()
	waitLocks(2)
	require.NoError(t, lock.Commit(ctx))
	require.NoError(t, <-changed)
	f.expect(401, <-login)
	var sessions int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM refresh_sessions WHERE user_id=$1::uuid`, user.ID).Scan(&sessions))
	require.Zero(t, sessions, "a password check preceding completed recovery cannot mint a session")
}
