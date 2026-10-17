package engine

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func passkeyEnrollmentFlow(t *testing.T) *accountFlow {
	t.Helper()
	cfg := testConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	cfg.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP, iam.TwoFactorSMS}
	// Old preference values must not advertise a presence-only ceremony.
	cfg.Passkeys = config.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}, UserVerification: "discouraged"}
	return newAccountFlow(t, testdb.ScratchPostgres(t).Pool, cfg, config.Deps{})
}

func pendingPasskeyEnrollment(t *testing.T, f *accountFlow, email, password string) iam.TokenSet {
	t.Helper()
	login := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": email, "password": password}))
	require.Equal(t, httpapi.AuthEnrollmentRequired, login.Status, login.raw)
	require.NotNil(t, login.Enrollment)
	require.Empty(t, login.tokens().AccessToken, "an enrollment grant is not a full session")
	return login.Enrollment.TokenSet
}

func beginMandatoryKey(t *testing.T, f *accountFlow, grant iam.TokenSet) *protocol.CredentialCreation {
	t.Helper()
	start := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/enroll/begin", grant.AccessToken, nil))
	var creation protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(start.raw), &creation))
	require.Equal(t, protocol.VerificationRequired, creation.Response.AuthenticatorSelection.UserVerification)
	require.Empty(t, creation.Response.AuthenticatorSelection.AuthenticatorAttachment, "platform and FIDO2 hardware keys remain choices")
	return &creation
}

func TestRequiredPasskeyEnrollmentCompletesUVSessionWithoutOTP(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	for _, hardware := range []bool{false, true} {
		user := newUser(t, f.engine, "firstpasskey")
		grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
		require.GreaterOrEqual(t, f.request(http.MethodGet, "/me", grant.AccessToken, nil).status, 400)
		authenticator := passkeytest.New(t, "https://app.example")
		authenticator.BackupEligible, authenticator.BackupState = !hardware, !hardware
		creation := beginMandatoryKey(t, f, grant)
		proof := json.RawMessage(authenticator.Register(t, creation))
		done := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, proof))
		require.Equal(t, httpapi.AuthComplete, done.Status, done.raw)
		f.session(done.tokens(), "pwd", "swk", "mfa")
		keys, err := f.engine.ListPasskeys(t.Context(), user.ID)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		var security authflow.UserSecurity
		reply := f.expect(http.StatusOK, f.request(http.MethodGet, "/me/security", done.tokens().AccessToken, nil))
		require.NoError(t, json.Unmarshal([]byte(reply.raw), &security))
		require.True(t, security.TwoFactor.Required)
		require.True(t, security.TwoFactor.PasskeysEnrolled)
		require.False(t, security.TwoFactor.Enabled, "no extra OTP factor was created")
		require.GreaterOrEqual(t, f.request(http.MethodPost, "/me/passkeys/enroll/begin", done.tokens().AccessToken, nil).status, 400, "ordinary sessions use normal key management")
		f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, proof))
		require.ErrorIs(t, f.engine.DeletePasskey(t.Context(), user.ID, keys[0].ID), iam.ErrTwoFARequiredByPolicy)
		// A UV passkey is a replacement for a mandatory OTP factor, not an
		// additional OTP requirement that the account can never remove.
		setup := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", done.tokens().AccessToken, map[string]any{"method": "totp"}))
		otp, err := totpCode(setup.Secret, time.Now().Unix()/totpPeriod)
		require.NoError(t, err)
		f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", done.tokens().AccessToken, map[string]any{"method": "totp", "code": otp}))
		require.NoError(t, f.engine.Disable2FA(t.Context(), user.ID))
		require.ErrorIs(t, f.engine.DeletePasskey(t.Context(), user.ID, keys[0].ID), iam.ErrTwoFARequiredByPolicy)
		again := f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})
		require.GreaterOrEqual(t, again.status, 400)
		require.Empty(t, again.tokens().AccessToken)
		start := f.expect(http.StatusOK, f.post("/passkeys/login/begin", nil))
		var assertion protocol.CredentialAssertion
		require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
		require.Equal(t, protocol.VerificationRequired, assertion.Response.UserVerification)
		signedIn := f.expect(http.StatusOK, f.post("/passkeys/login/finish", json.RawMessage(authenticator.Assert(t, &assertion, 1))))
		f.session(signedIn.tokens(), "swk", "mfa")
	}
}

func TestRequiredPasskeyEnrollmentRejectsWrongOwnerNonceAndCredentialGeneration(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	user, other := newUser(t, f.engine, "keyowner"), newUser(t, f.engine, "otherkeyowner")
	grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	otherGrant := pendingPasskeyEnrollment(t, f, *other.Email, testPassword)
	authenticator := passkeytest.New(t, "https://app.example")
	creation := beginMandatoryKey(t, f, grant)
	f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/me/passkeys/enroll/finish", otherGrant.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	creation = beginMandatoryKey(t, f, grant)
	newer := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	creation = beginMandatoryKey(t, f, newer)
	require.NoError(t, f.engine.RequestPasswordReset(t.Context(), *user.Email, time.Hour, nil, nil))
	reset := f.email.Last(t, iam.MessagePasswordReset, *user.Email).Token
	_, err := f.engine.ConfirmPasswordReset(t.Context(), reset, "Changed-before-key-12345")
	require.NoError(t, err)
	f.expect(http.StatusUnauthorized, f.request(http.MethodPost, "/me/passkeys/enroll/finish", newer.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	for _, id := range []string{user.ID, other.ID} {
		keys, err := f.engine.ListPasskeys(t.Context(), id)
		require.NoError(t, err)
		require.Empty(t, keys)
	}
	pendingPasskeyEnrollment(t, f, *user.Email, "Changed-before-key-12345")
}

func TestPasskeyEnrollmentRejectsPresenceOnlyAndStaleNormalCreation(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	user := newUser(t, f.engine, "uvonly")
	grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	authenticator := passkeytest.New(t, "https://app.example")
	authenticator.UserVerified = false
	creation := beginMandatoryKey(t, f, grant)
	f.expect(http.StatusBadRequest, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	keys, err := f.engine.ListPasskeys(t.Context(), user.ID)
	require.NoError(t, err)
	require.Empty(t, keys)
	authenticator.UserVerified = true
	creation = beginMandatoryKey(t, f, grant)
	done := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	start := f.expect(http.StatusOK, f.post("/passkeys/login/begin", nil))
	var assertion protocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
	authenticator.UserVerified = false
	refused := f.post("/passkeys/login/finish", json.RawMessage(authenticator.Assert(t, &assertion, 1)))
	require.GreaterOrEqual(t, refused.status, 400)
	require.Empty(t, refused.tokens().AccessToken)
	// A regular registration begun under a retired credential generation also cannot attach a key.
	authenticator.UserVerified = true
	regular := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/register/begin", done.tokens().AccessToken, nil))
	require.NoError(t, json.Unmarshal([]byte(regular.raw), &creation))
	require.NoError(t, f.engine.adminSetPassword(t.Context(), user.ID, "Retire-key-ceremony-12345"))
	replacement := passkeytest.New(t, "https://app.example")
	_, err = f.engine.FinishPasskeyRegistration(t.Context(), user.ID, replacement.Register(t, creation))
	require.Error(t, err)
	keys, err = f.engine.ListPasskeys(t.Context(), user.ID)
	require.NoError(t, err)
	require.Len(t, keys, 1)
}

func TestAnotherRPPasskeyAndUnavailableSMSCannotBeReplacedByPasswordOnlyEnrollment(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	user := newUser(t, f.engine, "otherrp")
	grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	cfg := f.engine.cfg
	cfg.Passkeys = config.PasskeyConfig{RPID: "other.example", RPDisplayName: "Other", Origins: []string{"https://other.example"}}
	cfg.Frontend.BaseURL = "https://other.example"
	peer := newTestEngine(t, cfg, config.Deps{Postgres: f.engine.pg})
	authenticator := passkeytest.New(t, "https://other.example")
	creation, err := peer.BeginPasskeyRegistration(t.Context(), user.ID)
	require.NoError(t, err)
	_, err = peer.FinishPasskeyRegistration(t.Context(), user.ID, authenticator.Register(t, creation))
	require.NoError(t, err)
	require.GreaterOrEqual(t, f.request(http.MethodPost, "/me/passkeys/enroll/begin", grant.AccessToken, nil).status, 400)
	login := f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})
	require.NotEqual(t, httpapi.AuthEnrollmentRequired, login.Status)
	require.Empty(t, login.tokens().AccessToken)
	smsUser := newUser(t, f.engine, "offlinesms")
	pending := pendingPasskeyEnrollment(t, f, *smsUser.Email, testPassword)
	phone := "+15550100099"
	_, err = f.engine.enableFactor(t.Context(), smsUser.ID, "sms", &phone, authflow.FirstFactorOnly)
	require.NoError(t, err)
	// Dependency health is separate from persisted enrollment; a missing sender cannot clear this slot.
	f.engine.smsHealth.set(time.Now(), errors.New("SMS provider unavailable"))
	require.False(t, f.engine.SMSAvailable())
	require.GreaterOrEqual(t, f.request(http.MethodPost, "/me/passkeys/enroll/begin", pending.AccessToken, nil).status, 400)
}

func TestFirstPasskeyAndLoginSessionRollbackTogether(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	user := newUser(t, f.engine, "atomickey")
	grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	authenticator := passkeytest.New(t, "https://app.example")
	creation := beginMandatoryKey(t, f, grant)
	_, err := f.engine.pg.Exec(t.Context(), `CREATE FUNCTION reject_key_session() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected key session failure'; END $$; CREATE TRIGGER reject_key_session BEFORE INSERT ON refresh_sessions FOR EACH ROW EXECUTE FUNCTION reject_key_session()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = f.engine.pg.Exec(t.Context(), `DROP TRIGGER IF EXISTS reject_key_session ON refresh_sessions; DROP FUNCTION IF EXISTS reject_key_session()`)
	})
	f.expect(http.StatusInternalServerError, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	keys, err := f.engine.ListPasskeys(t.Context(), user.ID)
	require.NoError(t, err)
	require.Empty(t, keys, "a failed session cannot leave a new login credential")
}
