package engine

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestEmailedPasswordResetPreservesProvenMFAAndRetiresUnprovenCredentials(t *testing.T) {
	for _, proven := range []bool{true, false} {
		t.Run(map[bool]string{true: "established-account", false: "unproven-registration"}[proven], func(t *testing.T) {
			cfg := testConfig()
			cfg.TwoFactor.Mode = iam.TwoFactorOptional
			cfg.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP, iam.TwoFactorSMS}
			cfg.Passkeys = config.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
			f := newAccountFlow(t, testdb.ScratchPostgres(t).Pool, cfg, config.Deps{})
			user := newUser(t, f.engine, "resetmfa")
			primary := f.expect(http.StatusOK, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": testPassword})).tokens()
			setup := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/2fa/setup", primary.AccessToken, map[string]any{"method": "totp"}))
			code, err := totpCode(setup.Secret, time.Now().Unix()/totpPeriod)
			require.NoError(t, err)
			enrolled := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/2fa/factors", primary.AccessToken, map[string]any{"method": "totp", "code": code}))
			var recovery struct {
				BackupCodes []string `json:"backup_codes"`
			}
			require.NoError(t, json.Unmarshal([]byte(enrolled.raw), &recovery))
			require.NotEmpty(t, recovery.BackupCodes)
			authenticator := passkeytest.New(t, "https://app.example")
			creation, err := f.engine.BeginPasskeyRegistration(t.Context(), user.ID)
			require.NoError(t, err)
			key, err := f.engine.FinishPasskeyRegistration(t.Context(), user.ID, authenticator.Register(t, creation))
			require.NoError(t, err)
			if !proven {
				// Historical/pre-proof credentials belong to the unproven claimant,
				// not the owner who now proves this mailbox for the first time.
				_, err := f.engine.pg.Exec(t.Context(), `UPDATE users SET email_verified=false WHERE id=$1`, user.ID)
				require.NoError(t, err)
			}
			require.NoError(t, f.engine.RequestPasswordReset(t.Context(), *user.Email, time.Hour, nil, nil))
			reset := f.email.Last(t, iam.MessagePasswordReset, *user.Email).Token
			_, err = f.engine.ConfirmPasswordReset(t.Context(), reset, "Recovered-password-12345")
			require.NoError(t, err)
			var active int
			require.NoError(t, f.engine.pg.QueryRow(t.Context(), `SELECT count(*) FROM refresh_sessions WHERE user_id=$1 AND revoked_at IS NULL`, user.ID).Scan(&active))
			require.Zero(t, active, "password reset never issues a session")
			keys, err := f.engine.ListPasskeys(t.Context(), user.ID)
			require.NoError(t, err)
			settings, settingsErr := f.engine.Get2FASettings(t.Context(), user.ID)
			next := f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Recovered-password-12345"})
			if !proven {
				require.Empty(t, keys)
				require.ErrorIs(t, settingsErr, pgx.ErrNoRows)
				require.Equal(t, httpapi.AuthComplete, next.Status, next.raw)
				return
			}
			require.Len(t, keys, 1)
			require.Equal(t, key.ID, keys[0].ID)
			require.NoError(t, settingsErr)
			require.Len(t, settings.Factors, 1)
			require.Equal(t, "totp", settings.Factors[0].Method)
			require.Equal(t, httpapi.AuthSecondFactorRequired, next.Status, next.raw)
			require.Empty(t, next.tokens().AccessToken, "an emailed reset cannot bypass enabled MFA")
			bare := f.post("/2fa/verify", map[string]any{"user_id": user.ID, "code": recovery.BackupCodes[0], "backup_code": true})
			require.GreaterOrEqual(t, bare.status, 400)
			require.Empty(t, bare.tokens().AccessToken, "backup codes are not primary sign-in credentials")
			body := map[string]any{"user_id": user.ID, "challenge": next.SecondFactor.Challenge, "code": recovery.BackupCodes[0], "backup_code": true}
			done := f.expect(http.StatusOK, f.post("/2fa/verify", body))
			f.session(done.tokens(), "pwd", "backup_code", "otp", "mfa")
			repeated := f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Recovered-password-12345"})
			require.Equal(t, httpapi.AuthSecondFactorRequired, repeated.Status, repeated.raw)
			body["challenge"] = repeated.SecondFactor.Challenge
			f.expect(http.StatusUnauthorized, f.post("/2fa/verify", body))
			start := f.expect(http.StatusOK, f.post("/passkeys/login/begin", nil))
			var assertion protocol.CredentialAssertion
			require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
			passkey := f.expect(http.StatusOK, f.post("/passkeys/login/finish", json.RawMessage(authenticator.Assert(t, &assertion, 1))))
			f.session(passkey.tokens(), "swk", "mfa")
		})
	}
}

func TestEmailOnlyFactorCannotSatisfyRequiredMFAAndCanUpgradeToUVPasskey(t *testing.T) {
	f := passkeyEnrollmentFlow(t)
	user := newUser(t, f.engine, "legacyemail")
	_, err := f.engine.enableFactor(t.Context(), user.ID, "email", nil, authflow.FirstFactorOnly)
	require.NoError(t, err)
	require.ErrorIs(t, f.engine.requireUserMFAEnrollment(t.Context(), f.engine.pg, user.ID), iam.ErrTwoFAEnrollmentRequired)
	grant := pendingPasskeyEnrollment(t, f, *user.Email, testPassword)
	creation := beginMandatoryKey(t, f, grant)
	authenticator := passkeytest.New(t, "https://app.example")
	done := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/enroll/finish", grant.AccessToken, json.RawMessage(authenticator.Register(t, creation))))
	f.session(done.tokens(), "pwd", "swk", "mfa")
	require.NoError(t, f.engine.requireUserMFAEnrollment(t.Context(), f.engine.pg, user.ID))
	status := authflow.MFAStatus{Enabled: true, Satisfied: true}
	require.Error(t, f.engine.requireSessionMFAStateOn(t.Context(), f.engine.pg, user.ID, []string{"pwd", "email", "otp", "mfa"}, status, nil), "a legacy email-MFA token cannot use newly privileged authority")
	require.NoError(t, f.engine.requireSessionMFAStateOn(t.Context(), f.engine.pg, user.ID, []string{"swk", "mfa"}, status, nil))
}

func TestStrongerMFAPolicyRetiresLegacyDelegationsWithoutRefusingStartup(t *testing.T) {
	f := newCredentialFixture(t)
	require.NoError(t, f.e.markEmailVerified(t.Context(), f.founder.ID))
	_, err := f.e.enableFactor(t.Context(), f.founder.ID, "email", nil, authflow.FirstFactorOnly)
	require.NoError(t, err)
	issued := f.issue(t, f.founder, "member", false)
	cfg := credentialConfig(credentialRoles(false))
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	cfg.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP, iam.TwoFactorSMS}
	current := newTestEngine(t, cfg, config.Deps{Postgres: f.pool})
	requireCredentialsCovered(t, current)
	f.requireDead(t, issued)
}

func TestMFACatalogFingerprintUsesConfiguredPolicyNotDeliveryHealth(t *testing.T) {
	engine := &Engine{cfg: testConfig()}
	engine.cfg.TwoFactor.Mode = iam.TwoFactorOptional
	engine.cfg.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP}
	original := engine.roleCatalogFingerprint()
	engine.cfg.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorSMS}
	configured := engine.roleCatalogFingerprint()
	require.NotEqual(t, original, configured)
	engine.smsHealth.set(time.Now(), errors.New("provider outage"))
	require.Equal(t, configured, engine.roleCatalogFingerprint(), "delivery failures must not change enrollment policy or revoke delegations")
}
