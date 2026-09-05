package authcore

// Engine-level pins for the login / register / external-login / 2FA-enrollment
// outcome types (ak#318): every branch of each closed outcome set, against the
// real Postgres store and the memory ephemeral store, with no HTTP in the loop.

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	memorystore "github.com/open-rails/authkit/internal/storage/memory"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

type flowEmailSender struct {
	mu       sync.Mutex
	codes    map[string]string
	welcomes []string
	fail     error
}

func (f *flowEmailSender) SendVerification(_ context.Context, email, _ string, msg VerificationMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return f.fail
	}
	if f.codes == nil {
		f.codes = map[string]string{}
	}
	f.codes[email] = msg.Code
	return nil
}
func (f *flowEmailSender) SendPasswordResetLink(context.Context, string, string, string) error {
	return nil
}
func (f *flowEmailSender) SendAccountRegistrationInvite(context.Context, string, string) error {
	return nil
}
func (f *flowEmailSender) SendLoginCode(context.Context, string, string, string) error { return nil }
func (f *flowEmailSender) SendWelcome(_ context.Context, email, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.welcomes = append(f.welcomes, email)
	return nil
}
func (f *flowEmailSender) SendContactChanged(context.Context, string, string, ContactChange) error {
	return nil
}
func (f *flowEmailSender) SendDeviceKeyEnrolled(context.Context, string, string, DeviceKeyNotice) error {
	return nil
}
func (f *flowEmailSender) code(email string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codes[email]
}

type flowSMSSender struct {
	mu    sync.Mutex
	codes map[string]string
}

func (f *flowSMSSender) SendVerification(_ context.Context, phone string, msg VerificationMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codes == nil {
		f.codes = map[string]string{}
	}
	f.codes[phone] = msg.Code
	return nil
}
func (f *flowSMSSender) SendPasswordResetLink(context.Context, string, string) error { return nil }
func (f *flowSMSSender) SendLoginCode(_ context.Context, phone, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.codes == nil {
		f.codes = map[string]string{}
	}
	f.codes[phone] = code
	return nil
}
func (f *flowSMSSender) SendContactChanged(context.Context, string, ContactChange) error { return nil }
func (f *flowSMSSender) code(phone string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.codes[phone]
}

type flowHarness struct {
	svc   *Service
	pool  *pgxpool.Pool
	email *flowEmailSender
	sms   *flowSMSSender
}

func newFlowHarness(t *testing.T, mutate func(*Config)) *flowHarness {
	t.Helper()
	pool := testdb.Pool(t)
	signer, err := jwtkit.NewEd25519Signer("flow-test")
	require.NoError(t, err)
	cfg := Config{
		Token:        TokenConfig{Issuer: "https://test", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}, AccessTokenDuration: time.Hour, RefreshTokenDuration: 24 * time.Hour},
		Registration: RegistrationConfig{Verification: RegistrationVerificationNone, NativeUserMode: RegistrationModeOpen},
		TwoFactor:    TwoFactorConfig{Mode: TwoFactorOptional, TOTPSecretKey: []byte("0123456789abcdef0123456789abcdef")},
		Ephemeral:    EphemeralConfig{AllowMemory: true},
	}
	if mutate != nil {
		mutate(&cfg)
	}
	h := &flowHarness{pool: pool, email: &flowEmailSender{}, sms: &flowSMSSender{}}
	h.svc = mustNewService(t, cfg, Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"flow-test": signer.PublicKey()}},
		WithPostgres(pool), WithEphemeralStore(memorystore.NewKV()), WithEmailSender(h.email), WithSMSSender(h.sms))
	return h
}

func flowSuffix() string { return fmt.Sprint(time.Now().UnixNano()) }

// passwordUser creates a verified, password-backed account.
func (h *flowHarness) passwordUser(t *testing.T, tag, pass string) (*User, string) {
	t.Helper()
	ctx := context.Background()
	suffix := flowSuffix()
	email := tag + "-" + suffix + "@example.com"
	u, err := h.svc.CreateUser(ctx, email, tag+suffix)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = h.pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	phc, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, h.svc.UpsertPasswordHash(ctx, u.ID, phc, "argon2id", nil))
	require.NoError(t, h.svc.MarkEmailVerified(ctx, u.ID))
	return u, email
}

func TestPasswordLoginOutcomes_DB(t *testing.T) {
	ctx := context.Background()
	const pass = "Correct-horse-battery-1"

	t.Run("session issued by email and by username", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		u, email := h.passwordUser(t, "login-ok", pass)
		for _, identifier := range []string{email, *u.Username} {
			out, err := h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: identifier, Password: pass, UserAgent: "ua", IP: "203.0.113.9"})
			require.NoError(t, err)
			require.Equal(t, LoginSessionIssued, out.Kind, identifier)
			require.Equal(t, u.ID, out.UserID)
			require.NotEmpty(t, out.Session.AccessToken)
			require.NotEmpty(t, out.Session.RefreshToken)
			require.NotEmpty(t, out.Session.SessionID)
		}
	})

	t.Run("rejected: unknown identifier, wrong password, banned", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		u, email := h.passwordUser(t, "login-rej", pass)
		out, err := h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: "nobody-" + flowSuffix() + "@example.com", Password: pass})
		require.NoError(t, err)
		require.Equal(t, LoginRejected, out.Kind)
		require.ErrorIs(t, out.Reason, ErrInvalidCredentials)

		out, err = h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: "wrong-" + pass})
		require.NoError(t, err)
		require.Equal(t, LoginRejected, out.Kind)
		require.ErrorIs(t, out.Reason, ErrInvalidCredentials)
		require.Equal(t, u.ID, out.UserID)

		require.NoError(t, h.svc.BanUser(ctx, u.ID, nil, nil, u.ID))
		out, err = h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: pass})
		require.NoError(t, err)
		require.Equal(t, LoginRejected, out.Kind)
		require.ErrorIs(t, out.Reason, ErrUserBanned)
	})

	t.Run("verification required parks an unverified account after the password checks", func(t *testing.T) {
		h := newFlowHarness(t, func(c *Config) { c.Registration.Verification = RegistrationVerificationRequired })
		u, email := h.passwordUser(t, "login-unverified", pass)
		require.NoError(t, h.svc.ClearEmailVerified(ctx, u.ID))

		out, err := h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: "wrong-" + pass})
		require.NoError(t, err)
		require.Equal(t, LoginRejected, out.Kind, "the password gate runs before any send")
		require.Empty(t, h.email.code(email), "no code for a wrong password")

		out, err = h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: pass})
		require.NoError(t, err)
		require.Equal(t, LoginVerificationRequired, out.Kind)
		require.Equal(t, &VerificationRequired{Identifier: email, Channel: "email"}, out.Verification)
		require.NotEmpty(t, h.email.code(email), "a fresh verification code was sent")

		h.email.fail = fmt.Errorf("%w: smtp down", authkit.ErrEmailDeliveryFailed)
		_, err = h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: pass})
		require.ErrorIs(t, err, ErrEmailVerificationSendFailed)
		require.ErrorIs(t, err, authkit.ErrEmailDeliveryFailed, "the delivery sentinel stays visible")
		var fe *FlowError
		require.ErrorAs(t, err, &fe)
		require.Equal(t, "send_email_verification", fe.Stage)
	})

	t.Run("pending email registration recovers into verification required", func(t *testing.T) {
		h := newFlowHarness(t, func(c *Config) { c.Registration.Verification = RegistrationVerificationRequired })
		suffix := flowSuffix()
		email := "login-pending-" + suffix + "@example.com"
		phc, err := password.HashArgon2id(pass)
		require.NoError(t, err)
		_, err = h.svc.CreatePendingRegistrationWithLanguage(ctx, email, "pending"+suffix, phc, 0, "")
		require.NoError(t, err)

		out, err := h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: "wrong-" + pass})
		require.NoError(t, err)
		require.Equal(t, LoginRejected, out.Kind)

		out, err = h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: pass})
		require.NoError(t, err)
		require.Equal(t, LoginVerificationRequired, out.Kind)
		require.Equal(t, "email", out.Verification.Channel)
	})

	t.Run("two-factor required issues a challenge", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		u, email := h.passwordUser(t, "login-2fa", pass)
		_, err := h.svc.Enable2FA(ctx, u.ID, "email", nil, AllowAdditionalFactors)
		require.NoError(t, err)

		out, err := h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: pass})
		require.NoError(t, err)
		require.Equal(t, LoginTwoFactorRequired, out.Kind)
		require.Equal(t, u.ID, out.UserID)
		require.Equal(t, "email", out.Challenge.Method)
		require.NotEmpty(t, out.Challenge.Challenge)
		require.Len(t, out.Challenge.Factors, 1)
		ok, err := h.svc.Verify2FAChallenge(ctx, u.ID, out.Challenge.Challenge)
		require.NoError(t, err)
		require.True(t, ok, "the challenge is the one the 2FA verify step consumes")
	})

	t.Run("two-factor enrollment required under a mandatory-MFA deployment", func(t *testing.T) {
		h := newFlowHarness(t, func(c *Config) { c.TwoFactor.Mode = TwoFactorRequired })
		u, email := h.passwordUser(t, "login-enroll", pass)
		out, err := h.svc.PasswordLogin(ctx, PasswordLoginInput{Identifier: email, Password: pass})
		require.NoError(t, err)
		require.Equal(t, LoginTwoFAEnrollmentRequired, out.Kind)
		require.Equal(t, u.ID, out.UserID)
		require.Nil(t, out.Session)
	})
}

func TestRegisterOutcomes_DB(t *testing.T) {
	ctx := context.Background()
	const pass = "Correct-horse-battery-1"
	cleanupEmail := func(t *testing.T, h *flowHarness, email string) {
		t.Cleanup(func() { _, _ = h.pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1`, email) })
	}

	t.Run("verification required: verify_email with a code sent", func(t *testing.T) {
		h := newFlowHarness(t, func(c *Config) { c.Registration.Verification = RegistrationVerificationRequired })
		suffix := flowSuffix()
		email := "reg-verify-" + suffix + "@example.com"
		cleanupEmail(t, h, email)
		out, err := h.svc.Register(ctx, RegisterInput{Identifier: email, Username: "regverify" + suffix, Password: pass})
		require.NoError(t, err)
		require.Equal(t, RegisterVerifyEmail, out.Kind)
		require.Equal(t, email, *out.Email)
		require.Nil(t, out.Session)
		require.NotEmpty(t, h.email.code(email))
	})

	t.Run("no verification: session issued", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		suffix := flowSuffix()
		email := "reg-session-" + suffix + "@example.com"
		cleanupEmail(t, h, email)
		out, err := h.svc.Register(ctx, RegisterInput{Identifier: email, Username: "regsession" + suffix, Password: pass, UserAgent: "ua", IP: "203.0.113.9"})
		require.NoError(t, err)
		require.Equal(t, RegisterSessionIssued, out.Kind)
		require.NotEmpty(t, out.Session.AccessToken)
		require.Equal(t, "regsession"+suffix, out.Username)
	})

	t.Run("phone: verify_phone with an SMS code", func(t *testing.T) {
		h := newFlowHarness(t, func(c *Config) { c.Registration.Verification = RegistrationVerificationRequired })
		suffix := flowSuffix()
		phone := "+1555" + suffix[len(suffix)-7:]
		out, err := h.svc.Register(ctx, RegisterInput{Identifier: phone, Username: "regphone" + suffix, Password: pass})
		require.NoError(t, err)
		require.Equal(t, RegisterVerifyPhone, out.Kind)
		require.Equal(t, phone, *out.Phone)
		require.NotEmpty(t, h.sms.code(phone))
	})

	t.Run("input errors are sentinels", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		u, email := h.passwordUser(t, "regtaken", pass)
		suffix := flowSuffix()
		cases := []struct {
			name string
			in   RegisterInput
			want error
		}{
			{"email in use", RegisterInput{Identifier: email, Username: "fresh" + suffix, Password: pass}, ErrEmailInUse},
			{"not an email or phone", RegisterInput{Identifier: "not-an-identifier", Username: "fresh" + suffix, Password: pass}, authkit.ErrInvalidIdentifier},
			{"empty identifier", RegisterInput{Identifier: " ", Username: "fresh" + suffix, Password: pass}, authkit.ErrInvalidIdentifier},
		}
		for _, tc := range cases {
			_, err := h.svc.Register(ctx, tc.in)
			require.ErrorIs(t, err, tc.want, tc.name)
		}
		_, err := h.svc.Register(ctx, RegisterInput{Identifier: "fresh-" + suffix + "@example.com", Username: "fresh" + suffix, Password: "short"})
		require.NotEmpty(t, ValidationErrorCode(err), "a weak password is a validation code")
		_, err = h.svc.Register(ctx, RegisterInput{Identifier: "fresh-" + suffix + "@example.com", Username: *u.Username, Password: pass})
		require.Equal(t, "owner_slug_taken", ValidationErrorCode(err), "a taken username fails the claim check first")
	})

	t.Run("closed registration and a missing sender", func(t *testing.T) {
		closed := newFlowHarness(t, func(c *Config) { c.Registration.NativeUserMode = RegistrationModeClosed })
		suffix := flowSuffix()
		_, err := closed.svc.Register(ctx, RegisterInput{Identifier: "closed-" + suffix + "@example.com", Username: "closed" + suffix, Password: pass})
		require.ErrorIs(t, err, ErrRegistrationDisabled)

		noSender := mustNewService(t, Config{
			Token:        TokenConfig{Issuer: "https://test"},
			Registration: RegistrationConfig{Verification: RegistrationVerificationRequired, NativeUserMode: RegistrationModeOpen, AllowMissingSenders: true},
			Ephemeral:    EphemeralConfig{AllowMemory: true},
		}, Keyset{}, WithPostgres(closed.pool), WithEphemeralStore(memorystore.NewKV()))
		_, err = noSender.Register(ctx, RegisterInput{Identifier: "nosender-" + suffix + "@example.com", Username: "nosender" + suffix, Password: pass})
		require.ErrorIs(t, err, authkit.ErrEmailRegistrationUnavailable)
		_, err = noSender.Register(ctx, RegisterInput{Identifier: "+1555" + suffix[len(suffix)-7:], Username: "nosender" + suffix, Password: pass})
		require.ErrorIs(t, err, authkit.ErrPhoneRegistrationUnavailable)
	})
}

func TestExternalLoginOutcomes_DB(t *testing.T) {
	ctx := context.Background()
	identity := func(tag, suffix string, verified bool) ExternalIdentity {
		return ExternalIdentity{Provider: "github", Issuer: "https://github.com", Subject: tag + "-" + suffix, Email: tag + "-" + suffix + "@example.com", EmailVerified: verified, PreferredUsername: tag + suffix}
	}
	cleanupUser := func(t *testing.T, h *flowHarness, id string) {
		t.Cleanup(func() { _, _ = h.pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id) })
	}

	t.Run("fresh identity: account created, welcome sent, session issued; second login reuses it", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		id := identity("ext-new", flowSuffix(), true)
		out, err := h.svc.CompleteExternalLogin(ctx, ExternalLoginInput{Identity: id, Event: "oidc_login", UserAgent: "ua", IP: "203.0.113.9"})
		require.NoError(t, err)
		cleanupUser(t, h, out.UserID)
		require.Equal(t, ExternalSessionIssued, out.Kind)
		require.True(t, out.Created)
		require.NotEmpty(t, out.Session.AccessToken)
		require.Contains(t, h.email.welcomes, id.Email)

		again, err := h.svc.CompleteExternalLogin(ctx, ExternalLoginInput{Identity: id, Event: "oidc_login"})
		require.NoError(t, err)
		require.False(t, again.Created)
		require.Equal(t, out.UserID, again.UserID)
	})

	t.Run("existing local email refuses a silent link; the authenticated link flow binds it", func(t *testing.T) {
		h := newFlowHarness(t, nil)
		victim, email := h.passwordUser(t, "ext-victim", "Correct-horse-battery-1")
		id := ExternalIdentity{Provider: "github", Issuer: "https://github.com", Subject: "attacker-" + flowSuffix(), Email: email, EmailVerified: true}
		_, err := h.svc.CompleteExternalLogin(ctx, ExternalLoginInput{Identity: id})
		require.ErrorIs(t, err, ErrAccountExistsLinkRequired)
		linked, _, _ := h.svc.GetProviderLinkByIssuer(ctx, id.Issuer, id.Subject)
		require.Empty(t, linked)

		out, err := h.svc.CompleteExternalLogin(ctx, ExternalLoginInput{Identity: id, LinkUserID: victim.ID, Event: "oidc_login"})
		require.NoError(t, err)
		require.Equal(t, victim.ID, out.UserID)
		require.False(t, out.Created)
	})

	t.Run("closed registration blocks auto-create", func(t *testing.T) {
		closed := newFlowHarness(t, func(c *Config) { c.Registration.NativeUserMode = RegistrationModeClosed })
		_, err := closed.svc.CompleteExternalLogin(ctx, ExternalLoginInput{Identity: identity("ext-closed", flowSuffix(), true)})
		require.ErrorIs(t, err, ErrRegistrationDisabled)
	})

	t.Run("enrollment required under mandatory MFA", func(t *testing.T) {
		mfa := newFlowHarness(t, func(c *Config) { c.TwoFactor.Mode = TwoFactorRequired })
		out, err := mfa.svc.CompleteExternalLogin(ctx, ExternalLoginInput{Identity: identity("ext-mfa", flowSuffix(), true)})
		require.NoError(t, err)
		cleanupUser(t, mfa, out.UserID)
		require.Equal(t, ExternalTwoFAEnrollmentRequired, out.Kind)
		require.True(t, out.Created)
		require.Nil(t, out.Session)
	})
}

func TestTwoFactorEnrollOutcomes_DB(t *testing.T) {
	ctx := context.Background()
	h := newFlowHarness(t, nil)
	u, _ := h.passwordUser(t, "enroll", "Correct-horse-battery-1")

	scope, err := h.svc.BeginTwoFactorEnrollment(ctx, u.ID, false, "")
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollmentScope{Mode: AllowAdditionalFactors}, scope)

	_, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "carrier-pigeon"})
	require.ErrorIs(t, err, ErrInvalidTwoFAMethod)
	_, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "sms"})
	require.ErrorIs(t, err, ErrPhoneNumberRequired)
	_, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "sms", PhoneNumber: "5551234567"})
	require.ErrorIs(t, err, ErrPhoneNumberMustBeE164)

	// SMS: the setup code goes out, a wrong code is rejected, the right one enables.
	phone := "+15551230" + flowSuffix()[14:]
	out, err := h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "sms", PhoneNumber: phone})
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollCodeSent, out.Kind)
	code := h.sms.code(phone)
	require.NotEmpty(t, code)
	_, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "sms", PhoneNumber: phone, Code: "000000"})
	require.ErrorIs(t, err, ErrInvalidCode)
	out, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "sms", PhoneNumber: phone, Code: code})
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollEnabled, out.Kind)
	require.Equal(t, "sms", out.Method)
	require.NotEmpty(t, out.BackupCodes, "the first factor mints backup codes")

	// Email enables as an additional factor and can be made the default; a
	// second factor of the same method is a conflict.
	out, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "email"})
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollEnabled, out.Kind)
	require.Empty(t, out.BackupCodes, "backup codes are minted once")
	_, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "email"})
	require.ErrorIs(t, err, ErrTwoFAFactorExists)
	settings, err := h.svc.Get2FASettings(ctx, u.ID)
	require.NoError(t, err)
	var emailFactor TwoFactorFactor
	for _, f := range settings.Factors {
		if f.Method == "email" {
			emailFactor = f
		}
	}
	require.NotEmpty(t, emailFactor.ID)
	out, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, MakeDefault: true, FactorID: emailFactor.ID})
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollDefaultSet, out.Kind)

	// TOTP: the secret is handed out first; a wrong code is invalid.
	out, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "totp"})
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollTOTPStarted, out.Kind)
	require.NotEmpty(t, out.Secret)
	require.True(t, strings.HasPrefix(out.OTPAuthURI, "otpauth://"))
	_, err = h.svc.EnrollTwoFactor(ctx, TwoFactorEnrollInput{UserID: u.ID, Mode: scope.Mode, Method: "totp", Code: "000000"})
	require.ErrorIs(t, err, ErrInvalidCode)

	// An enrollment-only token may fill the first factor only.
	_, err = h.svc.BeginTwoFactorEnrollment(ctx, u.ID, true, "")
	require.ErrorIs(t, err, ErrTwoFAFactorExists)
	fresh, _ := h.passwordUser(t, "enroll-first", "Correct-horse-battery-1")
	scope, err = h.svc.BeginTwoFactorEnrollment(ctx, fresh.ID, true, "")
	require.NoError(t, err)
	require.Equal(t, TwoFactorEnrollmentScope{Mode: FirstFactorOnly}, scope)
	_, err = h.svc.BeginTwoFactorEnrollment(ctx, fresh.ID, true, "some-session")
	require.ErrorIs(t, err, ErrTwoFAFactorExists, "a full session must not use the enrollment-only path")
}

func TestUserProfileProjection_DB(t *testing.T) {
	ctx := context.Background()
	h := newFlowHarness(t, nil)
	u, email := h.passwordUser(t, "profile", "Correct-horse-battery-1")
	_, err := h.svc.Enable2FA(ctx, u.ID, "email", nil, AllowAdditionalFactors)
	require.NoError(t, err)
	require.NoError(t, h.svc.LinkProviderByIssuer(ctx, u.ID, "https://github.com", "github", "profile-"+flowSuffix(), nil))

	authTime := time.Now().Add(-time.Minute)
	profile, err := h.svc.UserProfile(ctx, ProfileInput{
		UserID: u.ID, ClaimsUsername: "ignored", AuthTime: authTime, StepUpSatisfied: true,
		EnabledProviders:       []string{"github", "google"},
		ProviderSupportsStepUp: func(p string) bool { return p == "github" },
	})
	require.NoError(t, err)
	require.Equal(t, u.ID, profile.ID)
	require.Equal(t, *u.Username, profile.Username, "the row's username wins over the claim")
	require.Equal(t, email, *profile.Email)
	require.True(t, profile.EmailVerified)
	require.True(t, profile.HasPassword)
	require.Equal(t, []string{"github"}, profile.LinkedProviders)
	require.Equal(t, []string{"github", "google"}, profile.EnabledProviders)
	require.Equal(t, []string{"password", "2fa", "github"}, profile.Security.StepUpMethods)
	require.True(t, profile.Security.MFAEnabled)
	require.False(t, profile.Security.StepUpRequiredForSensitiveActions)
	require.NotNil(t, profile.Security.LastAuthenticatedAt)
	require.NotNil(t, profile.Security.StepUp2FA)
	require.Equal(t, "email", profile.Security.StepUp2FA.DefaultMethod)
	require.Equal(t, MaskDestination(email), profile.Security.StepUp2FA.Options[0].VerificationID)
	require.Len(t, profile.Availability, 1)
	require.Equal(t, authkit.ActionUpdateUsername, profile.Availability[0].Action)

	_, err = h.svc.UserProfile(ctx, ProfileInput{UserID: "00000000-0000-7000-8000-000000000000"})
	var fe *FlowError
	require.ErrorAs(t, err, &fe)
	require.Equal(t, "load_user", fe.Stage)
	require.False(t, errors.Is(err, nil))
}
