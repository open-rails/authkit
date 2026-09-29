package httpapi

import (
	"context"
	"net"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/oidcstate"
	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/jwtkit"
)

// flowsBackend is the login, registration, 2FA, passkey, SIWS, OIDC,
// device-key, password and contact-verification flows.
type flowsBackend interface {
	RequireProvenContact(ctx context.Context, userID string) error
	BeginDeviceKeyEnrollment(ctx context.Context, email, publicKey, label string) (authflow.DeviceKeyChallenge, error)
	BeginDeviceKeyLogin(ctx context.Context, deviceKeyID string) (authflow.DeviceKeyChallenge, error)
	BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, error)
	BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error)
	BeginTwoFactorEnrollment(ctx context.Context, userID string, enrollmentToken bool, sessionID string) (authflow.TwoFactorEnrollmentScope, error)
	ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error
	CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error)
	CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error)
	CheckUserPassword(ctx context.Context, userID, pass string) error
	CompleteExternalLogin(ctx context.Context, in authflow.ExternalLoginInput) (authflow.LoginOutcome, error)
	CompleteLoginChallenge(ctx context.Context, in authflow.LoginChallengeInput) (authflow.LoginOutcome, error)
	Settings() authflow.Settings
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error)
	ConfirmVerification(ctx context.Context, in authflow.VerificationInput) (authflow.LoginOutcome, error)
	ContinueRefreshMFA(ctx context.Context, userID, sessionID string) (authflow.LoginOutcome, error)
	DeletePasskey(ctx context.Context, userID, id string) error
	DeletePendingPhoneRegistrationByPhone(ctx context.Context, phone string) error
	DeletePendingRegistrationByEmail(ctx context.Context, email string) error
	Disable2FAFactorWithRemovedRoles(ctx context.Context, userID, factorID string) ([]authflow.RemovedMFARoleAssignment, error)
	Disable2FAWithRemovedRoles(ctx context.Context, userID string) ([]authflow.RemovedMFARoleAssignment, error)
	EnrollTwoFactor(ctx context.Context, in authflow.TwoFactorEnrollInput) (authflow.TwoFactorEnrollOutcome, error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (idToken string, expiresAt time.Time, newRefresh string, err error)
	FinishDeviceKeyEnrollment(ctx context.Context, enrollmentID, code, signature, secondFactor string) (authflow.DeviceKeyAuthResult, error)
	FinishDeviceKeyLogin(ctx context.Context, challengeID, signature string) (authflow.DeviceKeyAuthResult, error)
	FinishPasskeyLogin(ctx context.Context, response []byte, userAgent string, ip net.IP) (authflow.LoginOutcome, error)
	ConfirmAccountRecovery(ctx context.Context, token string) error
	FinishPasskeyRegistration(ctx context.Context, userID string, response []byte) (authflow.Passkey, error)
	GenerateSIWSChallenge(ctx context.Context, domain, address, username string) (siws.SignInInput, error)
	Get2FASettings(ctx context.Context, userID string) (*authflow.TwoFactorSettings, error)
	GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error)
	HasEmailSender() bool
	HasPassword(ctx context.Context, userID string) (bool, error)
	HasProviderLink(ctx context.Context, userID, issuer, providerSlug string) (bool, error)
	JWKS() jwtkit.JWKS
	LinkSolanaWallet(ctx context.Context, userID string, output siws.SignInOutput) error
	ListPasskeys(ctx context.Context, userID string) ([]authflow.Passkey, error)
	LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string)
	MarkSessionAuthenticated(ctx context.Context, userID, sessionID string) error
	MarkSessionAuthenticatedWithMethods(ctx context.Context, userID, sessionID string, authMethods []string) error
	NamingPolicy() iam.NamingPolicy
	PasskeysEnabled() bool
	PasswordLogin(ctx context.Context, in authflow.PasswordLoginInput) (authflow.LoginOutcome, error)
	PasswordlessLogin(ctx context.Context, in authflow.PasswordlessLoginInput) (authflow.LoginOutcome, error)
	ProviderSlugs(ctx context.Context, userID string) ([]string, error)
	PublicNativeUserRegistrationEnabled() bool
	RecordFailedDeviceKeyEnrollment(ctx context.Context, enrollmentID string)
	PutOIDCState(ctx context.Context, state string, data oidcstate.StateData) error
	ConsumeOIDCState(ctx context.Context, state string) (oidcstate.StateData, bool, error)
	RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error)
	Register(ctx context.Context, in authflow.RegisterInput) (authflow.RegisterOutcome, error)
	RegistrationVerificationEnabled() bool
	RenamePasskey(ctx context.Context, userID, id, label string) error
	RequestEmailChange(ctx context.Context, userID, newEmail string) error
	RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error
	RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error
	RequestPhoneChange(ctx context.Context, userID, newPhone string) error
	RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error
	RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error
	Require2FAForStepUpMethod(ctx context.Context, userID, sessionID, method string) (destination, selectedMethod string, factor authflow.TwoFactorFactor, err error)
	ResendLoginChallenge(ctx context.Context, userID, nonce, factorID string) (*authflow.TwoFactorChallenge, error)
	ResendRegistration(ctx context.Context, identifier string) (bool, error)
	SMSAvailable() bool
	SendWelcome(ctx context.Context, userID string)
	SessionFreshness(ctx context.Context, userID, sessionID string, now time.Time) (authflow.SessionFreshness, error)
	SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error
	StartPasswordless(ctx context.Context, req authflow.PasswordlessStartRequest) (authflow.PasswordlessStartResult, error)
	TwoFactorAllowedMethods() []string
	TwoFactorEnabled() bool
	UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error)
	ValidatePassword(value string, identifiers ...string) error
	ValidateUsername(username string) error
	ValidateUsernameForRegistration(ctx context.Context, username string) (string, error)
	ValidateVerificationConfiguration() error
	Verify2FAStepUpMethodCode(ctx context.Context, userID, sessionID, method, code string) (bool, error)
	VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error)
	VerifyPendingPassword(ctx context.Context, email, pass string) bool
	VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool
	VerifySIWSAndLogin(ctx context.Context, output siws.SignInOutput, extra map[string]any) (authflow.LoginOutcome, error)
}
