package embedded

import (
	context "context"
	crypto "crypto"
	protocol "github.com/go-webauthn/webauthn/protocol"
	pgxpool "github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	siws "github.com/open-rails/authkit/internal/siws"
	jwtkit "github.com/open-rails/authkit/jwtkit"
	oidckit "github.com/open-rails/authkit/oidckit"
	verify "github.com/open-rails/authkit/verify"
	net "net"
	time "time"
)

// HTTPBackend is a local transport construction capability supplied only to
// HTTPConfiguration.BuildHTTP. It is not the portable application Client, and
// Runtime deliberately provides no accessor for it.
type HTTPBackend interface {
	authkit.Client
	verify.Enricher
	AssignGroupRoleFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, subject authkit.Subject, role authkit.Role) error
	RemoveGroupSubjectFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, subject authkit.Subject) error
	CheckDelegatedGrant(ctx context.Context, userID string, permissions []string) error
	RevokeAPIKeyFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, tokenID string) (bool, error)
	RevokeGroupInviteLinkFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, linkID string) error
	AdminRevokeAccountSessionsAs(ctx context.Context, actorUserID, userID string) (authkit.AccountSessionRevocation, error)
	UnbanUserAs(ctx context.Context, actorUserID, userID string) error
	RequireProvenContact(ctx context.Context, userID string) error
	AssignRemoteApplicationRoleAs(ctx context.Context, actorUserID string, group authkit.GroupRef, appSlug string, role authkit.Role) error
	BeginDeviceKeyEnrollment(ctx context.Context, email, publicKey, label string) (DeviceKeyChallenge, error)
	BeginDeviceKeyLogin(ctx context.Context, deviceKeyID string) (DeviceKeyChallenge, error)
	BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, error)
	BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error)
	BeginTwoFactorEnrollment(ctx context.Context, userID string, enrollmentToken bool, sessionID string) (TwoFactorEnrollmentScope, error)
	ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error
	CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error)
	CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error)
	CheckSMSHealth(ctx context.Context) error
	CheckUserPassword(ctx context.Context, userID, pass string) error
	ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error)
	CompleteExternalLogin(ctx context.Context, in ExternalLoginInput) (LoginOutcome, error)
	CompleteLoginChallenge(ctx context.Context, in LoginChallengeInput) (LoginOutcome, error)
	Config() Config
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error)
	ConfirmVerification(ctx context.Context, in VerificationInput) (LoginOutcome, error)
	ContinueRefreshMFA(ctx context.Context, userID, sessionID string) (LoginOutcome, error)
	CreateAccountRegistrationInvite(ctx context.Context, req CreateAccountRegistrationInviteRequest) (AccountRegistrationInviteCreated, error)
	CreateInstanceForSubject(ctx context.Context, group authkit.GroupRef, displayName, ownerUserID string) (CreateInstanceResult, error)
	DefineGroupCustomRole(ctx context.Context, actorUserID string, group authkit.GroupRef, def authkit.CustomRoleDef) error
	DelegationAuthorizer() DelegationAuthorizer
	DeleteGroupCustomRole(ctx context.Context, actorUserID string, group authkit.GroupRef, role authkit.Role) error
	DeletePasskey(ctx context.Context, userID, id string) error
	DeletePendingPhoneRegistrationByPhone(ctx context.Context, phone string) error
	DeletePendingRegistrationByEmail(ctx context.Context, email string) error
	DeleteRemoteApplication(ctx context.Context, issuer string) error
	DeleteRemoteApplicationFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, slug string) error
	UpsertRemoteApplicationFromClaims(ctx context.Context, claims verify.Claims, group authkit.GroupRef, in authkit.RemoteApplication) (*authkit.RemoteApplication, error)
	Disable2FAFactorWithRemovedRoles(ctx context.Context, userID, factorID string) ([]RemovedMFARoleAssignment, error)
	Disable2FAWithRemovedRoles(ctx context.Context, userID string) ([]RemovedMFARoleAssignment, error)
	EnrollTwoFactor(ctx context.Context, in TwoFactorEnrollInput) (TwoFactorEnrollOutcome, error)
	ExchangeRefreshToken(ctx context.Context, refreshToken string, ua string, ip net.IP) (idToken string, expiresAt time.Time, newRefresh string, err error)
	FinishDeviceKeyEnrollment(ctx context.Context, enrollmentID, code, signature, secondFactor string) (DeviceKeyAuthResult, error)
	FinishDeviceKeyLogin(ctx context.Context, challengeID, signature string) (DeviceKeyAuthResult, error)
	FinishPasskeyLogin(ctx context.Context, response []byte, userAgent string, ip net.IP) (LoginOutcome, error)
	ConfirmAccountRecovery(ctx context.Context, token string) error
	FinishPasskeyRegistration(ctx context.Context, userID string, response []byte) (Passkey, error)
	GenerateSIWSChallenge(ctx context.Context, domain, address, username string) (siws.SignInInput, error)
	Get2FASettings(ctx context.Context, userID string) (*TwoFactorSettings, error)
	GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*PendingRegistration, error)
	GetPendingRegistrationByEmail(ctx context.Context, email string) (*PendingRegistration, error)
	GetPreferredLanguage(ctx context.Context, userID string) (PreferredLanguage, error)
	GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error)
	GetRemoteApplicationBySlug(ctx context.Context, slug string) (*RemoteApplication, error)
	GroupNamingState(ctx context.Context, id string) (authkit.NamingState, error)
	HasEmailSender() bool
	HasPassword(ctx context.Context, userID string) (bool, error)
	HasProviderLink(ctx context.Context, userID, issuer, providerSlug string) (bool, error)
	JWKS() jwtkit.JWKS
	LinkSolanaWallet(ctx context.Context, userID string, output siws.SignInOutput) error
	ListDeviceKeys(ctx context.Context, userID, currentID string) ([]DeviceKey, error)
	ListPasskeys(ctx context.Context, userID string) ([]Passkey, error)
	ListRemoteApplicationsForGroup(ctx context.Context, group authkit.GroupRef) ([]RemoteApplication, error)
	ListSessionEvents(ctx context.Context, userID string, eventTypes ...SessionEventType) ([]AuthSessionEvent, error)
	ListUserSessions(ctx context.Context, userID string) ([]Session, error)
	LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string)
	MarkSessionAuthenticated(ctx context.Context, userID, sessionID string) error
	MarkSessionAuthenticatedWithMethods(ctx context.Context, userID, sessionID string, authMethods []string) error
	MintDelegatedAccessToken(ctx context.Context, p DelegatedAccessParams) (string, error)
	NamingPolicy() authkit.NamingPolicy
	PasskeysEnabled() bool
	PasswordLogin(ctx context.Context, in PasswordLoginInput) (LoginOutcome, error)
	PasswordlessLogin(ctx context.Context, in PasswordlessLoginInput) (LoginOutcome, error)
	PermissionGroupSchema() *GroupSchema
	Postgres() *pgxpool.Pool
	ProviderSlugs(ctx context.Context, userID string) ([]string, error)
	PublicKeysByKID() map[string]crypto.PublicKey
	PublicNativeUserRegistrationEnabled() bool
	RecordFailedDeviceKeyEnrollment(ctx context.Context, enrollmentID string)
	RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (RedeemGroupInviteLinkResult, error)
	PutOIDCState(ctx context.Context, state string, data oidckit.StateData) error
	ConsumeOIDCState(ctx context.Context, state string) (oidckit.StateData, bool, error)
	RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error)
	Register(ctx context.Context, in RegisterInput) (RegisterOutcome, error)
	RegisterApplicationFromDomain(ctx context.Context, domain string) (*RegisteredApplication, error)
	RegistrationVerificationEnabled() bool
	RenamePasskey(ctx context.Context, userID, id, label string) error
	RequestEmailChange(ctx context.Context, userID, newEmail string) error
	RequestEmailVerification(ctx context.Context, email string, ttl time.Duration) error
	RequestPasswordReset(ctx context.Context, email string, ttl time.Duration, ip *string, ua *string) error
	RequestPhoneChange(ctx context.Context, userID, newPhone string) error
	RequestPhonePasswordReset(ctx context.Context, phone string, ttl time.Duration, ip *string, ua *string) error
	RequestPhoneVerification(ctx context.Context, phone string, ttl time.Duration) error
	Require2FAForStepUpMethod(ctx context.Context, userID, sessionID, method string) (destination, selectedMethod string, factor TwoFactorFactor, err error)
	ResendLoginChallenge(ctx context.Context, userID, nonce, factorID string) (*TwoFactorChallenge, error)
	ResendRegistration(ctx context.Context, identifier string) (bool, error)
	RevokeDeviceKey(ctx context.Context, userID, currentID, targetID string) error
	RevokeIssuerSessions(ctx context.Context, userID string, keepSessionID *string) error
	RevokeOtherDeviceKeys(ctx context.Context, userID, currentID string) error
	RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error
	SMSAvailable() bool
	SMSHealthy() bool
	Schema() string
	SendWelcome(ctx context.Context, userID string)
	SessionFreshness(ctx context.Context, userID, sessionID string, now time.Time) (SessionFreshness, error)
	SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error
	SetPreferredLanguage(ctx context.Context, userID, language string) error
	SoftDeleteUser(ctx context.Context, id string) error
	SoftDeleteUserAs(ctx context.Context, actorUserID, userID string) error
	RestoreUserAs(ctx context.Context, actorUserID, userID string) error
	StartPasswordless(ctx context.Context, req PasswordlessStartRequest) (PasswordlessStartResult, error)
	TwoFactorAllowedMethods() []string
	TwoFactorEnabled() bool
	UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error)
	UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update authkit.GroupInstanceUpdate) (authkit.GroupInstance, error)
	UserNamingState(ctx context.Context, id string) (authkit.NamingState, error)
	UserProfile(ctx context.Context, in ProfileInput) (authkit.UserProfile, error)
	ValidatePassword(value string, identifiers ...string) error
	ValidateUsername(username string) error
	ValidateUsernameForRegistration(ctx context.Context, username string) (string, error)
	ValidateVerificationConfiguration() error
	Verify2FAStepUpMethodCode(ctx context.Context, userID, sessionID, method, code string) (bool, error)
	VerifyBackupCode(ctx context.Context, userID, backupCode string) (bool, error)
	VerifyPendingPassword(ctx context.Context, email, pass string) bool
	VerifyPendingPhonePassword(ctx context.Context, phone, pass string) bool
	VerifySIWSAndLogin(ctx context.Context, output siws.SignInOutput, extra map[string]any) (LoginOutcome, error)
}
