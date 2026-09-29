package httpapi

import (
	context "context"
	crypto "crypto"
	net "net"
	time "time"

	protocol "github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/oidcstate"
	"github.com/open-rails/authkit/internal/rbac"
	siws "github.com/open-rails/authkit/internal/siws"
	jwtkit "github.com/open-rails/authkit/jwtkit"
	verify "github.com/open-rails/authkit/verify"
)

// Backend is the engine capability the HTTP layer drives. The engine
// implements it; hosts never see it.
type Backend interface {
	AdminGetUser(ctx context.Context, id string) (*iam.AdminUser, error)
	AdminListUsers(ctx context.Context, opts iam.AdminUserListOptions) (*iam.AdminListUsersResult, error)
	BanUser(ctx context.Context, userID string, reason *string, until *time.Time, bannedBy string) error
	Can(ctx context.Context, subject iam.Subject, group iam.GroupRef, perm iam.Perm) (bool, error)
	CanOnGroup(ctx context.Context, subject iam.Subject, groupID string, perm iam.Perm) (bool, error)
	CreateGroupInviteLink(ctx context.Context, req iam.CreateGroupInviteLinkRequest) (iam.GroupInviteLinkCreated, error)
	GetUserByEmail(ctx context.Context, email string) (*iam.User, error)
	GetUserByPhone(ctx context.Context, phone string) (*iam.User, error)
	GroupInstanceForSlug(ctx context.Context, group iam.GroupRef) (iam.GroupInstance, error)
	ListAPIKeys(ctx context.Context, group iam.GroupRef) ([]iam.APIKey, error)
	ListEffectivePermissions(ctx context.Context, subject iam.Subject, group iam.GroupRef) ([]iam.Perm, error)
	ListGroupInviteLinks(ctx context.Context, group iam.GroupRef) ([]iam.GroupInviteLink, error)
	ListGroupMembers(ctx context.Context, group iam.GroupRef) ([]iam.GroupMember, error)
	ListSubjectGroups(ctx context.Context, subject iam.Subject) ([]iam.SubjectGroupMembership, error)
	MintAccessToken(ctx context.Context, userID string, extra map[string]any) (string, time.Time, error)
	MintAPIKey(ctx context.Context, group iam.GroupRef, opts iam.APIKeyMintOptions) (iam.APIKey, string, error)
	PublicUsersByIDs(ctx context.Context, ids []string) (map[string]iam.PublicUserRef, error)
	UpdateUsername(ctx context.Context, id, username string) error
	verify.Enricher
	AssignGroupRoleFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, subject iam.Subject, role iam.Role) error
	RemoveGroupSubjectFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, subject iam.Subject) error
	CheckDelegatedGrant(ctx context.Context, userID string, permissions []string) error
	RevokeAPIKeyFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, tokenID string) (bool, error)
	RevokeGroupInviteLinkFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, linkID string) error
	AdminRevokeAccountSessionsAs(ctx context.Context, actorUserID, userID string) (iam.AccountSessionRevocation, error)
	UnbanUserAs(ctx context.Context, actorUserID, userID string) error
	RequireProvenContact(ctx context.Context, userID string) error
	AssignRemoteApplicationRoleAs(ctx context.Context, actorUserID string, group iam.GroupRef, appSlug string, role iam.Role) error
	BeginDeviceKeyEnrollment(ctx context.Context, email, publicKey, label string) (authflow.DeviceKeyChallenge, error)
	BeginDeviceKeyLogin(ctx context.Context, deviceKeyID string) (authflow.DeviceKeyChallenge, error)
	BeginPasskeyLogin(ctx context.Context) (*protocol.CredentialAssertion, error)
	BeginPasskeyRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, error)
	BeginTwoFactorEnrollment(ctx context.Context, userID string, enrollmentToken bool, sessionID string) (authflow.TwoFactorEnrollmentScope, error)
	ChangePassword(ctx context.Context, userID, current, new string, keepSessionID *string) error
	CheckPendingRegistrationConflict(ctx context.Context, email, username string) (bool, bool, error)
	CheckPhoneRegistrationConflict(ctx context.Context, phone, username string) (bool, bool, error)
	CheckSMSHealth(ctx context.Context) error
	CheckUserPassword(ctx context.Context, userID, pass string) error
	ClaimDPoPProof(ctx context.Context, key string, ttl time.Duration) (bool, error)
	CompleteExternalLogin(ctx context.Context, in authflow.ExternalLoginInput) (authflow.LoginOutcome, error)
	CompleteLoginChallenge(ctx context.Context, in authflow.LoginChallengeInput) (authflow.LoginOutcome, error)
	Settings() authflow.Settings
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) (string, error)
	ConfirmVerification(ctx context.Context, in authflow.VerificationInput) (authflow.LoginOutcome, error)
	ContinueRefreshMFA(ctx context.Context, userID, sessionID string) (authflow.LoginOutcome, error)
	CreateAccountRegistrationInvite(ctx context.Context, req authflow.CreateAccountRegistrationInviteRequest) (authflow.AccountRegistrationInviteCreated, error)
	CreateInstanceForSubject(ctx context.Context, group iam.GroupRef, displayName, ownerUserID string) (authflow.CreateInstanceResult, error)
	DefineGroupCustomRole(ctx context.Context, actorUserID string, group iam.GroupRef, def authflow.CustomRoleDef) error
	DelegationAuthorizer() iam.DelegationAuthorizer
	DeleteGroupCustomRole(ctx context.Context, actorUserID string, group iam.GroupRef, role iam.Role) error
	DeletePasskey(ctx context.Context, userID, id string) error
	DeletePendingPhoneRegistrationByPhone(ctx context.Context, phone string) error
	DeletePendingRegistrationByEmail(ctx context.Context, email string) error
	DeleteRemoteApplication(ctx context.Context, issuer string) error
	DeleteRemoteApplicationFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, slug string) error
	UpsertRemoteApplicationFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, in iam.RemoteApplication) (*iam.RemoteApplication, error)
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
	GetPendingPhoneRegistrationByPhone(ctx context.Context, phone string) (*authflow.PendingRegistration, error)
	GetPendingRegistrationByEmail(ctx context.Context, email string) (*authflow.PendingRegistration, error)
	GetPreferredLanguage(ctx context.Context, userID string) (authflow.PreferredLanguage, error)
	GetProviderLinkByIssuer(ctx context.Context, issuer, subject string) (string, *string, error)
	GetRemoteApplicationBySlug(ctx context.Context, slug string) (*iam.RemoteApplication, error)
	GroupNamingState(ctx context.Context, id string) (iam.NamingState, error)
	HasEmailSender() bool
	HasPassword(ctx context.Context, userID string) (bool, error)
	HasProviderLink(ctx context.Context, userID, issuer, providerSlug string) (bool, error)
	JWKS() jwtkit.JWKS
	LinkSolanaWallet(ctx context.Context, userID string, output siws.SignInOutput) error
	ListDeviceKeys(ctx context.Context, userID, currentID string) ([]authflow.DeviceKey, error)
	ListPasskeys(ctx context.Context, userID string) ([]authflow.Passkey, error)
	ListRemoteApplicationsForGroup(ctx context.Context, group iam.GroupRef) ([]iam.RemoteApplication, error)
	ListSessionEvents(ctx context.Context, userID string, eventTypes ...authflow.SessionEventType) ([]authflow.AuthSessionEvent, error)
	ListUserSessions(ctx context.Context, userID string) ([]authflow.Session, error)
	LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string)
	MarkSessionAuthenticated(ctx context.Context, userID, sessionID string) error
	MarkSessionAuthenticatedWithMethods(ctx context.Context, userID, sessionID string, authMethods []string) error
	MintDelegatedAccessToken(ctx context.Context, p iam.DelegatedAccessParams) (string, error)
	NamingPolicy() iam.NamingPolicy
	PasskeysEnabled() bool
	PasswordLogin(ctx context.Context, in authflow.PasswordLoginInput) (authflow.LoginOutcome, error)
	PasswordlessLogin(ctx context.Context, in authflow.PasswordlessLoginInput) (authflow.LoginOutcome, error)
	PermissionGroupSchema() *rbac.Schema
	ProviderSlugs(ctx context.Context, userID string) ([]string, error)
	PublicKeysByKID() map[string]crypto.PublicKey
	PublicNativeUserRegistrationEnabled() bool
	RecordFailedDeviceKeyEnrollment(ctx context.Context, enrollmentID string)
	RedeemGroupInviteLink(ctx context.Context, code, redeemerUserID string) (authflow.RedeemGroupInviteLinkResult, error)
	PutOIDCState(ctx context.Context, state string, data oidcstate.StateData) error
	ConsumeOIDCState(ctx context.Context, state string) (oidcstate.StateData, bool, error)
	RegenerateBackupCodes(ctx context.Context, userID string) ([]string, error)
	Register(ctx context.Context, in authflow.RegisterInput) (authflow.RegisterOutcome, error)
	RegisterApplicationFromDomain(ctx context.Context, domain string) (*authflow.RegisteredApplication, error)
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
	RevokeDeviceKey(ctx context.Context, userID, currentID, targetID string) error
	RevokeIssuerSessions(ctx context.Context, userID string, keepSessionID *string) error
	RevokeOtherDeviceKeys(ctx context.Context, userID, currentID string) error
	RevokeSessionByIDForUser(ctx context.Context, userID, sessionID string) error
	SMSAvailable() bool
	SMSHealthy() bool
	SendWelcome(ctx context.Context, userID string)
	SessionFreshness(ctx context.Context, userID, sessionID string, now time.Time) (authflow.SessionFreshness, error)
	SetPasswordAfterFreshAuth(ctx context.Context, userID, new string, keepSessionID *string) error
	SetPreferredLanguage(ctx context.Context, userID, language string) error
	SoftDeleteUser(ctx context.Context, id string) error
	SoftDeleteUserAs(ctx context.Context, actorUserID, userID string) error
	RestoreUserAs(ctx context.Context, actorUserID, userID string) error
	StartPasswordless(ctx context.Context, req authflow.PasswordlessStartRequest) (authflow.PasswordlessStartResult, error)
	TwoFactorAllowedMethods() []string
	TwoFactorEnabled() bool
	UnlinkProviderUnlessLast(ctx context.Context, userID, provider string) (bool, error)
	UpdateGroupInstanceAs(ctx context.Context, actorUserID, groupID string, update iam.GroupInstanceUpdate) (iam.GroupInstance, error)
	UserNamingState(ctx context.Context, id string) (iam.NamingState, error)
	UserProfile(ctx context.Context, in authflow.ProfileInput) (authflow.UserProfile, error)
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
