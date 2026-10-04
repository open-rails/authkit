package httpapi

//go:generate go run ../cmd/contract

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/keys"
)

// Surface is where a route is anchored beneath the mount's base path.
type Surface string

const (
	SurfaceAPI  Surface = ""     // the JSON API, beneath the API path
	SurfaceOIDC Surface = "oidc" // browser OIDC navigations, beneath OIDCPath
	SurfaceBase Surface = "base" // the issuer's own paths (JWKS)
)

// Feature is the configuration a route needs to be mounted.
type Feature string

const (
	Always              Feature = ""
	FeaturePasskeys     Feature = "passkeys"     // Passkeys.RPID set
	FeaturePasswordless Feature = "passwordless" // passwordless login on
	FeatureRegistration Feature = "registration" // registration not closed
	FeatureTwoFactor    Feature = "two_factor"   // two-factor authentication not disabled
	FeatureSolana       Feature = "solana"       // a Solana network set
	FeatureOIDC         Feature = "oidc"         // an identity provider configured
	FeatureDelegated    Feature = "delegated"    // delegated-token audiences declared
	FeatureDeviceKeys   Feature = "device_keys"  // device keys on
	FeatureGroups       Feature = "groups"       // a persona besides root
	FeatureAPIKeys      Feature = "api_keys"     // a persona whose groups hold API keys
)

// Features lists every Feature a route can be mounted under.
var Features = []Feature{FeaturePasskeys, FeaturePasswordless, FeatureRegistration, FeatureTwoFactor, FeatureSolana, FeatureOIDC, FeatureDelegated, FeatureDeviceKeys, FeatureGroups, FeatureAPIKeys}

// Reply is one success outcome of a route: its status and body. Body is a
// zero value of the body's type, nil for none.
type Reply struct {
	Status int
	Body   any
}

// RouteSpec is one route of AuthKit's HTTP surface: the static catalog entry
// that mounts it, gates it and documents it. Paths are prefix-neutral, with
// ServeMux wildcards.
type RouteSpec struct {
	Method  string
	Path    string
	Surface Surface
	Group   iam.RouteGroup
	// Auth is the tier the route enforces before its handler runs.
	Auth iam.RouteAuthTier
	// Perm is the permission the route requires; `<persona>` stands for the
	// addressed group's persona. The route checks it when Auth is
	// AuthPermission; otherwise the operation does.
	Perm string
	// Bucket is the per-IP rate-limit bucket applied in front of the handler;
	// every route has one. Per-identifier and branch-specific buckets stay in
	// the handler.
	Bucket string
	// MountedWhen is the configuration the route needs.
	MountedWhen Feature
	// StepUp: the caller must have signed in recently (a step-up, MFA-fresh
	// when enrolled), checked after the session (M7).
	StepUp bool
	// MFAEnrollmentExempt marks the 2FA enroll/challenge/verify surface a
	// forced-enrollment-gated user must still reach (#243).
	MFAEnrollmentExempt bool
	// Query, Request: the query string and the JSON body (zero values; nil
	// for none). Responses: every success outcome.
	Query     any
	Request   any
	Responses []Reply

	serve func(*Service) http.Handler
	// Handler is the mounted handler, set by APIRoutes and OIDCBrowserRoutes.
	Handler http.Handler
}

func handle(f func(*Service, http.ResponseWriter, *http.Request)) func(*Service) http.Handler {
	return func(s *Service) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f(s, w, r) })
	}
}

func groupOp(op GroupOp) func(*Service) http.Handler {
	return func(s *Service) http.Handler { return s.GroupHandler(op) }
}

func replyOK(body any) []Reply      { return []Reply{{http.StatusOK, body}} }
func replyCreated(body any) []Reply { return []Reply{{http.StatusCreated, body}} }

var (
	replyNoContent = []Reply{{Status: http.StatusNoContent}}
	replyAccepted  = []Reply{{Status: http.StatusAccepted}}
)

// Catalog is AuthKit's whole HTTP surface, every route a configuration can
// mount. It needs no database: APIRoutes and OIDCBrowserRoutes select a
// Service's routes from it, and internal/cmd/contract generates openapi.json
// and the TypeScript wire types from it.
func Catalog() []RouteSpec {
	const (
		GET, POST, PUT, PATCH, DELETE                                           = http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete
		auth, deviceKeys, registration, account, admin, groups, oidc, delegated = iam.RouteAuth, iam.RouteDeviceKeys, iam.RouteRegistration, iam.RouteAccount, iam.RouteAdmin, iam.RoutePermissionGroups, iam.RouteBrowserOIDC, iam.RouteDelegated
		public, optional, required, session, permission                         = iam.AuthPublic, iam.AuthOptional, iam.AuthRequired, iam.AuthSession, iam.AuthPermission
	)
	type (
		creation  = protocol.CredentialCreation
		assertion = protocol.CredentialAssertion
	)
	signedIn := replyOK(AuthResult{})
	usersRead := ident.RootUsersRead.String()
	return []RouteSpec{
		{Method: GET, Path: iam.JWKSPath, Surface: SurfaceBase, Group: auth, Auth: public, Bucket: RLJWKSRead,
			Responses: replyOK(keys.JWKS{}), serve: func(s *Service) http.Handler { return s.JWKSHandler() }},

		// Signing in. Every answer that signs in, or names the next step, is
		// an AuthResult.
		{Method: GET, Path: "/capabilities", Group: auth, Auth: public, Bucket: RLCapabilitiesRead,
			Responses: replyOK(Capabilities{}), serve: handle((*Service).handleCapabilitiesGET)},
		{Method: POST, Path: "/token", Group: auth, Auth: public, Bucket: RLTokenRefresh,
			Request: TokenRefreshRequest{}, Responses: signedIn, serve: handle((*Service).handleAuthTokenPOST)},
		// Ends the caller's sign-in: its refresh session, or a device-key
		// token's key. Idempotent, so it stays AuthRequired.
		{Method: DELETE, Path: "/logout", Group: auth, Auth: required, Bucket: RLSessionLogout,
			Responses: replyNoContent, serve: handle((*Service).handleLogoutDELETE)},
		{Method: POST, Path: "/password/login", Group: auth, Auth: public, Bucket: RLPasswordLogin,
			Request: PasswordLoginRequest{}, Responses: signedIn, serve: handle((*Service).handlePasswordLoginPOST)},
		{Method: POST, Path: "/2fa/challenge", Group: auth, Auth: public, Bucket: RL2FAVerify, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorChallengeRequest{}, Responses: signedIn, serve: handle((*Service).handleUser2FAChallengePOST)},
		{Method: POST, Path: "/2fa/verify", Group: auth, Auth: public, Bucket: RL2FAVerify, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorVerifyRequest{}, Responses: signedIn, serve: handle((*Service).handleUser2FAVerifyPOST)},
		{Method: POST, Path: "/account/recovery/confirm", Group: auth, Auth: public, Bucket: RLPasswordLogin,
			Request: TokenRequest{}, Responses: replyNoContent, serve: handle((*Service).handleAccountRecoveryConfirmPOST)},
		{Method: POST, Path: "/passwordless/start", Group: auth, Auth: public, Bucket: RLPasswordlessStart, MountedWhen: FeaturePasswordless,
			Request: PasswordlessStartRequest{}, Responses: replyAccepted, serve: handle((*Service).handlePasswordlessStartPOST)},
		{Method: POST, Path: "/passwordless/confirm", Group: auth, Auth: public, Bucket: RLPasswordlessConfirm, MountedWhen: FeaturePasswordless,
			Request: CodeOrLinkRequest{}, Responses: signedIn, serve: handle((*Service).handlePasswordlessConfirmPOST)},
		{Method: POST, Path: "/passkeys/login/begin", Group: auth, Auth: public, Bucket: RLPasskeyLogin, MountedWhen: FeaturePasskeys,
			Responses: replyOK(assertion{}), serve: handle((*Service).handlePasskeyLoginBeginPOST)},
		{Method: POST, Path: "/passkeys/login/finish", Group: auth, Auth: public, Bucket: RLPasskeyLogin, MountedWhen: FeaturePasskeys,
			Request: WebAuthnCredential{}, Responses: signedIn, serve: handle((*Service).handlePasskeyLoginFinishPOST)},
		{Method: POST, Path: "/password/reset/request", Group: auth, Auth: public, Bucket: RLPasswordResetRequest,
			Request: IdentifierRequest{}, Responses: replyAccepted, serve: handle((*Service).handlePasswordResetRequestPOST)},
		{Method: POST, Path: "/password/reset/confirm", Group: auth, Auth: public, Bucket: RLPasswordResetConfirm,
			Request: PasswordResetConfirmRequest{}, Responses: replyNoContent, serve: handle((*Service).handlePasswordResetConfirmPOST)},
		{Method: POST, Path: "/solana/challenge", Group: auth, Auth: public, Bucket: RLSolanaChallenge, MountedWhen: FeatureSolana,
			Request: SolanaChallengeRequest{}, Responses: replyOK(SolanaChallenge{}), serve: handle((*Service).handleSolanaChallengePOST)},
		{Method: POST, Path: "/solana/login", Group: auth, Auth: public, Bucket: RLSolanaLogin, MountedWhen: FeatureSolana,
			Request: SolanaSignInRequest{}, Responses: signedIn, serve: handle((*Service).handleSolanaLoginPOST)},
		// Browser OIDC's JSON half: the login start, and the trade of a
		// callback's one-time code for its AuthResult (no token rides a URL).
		{Method: POST, Path: "/oidc/{provider}/login/start", Group: oidc, Auth: public, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Request: OIDCLoginStartRequest{}, Responses: replyOK(OIDCStart{}), serve: handle((*Service).handleOIDCLoginStartPOST)},
		{Method: POST, Path: "/oidc/exchange", Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Request: OIDCExchangeRequest{}, Responses: signedIn, serve: handle((*Service).handleOIDCExchangePOST)},

		{Method: POST, Path: "/device-keys/enroll/begin", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyEnrollBegin, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyEnrollBeginRequest{}, Responses: replyOK(DeviceKeyEnrollment{}), serve: handle((*Service).handleDeviceKeyEnrollBeginPOST)},
		{Method: POST, Path: "/device-keys/enroll/finish", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyEnrollFinish, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyEnrollFinishRequest{}, Responses: signedIn, serve: handle((*Service).handleDeviceKeyEnrollFinishPOST)},
		{Method: POST, Path: "/device-keys/login/begin", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyLoginBegin, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyLoginBeginRequest{}, Responses: replyOK(DeviceKeyLoginChallenge{}), serve: handle((*Service).handleDeviceKeyLoginBeginPOST)},
		{Method: POST, Path: "/device-keys/login/finish", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyLoginFinish, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyLoginFinishRequest{}, Responses: signedIn, serve: handle((*Service).handleDeviceKeyLoginFinishPOST)},
		// Revokes the caller's other device keys: the recovery a new key's
		// email-proven enrollment token may run.
		{Method: DELETE, Path: "/device-keys", Group: deviceKeys, Auth: session, Bucket: RLDeviceKeyManage, MountedWhen: FeatureDeviceKeys,
			Responses: replyNoContent, serve: handle((*Service).handleDeviceKeysDELETE)},

		{Method: POST, Path: "/register", Group: registration, Auth: public, Bucket: RLRegisterCreate, MountedWhen: FeatureRegistration,
			Request: RegisterRequest{}, Responses: []Reply{{http.StatusOK, AuthResult{}}, {http.StatusAccepted, nil}}, serve: handle((*Service).handleRegisterUnifiedPOST)},
		{Method: GET, Path: "/register/availability", Group: registration, Auth: public, Bucket: RLRegisterAvailability,
			Query: AvailabilityQuery{}, Responses: replyOK(Availability{}), serve: handle((*Service).handleRegisterAvailabilityGET)},
		{Method: POST, Path: "/register/abandon", Group: registration, Auth: public, Bucket: RLRegisterAbandon, MountedWhen: FeatureRegistration,
			Request: IdentifierPasswordRequest{}, Responses: replyNoContent, serve: handle((*Service).handlePendingRegistrationAbandonPOST)},

		// Proving an address. Changing the caller's own is PUT /me/email and
		// /me/phone; its code is confirmed here, signed in.
		{Method: POST, Path: "/verify/request", Group: account, Auth: public, Bucket: RLVerifyRequest,
			Request: IdentifierRequest{}, Responses: replyAccepted, serve: handle((*Service).handleVerifyRequestPOST)},
		{Method: POST, Path: "/verify/confirm", Group: account, Auth: optional, Bucket: RLVerifyConfirm,
			Request: VerifyConfirmRequest{}, Responses: []Reply{{http.StatusOK, AuthResult{}}, {http.StatusNoContent, nil}}, serve: handle((*Service).handleVerifyConfirmPOST)},

		// The caller's own account.
		{Method: GET, Path: "/me", Group: account, Auth: required, Bucket: RLMeRead,
			Responses: replyOK(UserProfile{}), serve: handle((*Service).handleMeGET)},
		{Method: PATCH, Path: "/me", Group: account, Auth: session, Bucket: RLMeUpdate,
			Request: ProfileUpdateRequest{}, Responses: replyOK(UserProfile{}), serve: handle((*Service).handleMePATCH)},
		{Method: DELETE, Path: "/me", Group: account, Auth: session, StepUp: true, Bucket: RLMeDelete,
			Responses: replyNoContent, serve: handle((*Service).handleMeDELETE)},
		{Method: GET, Path: "/me/security", Group: account, Auth: required, Bucket: RLMeRead,
			Responses: replyOK(UserSecurity{}), serve: handle((*Service).handleMeSecurityGET)},
		{Method: PUT, Path: "/me/password", Group: account, Auth: session, StepUp: true, Bucket: RLMePasswordChange,
			Request: PasswordChangeRequest{}, Responses: replyNoContent, serve: handle((*Service).handleMePasswordPUT)},
		{Method: PUT, Path: "/me/email", Group: account, Auth: session, StepUp: true, Bucket: RLMeContactChange,
			Request: EmailChangeRequest{}, Responses: replyAccepted, serve: handle((*Service).handleMeEmailPUT)},
		{Method: PUT, Path: "/me/phone", Group: account, Auth: session, StepUp: true, Bucket: RLMeContactChange,
			Request: PhoneChangeRequest{}, Responses: replyAccepted, serve: handle((*Service).handleMePhonePUT)},
		{Method: DELETE, Path: "/me/phone", Group: account, Auth: session, StepUp: true, Bucket: RLMeUpdate,
			Responses: replyNoContent, serve: handle((*Service).handleMePhoneDELETE)},
		{Method: GET, Path: "/me/sessions", Group: account, Auth: required, Bucket: RLSessionList,
			Responses: replyOK(iam.ListPage[iam.Session]{}), serve: handle((*Service).handleMeSessionsGET)},
		// Signs out every other session; the caller's stays (logout ends it).
		{Method: DELETE, Path: "/me/sessions", Group: account, Auth: session, Bucket: RLSessionRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleMeSessionsDELETE)},
		{Method: DELETE, Path: "/me/sessions/{id}", Group: account, Auth: session, Bucket: RLSessionRevoke,
			Responses: replyNoContent, serve: handle((*Service).handleMeSessionDELETE)},
		{Method: GET, Path: "/me/session-events", Group: account, Auth: required, Bucket: RLSessionList,
			Query: SessionEventQuery{}, Responses: replyOK(iam.ListPage[iam.SessionEvent]{}), serve: handle((*Service).handleMeSessionEventsGET)},
		{Method: DELETE, Path: "/me/providers/{provider}", Group: account, Auth: session, StepUp: true, Bucket: RLMeProviderUnlink,
			Responses: replyNoContent, serve: handle((*Service).handleMeProviderDELETE)},
		// Passkeys and device keys in one view; each protocol keeps its own
		// sign-in and enrollment.
		{Method: GET, Path: "/me/sign-in-keys", Group: account, Auth: required, Bucket: RLSessionList,
			Responses: replyOK(iam.ListPage[SignInKey]{}), serve: handle((*Service).handleSignInKeysGET)},
		{Method: PATCH, Path: "/me/sign-in-keys/{id}", Group: account, Auth: session, StepUp: true, Bucket: RLDeviceKeyManage,
			Request: LabelRequest{}, Responses: replyOK(SignInKey{}), serve: handle((*Service).handleSignInKeyPATCH)},
		{Method: DELETE, Path: "/me/sign-in-keys/{id}", Group: account, Auth: session, StepUp: true, Bucket: RLDeviceKeyManage,
			Responses: replyNoContent, serve: handle((*Service).handleSignInKeyDELETE)},
		{Method: POST, Path: "/me/passkeys/register/begin", Group: account, Auth: session, StepUp: true, Bucket: RLPasskeyRegister, MountedWhen: FeaturePasskeys,
			Responses: replyOK(creation{}), serve: handle((*Service).handlePasskeyRegisterBeginPOST)},
		{Method: POST, Path: "/me/passkeys/register/finish", Group: account, Auth: session, StepUp: true, Bucket: RLPasskeyRegister, MountedWhen: FeaturePasskeys,
			Request: WebAuthnCredential{}, Responses: replyCreated(SignInKey{}), serve: handle((*Service).handlePasskeyRegisterFinishPOST)},
		{Method: POST, Path: "/me/step-up/password", Group: account, Auth: session, Bucket: RLStepUpPassword,
			Request: PasswordRequest{}, Responses: signedIn, serve: handle((*Service).handlePasswordStepUpPOST)},
		{Method: POST, Path: "/me/step-up/2fa/send", Group: account, Auth: session, Bucket: RLStepUp2FASend, MountedWhen: FeatureTwoFactor,
			Request: TwoFactorSendRequest{}, Responses: replyAccepted, serve: handle((*Service).handleTwoFactorStepUpSendPOST)},
		{Method: POST, Path: "/me/step-up/2fa", Group: account, Auth: session, Bucket: RL2FAVerify, MountedWhen: FeatureTwoFactor,
			Request: TwoFactorStepUpRequest{}, Responses: signedIn, serve: handle((*Service).handleTwoFactorStepUpPOST)},
		// Step-up by a code to a proven email or phone, the linked wallet or a
		// passkey (step_up_required's step_up_methods).
		{Method: POST, Path: "/me/step-up/code/send", Group: account, Auth: session, Bucket: RLStepUpCodeSend,
			Request: StepUpCodeSendRequest{}, Responses: replyAccepted, serve: handle((*Service).handleStepUpCodeSendPOST)},
		{Method: POST, Path: "/me/step-up/code", Group: account, Auth: session, Bucket: RLStepUpCode,
			Request: CodeRequest{}, Responses: signedIn, serve: handle((*Service).handleStepUpCodePOST)},
		{Method: POST, Path: "/me/step-up/solana/challenge", Group: account, Auth: session, Bucket: RLStepUpChallenge, MountedWhen: FeatureSolana,
			Responses: replyOK(SolanaChallenge{}), serve: handle((*Service).handleSolanaStepUpChallengePOST)},
		{Method: POST, Path: "/me/step-up/solana", Group: account, Auth: session, Bucket: RLStepUpSignature, MountedWhen: FeatureSolana,
			Request: SolanaSignInRequest{}, Responses: signedIn, serve: handle((*Service).handleSolanaStepUpPOST)},
		{Method: POST, Path: "/me/step-up/passkey/begin", Group: account, Auth: session, Bucket: RLStepUpChallenge, MountedWhen: FeaturePasskeys,
			Responses: replyOK(assertion{}), serve: handle((*Service).handlePasskeyStepUpBeginPOST)},
		{Method: POST, Path: "/me/step-up/passkey", Group: account, Auth: session, Bucket: RLStepUpSignature, MountedWhen: FeaturePasskeys,
			Request: WebAuthnCredential{}, Responses: signedIn, serve: handle((*Service).handlePasskeyStepUpPOST)},
		{Method: POST, Path: "/oidc/{provider}/link/start", Group: account, Auth: session, StepUp: true, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Responses: replyOK(OIDCStart{}), serve: handle((*Service).handleOIDCLinkStartPOST)},
		{Method: POST, Path: "/oidc/{provider}/step-up/start", Group: account, Auth: session, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Request: ReturnToRequest{}, Responses: replyOK(OIDCStart{}), serve: handle((*Service).handleOIDCStepUpStartPOST)},

		// Second factors, listed by GET /me/security. An enrollment token
		// (AuthResult enrollment_required) reaches setup and factors, with no
		// step-up.
		{Method: POST, Path: "/me/2fa/setup", Group: account, Auth: session, Bucket: RL2FAEnable, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorSetupRequest{}, Responses: replyOK(TwoFactorSetup{}), serve: handle((*Service).handleMe2FASetupPOST)},
		{Method: POST, Path: "/me/2fa/factors", Group: account, Auth: session, Bucket: RL2FAEnable, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorFactorCreateRequest{}, Responses: replyCreated(TwoFactorFactorCreated{}), serve: handle((*Service).handleMe2FAFactorsPOST)},
		{Method: PATCH, Path: "/me/2fa/factors/{id}", Group: account, Auth: session, StepUp: true, Bucket: RLMeUpdate, MountedWhen: FeatureTwoFactor,
			Request: TwoFactorFactorUpdateRequest{}, Responses: replyOK(TwoFactorFactor{}), serve: handle((*Service).handleMe2FAFactorPATCH)},
		{Method: DELETE, Path: "/me/2fa/factors/{id}", Group: account, Auth: session, StepUp: true, Bucket: RL2FADisable, MountedWhen: FeatureTwoFactor,
			Responses: replyNoContent, serve: handle((*Service).handleMe2FAFactorDELETE)},
		{Method: DELETE, Path: "/me/2fa", Group: account, Auth: session, StepUp: true, Bucket: RL2FADisable, MountedWhen: FeatureTwoFactor,
			Responses: replyNoContent, serve: handle((*Service).handleMe2FADELETE)},
		{Method: POST, Path: "/me/2fa/backup-codes", Group: account, Auth: session, StepUp: true, Bucket: RL2FARegenerateCodes, MountedWhen: FeatureTwoFactor,
			Responses: replyOK(BackupCodes{}), serve: handle((*Service).handleMe2FABackupCodesPOST)},

		{Method: PUT, Path: "/me/solana-wallet", Group: account, Auth: session, StepUp: true, Bucket: RLSolanaLink, MountedWhen: FeatureSolana,
			Request: SolanaSignInRequest{}, Responses: replyOK(authflow.SolanaLinkedAccount{}), serve: handle((*Service).handleMeSolanaWalletPUT)},
		{Method: GET, Path: "/me/groups", Group: account, Auth: required, Bucket: RLMeGroupsRead,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.Membership]{}), serve: handle((*Service).handleMeGroupsGET)},
		// The caller's role and permissions in one group (?group_id=; root by
		// default), expanded.
		{Method: GET, Path: "/me/permissions", Group: account, Auth: required, Bucket: RLMePermissionsRead,
			Query: GroupQuery{}, Responses: replyOK(PermissionSet{}), serve: handle((*Service).handleMePermissionsGET)},
		// Other people, as anyone may see them, public metadata included:
		// public profile pages need no sign-in.
		{Method: GET, Path: "/users", Group: account, Auth: public, Bucket: RLUsersRead,
			Query: UsersQuery{}, Responses: replyOK(iam.ListPage[iam.PublicUser]{}), serve: handle((*Service).handleUsersGET)},

		// The user directory: reads are gated here; mutations are for signed-in
		// users who signed in recently, and the engine checks their permission
		// (rule ACCT).
		{Method: GET, Path: "/admin/users", Group: admin, Auth: permission, Perm: usersRead, Bucket: RLAdminRead,
			Query: UserListQuery{}, Responses: replyOK(iam.ListPage[iam.UserEntry]{}), serve: handle((*Service).handleAdminUsersListGET)},
		{Method: GET, Path: "/admin/users/{user_id}", Group: admin, Auth: permission, Perm: usersRead, Bucket: RLAdminRead,
			Responses: replyOK(iam.UserEntry{}), serve: handle((*Service).handleAdminUserGET)},
		{Method: PATCH, Path: "/admin/users/{user_id}", Group: admin, Auth: session, StepUp: true, Perm: ident.RootUsersManage.String(), Bucket: RLAdminWrite,
			Request: AdminUserUpdateRequest{}, Responses: replyOK(iam.UserEntry{}), serve: handle((*Service).handleAdminUserPATCH)},
		{Method: DELETE, Path: "/admin/users/{user_id}", Group: admin, Auth: session, StepUp: true, Perm: ident.RootUsersDelete.String(), Bucket: RLAdminWrite,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserDeleteDELETE)},
		{Method: POST, Path: "/admin/users/{user_id}/restore", Group: admin, Auth: session, StepUp: true, Perm: ident.RootUsersDelete.String(), Bucket: RLAdminWrite,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserRestorePOST)},
		{Method: PUT, Path: "/admin/users/{user_id}/ban", Group: admin, Auth: session, StepUp: true, Perm: ident.RootUsersBan.String(), Bucket: RLAdminWrite,
			Request: BanRequest{}, Responses: replyNoContent, serve: handle((*Service).handleAdminUserBanPUT)},
		{Method: DELETE, Path: "/admin/users/{user_id}/ban", Group: admin, Auth: session, StepUp: true, Perm: ident.RootUsersBan.String(), Bucket: RLAdminWrite,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserBanDELETE)},
		{Method: GET, Path: "/admin/users/{user_id}/sessions", Group: admin, Auth: permission, Perm: usersRead, Bucket: RLAdminRead,
			Responses: replyOK(iam.ListPage[iam.Session]{}), serve: handle((*Service).handleAdminUserSessionsGET)},
		// Revokes every session and device key of the account.
		{Method: DELETE, Path: "/admin/users/{user_id}/sessions", Group: admin, Auth: session, StepUp: true, Perm: ident.RootUsersManage.String(), Bucket: RLAdminWrite,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserSessionsDELETE)},
		{Method: GET, Path: "/admin/users/{user_id}/session-events", Group: admin, Auth: permission, Perm: usersRead, Bucket: RLAdminRead,
			Query: SessionEventQuery{}, Responses: replyOK(iam.ListPage[iam.SessionEvent]{}), serve: handle((*Service).handleAdminUserSessionEventsGET)},

		// #261: users exchange their session for a short-lived delegated token
		// aimed at the configured audiences.
		{Method: POST, Path: "/delegated/token", Group: delegated, Auth: session, Bucket: RLDelegatedTokenMint, MountedWhen: FeatureDelegated,
			Request: DelegatedTokenRequest{}, Responses: replyOK(iam.TokenSet{}), serve: handle((*Service).handleDelegatedTokenPOST)},

		// Group management: each route resolves {group_id} (`root` is the root
		// group), refuses a group whose persona lacks the route, and checks
		// Perm in the group. A root-group change needs a recent sign-in.
		{Method: GET, Path: "/groups/{group_id}/members", Group: groups, Auth: permission, Perm: OpMembersList.catalogPermission(), Bucket: RLGroupRead,
			Query: MemberListQuery{}, Responses: replyOK(iam.ListPage[iam.GroupMember]{}), serve: groupOp(OpMembersList)},
		// {kind} is `users`; the segment leaves room for other subject kinds.
		{Method: PUT, Path: "/groups/{group_id}/members/{kind}/{id}", Group: groups, Auth: permission, Perm: OpMemberSet.catalogPermission(), Bucket: RLGroupWrite,
			Request: MemberRoleRequest{}, Responses: replyOK(iam.GroupMember{}), serve: groupOp(OpMemberSet)},
		{Method: DELETE, Path: "/groups/{group_id}/members/{kind}/{id}", Group: groups, Auth: permission, Perm: OpMemberRemove.catalogPermission(), Bucket: RLGroupWrite,
			Responses: replyNoContent, serve: groupOp(OpMemberRemove)},
		{Method: GET, Path: "/groups/{group_id}/roles", Group: groups, Auth: permission, Perm: OpRolesList.catalogPermission(), Bucket: RLGroupRead,
			Responses: replyOK(iam.ListPage[RoleInfo]{}), serve: groupOp(OpRolesList)},
		{Method: GET, Path: "/groups/{group_id}/invitations", Group: groups, Auth: permission, Perm: OpInvitationsList.catalogPermission(), Bucket: RLGroupRead,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.Invitation]{}), serve: groupOp(OpInvitationsList)},
		// A link answers its code once (201); an emailed invitation answers
		// 202 whoever holds the address.
		{Method: POST, Path: "/groups/{group_id}/invitations", Group: groups, Auth: permission, Perm: OpInvitationCreate.catalogPermission(), Bucket: RLInviteCreate,
			Request: InvitationCreateRequest{}, Responses: []Reply{{http.StatusCreated, iam.InvitationCreated{}}, {http.StatusAccepted, nil}}, serve: groupOp(OpInvitationCreate)},
		{Method: DELETE, Path: "/groups/{group_id}/invitations/{id}", Group: groups, Auth: permission, Perm: OpInvitationRevoke.catalogPermission(), Bucket: RLGroupWrite,
			Responses: replyNoContent, serve: groupOp(OpInvitationRevoke)},
		{Method: GET, Path: "/groups/{group_id}/api-keys", Group: groups, Auth: permission, Perm: OpAPIKeysList.catalogPermission(), Bucket: RLGroupRead, MountedWhen: FeatureAPIKeys,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.APIKey]{}), serve: groupOp(OpAPIKeysList)},
		{Method: POST, Path: "/groups/{group_id}/api-keys", Group: groups, Auth: permission, Perm: OpAPIKeyMint.catalogPermission(), Bucket: RLAPIKeyCreate, MountedWhen: FeatureAPIKeys,
			Request: APIKeyCreateRequest{}, Responses: replyCreated(iam.APIKeyCreated{}), serve: groupOp(OpAPIKeyMint)},
		{Method: DELETE, Path: "/groups/{group_id}/api-keys/{id}", Group: groups, Auth: permission, Perm: OpAPIKeyRevoke.catalogPermission(), Bucket: RLGroupWrite, MountedWhen: FeatureAPIKeys,
			Responses: replyNoContent, serve: groupOp(OpAPIKeyRevoke)},
		{Method: POST, Path: "/invitations/redeem", Group: groups, Auth: session, Bucket: RLInviteRedeem,
			Request: InvitationRedeemRequest{}, Responses: replyOK(iam.Membership{}), serve: handle((*Service).handleInvitationRedeemPOST)},

		// Browser OIDC: navigations and the provider's one callback, which
		// completes a login, link or step-up alike. A callback asked for JSON
		// answers the AuthResult; a redirect or popup carries a one-time code
		// for POST /oidc/exchange.
		{Method: GET, Path: "/{provider}/login", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Query: OIDCLoginQuery{}, Responses: []Reply{{Status: http.StatusFound}}, serve: handle((*Service).handleOIDCLoginGET)},
		{Method: GET, Path: "/{provider}/callback", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Query: OIDCCallbackQuery{}, Responses: oidcCallbackReplies, serve: handle((*Service).handleOIDCCallbackGET)},
		// response_mode=form_post providers (Apple) deliver the same response
		// as a cross-site POST body (#295).
		{Method: POST, Path: "/{provider}/callback", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Responses: oidcCallbackReplies, serve: handle((*Service).handleOIDCCallbackGET)},
	}
}

// A callback redirects to the frontend, a step-up's return_to or the popup
// document; asked for JSON it answers the AuthResult, or 204 for a linked
// provider.
var oidcCallbackReplies = []Reply{{Status: http.StatusFound}, {http.StatusOK, AuthResult{}}, {Status: http.StatusNoContent}}
