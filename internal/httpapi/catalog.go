package httpapi

//go:generate go run ../cmd/contract

import (
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/keys"
)

// Surface is where a route is anchored beneath the mount's base path.
type Surface string

const (
	SurfaceAPI  Surface = "api"  // the JSON API, beneath the API path
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
	// Bucket is the per-IP rate-limit bucket applied in front of the handler
	// ("" = none). Per-identifier and branch-specific buckets stay in the
	// handler.
	Bucket string
	// MountedWhen is the configuration the route needs.
	MountedWhen Feature
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
		GET, POST, PUT, PATCH, DELETE = http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete
		auth, deviceKeys, registration, account, admin, groups, oidc, delegated = iam.RouteAuth, iam.RouteDeviceKeys, iam.RouteRegistration, iam.RouteAccount, iam.RouteAdmin, iam.RoutePermissionGroups, iam.RouteBrowserOIDC, iam.RouteDelegated
		public, optional, required, session, permission = iam.AuthPublic, iam.AuthOptional, iam.AuthRequired, iam.AuthSession, iam.AuthPermission
	)
	type (
		tokens    = iam.TokenSet
		creation  = protocol.CredentialCreation
		assertion = protocol.CredentialAssertion
	)
	usersRead := ident.RootUsersRead.String()
	rootMembers := ident.MembersManage(iam.RootPersona).String()
	return []RouteSpec{
		{Method: GET, Path: iam.JWKSPath, Surface: SurfaceBase, Group: auth, Auth: public,
			Responses: replyOK(keys.JWKS{}), serve: func(s *Service) http.Handler { return s.JWKSHandler() }},

		{Method: GET, Path: "/capabilities", Group: auth, Auth: public,
			Responses: replyOK(Capabilities{}), serve: handle((*Service).handleCapabilitiesGET)},
		{Method: POST, Path: "/token", Group: auth, Auth: public, Bucket: RLAuthToken,
			Request: TokenRefreshRequest{}, Responses: replyOK(tokens{}), serve: handle((*Service).handleAuthTokenPOST)},
		{Method: DELETE, Path: "/logout", Group: auth, Auth: required, Bucket: RLAuthLogout,
			Responses: replyNoContent, serve: handle((*Service).handleLogoutDELETE)},
		{Method: POST, Path: "/password/login", Group: auth, Auth: public, Bucket: RLPasswordLogin,
			Request: PasswordLoginRequest{}, Responses: replyOK(tokens{}), serve: handle((*Service).handlePasswordLoginPOST)},
		{Method: POST, Path: "/account/recovery/confirm", Group: auth, Auth: public, Bucket: RLPasswordLogin,
			Request: TokenRequest{}, Responses: replyNoContent, serve: handle((*Service).handleAccountRecoveryConfirmPOST)},
		{Method: POST, Path: "/passwordless/start", Group: auth, Auth: public, Bucket: RLPasswordlessStart, MountedWhen: FeaturePasswordless,
			Request: PasswordlessStartRequest{}, Responses: replyAccepted, serve: handle((*Service).handlePasswordlessStartPOST)},
		{Method: POST, Path: "/passwordless/confirm", Group: auth, Auth: public, Bucket: RLPasswordlessConfirm, MountedWhen: FeaturePasswordless,
			Request: CodeOrLinkRequest{}, Responses: replyOK(PasswordlessResult{}), serve: handle((*Service).handlePasswordlessConfirmPOST)},
		{Method: POST, Path: "/passkeys/login/begin", Group: auth, Auth: public, Bucket: RLPasskeyLogin, MountedWhen: FeaturePasskeys,
			Responses: replyOK(assertion{}), serve: handle((*Service).handlePasskeyLoginBeginPOST)},
		{Method: POST, Path: "/passkeys/login/finish", Group: auth, Auth: public, Bucket: RLPasskeyLogin, MountedWhen: FeaturePasskeys,
			Request: WebAuthnCredential{}, Responses: replyOK(tokens{}), serve: handle((*Service).handlePasskeyLoginFinishPOST)},

		{Method: POST, Path: "/device-keys/enroll/begin", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyEnrollBegin, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyEnrollBeginRequest{}, Responses: replyOK(DeviceKeyEnrollment{}), serve: handle((*Service).handleDeviceKeyEnrollBeginPOST)},
		{Method: POST, Path: "/device-keys/enroll/finish", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyEnrollFinish, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyEnrollFinishRequest{}, Responses: replyOK(DeviceKeySession{}), serve: handle((*Service).handleDeviceKeyEnrollFinishPOST)},
		{Method: POST, Path: "/device-keys/login/begin", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyLoginBegin, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyLoginBeginRequest{}, Responses: replyOK(DeviceKeyLoginChallenge{}), serve: handle((*Service).handleDeviceKeyLoginBeginPOST)},
		{Method: POST, Path: "/device-keys/login/finish", Group: deviceKeys, Auth: public, Bucket: RLDeviceKeyLoginFinish, MountedWhen: FeatureDeviceKeys,
			Request: DeviceKeyLoginFinishRequest{}, Responses: replyOK(DeviceKeySession{}), serve: handle((*Service).handleDeviceKeyLoginFinishPOST)},
		{Method: GET, Path: "/device-keys", Group: deviceKeys, Auth: required, Bucket: RLDeviceKeysManage, MountedWhen: FeatureDeviceKeys,
			Responses: replyOK(iam.ListPage[iam.DeviceKey]{}), serve: handle((*Service).handleDeviceKeysGET)},
		{Method: DELETE, Path: "/device-keys/{id}", Group: deviceKeys, Auth: required, Bucket: RLDeviceKeysManage, MountedWhen: FeatureDeviceKeys,
			Responses: replyNoContent, serve: handle((*Service).handleDeviceKeyDELETE)},
		{Method: POST, Path: "/device-keys/revoke-others", Group: deviceKeys, Auth: session, Bucket: RLDeviceKeysManage, MountedWhen: FeatureDeviceKeys,
			Responses: replyNoContent, serve: handle((*Service).handleDeviceKeysRevokeOthersPOST)},
		{Method: POST, Path: "/password/reset/request", Group: auth, Auth: public, Bucket: RLPasswordResetRequest,
			Request: IdentifierRequest{}, Responses: replyAccepted, serve: handle((*Service).handlePasswordResetRequestPOST)},
		{Method: POST, Path: "/password/reset/confirm", Group: auth, Auth: public, Bucket: RLPasswordResetConfirm,
			Request: PasswordResetConfirmRequest{}, Responses: replyNoContent, serve: handle((*Service).handlePasswordResetConfirmPOST)},

		{Method: POST, Path: "/register", Group: registration, Auth: public, Bucket: RLAuthRegister, MountedWhen: FeatureRegistration,
			Request: RegisterRequest{}, Responses: replyOK(RegistrationResult{}), serve: handle((*Service).handleRegisterUnifiedPOST)},
		{Method: GET, Path: "/register/availability", Group: registration, Auth: public, Bucket: RLAuthRegisterAvailability,
			Query: AvailabilityQuery{}, Responses: replyOK(Availability{}), serve: handle((*Service).handleRegisterAvailabilityGET)},
		{Method: POST, Path: "/register/abandon", Group: registration, Auth: public, Bucket: RLAuthRegisterAbandon, MountedWhen: FeatureRegistration,
			Request: IdentifierPasswordRequest{}, Responses: replyNoContent, serve: handle((*Service).handlePendingRegistrationAbandonPOST)},

		// #312: one route per contact flow; the channel comes from the
		// identifier. Signed in, /verify/request changes the address, and a
		// password in the body re-authenticates the session first.
		{Method: POST, Path: "/verify/request", Group: account, Auth: optional, Bucket: RLVerifyRequest,
			Request: IdentifierPasswordRequest{}, Responses: []Reply{{http.StatusAccepted, nil}, {http.StatusOK, StepUpResult{}}}, serve: handle((*Service).handleVerifyRequestPOST)},
		{Method: POST, Path: "/verify/confirm", Group: account, Auth: optional, Bucket: RLVerifyConfirm,
			Request: CodeOrLinkRequest{}, Responses: []Reply{{http.StatusOK, tokens{}}, {http.StatusNoContent, nil}}, serve: handle((*Service).handleVerifyConfirmPOST)},

		{Method: POST, Path: "/user/password", Group: account, Auth: session, Bucket: RLUserPasswordChange,
			Request: PasswordChangeRequest{}, Responses: []Reply{{http.StatusNoContent, nil}, {http.StatusOK, StepUpResult{}}}, serve: handle((*Service).handleUserPasswordPOST)},
		{Method: GET, Path: "/user/sessions", Group: account, Auth: required, Bucket: RLAuthSessionsList,
			Responses: replyOK(iam.ListPage[iam.Session]{}), serve: handle((*Service).handleUserSessionsGET)},
		{Method: DELETE, Path: "/user/sessions/{id}", Group: account, Auth: session, Bucket: RLAuthSessionsRevoke,
			Responses: replyNoContent, serve: handle((*Service).handleUserSessionDELETE)},
		{Method: DELETE, Path: "/user/sessions", Group: account, Auth: session, Bucket: RLAuthSessionsRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleUserSessionsDELETE)},
		{Method: GET, Path: "/me", Group: account, Auth: required, Bucket: RLUserMe,
			Responses: replyOK(UserProfile{}), serve: handle((*Service).handleUserMeGET)},
		{Method: PATCH, Path: "/user/username", Group: account, Auth: session, Bucket: RLUserUpdateUsername,
			Request: UsernameRequest{}, Responses: replyOK(UsernameChange{}), serve: handle((*Service).handleUserUsernamePATCH)},
		{Method: PATCH, Path: "/user/preferred-language", Group: account, Auth: session, Bucket: RLUserPreferredLanguage,
			Request: PreferredLanguageRequest{}, Responses: replyOK(PreferredLanguage{}), serve: handle((*Service).handleUserPreferredLanguagePATCH)},
		{Method: DELETE, Path: "/user", Group: account, Auth: session, Bucket: RLUserDelete,
			Request: PasswordRequest{}, Responses: replyNoContent, serve: handle((*Service).handleUserDeleteDELETE)},
		{Method: DELETE, Path: "/user/providers/{provider}", Group: account, Auth: session, Bucket: RLUserUnlinkProvider,
			Request: PasswordRequest{}, Responses: replyNoContent, serve: handle((*Service).handleUserUnlinkProviderDELETE)},
		{Method: POST, Path: "/passkeys/register/begin", Group: account, Auth: session, Bucket: RLPasskeyRegister, MountedWhen: FeaturePasskeys,
			Responses: replyOK(creation{}), serve: handle((*Service).handlePasskeyRegisterBeginPOST)},
		{Method: POST, Path: "/passkeys/register/finish", Group: account, Auth: session, Bucket: RLPasskeyRegister, MountedWhen: FeaturePasskeys,
			Request: WebAuthnCredential{}, Responses: replyCreated(iam.Passkey{}), serve: handle((*Service).handlePasskeyRegisterFinishPOST)},
		{Method: GET, Path: "/passkeys", Group: account, Auth: required, MountedWhen: FeaturePasskeys,
			Responses: replyOK(iam.ListPage[iam.Passkey]{}), serve: handle((*Service).handlePasskeysGET)},
		{Method: PATCH, Path: "/passkeys/{id}", Group: account, Auth: session, MountedWhen: FeaturePasskeys,
			Request: LabelRequest{}, Responses: replyOK(iam.Passkey{}), serve: handle((*Service).handlePasskeyPATCH)},
		{Method: DELETE, Path: "/passkeys/{id}", Group: account, Auth: session, MountedWhen: FeaturePasskeys,
			Responses: replyNoContent, serve: handle((*Service).handlePasskeyDELETE)},

		{Method: POST, Path: "/step-up/password", Group: account, Auth: session, Bucket: RLPasswordStepUp,
			Request: PasswordRequest{}, Responses: replyOK(StepUpResult{}), serve: handle((*Service).handlePasswordStepUpPOST)},
		{Method: POST, Path: "/step-up/2fa", Group: account, Auth: session, Bucket: RL2FAVerify, MountedWhen: FeatureTwoFactor,
			Request: TwoFactorStepUpRequest{}, Responses: replyOK(StepUpResult{}), serve: handle((*Service).handleTwoFactorStepUpPOST)},

		{Method: POST, Path: "/oidc/{provider}/link/start", Group: account, Auth: session, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Responses: replyOK(OIDCStart{}), serve: handle((*Service).handleOIDCLinkStartPOST)},
		{Method: POST, Path: "/oidc/{provider}/step-up/start", Group: account, Auth: session, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Request: ReturnToRequest{}, Responses: replyOK(OIDCStart{}), serve: handle((*Service).handleOIDCStepUpStartPOST)},

		{Method: GET, Path: "/user/2fa", Group: account, Auth: required, Bucket: RLUserMe, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Responses: replyOK(TwoFactorStatus{}), serve: handle((*Service).handleUser2FAStatusGET)},
		{Method: POST, Path: "/user/2fa", Group: account, Auth: session, Bucket: RL2FAEnable, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorEnrollRequest{}, Responses: []Reply{{http.StatusOK, TwoFactorEnrollResult{}}, {http.StatusAccepted, nil}, {http.StatusNoContent, nil}}, serve: handle((*Service).handleUser2FAPOST)},
		// Answers the roles the removal took away (the one DELETE with a body,
		// until #407's factor resource).
		{Method: DELETE, Path: "/user/2fa", Group: account, Auth: session, Bucket: RL2FADisable, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Query: TwoFactorFactorQuery{}, Responses: replyOK(RemovedRoles{}), serve: handle((*Service).handleUser2FADELETE)},
		{Method: POST, Path: "/user/2fa/backup-codes", Group: account, Auth: session, Bucket: RL2FARegenerateCodes, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Responses: replyOK(BackupCodes{}), serve: handle((*Service).handleUser2FABackupCodesPOST)},
		// Resends the login challenge's code; answers 403 2fa_required with the
		// challenge (#407 makes it a result).
		{Method: POST, Path: "/2fa/challenge", Group: auth, Auth: public, Bucket: RL2FAVerify, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorChallengeRequest{}, serve: handle((*Service).handleUser2FAChallengePOST)},
		{Method: POST, Path: "/2fa/verify", Group: auth, Auth: public, Bucket: RL2FAVerify, MountedWhen: FeatureTwoFactor, MFAEnrollmentExempt: true,
			Request: TwoFactorVerifyRequest{}, Responses: replyOK(tokens{}), serve: handle((*Service).handleUser2FAVerifyPOST)},

		{Method: POST, Path: "/solana/challenge", Group: auth, Auth: public, Bucket: RLSolanaChallenge, MountedWhen: FeatureSolana,
			Request: SolanaChallengeRequest{}, Responses: replyOK(SolanaChallenge{}), serve: handle((*Service).handleSolanaChallengePOST)},
		{Method: POST, Path: "/solana/login", Group: auth, Auth: public, Bucket: RLSolanaLogin, MountedWhen: FeatureSolana,
			Request: SolanaSignInRequest{}, Responses: replyOK(SolanaLoginResult{}), serve: handle((*Service).handleSolanaLoginPOST)},
		{Method: POST, Path: "/solana/link", Group: account, Auth: session, Bucket: RLSolanaLink, MountedWhen: FeatureSolana,
			Request: SolanaSignInRequest{}, Responses: replyOK(SolanaLink{}), serve: handle((*Service).handleSolanaLinkPOST)},

		// The user directory: reads are gated here; mutations are for signed-in
		// users and the engine checks their permission (rule ACCT).
		{Method: GET, Path: "/admin/users", Group: admin, Auth: permission, Perm: usersRead, Bucket: RLAdminUserSessionsList,
			Query: UserListQuery{}, Responses: replyOK(iam.ListPage[iam.UserEntry]{}), serve: handle((*Service).handleAdminUsersListGET)},
		{Method: GET, Path: "/admin/users/{user_id}", Group: admin, Auth: permission, Perm: usersRead,
			Responses: replyOK(iam.UserEntry{}), serve: handle((*Service).handleAdminUserGET)},
		{Method: GET, Path: "/admin/users/{user_id}/signins", Group: admin, Auth: permission, Perm: usersRead,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.SessionEvent]{}), serve: handle((*Service).handleAdminUserSigninsGET)},
		{Method: POST, Path: "/admin/users/{user_id}/ban", Group: admin, Auth: session, Perm: ident.RootUsersBan.String(), Bucket: RLAdminUserSessionsRevokeAll,
			Request: BanRequest{}, Responses: replyNoContent, serve: handle((*Service).handleAdminUsersBanPOST)},
		{Method: POST, Path: "/admin/users/{user_id}/unban", Group: admin, Auth: session, Perm: ident.RootUsersBan.String(), Bucket: RLAdminUserSessionsRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUsersUnbanPOST)},
		{Method: POST, Path: "/admin/users/{user_id}/sessions/revoke", Group: admin, Auth: session, Perm: ident.RootUsersManage.String(), Bucket: RLAdminUserSessionsRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserSessionsRevokePOST)},
		{Method: DELETE, Path: "/admin/users/{user_id}", Group: admin, Auth: session, Perm: ident.RootUsersDelete.String(), Bucket: RLAdminUserSessionsRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserDeleteDELETE)},
		{Method: POST, Path: "/admin/users/{user_id}/restore", Group: admin, Auth: session, Perm: ident.RootUsersDelete.String(), Bucket: RLAdminUserSessionsRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserRestorePOST)},
		// Root roles: the engine enforces root:members:manage, coverage of the
		// role, the last owner and MFA.
		{Method: GET, Path: "/admin/roles", Group: admin, Auth: permission, Perm: ident.MembersRead(iam.RootPersona).String(),
			Responses: replyOK(iam.ListPage[RoleInfo]{}), serve: handle((*Service).handleAdminRolesGET)},
		{Method: PUT, Path: "/admin/users/{user_id}/roles/{role}", Group: admin, Auth: session, Perm: rootMembers, Bucket: RLAdminUserSessionsRevokeAll,
			Responses: replyOK(iam.GroupMember{}), serve: handle((*Service).handleAdminUserRolePUT)},
		{Method: DELETE, Path: "/admin/users/{user_id}/roles/{role}", Group: admin, Auth: session, Perm: rootMembers, Bucket: RLAdminUserSessionsRevokeAll,
			Responses: replyNoContent, serve: handle((*Service).handleAdminUserRoleDELETE)},

		// #261: users exchange their session for a short-lived delegated token
		// aimed at the configured audiences.
		{Method: POST, Path: "/delegated/token", Group: delegated, Auth: session, Bucket: RLDelegatedTokenMint, MountedWhen: FeatureDelegated,
			Request: DelegatedTokenRequest{}, Responses: replyOK(tokens{}), serve: handle((*Service).handleDelegatedTokenPOST)},

		// Group management: each route resolves {group_id}, refuses a group
		// whose persona lacks the route, and checks Perm in the group.
		{Method: GET, Path: "/groups/{group_id}/members", Group: groups, Auth: permission, Perm: OpMembersList.catalogPermission(), MountedWhen: FeatureGroups,
			Query: MemberListQuery{}, Responses: replyOK(iam.ListPage[iam.GroupMember]{}), serve: groupOp(OpMembersList)},
		{Method: POST, Path: "/groups/{group_id}/members", Group: groups, Auth: permission, Perm: OpMemberAdd.catalogPermission(), MountedWhen: FeatureGroups,
			Request: MemberAddRequest{}, Responses: []Reply{{http.StatusOK, iam.GroupMember{}}, {http.StatusAccepted, nil}}, serve: groupOp(OpMemberAdd)},
		{Method: DELETE, Path: "/groups/{group_id}/members/{user}", Group: groups, Auth: permission, Perm: OpMemberRemove.catalogPermission(), MountedWhen: FeatureGroups,
			Responses: replyNoContent, serve: groupOp(OpMemberRemove)},
		{Method: PUT, Path: "/groups/{group_id}/members/{user}/roles/{role}", Group: groups, Auth: permission, Perm: OpMemberRoleAssign.catalogPermission(), MountedWhen: FeatureGroups,
			Responses: replyOK(iam.GroupMember{}), serve: groupOp(OpMemberRoleAssign)},
		{Method: GET, Path: "/groups/{group_id}/roles", Group: groups, Auth: permission, Perm: OpRolesList.catalogPermission(), MountedWhen: FeatureGroups,
			Responses: replyOK(iam.ListPage[RoleInfo]{}), serve: groupOp(OpRolesList)},
		{Method: GET, Path: "/groups/{group_id}/api-keys", Group: groups, Auth: permission, Perm: OpAPIKeysList.catalogPermission(), MountedWhen: FeatureAPIKeys,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.APIKey]{}), serve: groupOp(OpAPIKeysList)},
		{Method: POST, Path: "/groups/{group_id}/api-keys", Group: groups, Auth: permission, Perm: OpAPIKeyMint.catalogPermission(), MountedWhen: FeatureAPIKeys,
			Request: APIKeyCreateRequest{}, Responses: replyCreated(iam.APIKeyCreated{}), serve: groupOp(OpAPIKeyMint)},
		{Method: DELETE, Path: "/groups/{group_id}/api-keys/{key}", Group: groups, Auth: permission, Perm: OpAPIKeyRevoke.catalogPermission(), MountedWhen: FeatureAPIKeys,
			Responses: replyNoContent, serve: groupOp(OpAPIKeyRevoke)},
		{Method: GET, Path: "/groups/{group_id}/invites/links", Group: groups, Auth: permission, Perm: OpInviteLinkList.catalogPermission(), MountedWhen: FeatureGroups,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.Invitation]{}), serve: groupOp(OpInviteLinkList)},
		{Method: POST, Path: "/groups/{group_id}/invites/links", Group: groups, Auth: permission, Perm: OpInviteLinkMint.catalogPermission(), MountedWhen: FeatureGroups,
			Request: InvitationCreateRequest{}, Responses: replyCreated(iam.InvitationCreated{}), serve: groupOp(OpInviteLinkMint)},
		{Method: DELETE, Path: "/groups/{group_id}/invites/links/{link}", Group: groups, Auth: permission, Perm: OpInviteLinkRevoke.catalogPermission(), MountedWhen: FeatureGroups,
			Responses: replyNoContent, serve: groupOp(OpInviteLinkRevoke)},
		{Method: GET, Path: "/me/groups", Group: account, Auth: required,
			Query: PageQuery{}, Responses: replyOK(iam.ListPage[iam.Membership]{}), serve: handle((*Service).handleMeGroupsGET)},
		// #421: the caller's effective grants in one group (?group_id=; the
		// root group by default).
		{Method: GET, Path: "/me/permissions", Group: account, Auth: required,
			Query: GroupQuery{}, Responses: replyOK(PermissionSet{}), serve: handle((*Service).handleMePermissionsGET)},
		{Method: POST, Path: "/invites/redeem", Group: groups, Auth: session, Bucket: RLInviteRedeem, MountedWhen: FeatureGroups,
			Request: InviteRedeemRequest{}, Responses: replyOK(iam.Membership{}), serve: handle((*Service).handleInviteRedeemPOST)},

		// Browser OIDC: navigations and the provider's callbacks. A callback
		// asked for JSON (Accept, or ?format=json on a step-up) answers JSON.
		{Method: GET, Path: "/{provider}/login", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Query: OIDCLoginQuery{}, Responses: []Reply{{Status: http.StatusFound}}, serve: handle((*Service).handleOIDCLoginGET)},
		{Method: POST, Path: "/{provider}/login", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCStart, MountedWhen: FeatureOIDC,
			Request: OIDCLoginRequest{}, Responses: replyOK(OIDCStart{}), serve: handle((*Service).handleOIDCLoginPOST)},
		{Method: GET, Path: "/{provider}/callback", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Query: OIDCCallbackQuery{}, Responses: oidcCallbackReplies, serve: handle((*Service).handleOIDCCallbackGET)},
		{Method: GET, Path: "/{provider}/step-up/callback", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Query: OIDCCallbackQuery{}, Responses: oidcStepUpReplies, serve: handle((*Service).handleOIDCCallbackGET)},
		// response_mode=form_post providers (Apple) deliver the same response
		// as a cross-site POST body (#295).
		{Method: POST, Path: "/{provider}/callback", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Responses: oidcCallbackReplies, serve: handle((*Service).handleOIDCCallbackGET)},
		{Method: POST, Path: "/{provider}/step-up/callback", Surface: SurfaceOIDC, Group: oidc, Auth: public, Bucket: RLOIDCCallback, MountedWhen: FeatureOIDC,
			Responses: oidcStepUpReplies, serve: handle((*Service).handleOIDCCallbackGET)},
	}
}

var (
	// A login callback redirects to the frontend (or answers the popup
	// document); asked for JSON it answers the session, or 204 for a linked
	// provider.
	oidcCallbackReplies = []Reply{{Status: http.StatusFound}, {http.StatusOK, OIDCLoginResult{}}, {Status: http.StatusNoContent}}
	oidcStepUpReplies   = []Reply{{Status: http.StatusFound}, {http.StatusOK, OIDCStepUpResult{}}}
)
