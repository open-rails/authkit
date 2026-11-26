package iam

// HTTP contract vocabulary: route groups and gates, the route catalog entry,
// and the issuer-relative paths and cookie names clients depend on.

// RouteGroup names one capability of AuthKit's HTTP surface. Hosts mount the
// default groups (DefaultRouteGroups) or select exactly the ones they
// expose; the opt-in features are groups of their own.
type RouteGroup string

const (
	RouteAuth RouteGroup = "auth"
	// RouteDeviceKeys is the refreshless native-client login surface: email
	// enrollment plus Ed25519 challenge authentication. Opt-in: enrollment
	// is an email-code login, and the jwt-bearer grant needs it.
	RouteDeviceKeys RouteGroup = "device_keys"
	// RoutePasswordless is passwordless sign-in by a code or link sent to
	// the account's email or phone. Opt-in.
	RoutePasswordless RouteGroup = "passwordless"
	// RoutePersonalAccessTokens is users' own noninteractive tokens: the
	// /me/personal-access-tokens routes, and the tokens they issue. Opt-in.
	RoutePersonalAccessTokens RouteGroup = "personal_access_tokens"
	// RouteInvitations is invite links and emailed invitations into a
	// group, and redeeming them. Without it only the host's own
	// Client.CreateInvitation calls issue any.
	RouteInvitations RouteGroup = "invitations"
	// RouteSetup is the first administrator's setup: while no account holds
	// a role on root, Start logs a single-use link that creates the owner.
	RouteSetup            RouteGroup = "setup"
	RouteRegistration     RouteGroup = "registration"
	RouteAccount          RouteGroup = "account"
	RouteAdmin            RouteGroup = "admin"
	RoutePermissionGroups RouteGroup = "groups"
	RouteBrowserOIDC      RouteGroup = "browser_oidc"
	// RouteAuthorizationServer is the OAuth 2.0 authorization server and
	// OpenID provider: issuer metadata, authorize, token, userinfo,
	// revocation and RP-initiated logout beneath the issuer's path, and the
	// API the SPA approves sign-in requests through. Mounted only when
	// Config.AuthorizationServer declares clients.
	RouteAuthorizationServer RouteGroup = "authorization_server"
	// RouteSCIM is the read-only SCIM 2.0 service provider beneath the
	// issuer's path (/scim/v2), for client-credentials tokens with scope
	// scim:read. Mounted with the authorization server.
	RouteSCIM RouteGroup = "scim"
)

// RouteAuthTier is the authentication a route enforces before its handler runs.
type RouteAuthTier string

const (
	AuthPublic     RouteAuthTier = "public"     // no credential
	AuthOptional   RouteAuthTier = "optional"   // the identity, when a credential is present
	AuthRequired   RouteAuthTier = "required"   // a verified identity
	AuthSession    RouteAuthTier = "session"    // a verified identity whose session or device key is still active
	AuthPermission RouteAuthTier = "permission" // a verified identity holding Route.Permission, its session checked
)

// Route is one mounted endpoint. Path is the full net/http pattern path
// ("/api/v1/admin/users/{id}"); Auth and Permission describe the route-level
// gate, not every handler-specific authorization check.
type Route struct {
	Method     string
	Path       string
	Group      RouteGroup
	Auth       RouteAuthTier
	Permission string // `<persona>` stands for the group's persona
}

// Pattern is the route's net/http ServeMux pattern: "GET /api/v1/me".
func (r Route) Pattern() string { return r.Method + " " + r.Path }

// JWKSPath serves the issuer's public signing keys beneath the issuer's path
// (the issuer's path), so verifiers derive it: issuer + JWKSPath.
const JWKSPath = "/.well-known/jwks.json"

// The authorization server's endpoints beneath the issuer's path, as its
// metadata (OpenIDConfigurationPath) advertises them.
const (
	OpenIDConfigurationPath         = "/.well-known/openid-configuration"
	AuthorizationServerMetadataPath = "/.well-known/oauth-authorization-server"
	OAuthAuthorizePath              = "/oauth2/authorize"
	OAuthTokenPath                  = "/oauth2/token"
	OAuthUserInfoPath               = "/oauth2/userinfo"
	OAuthRevocationPath             = "/oauth2/revoke"
	OAuthEndSessionPath             = "/oauth2/end_session"
)

const (
	// RefreshCookieName is the legacy, unscoped HTTPS refresh-cookie name.
	// New cookie mounts derive an issuer-specific name unless overridden.
	// Browsers
	// accept a __Host- cookie only when it is Secure, host-only and Path=/, so
	// a sibling subdomain can neither plant nor shadow it.
	RefreshCookieName = "__Host-authkit_rt"
	// InsecureRefreshCookieName is the legacy plain-HTTP cookie name, still
	// accepted for migration after the token's issuer ownership is verified.
	InsecureRefreshCookieName = "authkit_rt"
)

// DefaultRouteGroups are the groups a nil HTTPConfig.Groups mounts: every
// group but the opt-in RouteDeviceKeys, RoutePasswordless and
// RoutePersonalAccessTokens. Append those to it to mount them too.
func DefaultRouteGroups() []RouteGroup {
	return []RouteGroup{RouteAuth, RouteRegistration, RouteAccount, RouteAdmin, RoutePermissionGroups, RouteInvitations, RouteSetup, RouteBrowserOIDC, RouteAuthorizationServer, RouteSCIM}
}
