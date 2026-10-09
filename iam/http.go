package iam

// HTTP contract vocabulary: route groups and gates, the route catalog entry,
// and the issuer-relative paths and cookie names clients depend on.

// RouteGroup names one capability of AuthKit's HTTP surface. Hosts mount the
// default groups or select exactly the ones they expose.
type RouteGroup string

const (
	RouteAuth RouteGroup = "auth"
	// RouteDeviceKeys is the refreshless native-client login surface: email
	// enrollment plus Ed25519 challenge authentication.
	RouteDeviceKeys       RouteGroup = "device_keys"
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
// (the mount's BasePath), so verifiers derive it: issuer + JWKSPath.
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
	// RefreshCookieName is the refresh cookie on HTTPS deployments. Browsers
	// accept a __Host- cookie only when it is Secure, host-only and Path=/, so
	// a sibling subdomain can neither plant nor shadow it.
	RefreshCookieName = "__Host-authkit_rt"
	// InsecureRefreshCookieName is used only on plain-HTTP deployments (local
	// development), where browsers refuse __Host- cookies.
	InsecureRefreshCookieName = "authkit_rt"
)
