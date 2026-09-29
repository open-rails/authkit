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
	RoutePermissionGroups RouteGroup = "permission_groups"
	RouteBrowserOIDC      RouteGroup = "browser_oidc"
	// RouteDelegated is the delegated-token mint surface (POST
	// /delegated/token), mounted only when Config.Delegated declares audiences.
	RouteDelegated RouteGroup = "delegated"
)

// RouteAuthTier is the authentication a route enforces before its handler runs.
type RouteAuthTier string

const (
	AuthPublic     RouteAuthTier = "public"     // no principal
	AuthOptional   RouteAuthTier = "optional"   // principal used when present
	AuthRequired   RouteAuthTier = "required"   // valid principal
	AuthSession    RouteAuthTier = "session"    // valid principal whose session or device key is still active
	AuthPermission RouteAuthTier = "permission" // valid principal holding Route.Permission, its session checked
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

// JWKSPath serves the issuer's public signing keys beneath the issuer's path
// (the mount's BasePath), so verifiers derive it: issuer + JWKSPath.
const JWKSPath = "/.well-known/jwks.json"

const (
	// RefreshCookieName is the refresh cookie on HTTPS deployments. Browsers
	// accept a __Host- cookie only when it is Secure, host-only and Path=/, so
	// a sibling subdomain can neither plant nor shadow it.
	RefreshCookieName = "__Host-authkit_rt"
	// InsecureRefreshCookieName is used only on plain-HTTP deployments (local
	// development), where browsers refuse __Host- cookies.
	InsecureRefreshCookieName = "authkit_rt"
)
