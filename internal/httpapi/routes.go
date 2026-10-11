package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
)

// APIRoutes returns this Service's JSON API routes: the catalog's API routes
// its configuration mounts, in the given groups (all when none), each wrapped
// in its gate, rate limit and language middleware.
func (s *Service) APIRoutes(groups ...iam.RouteGroup) []RouteSpec {
	return s.routes(SurfaceAPI, groups, func(route RouteSpec, h http.Handler) http.Handler {
		if route.StepUp {
			h = s.requireRecentSignIn(h)
		}
		return s.rateLimitedRoute(route.Bucket, s.authenticate(route.Auth, h))
	})
}

// OAuthRoutes returns the authorization server's protocol routes,
// prefix-neutral: issuer-relative paths beneath the base path.
func (s *Service) OAuthRoutes(groups ...iam.RouteGroup) []RouteSpec {
	return s.routes(SurfaceOAuth, groups, func(route RouteSpec, h http.Handler) http.Handler {
		return s.rateLimitedRoute(route.Bucket, h)
	})
}

// SCIMRoutes returns the SCIM service provider's routes, prefix-neutral.
func (s *Service) SCIMRoutes(groups ...iam.RouteGroup) []RouteSpec {
	return s.routes(SurfaceSCIM, groups, func(route RouteSpec, h http.Handler) http.Handler {
		return s.rateLimitedRoute(route.Bucket, h)
	})
}

// OIDCBrowserRoutes returns the browser OIDC routes, prefix-neutral.
func (s *Service) OIDCBrowserRoutes(groups ...iam.RouteGroup) []RouteSpec {
	return s.routes(SurfaceOIDC, groups, func(route RouteSpec, h http.Handler) http.Handler {
		return s.rateLimitedRoute(route.Bucket, h)
	})
}

func (s *Service) routes(surface Surface, groups []iam.RouteGroup, wrap func(RouteSpec, http.Handler) http.Handler) []RouteSpec {
	if s == nil || s.svc == nil {
		return nil
	}
	selected := routeGroupSet(groups)
	var out []RouteSpec
	for _, route := range Catalog() {
		if route.Surface != surface || !selected(route.Group) || !s.mounts(route.MountedWhen) {
			continue
		}
		h := route.serve(s)
		// A root permission is checked here; a group route checks its own
		// (GroupHandler), since it first resolves the group.
		if route.Auth == iam.AuthPermission && strings.HasPrefix(route.Perm, iam.RootPersona().String()+":") {
			h = s.requirePermission(iam.RootGroup(), ident.Perm(route.Perm), h)
		}
		if route.signsIn() && s.countsDevices() {
			h = s.withSignInDevice(h)
		}
		route.Handler = s.languageMiddleware(s.withClientAddress(wrap(route, h)))
		out = append(out, route)
	}
	return out
}

// mounts reports whether this Service's configuration mounts routes that need f.
func (s *Service) mounts(f Feature) bool {
	cfg := s.cfg
	switch f {
	case Always:
		return true
	case FeaturePasskeys:
		return s.svc.PasskeysEnabled()
	case FeaturePasswordless:
		return cfg.Registration.PasswordlessLogin
	case FeatureRegistration:
		return cfg.Registration.NativeUserMode != iam.RegistrationModeClosed
	case FeatureTwoFactor:
		return s.svc.TwoFactorEnabled()
	case FeatureSolana:
		return cfg.SolanaNetwork != ""
	case FeatureOIDC:
		return len(s.providers) > 0
	case FeatureDeviceKeys:
		return cfg.DeviceKeys.Enabled
	case FeatureInvitations:
		return !cfg.Invitations.Disabled
	case FeatureNewDevices:
		return cfg.SignIn.NewDevicesPerAccount > 0 || s.smsSender
	case FeatureAuthorizationServer:
		return config.AuthorizationServerEnabled(cfg.AuthorizationServer)
	case FeatureTokenEndpoint:
		return config.AuthorizationServerEnabled(cfg.AuthorizationServer) || cfg.Resource.Enabled()
	case FeatureOAuthClients:
		return config.GroupClientsEnabled(cfg.AuthorizationServer)
	case FeatureGroups, FeatureAPIKeys, FeatureCustomRoles, FeatureRemoteApplications:
		schema := s.svc.PermissionGroupSchema()
		for _, name := range schema.Personas() {
			p, _ := schema.Persona(name)
			if f == FeatureGroups && name != iam.RootPersona() || f == FeatureAPIKeys && p.APIKeys || f == FeatureCustomRoles && p.CustomRoles ||
				f == FeatureRemoteApplications && p.RemoteApplications {
				return true
			}
		}
	}
	return false
}

func isOIDCPath(path string) bool {
	return strings.HasPrefix(path, "/oidc/")
}

// authenticate applies a route's declared tier (#412), so the catalog entry
// is the gate that runs: AuthSession adds the session check to Required, and
// AuthPermission's own check (requirePermission, GroupHandler) runs the same
// check through the identity's session binding.
func (s *Service) authenticate(tier iam.RouteAuthTier, h http.Handler) http.Handler {
	switch tier {
	case iam.AuthOptional:
		return verify.Optional(s.svc)(h)
	case iam.AuthRequired, iam.AuthPermission:
		return verify.Required(s.svc)(h)
	case iam.AuthSession:
		return verify.Required(s.svc)(s.requireSession(h))
	}
	return h
}

// requireRecentSignIn is RouteSpec.StepUp: the caller signed in recently
// (CheckRecentSignIn, MFA-fresh when enrolled), else step_up_required with how
// to step up. It runs after the route's tier.
func (s *Service) requireRecentSignIn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, err := callerClaims(r)
		if err == nil {
			err = s.svc.CheckRecentSignIn(r.Context(), claims)
		}
		if err != nil {
			writeError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitedRoute applies the route's per-IP bucket in front of next (#328):
// the registry, not each handler, owns the entry check.
func (s *Service) rateLimitedRoute(bucket string, next http.Handler) http.Handler {
	if bucket == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.rateLimited(w, r, bucket) {
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mfaEnrollmentExemptPaths returns the distinct Path values of the routes tagged
// MFAEnrollmentExempt — the authoritative 2FA enroll/challenge/verify surface a
// forced-enrollment-gated request must still reach (#243). NewMount anchors these
// at its prefix and registers them with the engine's AddMFAEnrollmentExemptRoutes, so the gate's
// allowlist is derived from the route registry rather than a hand-maintained list.
func mfaEnrollmentExemptPaths(specs []RouteSpec) []string {
	seen := make(map[string]bool, len(specs))
	out := make([]string, 0, len(specs))
	for _, spec := range specs {
		if !spec.MFAEnrollmentExempt || seen[spec.Path] {
			continue
		}
		seen[spec.Path] = true
		out = append(out, spec.Path)
	}
	return out
}

func routeGroupSet(groups []iam.RouteGroup) func(iam.RouteGroup) bool {
	if len(groups) == 0 {
		return func(iam.RouteGroup) bool { return true }
	}
	set := make(map[iam.RouteGroup]struct{}, len(groups))
	for _, group := range groups {
		set[group] = struct{}{}
	}
	return func(group iam.RouteGroup) bool {
		_, ok := set[group]
		return ok
	}
}
