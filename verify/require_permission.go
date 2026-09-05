package verify

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit"
)

// PermissionChecker checks live authority on an already resolved immutable group.
// Hosts resolve a name once at their request boundary and reuse its GroupID.
type PermissionChecker interface {
	CanOnGroup(ctx context.Context, subject authkit.Subject, groupID string, perm authkit.Perm) (bool, error)
}

// PermissionScope is a trusted request resolution. GroupID and AuthorityIssuer
// identify ownership; Persona and Instance describe its canonical public name.
type PermissionScope struct {
	GroupID         string
	AuthorityIssuer string
	Persona         authkit.Persona
	Instance        string
}

// Allow checks machine permission ceilings against the exact UUID and authority
// issuer. Unbound delegated permissions retain their explicit issuer-trust
// contract. Human permissions always come from live assignments on GroupID.
// A missing or mismatched machine binding never falls back to human authority.
func Allow(ctx context.Context, checker PermissionChecker, cl Claims, perm authkit.Perm, scope PermissionScope) (bool, error) {
	if cl.BoundToPermissionGroup() {
		return cl.HasPermission(perm) && cl.PermissionGroupAllows(scope), nil
	}
	if cl.PrincipalKind() != authkit.PrincipalKindUser && cl.HasPermission(perm) {
		return true, nil
	}
	if checker == nil || cl.UserID == "" || scope.GroupID == "" {
		return false, nil
	}
	return checker.CanOnGroup(ctx, authkit.UserSubject(cl.UserID), scope.GroupID, perm)
}

// RequirePermission authorizes the resolved group once and places that exact
// scope in the request context for the downstream handler. Missing resolution or
// any permission-check error denies. Unbound delegated authority is scope-free.
func RequirePermission(checker PermissionChecker, perm authkit.Perm, resolve func(*http.Request) PermissionScope) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cl, err := GetClaims(r.Context())
			if err != nil {
				forbidden(w, "forbidden")
				return
			}
			// Token-carried authority short-circuits without a scope ONLY for
			// unbound principals (delegated access — issuer trust + permissions).
			// A group-bound machine principal (#248) needs the resolved scope to
			// check its instance binding, so it falls through to Allow.
			if cl.PrincipalKind() != authkit.PrincipalKindUser && cl.HasPermission(perm) && !cl.BoundToPermissionGroup() {
				next.ServeHTTP(w, r)
				return
			}
			if resolve == nil {
				forbidden(w, "forbidden")
				return
			}
			scope := resolve(r)
			ok, err := Allow(r.Context(), checker, cl, perm, scope)
			if err != nil || !ok {
				forbidden(w, "forbidden")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPermissionScope(r.Context(), scope)))
		})
	}
}

// PermissionScopeFromContext returns the exact group authorized by middleware,
// so a domain handler does not resolve the mutable path a second time.
func PermissionScopeFromContext(ctx context.Context) (PermissionScope, bool) {
	scope, ok := ctx.Value(permissionScopeKey{}).(PermissionScope)
	return scope, ok
}

type permissionScopeKey struct{}

// WithPermissionScope carries an already authorized scope into a trusted host
// adapter's handler. Call only after Allow/AllowLive succeeds; this does not
// authorize anything itself.
func WithPermissionScope(ctx context.Context, scope PermissionScope) context.Context {
	return context.WithValue(ctx, permissionScopeKey{}, scope)
}
