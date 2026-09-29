package httpapi

import (
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// requirePermission gates AuthKit's own routes on perm in group, checked live
// for every actor kind: the engine resolves the actor's current grants (a
// user's roles on the group and on root, an API key's role, an application's
// grants in its controlling group) and applies any token ceiling. Delegated
// principals never reach AuthKit's management routes. Admin
// authority over the user directory is the root:users:* permissions on the
// root group, gated the same way.
func (s *Service) requirePermission(group iam.GroupRef, perm iam.Perm, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok {
			fail(w, errmodel.CodeUnauthenticated)
			return
		}
		actor, ok := verify.ActorFromClaims(claims)
		if !ok || actor.Kind() == iam.ActorDelegated {
			fail(w, errmodel.CodeForbidden)
			return
		}
		allowed, err := s.svc.Can(r.Context(), actor, group, perm)
		if err != nil {
			serverErr(w, "database_error", err)
			return
		}
		if !allowed {
			fail(w, errmodel.CodeForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}
