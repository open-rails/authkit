package httpapi

import (
	"errors"
	"net/http"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// requirePermission gates AuthKit's own routes on perm in group, checked live
// for every identity kind: the engine resolves the identity's current grants (a
// user's roles on the group and on root, an API key's role, an application's
// grants in its controlling group) and applies any token ceiling. Admin
// authority over the user directory is the root:users:* permissions on the
// root group, gated the same way.
func (s *Service) requirePermission(group iam.GroupRef, perm iam.Perm, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, ok := verify.IdentityFromContext(r.Context())
		if !ok {
			fail(w, errmodel.CodeUnauthenticated)
			return
		}
		if s := state(who); s.IsZero() {
			fail(w, errmodel.CodeForbidden)
			return
		}
		allowed, err := s.svc.Can(r.Context(), who, group, perm)
		if errors.Is(err, iam.ErrSessionRevoked) {
			writeError(w, err)
			return
		}
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
