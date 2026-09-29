package httpapi

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// requirePermission is the granular permission gate for AuthKit's intrinsic
// routes. It authorizes the calling principal against permission `perm` on the
// (persona, instanceSlug) permission group, for EVERY supported principal
// shape:
//   - user JWT: resolved through the permission-group (svc.Can, unioning the
//     user's roles on the group and on root), then current account
//     liveness before the sensitive operation;
//   - api-key / service, delegated, and remote-application principals: resolved
//     through their verified permission ceiling (claims.HasPermission); a
//     GROUP-BOUND machine principal (#248) must additionally match the gated
//     (persona, instanceSlug) exactly — its authority is valid only on the
//     group instance it was minted on.
//
// There is deliberately NO special "admin" authorization tier: admin authority
// over the user directory is simply the `root:users:*` permissions on the root
// group, gated here the same way every other permission is. Callers that gate an
// inherently root-scoped intrinsic route pass (iam.RootPersona, "", perm).
func (s *Service) requirePermission(group iam.GroupRef, perm iam.Perm, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok {
			fail(w, errmodel.CodeNotAuthenticated)
			return
		}
		group, err := s.svc.GroupInstanceForSlug(r.Context(), group)
		if err != nil {
			writeError(w, remap(err, groupScopeCodes))
			return
		}
		scope := verify.PermissionScope{GroupID: group.ID, AuthorityIssuer: s.settings.Issuer, Persona: group.Persona, Instance: group.InstanceSlug}
		switch {
		case claims.IsMachine():
			if claims.HasPermission(perm) && claims.PermissionGroupAllows(scope) {
				next.ServeHTTP(w, r)
				return
			}
		case strings.TrimSpace(claims.UserID) != "":
			allowed, err := s.svc.CanOnGroup(r.Context(), iam.UserSubject(claims.UserID), group.ID, perm)
			if err != nil {
				serverErr(w, "database_error", err)
				return
			}
			if allowed {
				// Permissions are current; native identity remains the verified
				// JWT snapshot. Hosts can explicitly select live-account checks.
				next.ServeHTTP(w, r)
				return
			}
		}
		fail(w, errmodel.CodeForbidden)
	})
}
