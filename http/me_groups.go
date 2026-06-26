package authhttp

import (
	"errors"
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// handleMeGroupLeave lets an authenticated user remove THEMSELF from a permission
// group instance (#193): DELETE /me/groups/{persona}/{instance_slug}. It is
// authorized by the caller's own auth token — no <persona>:members:manage, because
// you act only on yourself. Refuses with 409 cannot_remove_last_owner if the caller
// is the group's sole owner (leaving would orphan it). Leaving a group you are not in
// is an idempotent no-op.
func (s *Service) handleMeGroupLeave(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	persona := strings.TrimSpace(r.PathValue("persona"))
	instanceSlug := strings.TrimSpace(r.PathValue("instance_slug"))
	if persona == "" || instanceSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	err := s.svc.LeaveGroup(r.Context(), claims.UserID, persona, instanceSlug)
	if errors.Is(err, authkit.ErrCannotRemoveLastAdminRole) {
		sendErr(w, http.StatusConflict, ErrCannotRemoveLastOwner)
		return
	}
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       persona,
		"instance_slug": instanceSlug,
		"left":          true,
	})
}
