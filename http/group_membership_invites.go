package authhttp

import (
	"errors"
	"net/http"
	"strings"
	"time"

	authcore "github.com/open-rails/authkit/internal/authcore"
)

// #147 known-user permission-group invites: the invitee accepts/declines from
// their own account, so these routes authorize with the caller's OWN auth token
// (RouteAccount, required). No consumable code in the URL.

func (s *Service) handleMeGroupInvitesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	invites, err := s.svc.ListPendingGroupMembershipInvites(r.Context(), claims.UserID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(invites))
	for _, inv := range invites {
		data = append(data, map[string]any{
			"id":            inv.ID,
			"persona":       inv.Persona,
			"instance_slug": inv.InstanceSlug,
			"role":          inv.Role,
			"invited_by":    inv.InvitedBy,
			"expires_at":    inv.ExpiresAt.UTC().Format(time.RFC3339),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"object": "list", "data": data})
}

func (s *Service) handleMeGroupInviteAccept(w http.ResponseWriter, r *http.Request) {
	s.meGroupInviteRespond(w, r, true)
}

func (s *Service) handleMeGroupInviteDecline(w http.ResponseWriter, r *http.Request) {
	s.meGroupInviteRespond(w, r, false)
}

func (s *Service) meGroupInviteRespond(w http.ResponseWriter, r *http.Request, accept bool) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	inviteID := strings.TrimSpace(r.PathValue("id"))
	if inviteID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	var err error
	if accept {
		err = s.svc.AcceptGroupMembershipInvite(r.Context(), claims.UserID, inviteID)
	} else {
		err = s.svc.DeclineGroupMembershipInvite(r.Context(), claims.UserID, inviteID)
	}
	if errors.Is(err, authcore.ErrGroupMembershipInviteNotFound) {
		notFound(w, ErrNotFound)
		return
	}
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "invite_id": inviteID, "accepted": accept})
}
