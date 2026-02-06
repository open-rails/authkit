package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleOrgInvitesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, err := s.svc.ListOrgInvites(r.Context(), canonical, status)
	if err != nil {
		serverErr(w, "org_invites_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": items})
}

func (s *Service) handleOrgInvitesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	var body struct {
		UserID    string  `json:"user_id"`
		ExpiresAt *string `json:"expires_at,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	var expiresAt *time.Time
	if body.ExpiresAt != nil && strings.TrimSpace(*body.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*body.ExpiresAt))
		if err != nil {
			badRequest(w, "invalid_expires_at")
			return
		}
		parsed = parsed.UTC()
		expiresAt = &parsed
	}
	item, err := s.svc.CreateOrgInvite(r.Context(), canonical, strings.TrimSpace(body.UserID), claims.UserID, expiresAt)
	if err != nil {
		badRequest(w, "org_invite_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Service) handleOrgInviteRevokePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if orgSlug == "" || inviteID == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, _, isOwner, err := s.requireOrgOwner(r.Context(), claims.UserID, orgSlug)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return
		}
		serverErr(w, "org_lookup_failed")
		return
	}
	if !isOwner {
		forbidden(w, "forbidden")
		return
	}
	if err := s.svc.RevokeOrgInvite(r.Context(), canonical, inviteID); err != nil {
		if err == core.ErrInviteNotFound {
			notFound(w, "invite_not_found")
			return
		}
		badRequest(w, "org_invite_revoke_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleOrgInviteAcceptPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if inviteID == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := s.svc.AcceptOrgInvite(r.Context(), inviteID, claims.UserID); err != nil {
		switch err {
		case core.ErrInviteNotFound:
			notFound(w, "invite_not_found")
		case core.ErrInviteNotForUser:
			forbidden(w, "forbidden")
		case core.ErrInviteNotPending, core.ErrInviteExpired:
			badRequest(w, err.Error())
		default:
			badRequest(w, "org_invite_accept_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleOrgInviteDeclinePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if inviteID == "" {
		badRequest(w, "invalid_request")
		return
	}
	if err := s.svc.DeclineOrgInvite(r.Context(), inviteID, claims.UserID); err != nil {
		switch err {
		case core.ErrInviteNotFound:
			notFound(w, "invite_not_found")
		case core.ErrInviteNotForUser:
			forbidden(w, "forbidden")
		case core.ErrInviteNotPending, core.ErrInviteExpired:
			badRequest(w, err.Error())
		default:
			badRequest(w, "org_invite_decline_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserInvitesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, err := s.svc.ListUserInvites(r.Context(), claims.UserID, status)
	if err != nil {
		serverErr(w, "user_invites_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": items})
}
