package authhttp

import (
	"net/http"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

func (s *Service) handleTenantInvitesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	if tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantRead)
	if !gateOK {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, err := s.svc.ListTenantInvites(r.Context(), canonical, status)
	if err != nil {
		serverErr(w, "tenant_invites_lookup_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": items})
}

func (s *Service) handleTenantInvitesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	if tenantSlug == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantMembersManage)
	if !gateOK {
		return
	}
	var body struct {
		UserID    string  `json:"user_id"`
		Role      string  `json:"role,omitempty"`
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
	item, err := s.svc.CreateTenantInvite(r.Context(), canonical, strings.TrimSpace(body.UserID), claims.UserID, strings.TrimSpace(body.Role), expiresAt)
	if err != nil {
		badRequest(w, "tenant_invite_create_failed")
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Service) handleTenantInviteRevokePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	tenantSlug := strings.TrimSpace(r.PathValue("tenant"))
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if tenantSlug == "" || inviteID == "" {
		badRequest(w, "invalid_request")
		return
	}
	canonical, gateOK := s.requireTenantPermissionGin(w, r, claims, tenantSlug, core.PermTenantMembersManage)
	if !gateOK {
		return
	}
	if err := s.svc.RevokeTenantInvite(r.Context(), canonical, inviteID); err != nil {
		if err == core.ErrInviteNotFound {
			notFound(w, "invite_not_found")
			return
		}
		badRequest(w, "tenant_invite_revoke_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleTenantInviteAcceptPOST(w http.ResponseWriter, r *http.Request) {
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
	if err := s.svc.AcceptTenantInvite(r.Context(), inviteID, claims.UserID); err != nil {
		switch err {
		case core.ErrInviteNotFound:
			notFound(w, "invite_not_found")
		case core.ErrInviteNotForUser:
			forbidden(w, "forbidden")
		case core.ErrInviteNotPending, core.ErrInviteExpired:
			badRequest(w, err.Error())
		default:
			badRequest(w, "tenant_invite_accept_failed")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleTenantInviteDeclinePOST(w http.ResponseWriter, r *http.Request) {
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
	if err := s.svc.DeclineTenantInvite(r.Context(), inviteID, claims.UserID); err != nil {
		switch err {
		case core.ErrInviteNotFound:
			notFound(w, "invite_not_found")
		case core.ErrInviteNotForUser:
			forbidden(w, "forbidden")
		case core.ErrInviteNotPending, core.ErrInviteExpired:
			badRequest(w, err.Error())
		default:
			badRequest(w, "tenant_invite_decline_failed")
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
