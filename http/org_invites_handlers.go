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
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersRead)
	if !gateOK {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, err := s.svc.ListOrgInvites(r.Context(), canonical, status)
	if err != nil {
		serverErr(w, ErrOrgInvitesLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": items})
}

func (s *Service) handleOrgInvitesPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	if orgSlug == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersCreate)
	if !gateOK {
		return
	}
	var body struct {
		UserID    string  `json:"user_id"`
		Role      string  `json:"role,omitempty"`
		ExpiresAt *string `json:"expires_at,omitempty"`
	}
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	// NO-ESCALATION at invite time: an invite grants its role's permissions on
	// accept, so the inviter must hold every permission the role confers. This
	// stops a member with only member-create authority from minting an `owner`
	// (=`*`) invite. The same check runs again at accept time (the inviter may be
	// demoted before the invite is accepted). Same primitive as the direct
	// role-grant handler (handleOrgMemberRolesPOST).
	if err := s.svc.ValidateInviteRoleGrant(r.Context(), canonical, claims.UserID, strings.TrimSpace(body.Role)); err != nil {
		if err == core.ErrInviteRoleExceedsGrantor {
			forbidden(w, ErrRoleExceedsGrantor)
			return
		}
		serverErr(w, ErrPermissionValidateFailed)
		return
	}
	var expiresAt *time.Time
	if body.ExpiresAt != nil && strings.TrimSpace(*body.ExpiresAt) != "" {
		parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(*body.ExpiresAt))
		if err != nil {
			badRequest(w, ErrInvalidExpiresAt)
			return
		}
		parsed = parsed.UTC()
		expiresAt = &parsed
	}
	item, err := s.svc.CreateOrgInvite(r.Context(), canonical, strings.TrimSpace(body.UserID), claims.UserID, strings.TrimSpace(body.Role), expiresAt)
	if err != nil {
		badRequest(w, ErrOrgInviteCreateFailed)
		return
	}
	writeJSON(w, http.StatusCreated, item)
}

func (s *Service) handleOrgInviteRevokePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	orgSlug := strings.TrimSpace(r.PathValue("org"))
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if orgSlug == "" || inviteID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	canonical, gateOK := s.requireOrgPermissionGin(w, r, claims, orgSlug, core.PermOrgMembersDelete)
	if !gateOK {
		return
	}
	if err := s.svc.RevokeOrgInvite(r.Context(), canonical, inviteID); err != nil {
		if err == core.ErrInviteNotFound {
			notFound(w, ErrInviteNotFound)
			return
		}
		badRequest(w, ErrOrgInviteRevokeFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleOrgInviteAcceptPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if inviteID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.AcceptOrgInvite(r.Context(), inviteID, claims.UserID); err != nil {
		switch err {
		case core.ErrInviteNotFound:
			notFound(w, ErrInviteNotFound)
		case core.ErrInviteNotForUser:
			forbidden(w, ErrForbidden)
		case core.ErrInviteRoleExceedsGrantor:
			// The inviter no longer has authority to grant this role (demoted
			// since the invite was created). Refuse rather than escalate.
			forbidden(w, ErrRoleExceedsGrantor)
		case core.ErrInviteNotPending:
			badRequest(w, ErrOrgInviteNotPending)
		case core.ErrInviteExpired:
			badRequest(w, ErrOrgInviteExpired)
		default:
			badRequest(w, ErrOrgInviteAcceptFailed)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleOrgInviteDeclinePOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	inviteID := strings.TrimSpace(r.PathValue("invite_id"))
	if inviteID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.DeclineOrgInvite(r.Context(), inviteID, claims.UserID); err != nil {
		switch err {
		case core.ErrInviteNotFound:
			notFound(w, ErrInviteNotFound)
		case core.ErrInviteNotForUser:
			forbidden(w, ErrForbidden)
		case core.ErrInviteNotPending:
			badRequest(w, ErrOrgInviteNotPending)
		case core.ErrInviteExpired:
			badRequest(w, ErrOrgInviteExpired)
		default:
			badRequest(w, ErrOrgInviteDeclineFailed)
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleUserInvitesGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	items, err := s.svc.ListUserInvites(r.Context(), claims.UserID, status)
	if err != nil {
		serverErr(w, ErrUserInvitesLookupFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"invites": items})
}
