package authhttp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	core "github.com/PaulFidika/authkit/core"
	pwhash "github.com/PaulFidika/authkit/password"
)

type adminUsersListResponse struct {
	Object  string           `json:"object"`
	Data    []core.AdminUser `json:"data"`
	Total   int64            `json:"total"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
	HasMore bool             `json:"has_more"`
}

func (s *Service) handleAdminRolesGrantPOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" || req.Role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if s.svc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "roles_unavailable"})
		return
	}
	if err := s.svc.AssignRoleBySlug(r.Context(), req.UserID, req.Role); err != nil {
		serverErr(w, "assign_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminRolesRevokePOST(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminRolesRevoke) {
		tooMany(w)
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" || req.Role == "" {
		badRequest(w, "invalid_request")
		return
	}
	if s.svc == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "roles_unavailable"})
		return
	}
	if err := s.svc.RemoveRoleBySlug(r.Context(), req.UserID, req.Role); err != nil {
		serverErr(w, "revoke_failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersListGET(w http.ResponseWriter, r *http.Request) {
	if !s.allow(r, RLAdminUserSessionsList) {
		tooMany(w)
		return
	}
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page == 0 {
		page = 1
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size == 0 {
		size = 50
	}
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "All users"
	}
	search := r.URL.Query().Get("search")
	result, err := s.svc.AdminListUsers(r.Context(), page, size, filter, search, false)
	if err != nil {
		serverErr(w, "failed_to_list_users")
		return
	}
	hasMore := int64(result.Offset+result.Limit) < result.Total
	writeJSON(w, http.StatusOK, adminUsersListResponse{
		Object:  "list",
		Data:    result.Users,
		Total:   result.Total,
		Limit:   result.Limit,
		Offset:  result.Offset,
		HasMore: hasMore,
	})
}

func (s *Service) handleAdminUserGET(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user_id")
	u, err := s.svc.AdminGetUser(r.Context(), id)
	if err != nil || u == nil {
		notFound(w, "not_found")
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Service) handleAdminUsersBanPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string  `json:"user_id"`
		Reason *string `json:"reason"`
		Until  *string `json:"until"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.UserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminUserSessionsRevokeAll) {
		tooMany(w)
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, "unauthorized")
		return
	}
	var untilPtr *time.Time
	if req.Until != nil {
		untilStr := strings.TrimSpace(*req.Until)
		if untilStr != "" {
			parsed, err := time.Parse(time.RFC3339, untilStr)
			if err != nil {
				badRequest(w, "invalid_until")
				return
			}
			parsed = parsed.UTC()
			untilPtr = &parsed
		}
	}
	if err := s.svc.BanUser(r.Context(), req.UserID, req.Reason, untilPtr, claims.UserID); err != nil {
		serverErr(w, "failed_to_ban")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersUnbanPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.UserID) == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminUserSessionsRevokeAll) {
		tooMany(w)
		return
	}
	if err := s.svc.UnbanUser(r.Context(), req.UserID); err != nil {
		serverErr(w, "failed_to_unban")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersSetEmailPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
		Email  string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" || req.Email == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	if err := s.svc.UpdateEmail(r.Context(), req.UserID, req.Email); err != nil {
		badRequest(w, "failed_to_update_email")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersSetUsernamePOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		Username string `json:"username"`
	}
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" || req.Username == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	if err := s.svc.UpdateUsername(r.Context(), req.UserID, req.Username); err != nil {
		badRequest(w, "failed_to_update_username")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersSetPasswordPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" || req.Password == "" || pwhash.Validate(req.Password) != nil {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminRolesGrant) {
		tooMany(w)
		return
	}
	if err := s.svc.AdminSetPassword(r.Context(), req.UserID, req.Password); err != nil {
		badRequest(w, "failed_to_set_password")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUserToggleActivePOST(w http.ResponseWriter, r *http.Request) {
	var body struct {
		UserID string `json:"user_id"`
		Banned *bool  `json:"banned"`
	}
	if err := decodeJSON(r, &body); err != nil || body.UserID == "" || body.Banned == nil {
		badRequest(w, "invalid_request")
		return
	}

	if *body.Banned {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok || strings.TrimSpace(claims.UserID) == "" {
			unauthorized(w, "unauthorized")
			return
		}
		if err := s.svc.BanUser(r.Context(), body.UserID, nil, nil, claims.UserID); err != nil {
			serverErr(w, "failed_to_ban")
			return
		}
	} else {
		if err := s.svc.UnbanUser(r.Context(), body.UserID); err != nil {
			serverErr(w, "failed_to_unban")
			return
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"user_id": body.UserID,
		"banned":  *body.Banned,
	})
}

func (s *Service) handleAdminUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user_id")
	if id == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminUserSessionsRevokeAll) {
		tooMany(w)
		return
	}
	if err := s.svc.SoftDeleteUser(r.Context(), id); err != nil {
		serverErr(w, "failed_to_delete")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUserRestorePOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, "invalid_request")
		return
	}
	if !s.allow(r, RLAdminUserSessionsRevokeAll) {
		tooMany(w)
		return
	}
	if err := s.svc.RestoreUser(r.Context(), userID); err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			notFound(w, "not_found")
			return
		}
		serverErr(w, "failed_to_restore_user")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
}

func (s *Service) handleAdminDeletedUsersListGET(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page == 0 {
		page = 1
	}
	size, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if size == 0 {
		size = 50
	}
	filter := r.URL.Query().Get("filter")
	if filter == "" {
		filter = "All users"
	}
	search := r.URL.Query().Get("search")

	result, err := s.svc.AdminListUsers(r.Context(), page, size, filter, search, true)
	if err != nil {
		serverErr(w, "failed_to_list_deleted_users")
		return
	}
	hasMore := int64(result.Offset+result.Limit) < result.Total
	writeJSON(w, http.StatusOK, adminUsersListResponse{
		Object:  "list",
		Data:    result.Users,
		Total:   result.Total,
		Limit:   result.Limit,
		Offset:  result.Offset,
		HasMore: hasMore,
	})
}
