package authhttp

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	core "github.com/open-rails/authkit/core"
)

type adminUsersListResponse struct {
	Object  string           `json:"object"`
	Data    []core.AdminUser `json:"data"`
	Total   int64            `json:"total"`
	Limit   int              `json:"limit"`
	Offset  int              `json:"offset"`
	HasMore bool             `json:"has_more"`
}

// adminUserListOptionsFromQuery parses the admin dashboard query params:
// page, page_size, search, root_role, status, sort, order, entitlement.
func adminUserListOptionsFromQuery(r *http.Request) core.AdminUserListOptions {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	sort := core.AdminUserSort(strings.TrimSpace(q.Get("sort")))
	// Default newest-first; only an explicit order=asc flips it.
	desc := !strings.EqualFold(strings.TrimSpace(q.Get("order")), "asc")
	return core.AdminUserListOptions{
		Page:        page,
		PageSize:    size,
		Search:      strings.TrimSpace(q.Get("search")),
		Role:        strings.TrimSpace(q.Get("root_role")),
		Status:      core.AdminUserStatus(strings.TrimSpace(q.Get("status"))),
		Sort:        sort,
		Desc:        desc,
		Entitlement: strings.TrimSpace(q.Get("entitlement")),
	}
}

// requirePermission is the granular permission gate for AuthKit's intrinsic
// routes. It authorizes the calling principal against permission `perm` on the
// (groupType, resourceRef) permission-group, for EVERY supported principal
// shape:
//   - user JWT: resolved through the permission-group (svc.Can, walking the
//     parent chain to root and unioning assignments);
//   - api-key / service, delegated, and remote-application principals: resolved
//     through their verified permission ceiling (claims.HasPermission).
//
// There is deliberately NO special "admin" authorization tier: admin authority
// over the user directory is simply the `root:users:*` permissions on the root
// group, gated here the same way every other permission is. Callers that gate an
// inherently root-scoped intrinsic route pass (core.RootType, "", perm).
func (s *Service) requirePermission(groupType, resourceRef, perm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			unauthorized(w, ErrNotAuthenticated)
			return
		}
		switch {
		case claims.IsService() || claims.IsDelegated() || claims.IsRemoteApplication():
			if claims.HasPermission(perm) {
				next.ServeHTTP(w, r)
				return
			}
		case strings.TrimSpace(claims.UserID) != "":
			allowed, err := s.svc.Can(r.Context(), claims.UserID, core.SubjectKindUser, groupType, resourceRef, perm)
			if err != nil {
				serverErr(w, ErrDatabaseError)
				return
			}
			if allowed {
				next.ServeHTTP(w, r)
				return
			}
		}
		forbidden(w, ErrForbidden)
	})
}

func (s *Service) handleAdminUsersListGET(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLAdminUserSessionsList) {
		return
	}
	opts := adminUserListOptionsFromQuery(r)
	result, err := s.svc.AdminListUsers(r.Context(), opts)
	if err != nil {
		if errors.Is(err, core.ErrEntitlementFilterUnavailable) {
			badRequest(w, ErrEntitlementFilterUnavailable)
			return
		}
		serverErr(w, ErrFailedToListUsers)
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
		notFound(w, ErrNotFound)
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var untilPtr *time.Time
	if req.Until != nil {
		untilStr := strings.TrimSpace(*req.Until)
		if untilStr != "" {
			parsed, err := time.Parse(time.RFC3339, untilStr)
			if err != nil {
				badRequest(w, ErrInvalidUntil)
				return
			}
			parsed = parsed.UTC()
			untilPtr = &parsed
		}
	}
	if err := s.svc.BanUser(r.Context(), req.UserID, req.Reason, untilPtr, claims.UserID); err != nil {
		serverErr(w, ErrFailedToBan)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersUnbanPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.UserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	if err := s.svc.UnbanUser(r.Context(), req.UserID); err != nil {
		serverErr(w, ErrFailedToUnban)
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminRolesGrant) {
		return
	}
	if err := s.svc.UpdateEmail(r.Context(), req.UserID, req.Email); err != nil {
		badRequest(w, ErrFailedToUpdateEmail)
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
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminRolesGrant) {
		return
	}
	if err := s.svc.UpdateUsername(r.Context(), req.UserID, req.Username); err != nil {
		if err == core.ErrOwnerSlugTaken {
			badRequest(w, ErrOwnerSlugTaken)
			return
		}
		if code := ErrorCode(core.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, ErrFailedToUpdateUsername)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUsersSetPasswordPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID   string `json:"user_id"`
		Password string `json:"password"`
	}
	if err := decodeJSON(r, &req); err != nil || req.UserID == "" || req.Password == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := core.ValidatePassword(req.Password); err != nil {
		badRequest(w, ErrorCode(core.ValidationErrorCode(err)))
		return
	}
	if s.rateLimited(w, r, RLAdminRolesGrant) {
		return
	}
	if err := s.svc.AdminSetPassword(r.Context(), req.UserID, req.Password); err != nil {
		if code := ErrorCode(core.ValidationErrorCode(err)); code != "" {
			badRequest(w, code)
			return
		}
		badRequest(w, ErrFailedToSetPassword)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user_id")
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	if err := s.svc.SoftDeleteUser(r.Context(), id); err != nil {
		serverErr(w, ErrFailedToDelete)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUserRestorePOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	if err := s.svc.RestoreUser(r.Context(), userID); err != nil {
		if errors.Is(err, core.ErrUserNotFound) {
			notFound(w, ErrNotFound)
			return
		}
		serverErr(w, ErrFailedToRestoreUser)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
}

func (s *Service) handleAdminUserPasswordResetPOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminPasswordReset) {
		return
	}
	if !s.svc.HasEmailSender() {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": ErrEmailSenderUnavailable})
		return
	}
	u, err := s.svc.AdminGetUser(r.Context(), userID)
	if err != nil || u == nil {
		notFound(w, ErrNotFound)
		return
	}
	if u.Email == nil || strings.TrimSpace(*u.Email) == "" {
		sendErr(w, http.StatusUnprocessableEntity, ErrNoEmail)
		return
	}
	if err := s.svc.RequestPasswordReset(r.Context(), *u.Email, 0, nil, nil); err != nil {
		s.logInternalError(r, "admin_password_reset", "request_password_reset", "password_reset_request_failed", err)
		serverErr(w, ErrPasswordResetRequestFailed)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Service) handleAdminUserSessionsRevokePOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	if err := s.svc.AdminRevokeUserSessions(
		core.WithSessionRevokeReason(r.Context(), core.SessionRevokeReasonAdminRevokeAll),
		userID,
	); err != nil {
		serverErr(w, ErrFailedToRevokeSessions)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
