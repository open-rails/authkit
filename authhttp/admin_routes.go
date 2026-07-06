package authhttp

import (
	"errors"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-rails/authkit/embedded"
)

type adminUsersListResponse struct {
	Object  string              `json:"object"`
	Data    []authkit.AdminUser `json:"data"`
	Total   int64               `json:"total"`
	Limit   int                 `json:"limit"`
	Offset  int                 `json:"offset"`
	HasMore bool                `json:"has_more"`
}

// adminUserListOptionsFromQuery parses the admin dashboard query params:
// page, page_size, search, root_role, status, sort, order, entitlement.
func adminUserListOptionsFromQuery(r *http.Request) authkit.AdminUserListOptions {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	size, _ := strconv.Atoi(q.Get("page_size"))
	sort := authkit.AdminUserSort(strings.TrimSpace(q.Get("sort")))
	// Default newest-first; only an explicit order=asc flips it.
	desc := !strings.EqualFold(strings.TrimSpace(q.Get("order")), "asc")
	return authkit.AdminUserListOptions{
		Page:        page,
		PageSize:    size,
		Search:      strings.TrimSpace(q.Get("search")),
		Role:        strings.TrimSpace(q.Get("root_role")),
		Status:      authkit.AdminUserStatus(strings.TrimSpace(q.Get("status"))),
		Sort:        sort,
		Desc:        desc,
		Entitlement: strings.TrimSpace(q.Get("entitlement")),
	}
}

// requirePermission is the granular permission gate for AuthKit's intrinsic
// routes. It authorizes the calling principal against permission `perm` on the
// (persona, instanceSlug) permission group, for EVERY supported principal
// shape:
//   - user JWT: resolved through the permission-group (svc.Can, walking the
//     parent chain to root and unioning assignments);
//   - api-key / service, delegated, and remote-application principals: resolved
//     through their verified permission ceiling (claims.HasPermission); a
//     GROUP-BOUND machine principal (#248) must additionally match the gated
//     (persona, instanceSlug) exactly — its authority is valid only on the
//     group instance it was minted on.
//
// There is deliberately NO special "admin" authorization tier: admin authority
// over the user directory is simply the `root:users:*` permissions on the root
// group, gated here the same way every other permission is. Callers that gate an
// inherently root-scoped intrinsic route pass (embedded.RootPersona, "", perm).
func (s *Service) requirePermission(persona, instanceSlug, perm string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok {
			unauthorized(w, ErrNotAuthenticated)
			return
		}
		switch {
		case claims.PrincipalKind() != authkit.PrincipalKindUser:
			if claims.HasPermission(perm) && claims.PermissionGroupAllows(persona, instanceSlug) {
				next.ServeHTTP(w, r)
				return
			}
		case strings.TrimSpace(claims.UserID) != "":
			allowed, err := s.svc.Can(r.Context(), claims.UserID, embedded.SubjectKindUser, persona, instanceSlug, perm)
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
		if errors.Is(err, authkit.ErrEntitlementFilterUnavailable) {
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
	userID := strings.TrimSpace(r.PathValue("user_id"))
	var req struct {
		Reason *string `json:"reason"`
		Until  *string `json:"until"`
	}
	if err := decodeOptionalJSON(r, &req); err != nil || userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	var untilPtr *time.Time
	if req.Until == nil {
		badRequest(w, ErrInvalidUntil)
		return
	}
	untilStr := strings.TrimSpace(*req.Until)
	if untilStr == "" {
		badRequest(w, ErrInvalidUntil)
		return
	}
	if !strings.EqualFold(untilStr, "infinite") {
		parsed, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			badRequest(w, ErrInvalidUntil)
			return
		}
		parsed = parsed.UTC()
		if !parsed.After(time.Now().UTC()) {
			badRequest(w, ErrInvalidUntil)
			return
		}
		untilPtr = &parsed
	}
	if err := s.svc.BanUser(r.Context(), userID, req.Reason, untilPtr, claims.UserID); err != nil {
		if errors.Is(err, authkit.ErrInvalidUntil) {
			badRequest(w, ErrInvalidUntil)
			return
		}
		serverErr(w, ErrFailedToBan)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
}

func (s *Service) handleAdminUsersUnbanPOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminUserSessionsRevokeAll) {
		return
	}
	if err := s.svc.UnbanUser(r.Context(), userID); err != nil {
		serverErr(w, ErrFailedToUnban)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
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
		if errors.Is(err, authkit.ErrUserNotFound) {
			notFound(w, ErrNotFound)
			return
		}
		serverErr(w, ErrFailedToRestoreUser)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
}

func (s *Service) handleAdminUserRecoverPOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	var req struct {
		Email       string `json:"email"`
		PhoneNumber string `json:"phone_number"`
	}
	if err := decodeJSON(r, &req); err != nil || userID == "" || (strings.TrimSpace(req.Email) == "") == (strings.TrimSpace(req.PhoneNumber) == "") {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if s.rateLimited(w, r, RLAdminPasswordReset) {
		return
	}
	err := s.svc.AdminRecoverUser(r.Context(), userID, embedded.AdminRecoverUserInput{Email: req.Email, PhoneNumber: req.PhoneNumber})
	switch {
	case err == nil:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "user_id": userID})
	case errors.Is(err, authkit.ErrUserNotFound):
		notFound(w, ErrNotFound)
	case errors.Is(err, authkit.ErrEmailSenderUnavailable):
		sendErr(w, http.StatusServiceUnavailable, ErrEmailSenderUnavailable)
	case errors.Is(err, authkit.ErrSMSSenderUnavailable):
		sendErr(w, http.StatusServiceUnavailable, ErrSMSUnavailable)
	case errors.Is(err, authkit.ErrEmailInUse):
		badRequest(w, ErrEmailInUse)
	case errors.Is(err, authkit.ErrPhoneInUse):
		badRequest(w, ErrPhoneInUse)
	case embedded.ValidationErrorCode(err) != "":
		badRequest(w, ErrorCode(embedded.ValidationErrorCode(err)))
	case deliveryErrCode(err) != "":
		deliveryErr(w, deliveryErrCode(err))
	default:
		s.logInternalError(r, "admin_user_recover", "recover_user", "user_recover_failed", err)
		serverErr(w, ErrUserRecoverFailed)
	}
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
		embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonAdminRevokeAll),
		userID,
	); err != nil {
		serverErr(w, ErrFailedToRevokeSessions)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}
