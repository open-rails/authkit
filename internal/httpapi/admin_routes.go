package httpapi

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

// adminUserListOptionsFromQuery parses the admin directory query params:
// cursor, limit, search, root_role, status, sort, order, entitlement (#313).
// The cursor is opaque to clients; it encodes the next page's offset and the
// page size it was produced with, so a page walk never straddles a size change.
func adminUserListOptionsFromQuery(r *http.Request) (iam.AdminUserListOptions, bool) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	page := 1
	if cursor := strings.TrimSpace(q.Get("cursor")); cursor != "" {
		offset, size, ok := decodeAdminUsersCursor(cursor)
		if !ok || (limit != 0 && limit != size) {
			return iam.AdminUserListOptions{}, false
		}
		limit, page = size, offset/size+1
	}
	sort := iam.AdminUserSort(strings.TrimSpace(q.Get("sort")))
	// Default newest-first; only an explicit order=asc flips it.
	desc := !strings.EqualFold(strings.TrimSpace(q.Get("order")), "asc")
	return iam.AdminUserListOptions{
		Page:        page,
		PageSize:    limit,
		Search:      strings.TrimSpace(q.Get("search")),
		Role:        iam.Role(strings.TrimSpace(q.Get("root_role"))),
		Status:      iam.AdminUserStatus(strings.TrimSpace(q.Get("status"))),
		Sort:        sort,
		Desc:        desc,
		Entitlement: strings.TrimSpace(q.Get("entitlement")),
	}, true
}

func encodeAdminUsersCursor(offset, size int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset) + ":" + strconv.Itoa(size)))
}

func decodeAdminUsersCursor(cursor string) (offset, size int, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return 0, 0, false
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) != 2 {
		return 0, 0, false
	}
	offset, err1 := strconv.Atoi(parts[0])
	size, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil || offset < 0 || size <= 0 || offset%size != 0 {
		return 0, 0, false
	}
	return offset, size, true
}

// actorUserID is the signed-in user behind an account-authority route (ban,
// delete, sessions-revoke). These routes are user-only: the #286 no-escalation
// guard compares the actor's root grants with the target's, which a machine
// principal does not have.
func actorUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, iam.CodeUnauthorized)
		return "", false
	}
	return claims.UserID, true
}

func (s *Service) handleAdminUsersListGET(w http.ResponseWriter, r *http.Request) {
	opts, ok := adminUserListOptionsFromQuery(r)
	if !ok {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	result, err := s.svc.AdminListUsers(r.Context(), opts)
	if err != nil {
		writeError(w, err)
		return
	}
	next := ""
	if len(result.Users) > 0 && result.Limit > 0 && int64(result.Offset+result.Limit) < result.Total {
		next = encodeAdminUsersCursor(result.Offset+result.Limit, result.Limit)
	}
	writeList(w, result.Users, next)
}

func (s *Service) handleAdminUserGET(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user_id")
	u, err := s.svc.AdminGetUser(r.Context(), id)
	if err != nil || u == nil {
		notFound(w, iam.CodeNotFound)
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
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	var untilPtr *time.Time
	if req.Until == nil {
		badRequest(w, iam.CodeInvalidUntil)
		return
	}
	untilStr := strings.TrimSpace(*req.Until)
	if untilStr == "" {
		badRequest(w, iam.CodeInvalidUntil)
		return
	}
	if !strings.EqualFold(untilStr, "infinite") {
		parsed, err := time.Parse(time.RFC3339, untilStr)
		if err != nil {
			badRequest(w, iam.CodeInvalidUntil)
			return
		}
		parsed = parsed.UTC()
		if !parsed.After(time.Now().UTC()) {
			badRequest(w, iam.CodeInvalidUntil)
			return
		}
		untilPtr = &parsed
	}
	if err := s.svc.BanUser(r.Context(), userID, req.Reason, untilPtr, actor); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUsersUnbanPOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	if err := s.svc.UnbanUserAs(r.Context(), actor, userID); err != nil {
		if errors.Is(err, iam.ErrInsufficientRoleAuthority) || errors.Is(err, iam.ErrAccountAuthorityEscalation) {
			writeError(w, err)
			return
		}
		serverErr(w, iam.CodeFailedToUnban, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user_id")
	if id == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	if err := s.svc.SoftDeleteUserAs(r.Context(), actor, id); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserSessionsRevokePOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	result, err := s.svc.AdminRevokeAccountSessionsAs(r.Context(), actor, userID)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Service) handleAdminUserRestorePOST(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.PathValue("user_id"))
	if id == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	if err := s.svc.RestoreUserAs(r.Context(), actor, id); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}
