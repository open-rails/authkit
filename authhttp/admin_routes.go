package authhttp

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"

	"github.com/open-rails/authkit/embedded"
)

// adminUserListOptionsFromQuery parses the admin directory query params:
// cursor, limit, search, root_role, status, sort, order, entitlement (#313).
// The cursor is opaque to clients; it encodes the next page's offset and the
// page size it was produced with, so a page walk never straddles a size change.
func adminUserListOptionsFromQuery(r *http.Request) (authkit.AdminUserListOptions, bool) {
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	page := 1
	if cursor := strings.TrimSpace(q.Get("cursor")); cursor != "" {
		offset, size, ok := decodeAdminUsersCursor(cursor)
		if !ok || (limit != 0 && limit != size) {
			return authkit.AdminUserListOptions{}, false
		}
		limit, page = size, offset/size+1
	}
	sort := authkit.AdminUserSort(strings.TrimSpace(q.Get("sort")))
	// Default newest-first; only an explicit order=asc flips it.
	desc := !strings.EqualFold(strings.TrimSpace(q.Get("order")), "asc")
	return authkit.AdminUserListOptions{
		Page:        page,
		PageSize:    limit,
		Search:      strings.TrimSpace(q.Get("search")),
		Role:        authkit.Role(strings.TrimSpace(q.Get("root_role"))),
		Status:      authkit.AdminUserStatus(strings.TrimSpace(q.Get("status"))),
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
// inherently root-scoped intrinsic route pass (authkit.RootPersona, "", perm).
func (s *Service) requirePermission(group authkit.GroupRef, perm authkit.Perm, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := verify.ClaimsFromContext(r.Context())
		if !ok {
			unauthorized(w, ErrNotAuthenticated)
			return
		}
		group, err := s.svc.GroupInstanceForSlug(r.Context(), group)
		if errors.Is(err, authkit.ErrGroupNotFound) {
			forbidden(w, ErrForbidden)
			return
		}
		if err != nil {
			serverErr(w, ErrDatabaseError)
			return
		}
		scope := verify.PermissionScope{GroupID: group.ID, AuthorityIssuer: s.svc.Config().Token.Issuer, Persona: group.Persona, Instance: group.InstanceSlug}
		switch {
		case claims.PrincipalKind() != authkit.PrincipalKindUser:
			if claims.HasPermission(perm) && claims.PermissionGroupAllows(scope) {
				next.ServeHTTP(w, r)
				return
			}
		case strings.TrimSpace(claims.UserID) != "":
			allowed, err := s.svc.CanOnGroup(r.Context(), authkit.UserSubject(claims.UserID), group.ID, perm)
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

// actorUserID is the signed-in user behind an account-authority route (ban,
// delete, sessions-revoke). These routes are user-only: the #286 no-escalation
// guard compares the actor's root grants with the target's, which a machine
// principal does not have.
func actorUserID(w http.ResponseWriter, r *http.Request) (string, bool) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || strings.TrimSpace(claims.UserID) == "" {
		unauthorized(w, ErrUnauthorized)
		return "", false
	}
	return claims.UserID, true
}

func (s *Service) handleAdminUsersListGET(w http.ResponseWriter, r *http.Request) {
	opts, ok := adminUserListOptionsFromQuery(r)
	if !ok {
		badRequest(w, ErrInvalidRequest)
		return
	}
	result, err := s.svc.AdminListUsers(r.Context(), opts)
	if err != nil {
		if errors.Is(err, authkit.ErrEntitlementFilterUnavailable) {
			badRequest(w, ErrEntitlementFilterUnavailable)
			return
		}
		serverErr(w, ErrFailedToListUsers)
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
	actor, ok := actorUserID(w, r)
	if !ok {
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
	if err := s.svc.BanUser(r.Context(), userID, req.Reason, untilPtr, actor); err != nil {
		switch {
		case errors.Is(err, authkit.ErrInvalidUntil):
			badRequest(w, ErrInvalidUntil)
		case errors.Is(err, authkit.ErrAccountAuthorityEscalation):
			forbidden(w, ErrAccountAuthorityEscalation)
		default:
			serverErr(w, ErrFailedToBan)
		}
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUsersUnbanPOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	if err := s.svc.UnbanUser(r.Context(), userID); err != nil {
		serverErr(w, ErrFailedToUnban)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("user_id")
	if id == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	if err := s.svc.SoftDeleteUserAs(r.Context(), actor, id); err != nil {
		if errors.Is(err, authkit.ErrAccountAuthorityEscalation) {
			forbidden(w, ErrAccountAuthorityEscalation)
			return
		}
		serverErr(w, ErrFailedToDelete)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserSessionsRevokePOST(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(r.PathValue("user_id"))
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	actor, ok := actorUserID(w, r)
	if !ok {
		return
	}
	if err := s.svc.AdminRevokeUserSessionsAs(
		embedded.WithSessionRevokeReason(r.Context(), embedded.SessionRevokeReasonAdminRevokeAll),
		actor, userID,
	); err != nil {
		if errors.Is(err, authkit.ErrAccountAuthorityEscalation) {
			forbidden(w, ErrAccountAuthorityEscalation)
			return
		}
		serverErr(w, ErrFailedToRevokeSessions)
		return
	}
	noContent(w)
}
