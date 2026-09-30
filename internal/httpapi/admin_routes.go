package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// Account administration. Reads are gated by root:users:read at the route.
// Mutations take the verified actor and the engine applies rule ACCT; they are
// for signed-in users only, like root-role administration: API keys,
// applications and delegated tokens never reach the account plane.

// userQuery parses the directory query: cursor, limit, search, root_role,
// status, sort, order (default desc), entitlement.
func (s *Service) userQuery(r *http.Request) (iam.UserQuery, error) {
	var q UserListQuery
	if err := decodeQuery(r, &q); err != nil {
		return iam.UserQuery{}, err
	}
	page, err := q.Page()
	if err != nil {
		return iam.UserQuery{}, err
	}
	out := iam.UserQuery{
		Search:      q.Search,
		Status:      iam.UserStatus(q.Status),
		Entitlement: q.Entitlement,
		Sort:        iam.UserSort(q.Sort),
		Desc:        !strings.EqualFold(q.Order, "asc"),
		Page:        page,
		// The admin views show every account's entitlements.
		WithEntitlements: true,
	}
	if text := q.RootRole; text != "" {
		role, err := s.groupRole(iam.RootPersona, text)
		if err != nil {
			return iam.UserQuery{}, err
		}
		out.RootRole = role
	}
	return out, nil
}

func (s *Service) handleAdminUsersListGET(w http.ResponseWriter, r *http.Request) {
	q, err := s.userQuery(r)
	if err != nil {
		writeError(w, err)
		return
	}
	page, err := s.svc.ListUsers(r.Context(), q)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
}

func (s *Service) handleAdminUserGET(w http.ResponseWriter, r *http.Request) {
	u, err := s.svc.UserEntry(r.Context(), r.PathValue("user_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// accountActor is the signed-in user acting on an account route.
func accountActor(w http.ResponseWriter, r *http.Request) (iam.Actor, string, bool) {
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return iam.Actor{}, "", false
	}
	if _, ok := userActorID(w, actor); !ok {
		return iam.Actor{}, "", false
	}
	target := strings.TrimSpace(r.PathValue("user_id"))
	if target == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return iam.Actor{}, "", false
	}
	return actor, target, true
}

// handleAdminUserPATCH edits an account: an absent field is unchanged, an
// empty one clears it. The verified flags stay system-only.
func (s *Service) handleAdminUserPATCH(w http.ResponseWriter, r *http.Request) {
	var req AdminUserUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	update := iam.UserUpdate{Email: req.Email, Phone: req.PhoneNumber, Username: req.Username, AvatarURL: req.AvatarURL, PreferredLanguage: req.PreferredLanguage}
	if _, err := s.svc.UpdateUser(r.Context(), actor, target, update); err != nil {
		writeError(w, err)
		return
	}
	s.handleAdminUserGET(w, r)
}

// handleAdminUserBanPUT puts a ban in force, replacing any in force.
func (s *Service) handleAdminUserBanPUT(w http.ResponseWriter, r *http.Request) {
	var req BanRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	if req.Until != nil && !req.Until.After(time.Now()) {
		fail(w, errmodel.CodeInvalidUntil)
		return
	}
	ban := iam.Ban{Until: req.Until}
	if req.Reason != nil {
		ban.Reason = *req.Reason
	}
	if err := s.svc.Ban(r.Context(), actor, target, ban); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserBanDELETE(w http.ResponseWriter, r *http.Request) {
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	if err := s.svc.Unban(r.Context(), actor, target); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserDeleteDELETE(w http.ResponseWriter, r *http.Request) {
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	// One's own account is deleted through DELETE /me, behind its recent
	// sign-in and second factor (ak#417).
	if strings.EqualFold(target, actor.ID()) {
		writeError(w, iam.ErrCannotTargetSelf)
		return
	}
	res, err := s.svc.DeleteUsers(r.Context(), actor, []string{target})
	if err := opErr(res, err); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// handleAdminUserSessionsGET lists the account's live sessions on this
// issuer; none is the caller's current one.
func (s *Service) handleAdminUserSessionsGET(w http.ResponseWriter, r *http.Request) {
	sessions, err := s.svc.Sessions(r.Context(), r.PathValue("user_id"))
	if err != nil {
		writeError(w, err)
		return
	}
	all(w, sessions)
}

// handleAdminUserSessionsDELETE revokes every session and device key of the
// account.
func (s *Service) handleAdminUserSessionsDELETE(w http.ResponseWriter, r *http.Request) {
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	if _, err := s.svc.RevokeAccountSessions(r.Context(), actor, target); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserRestorePOST(w http.ResponseWriter, r *http.Request) {
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	res, err := s.svc.RestoreUsers(r.Context(), actor, []string{target})
	if err := opErr(res, err); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// opErr is a single-item batch call's failure: the call's or the item's.
func opErr(res []iam.OpResult, err error) error {
	if err == nil && len(res) == 1 {
		err = res[0].Err
	}
	return err
}
