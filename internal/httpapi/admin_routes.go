package httpapi

import (
	"net/http"
	"strconv"
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
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	out := iam.UserQuery{
		Search:      strings.TrimSpace(q.Get("search")),
		Status:      iam.UserStatus(strings.TrimSpace(q.Get("status"))),
		Entitlement: strings.TrimSpace(q.Get("entitlement")),
		Sort:        iam.UserSort(strings.TrimSpace(q.Get("sort"))),
		Desc:        !strings.EqualFold(strings.TrimSpace(q.Get("order")), "asc"),
		Page:        iam.PageRequest{Cursor: strings.TrimSpace(q.Get("cursor")), Limit: limit},
		// The admin views show every account's entitlements.
		WithEntitlements: true,
	}
	if text := strings.TrimSpace(q.Get("root_role")); text != "" {
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
		writeError(w, remap(err, notFoundCodes, groupOpCodes))
		return
	}
	page, err := s.svc.ListUsers(r.Context(), q)
	if err != nil {
		writeError(w, err)
		return
	}
	writeList(w, page.Items, page.Next)
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

func (s *Service) handleAdminUsersBanPOST(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Reason       string  `json:"reason"`
		Until        *string `json:"until"`
		KeepExisting bool    `json:"keep_existing"`
	}
	if err := decodeOptionalJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	if req.Until == nil || strings.TrimSpace(*req.Until) == "" {
		fail(w, errmodel.CodeInvalidUntil)
		return
	}
	ban := iam.Ban{Reason: req.Reason, KeepExisting: req.KeepExisting}
	if until := strings.TrimSpace(*req.Until); !strings.EqualFold(until, "infinite") {
		parsed, err := time.Parse(time.RFC3339, until)
		if err != nil {
			fail(w, errmodel.CodeInvalidUntil)
			return
		}
		ban.Until = &parsed
	}
	if err := s.svc.Ban(r.Context(), actor, target, ban); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUsersUnbanPOST(w http.ResponseWriter, r *http.Request) {
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
	res, err := s.svc.DeleteUsers(r.Context(), actor, []string{target})
	if err := opErr(res, err); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

func (s *Service) handleAdminUserSessionsRevokePOST(w http.ResponseWriter, r *http.Request) {
	actor, target, ok := accountActor(w, r)
	if !ok {
		return
	}
	result, err := s.svc.RevokeAccountSessions(r.Context(), actor, target)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
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
