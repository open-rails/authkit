package httpapi

// Member and role handlers of the group surface, plus the caller's own
// memberships and permissions.

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// memberRequest is the body for POST /groups/{group_id}/members.
type memberRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}

// groupMemberAdd assigns a user a role in the group by user_id. An email is an
// invitation, whoever holds the address: a role-carrying account invitation
// is emailed there, and the role lands only when its recipient accepts it (by
// registering with it, or by redeeming it signed in to the account that has
// verified the address). The answer is the same for every address, so it
// never reveals whether an account holds it.
func (s *Service) groupMemberAdd(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	group := iam.GroupByID(g.ID)
	var body memberRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	userID := strings.TrimSpace(body.UserID)
	email := contact.NormalizeEmail(body.Email)
	if (userID == "") == (email == "") {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role := iam.Role(strings.TrimSpace(body.Role))
	if role == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if email != "" {
		if err := contact.ValidateEmail(email); err != nil {
			writeError(w, err)
			return
		}
		if s.rateLimited(w, r, RLInviteCreate) || s.rateLimitedByIdentifier(w, r, RLInviteCreate, email) {
			return
		}
		// Authorized by THIS group's members:manage plus COVER(role), not
		// root:users:invite. Machine actors cannot issue invitations.
		invite, err := s.svc.CreateAccountInvite(r.Context(), actor, iam.NewAccountInvite{Email: email, Group: group, Role: role})
		if err != nil {
			s.writeGroupOpError(w, err)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok":       true,
			"group_id": g.ID,
			"persona":  g.Persona,
			"email":    email,
			"role":     role,
			"invited":  true,
			"invite": map[string]any{
				"id":   invite.ID,
				"code": invite.Code,
				"url":  invite.URL,
			},
		})
		return
	}
	res, err := s.svc.AssignGroupRoles(r.Context(), actor, group, []iam.Subject{iam.UserSubject(userID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"group_id": g.ID,
		"persona":  g.Persona,
		"user_id":  userID,
		"role":     role,
	})
}

// groupMemberRemove revokes the user's role in the group.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, userID string) {
	if userID == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.RemoveGroupMembers(r.Context(), actor, iam.GroupByID(g.ID), []iam.Subject{iam.UserSubject(userID)})
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"group_id": g.ID,
		"persona":  g.Persona,
		"user_id":  userID,
	})
}

// groupMemberRole assigns or replaces the user's single role in the group.
func (s *Service) groupMemberRole(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, userID string, role iam.Role) {
	role = iam.Role(strings.TrimSpace(string(role)))
	if userID == "" || role == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.AssignGroupRoles(r.Context(), actor, iam.GroupByID(g.ID), []iam.Subject{iam.UserSubject(userID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"group_id": g.ID,
		"persona":  g.Persona,
		"user_id":  userID,
		"role":     role,
	})
}

// groupMembersList lists the role assignments in a group, a page at a time
// (?cursor=, ?limit=, and ?kind= / ?role= filters, repeatable).
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	q := iam.MemberQuery{Page: groupPageRequest(r)}
	for _, k := range r.URL.Query()["kind"] {
		q.Kinds = append(q.Kinds, iam.SubjectKind(strings.TrimSpace(k)))
	}
	for _, role := range r.URL.Query()["role"] {
		q.Roles = append(q.Roles, iam.Role(strings.TrimSpace(role)))
	}
	page, err := s.svc.ListGroupMembers(r.Context(), iam.GroupByID(g.ID), q)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Items))
	for _, m := range page.Items {
		data = append(data, map[string]any{"subject_id": m.Subject.ID, "subject_kind": m.Subject.Kind, "role": m.Role})
	}
	out := map[string]any{
		"object":   "list",
		"group_id": g.ID,
		"persona":  g.Persona,
		"data":     data,
	}
	if page.Next != "" {
		out["next_cursor"] = page.Next
	}
	writeJSON(w, http.StatusOK, out)
}

// groupPageRequest reads ?cursor= and ?limit=.
func groupPageRequest(r *http.Request) iam.PageRequest {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	return iam.PageRequest{Cursor: strings.TrimSpace(r.URL.Query().Get("cursor")), Limit: limit}
}

// groupRolesList returns the role catalog declared for the group's persona:
// schema data, read after the route's authorization.
func (s *Service) groupRolesList(w http.ResponseWriter, g iam.Group) {
	roles, ok := s.svc.PermissionGroupSchema().Roles(g.Persona)
	if !ok {
		fail(w, errmodel.CodeNotFound)
		return
	}
	data := make([]map[string]any, 0, len(roles))
	for _, rd := range roles {
		perms := rd.Permissions
		if perms == nil {
			perms = []string{}
		}
		data = append(data, map[string]any{"name": rd.Name, "permissions": perms})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":   "list",
		"group_id": g.ID,
		"persona":  g.Persona,
		"data":     data,
	})
}

// handleMeGroupsGET is the cross-persona discovery endpoint: the caller's group
// memberships as {group_id, persona, role}, a page at a time.
func (s *Service) handleMeGroupsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	page, err := s.svc.ListSubjectGroups(r.Context(), iam.UserSubject(claims.UserID), groupPageRequest(r))
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(page.Items))
	for _, m := range page.Items {
		data = append(data, map[string]any{"group_id": m.Group.ID, "persona": m.Group.Persona, "role": m.Role})
	}
	writeList(w, data, page.Next)
}

// handleMePermissionsGET is the permission-introspection endpoint (#421): the
// caller's effective grant patterns in one group (?group_id=; default the
// root group; none in an unknown group), so a client can gate UI on
// permission strings (glob-matching with iam.Perm.Matches, the matcher the
// server enforces with) instead of re-deriving authority from role names.
// Globs like `root:*` (held by an owner) are returned verbatim.
func (s *Service) handleMePermissionsGET(w http.ResponseWriter, r *http.Request) {
	actor, ok := verify.ActorFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	id := strings.TrimSpace(r.URL.Query().Get("group_id"))
	group := iam.RootGroup()
	if id != "" {
		group = iam.GroupByID(id)
	}
	byGroup, err := s.svc.EffectivePermissions(r.Context(), actor, []iam.GroupRef{group})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	perms := []iam.Perm{}
	for gid, p := range byGroup {
		id, perms = gid, p
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":      "permission_set",
		"group_id":    id,
		"permissions": perms,
	})
}
