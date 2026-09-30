package httpapi

// Member and role handlers of the group surface, plus the caller's own
// memberships and permissions.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// groupMemberAdd assigns a user a role in the group by user_id. An email is an
// invitation, whoever holds the address: a role-carrying account invitation
// is emailed there, and the role lands only when its recipient accepts it (by
// registering with it, or by redeeming it signed in to the account that has
// verified the address). The answer is the same for every address, so it
// never reveals whether an account holds it.
func (s *Service) groupMemberAdd(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	group := iam.GroupByID(g.ID)
	var body MemberAddRequest
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
	if strings.TrimSpace(body.Role) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.groupRole(g.Persona, body.Role)
	if err != nil {
		writeError(w, err)
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
		if _, err := s.svc.CreateInvitation(r.Context(), actor, group, iam.NewInvitation{Email: email, Role: role}); err != nil {
			writeError(w, err)
			return
		}
		accepted(w)
		return
	}
	member, err := s.svc.SetGroupRole(r.Context(), actor, group, iam.UserSubject(userID), role)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

// groupMemberRemove revokes the user's role in the group.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, userID string) {
	if userID == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.RemoveGroupMember(r.Context(), actor, iam.GroupByID(g.ID), iam.UserSubject(userID)); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// groupMemberRole assigns or replaces the user's single role in the group.
func (s *Service) groupMemberRole(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, userID, text string) {
	if userID == "" || strings.TrimSpace(text) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.groupRole(g.Persona, text)
	if err != nil {
		writeError(w, err)
		return
	}
	member, err := s.svc.SetGroupRole(r.Context(), actor, iam.GroupByID(g.ID), iam.UserSubject(userID), role)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

// groupMembersList lists the role assignments in a group, a page at a time
// (?cursor=, ?limit=, and ?kind= / ?role= filters, repeatable).
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	var query MemberListQuery
	decodeQuery(r, &query)
	page, err := query.Page()
	if err != nil {
		writeError(w, err)
		return
	}
	q := iam.MemberQuery{Page: page}
	for _, k := range query.Kind {
		q.Kinds = append(q.Kinds, iam.SubjectKind(k))
	}
	for _, text := range query.Role {
		role, err := s.groupRole(g.Persona, text)
		if err != nil {
			writeError(w, err)
			return
		}
		q.Roles = append(q.Roles, role)
	}
	members, err := s.svc.ListGroupMembers(r.Context(), iam.GroupByID(g.ID), q)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, members)
}

// groupRolesList returns the role catalog declared for the group's persona:
// schema data, read after the route's authorization.
func (s *Service) groupRolesList(w http.ResponseWriter, g iam.Group) {
	roles, ok := s.svc.PermissionGroupSchema().Roles(g.Persona)
	if !ok {
		fail(w, errmodel.CodeNotFound)
		return
	}
	out := make([]RoleInfo, 0, len(roles))
	for _, rd := range roles {
		out = append(out, RoleInfo{Name: rd.Name, Permissions: rd.Permissions})
	}
	all(w, out)
}

// handleMeGroupsGET is the cross-persona discovery endpoint: the caller's group
// memberships, a page at a time.
func (s *Service) handleMeGroupsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	p, ok := readPage(w, r)
	if !ok {
		return
	}
	page, err := s.svc.ListMemberships(r.Context(), iam.UserSubject(claims.UserID), p)
	if err != nil {
		writeError(w, err)
		return
	}
	list(w, page)
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
	var q GroupQuery
	decodeQuery(r, &q)
	id := q.GroupID
	group := iam.RootGroup()
	if id != "" {
		group = iam.GroupByID(id)
	}
	byGroup, err := s.svc.EffectivePermissions(r.Context(), actor, []iam.GroupRef{group})
	if err != nil {
		writeError(w, err)
		return
	}
	perms := []iam.Perm{}
	for gid, p := range byGroup {
		id, perms = gid, p
	}
	writeJSON(w, http.StatusOK, PermissionSet{GroupID: id, Permissions: perms})
}
