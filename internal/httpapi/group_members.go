package httpapi

// Member and role handlers of the group surface, plus the caller's own
// memberships and permissions.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/verify"
)

// memberSubject is the member a {kind}/{id} path names. The one kind is
// `users`; any other is 404. Nobody changes their own root role (ak#417).
func memberSubject(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) (iam.Subject, bool) {
	if r.PathValue("kind") != "users" {
		fail(w, errmodel.CodeNotFound)
		return iam.Subject{}, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		fail(w, errmodel.CodeNotFound)
		return iam.Subject{}, false
	}
	if g.Persona == iam.RootPersona && actor.Kind() == iam.ActorUser && strings.EqualFold(id, actor.ID()) {
		writeError(w, iam.ErrCannotTargetSelf)
		return iam.Subject{}, false
	}
	return iam.UserSubject(id), true
}

// groupMemberSet makes the member hold the body's role in the group,
// replacing the one it holds.
func (s *Service) groupMemberSet(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	subject, ok := memberSubject(w, r, g, actor)
	if !ok {
		return
	}
	var body MemberRoleRequest
	if err := decodeJSON(r, &body); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if strings.TrimSpace(body.Role) == "" {
		fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("role"))
		return
	}
	role, err := s.groupRole(g.Persona, body.Role)
	if err != nil {
		writeError(w, err)
		return
	}
	member, err := s.svc.SetGroupRole(r.Context(), actor, iam.GroupByID(g.ID), subject, role)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

// groupMemberRemove takes the member's role in the group; a non-member
// answers 204 too.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	subject, ok := memberSubject(w, r, g, actor)
	if !ok {
		return
	}
	if err := s.svc.RemoveGroupMember(r.Context(), actor, iam.GroupByID(g.ID), subject); err != nil {
		writeError(w, err)
		return
	}
	noContent(w)
}

// groupMembersList lists the role assignments in a group, a page at a time
// (?cursor=, ?limit=, and ?kind= / ?role= filters, repeatable).
// ?expand=user adds each user member's PublicUser: what anyone may see.
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, g iam.Group) {
	var query MemberListQuery
	if !readQuery(w, r, &query) {
		return
	}
	page, err := query.Page()
	if err != nil {
		writeError(w, err)
		return
	}
	q := iam.MemberQuery{Page: page}
	for _, e := range query.Expand {
		if e != "user" {
			fail(w, errmodel.CodeInvalidRequest, errmodel.WithParam("expand"))
			return
		}
		q.WithUsers = true
	}
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
	persona, ok := s.svc.PermissionGroupSchema().Persona(g.Persona)
	if !ok {
		fail(w, errmodel.CodeNotFound)
		return
	}
	out := make([]RoleInfo, 0, len(persona.Roles))
	for _, rd := range persona.Roles {
		grants := make([]iam.Perm, 0, len(rd.Permissions))
		for _, g := range rd.Permissions {
			grants = append(grants, ident.Perm(g))
		}
		out = append(out, RoleInfo{Name: rd.Name, Permissions: expandGrants(persona.Permissions, grants)})
	}
	all(w, out)
}

// expandGrants is every permission of catalog some grant pattern covers:
// what a client checks by set membership.
func expandGrants(catalog, grants []iam.Perm) []iam.Perm {
	out := []iam.Perm{}
	for _, p := range catalog {
		for _, g := range grants {
			if p.Matches(g) {
				out = append(out, p)
				break
			}
		}
	}
	return out
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
	if !readQuery(w, r, &q) {
		return
	}
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
