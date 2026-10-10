package httpapi

// Member and role handlers of the group surface, plus the caller's own
// memberships and permissions.

import (
	"net/http"
	"slices"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/verify"
	"github.com/open-rails/helpers/auth"
)

// PathEnums are the values a path parameter takes, by name, for the
// generated contract: a member path's {kind} is the kind of subject it names.
var PathEnums = map[string][]string{"kind": {"users"}}

// memberSubject is the member a {kind}/{id} path names. The one kind is
// `users`; any other is 404. Nobody changes their own root role (ak#417).
func memberSubject(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) (iam.Subject, bool) {
	if !slices.Contains(PathEnums["kind"], r.PathValue("kind")) {
		fail(w, errmodel.CodeNotFound)
		return iam.Subject{}, false
	}
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		fail(w, errmodel.CodeNotFound)
		return iam.Subject{}, false
	}
	if g.Persona == iam.RootPersona() && state(who).IsUser() && strings.EqualFold(id, state(who).ID()) {
		writeError(w, iam.ErrCannotTargetSelf)
		return iam.Subject{}, false
	}
	return iam.UserSubject(id), true
}

// groupMemberSet makes the member hold the body's role in the group,
// replacing the one it holds.
func (s *Service) groupMemberSet(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	subject, ok := memberSubject(w, r, g, who)
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
	member, err := s.svc.SetGroupRole(r.Context(), who, iam.GroupByID(g.ID), subject, role)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, member)
}

// groupMemberRemove takes the member's role in the group; a non-member
// answers 204 too.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, g iam.Group, who auth.Identity) {
	subject, ok := memberSubject(w, r, g, who)
	if !ok {
		return
	}
	if err := s.svc.RemoveGroupMember(r.Context(), who, iam.GroupByID(g.ID), subject); err != nil {
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

// handleMePermissionsGET is the caller's role and permissions in one group
// (?group_id=, `root` or absent for the root group), the permissions expanded
// over the persona's catalog so a client gates UI by set membership. An
// unknown group has none.
func (s *Service) handleMePermissionsGET(w http.ResponseWriter, r *http.Request) {
	who, ok := verify.IdentityFromContext(r.Context())
	if !ok {
		fail(w, errmodel.CodeUnauthenticated)
		return
	}
	var q GroupQuery
	if !readQuery(w, r, &q) {
		return
	}
	ref := iam.RootGroup()
	if q.GroupID != "" {
		ref = groupRef(q.GroupID)
	}
	out := PermissionSet{GroupID: q.GroupID, Permissions: []iam.Perm{}}
	g, err := s.svc.Group(r.Context(), ref)
	if errmodel.CodeOf(err) == errmodel.CodeGroupNotFound || err == nil && g.DeletedAt != nil {
		writeJSON(w, http.StatusOK, out)
		return
	}
	if err != nil {
		writeError(w, err)
		return
	}
	out.GroupID = g.ID
	byGroup, err := s.svc.EffectivePermissions(r.Context(), who, []iam.GroupRef{iam.GroupByID(g.ID)})
	if err != nil {
		writeError(w, err)
		return
	}
	if persona, ok := s.svc.PermissionGroupSchema().Persona(g.Persona); ok {
		out.Permissions = rbac.Expand(persona.Permissions, byGroup[g.ID])
	}
	if state(who).IsUser() {
		subject := iam.UserSubject(state(who).ID())
		held, err := s.svc.GroupRoles(r.Context(), iam.GroupByID(g.ID), []iam.Subject{subject})
		if err != nil {
			writeError(w, err)
			return
		}
		if role, ok := held[subject]; ok && !role.IsZero() {
			out.Role = &role
		}
	}
	writeJSON(w, http.StatusOK, out)
}
