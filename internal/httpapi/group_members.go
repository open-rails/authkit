package httpapi

// Member and role handlers of the generated per-persona group surface, plus
// the caller's own memberships and permissions.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/contact"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/verify"
)

// memberRequest is the body for POST /<persona>/<instance_slug>/members.
type memberRequest struct {
	UserID string `json:"user_id"`
	Email  string `json:"email,omitempty"`
	Role   string `json:"role"`
}

// groupMemberAdd assigns a user a role in the group; an unknown email gets a
// role-carrying registration invite instead.
func (s *Service) groupMemberAdd(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
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
	}
	if email != "" {
		u, err := s.svc.GetUserByEmail(r.Context(), email)
		if errors.Is(err, pgx.ErrNoRows) {
			u = nil
		} else if err != nil {
			s.logInternalError(r, "permission_group_member_add", "lookup_email", "database_error", err)
			serverErr(w, "database_error", nil)
			return
		}
		if u == nil {
			if s.rateLimited(w, r, RLInviteCreate) || s.rateLimitedByIdentifier(w, r, RLInviteCreate, email) {
				return
			}
			// #147 register+join: mint ONE role-carrying account-registration invite.
			// Consuming the code authorizes the stranger's registration AND grants this
			// role on consume — one link covers register + join. Authorized by THIS
			// group's members:manage (the role-carrying create path), which does not
			// grant general root:users:invite authority. Machine actors cannot
			// issue invitations.
			invite, err := s.svc.CreateAccountInvite(r.Context(), actor, iam.NewAccountInvite{Email: email, Group: group, Role: role})
			if err != nil {
				s.writeGroupOpError(w, err)
				return
			}
			writeJSON(w, http.StatusAccepted, map[string]any{
				"ok":            true,
				"persona":       group.Persona(),
				"instance_slug": group.Slug(),
				"email":         email,
				"role":          role,
				"invited":       true,
				"invite": map[string]any{
					"id":   invite.ID,
					"code": invite.Code,
					"url":  invite.URL,
				},
			})
			return
		}
		userID = u.ID
	}
	res, err := s.svc.AssignGroupRoles(r.Context(), actor, group, []iam.Subject{iam.UserSubject(userID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"user_id":       userID,
		"role":          role,
	})
}

// groupMemberRemove revokes the user's role in the group.
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, userID string) {
	if userID == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.RemoveGroupMembers(r.Context(), actor, group, []iam.Subject{iam.UserSubject(userID)})
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"user_id":       userID,
	})
}

// groupMemberRole assigns or replaces the user's single role in the group.
func (s *Service) groupMemberRole(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, userID string, role iam.Role) {
	role = iam.Role(strings.TrimSpace(string(role)))
	if userID == "" || role == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	res, err := s.svc.AssignGroupRoles(r.Context(), actor, group, []iam.Subject{iam.UserSubject(userID)}, role)
	if !s.writeOpResult(w, res, err) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"user_id":       userID,
		"role":          role,
	})
}

// groupMembersList lists the role assignments in a group.
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, group iam.GroupRef, _ iam.Actor) {
	members, err := s.svc.ListGroupMembers(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(members))
	for _, m := range members {
		data = append(data, map[string]any{"subject_id": m.SubjectID, "subject_kind": m.SubjectKind, "role": m.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "list",
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"data":          data,
	})
}

// groupRolesList returns the role catalog declared for a persona (always
// available per the generator). This is pure schema data — no DB, no group
// resolution beyond the already-passed authorization.
func (s *Service) groupRolesList(w http.ResponseWriter, persona iam.Persona) {
	roles, ok := s.svc.PermissionGroupSchema().Roles(persona)
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
		"object":  "list",
		"persona": persona,
		"data":    data,
	})
}

// handleMeGroupsGET is the cross-persona discovery endpoint: the caller's group
// memberships as {persona, instance_slug, role}.
func (s *Service) handleMeGroupsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeNotAuthenticated)
		return
	}
	groups, err := s.svc.ListSubjectGroups(r.Context(), iam.UserSubject(claims.UserID))
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		// #269: the caller's OWN memberships carry the group uuid — they have
		// already passed the only authorization that could gate it, and this is
		// the discovery path a client uses to learn what it belongs to.
		data = append(data, map[string]any{"group_id": g.GroupID, "persona": g.Persona, "instance_slug": g.InstanceSlug, "role": g.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

// handleMePermissionsGET is the permission-introspection endpoint (#421): it
// returns the authenticated subject's effective grant PATTERNS within ONE group
// instance, so a client can gate UI on permission strings (glob-matching with
// iam.Perm.Matches, the same matcher the server enforces with) instead of
// re-deriving authority from role slugs. Scoped by ?persona= (default "root") and
// ?instance= (default "" — the singleton root group); a per-instance scope is
// required because perms are persona-namespaced. Globs like `root:*` (held by an
// owner) are returned VERBATIM.
func (s *Service) handleMePermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		fail(w, errmodel.CodeNotAuthenticated)
		return
	}
	persona := iam.Persona(strings.TrimSpace(r.URL.Query().Get("persona")))
	if persona == "" {
		persona = iam.RootPersona
	}
	group := iam.GroupBySlug(persona, r.URL.Query().Get("instance"))
	perms, err := s.svc.ListEffectivePermissions(r.Context(), iam.UserSubject(claims.UserID), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":        "permission_set",
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"permissions":   perms,
	})
}
