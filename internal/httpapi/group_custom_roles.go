package httpapi

// Custom-role handlers of the group surface.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
)

// customRoleRequest is the body for defining a per-group custom role. Whether
// holding it needs MFA follows from its permissions.
type customRoleRequest struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
}

// groupCustomRoleDefine creates or redefines a custom role in the group
// (custom-role personas only). A redefinition changes what every holder has,
// so the engine applies DefineGroupRole's authority rule. Validation failures
// are 400; an escalation attempt is 403.
func (s *Service) groupCustomRoleDefine(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor) {
	var body customRoleRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role, err := s.svc.DefineGroupRole(r.Context(), actor, iam.GroupByID(g.ID), body.Role, ident.Perms(body.Permissions)...)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"group_id":    g.ID,
		"persona":     g.Persona,
		"role":        role.Name(),
		"permissions": body.Permissions,
	})
}

// groupCustomRoleDelete removes a custom role from the group, and it from
// every holder, under the same authority rule as define.
func (s *Service) groupCustomRoleDelete(w http.ResponseWriter, r *http.Request, g iam.Group, actor iam.Actor, name string) {
	role := ident.Role(g.Persona, strings.TrimSpace(name))
	if role.IsZero() {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.DeleteGroupRole(r.Context(), actor, iam.GroupByID(g.ID), role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group_id": g.ID, "persona": g.Persona, "role": role.Name()})
}
