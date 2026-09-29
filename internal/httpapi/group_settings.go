package httpapi

// Settings, descriptor and custom-role handlers of the generated per-persona
// group surface.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
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
func (s *Service) groupCustomRoleDefine(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	var body customRoleRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	role := iam.Role(strings.TrimSpace(body.Role))
	if err := s.svc.DefineGroupRole(r.Context(), actor, group, iam.CustomRole{Name: role, Permissions: body.Permissions}); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"role":          role,
		"permissions":   body.Permissions,
	})
}

// groupCustomRoleDelete removes a custom role from the group, and it from
// every holder, under the same authority rule as define.
func (s *Service) groupCustomRoleDelete(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, role iam.Role) {
	if role == "" {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	if err := s.svc.DeleteGroupRole(r.Context(), actor, group, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "persona": group.Persona(), "instance_slug": group.Slug(), "role": role})
}

// groupInstanceDescriptor is the #269 instance-identity read
// (GET /<persona>/{instance_slug}), gated by <persona>:self:read — the read
// symmetric of the #264 PATCH. It answers with the instance's own uuid, which is
// the JOIN KEY a host needs to carry the group into its own (or a sibling
// service's) ledger; every route stays slug-addressed, so the id is knowable
// here and an address nowhere. A tombstoned slug forwards, and the descriptor
// reports the group's CURRENT live slug — so a caller holding an old reference
// learns the new one in the same call.
func (s *Service) groupInstanceDescriptor(w http.ResponseWriter, r *http.Request, group iam.GroupRef, _ iam.Actor) {
	inst, err := s.svc.Group(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	state, err := s.svc.GroupNamingState(r.Context(), inst.ID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"naming":        state,
		"ok":            true,
		"group_id":      inst.ID,
		"persona":       inst.Persona,
		"instance_slug": inst.Slug,
		"display_name":  inst.DisplayName,
	})
}

// groupUpdate is the #264 group-settings surface (PATCH /<persona>/{instance_slug}):
// display-name changes and slug renames, gated by <persona>:self:update
// (the owner holds it via the wildcard). The engine re-checks the actor and
// applies the change in one authority transaction.
func (s *Service) groupUpdate(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	var req struct {
		Slug        *string `json:"slug"`
		DisplayName *string `json:"display_name"`
	}
	if err := decodeJSON(r, &req); err != nil || (req.Slug == nil && req.DisplayName == nil) {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	// #264 anti-squat velocity: a slug rename is a CLAIM — capped per IP and
	// per actor (authkit owns anti-spam velocity; cost gates are the host's).
	if req.Slug != nil {
		if s.rateLimited(w, r, RLGroupSettings) || s.rateLimitedByIdentifier(w, r, RLGroupSettings, actor.String()) {
			return
		}
	}
	if req.DisplayName != nil && len(*req.DisplayName) > 256 {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}
	updated, err := s.svc.UpdateGroup(r.Context(), actor, group, iam.GroupUpdate{Slug: req.Slug, DisplayName: req.DisplayName})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	state, err := s.svc.GroupNamingState(r.Context(), updated.ID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group_id": updated.ID, "persona": updated.Persona, "instance_slug": updated.Slug, "display_name": updated.DisplayName, "naming": state})
}

// groupDelete soft-deletes the group (DELETE /<persona>/{instance_slug}),
// gated by <persona>:self:delete; the engine re-checks the actor.
func (s *Service) groupDelete(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	if _, err := s.svc.DeleteGroup(r.Context(), actor, group); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	noContent(w)
}
