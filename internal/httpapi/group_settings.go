package httpapi

// Settings, descriptor and custom-role handlers of the generated per-persona
// group surface.

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
)

// customRoleRequest is the body for defining a per-group custom role.
// RequiresMFA (#247) mirrors Role.RequiresMFA for catalog roles: a custom
// role granting sensitive perms can require MFA on the same assignment/redeem
// gate.
type customRoleRequest struct {
	Role        string   `json:"role"`
	Permissions []string `json:"permissions"`
	RequiresMFA bool     `json:"requires_mfa,omitempty"`
}

// groupCustomRoleDefine creates/updates a custom role in the group (custom-role
// personas only). #247 SECURITY: redefining an existing role is a deferred
// grant to every current holder, so this requires the SAME actor-authz
// (capability + no-escalation, covering old ∪ new grants) as a direct role
// assignment — DefineGroupCustomRole enforces it. Validation failures (bad
// perm, cross-persona, persona disallows custom roles) are client errors (400);
// an unknown resource is 404; an escalation attempt is 403.
func (s *Service) groupCustomRoleDefine(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	var body customRoleRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.Role) == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actorID, ok := userActorID(w, actor)
	if !ok {
		return
	}
	role := iam.Role(strings.TrimSpace(body.Role))
	if err := s.svc.DefineGroupCustomRole(r.Context(), actorID, group, authflow.CustomRoleDef{Role: role, Permissions: body.Permissions, RequiresMFA: body.RequiresMFA}); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"persona":       group.Persona(),
		"instance_slug": group.Slug(),
		"role":          role,
		"permissions":   body.Permissions,
		"requires_mfa":  body.RequiresMFA,
	})
}

// groupCustomRoleDelete removes a custom role from the group. #247 SECURITY:
// deleting a role is a deferred REVOKE from every current holder, gated by the
// same actor-authz as define.
func (s *Service) groupCustomRoleDelete(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor, role iam.Role) {
	if role == "" {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actorID, ok := userActorID(w, actor)
	if !ok {
		return
	}
	if err := s.svc.DeleteGroupCustomRole(r.Context(), actorID, group, role); err != nil {
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
	inst, err := s.svc.GroupInstanceForSlug(r.Context(), group)
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
		"instance_slug": inst.InstanceSlug,
		"display_name":  inst.DisplayName,
	})
}

// groupUpdate is the #264 group-settings surface (PATCH /<persona>/{instance_slug}):
// display-name changes and slug renames, gated by <persona>:self:update
// (the owner holds it via the wildcard). The captured UUID is retained through
// authorization, slug rename and display-name mutation in one transaction.
func (s *Service) groupUpdate(w http.ResponseWriter, r *http.Request, group iam.GroupRef, actor iam.Actor) {
	var req struct {
		Slug        *string `json:"slug"`
		DisplayName *string `json:"display_name"`
	}
	if err := decodeJSON(r, &req); err != nil || (req.Slug == nil && req.DisplayName == nil) {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	actorID, ok := userActorID(w, actor)
	if !ok {
		return
	}
	// #264 anti-squat velocity: a slug rename is a CLAIM — capped per IP and
	// per user (authkit owns anti-spam velocity; cost gates are the host's).
	if req.Slug != nil {
		if s.rateLimited(w, r, RLGroupSettings) || s.rateLimitedByIdentifier(w, r, RLGroupSettings, actorID) {
			return
		}
	}
	if req.DisplayName != nil && len(*req.DisplayName) > 256 {
		badRequest(w, iam.CodeInvalidRequest)
		return
	}
	inst, err := s.svc.GroupInstanceForSlug(r.Context(), group)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	updated, err := s.svc.UpdateGroupInstanceAs(r.Context(), actorID, inst.ID, iam.GroupInstanceUpdate{Slug: req.Slug, DisplayName: req.DisplayName})
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	state, err := s.svc.GroupNamingState(r.Context(), updated.ID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "group_id": updated.ID, "persona": updated.Persona, "instance_slug": updated.InstanceSlug, "display_name": updated.DisplayName, "naming": state})
}
