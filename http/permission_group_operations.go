package authhttp

// Operation handlers for the auto-generated per-persona group-management surface
// (#111, task #15). The caller is already AUTHORIZED (svc.Can passed) by the time
// these run; they decode input, call the public core Service API, and shape the
// JSON response. Group ids never appear here — everything is addressed by
// (persona, resource-id).

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// memberRequest is the body for POST /<persona>/<resource-id>/members. role is
// optional (defaults to the seeded base-membership role).
type memberRequest struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
}

// groupMemberAdd assigns a subject (user) a role in the group. The role defaults
// to the base-membership role when omitted. Idempotent at the store layer.
func (s *Service) groupMemberAdd(w http.ResponseWriter, r *http.Request, persona, resourceID string) {
	var body memberRequest
	if err := decodeJSON(r, &body); err != nil || strings.TrimSpace(body.UserID) == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	role := strings.TrimSpace(body.Role)
	if role == "" {
		role = core.MemberRoleName
	}
	if err := s.svc.AssignGroupRole(r.Context(), persona, resourceID, strings.TrimSpace(body.UserID), core.SubjectKindUser, role); err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"persona":     persona,
		"resource-id": resourceID,
		"user_id":     strings.TrimSpace(body.UserID),
		"role":        role,
	})
}

// groupMemberRemove revokes ALL of a user's roles in the group. Because the
// public Service API revokes per-role, "remove a member" decomposes into
// unassigning each catalog role the schema defines for the type; the membership
// is gone once none remain. Idempotent (unassigning an absent role is a no-op).
func (s *Service) groupMemberRemove(w http.ResponseWriter, r *http.Request, persona, resourceID, userID string) {
	if userID == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	roles, _ := s.svc.PermissionGroupSchema().Roles(persona)
	for _, rd := range roles {
		if err := s.svc.UnassignGroupRole(r.Context(), persona, resourceID, userID, core.SubjectKindUser, rd.Name); err != nil {
			s.writeGroupOpError(w, err)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"persona":     persona,
		"resource-id": resourceID,
		"user_id":     userID,
	})
}

// groupMemberRole assigns (PUT) or unassigns (DELETE) a single role for a user in
// the group. assign==true => AssignGroupRole, false => UnassignGroupRole.
func (s *Service) groupMemberRole(w http.ResponseWriter, r *http.Request, persona, resourceID, userID, role string, assign bool) {
	if userID == "" || role == "" {
		badRequest(w, ErrInvalidRequest)
		return
	}
	var err error
	if assign {
		err = s.svc.AssignGroupRole(r.Context(), persona, resourceID, userID, core.SubjectKindUser, role)
	} else {
		err = s.svc.UnassignGroupRole(r.Context(), persona, resourceID, userID, core.SubjectKindUser, role)
	}
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"persona":     persona,
		"resource-id": resourceID,
		"user_id":     userID,
		"role":        role,
	})
}

// groupMembersList lists the members of a group.
//
// The public core Service API does not expose a "list members of a group"
// method (the store's WalkAssignments is per-subject, and surfacing a roster
// would require a new core method). Per the task's constraint to NOT touch core,
// this returns an empty roster with a TODO marker rather than reaching past the
// documented Service API. Wire fully once core grows a group-roster method.
func (s *Service) groupMembersList(w http.ResponseWriter, r *http.Request, persona, resourceID string) {
	members, err := s.svc.ListGroupMembers(r.Context(), persona, resourceID)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(members))
	for _, m := range members {
		data = append(data, map[string]any{"subject-id": m.SubjectID, "subject-kind": m.SubjectKind, "role": m.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object":      "list",
		"persona":     persona,
		"resource-id": resourceID,
		"data":        data,
	})
}

// groupRolesList returns the role catalog declared for a persona (always
// available per the generator). This is pure schema data — no DB, no group
// resolution beyond the already-passed authorization.
func (s *Service) groupRolesList(w http.ResponseWriter, persona string) {
	roles, ok := s.svc.PermissionGroupSchema().Roles(persona)
	if !ok {
		notFound(w, ErrNotFound)
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
// memberships as {persona, resource-id, role}.
//
// Listing a subject's memberships across ALL groups requires a core method that
// does not exist on the public Service API (WalkAssignments resolves a SINGLE
// target group's chain, not a global membership scan). Per the task's constraint
// to NOT touch core, this returns an empty list with a TODO rather than adding a
// core store walk. Wire fully once core exposes a per-subject membership listing.
func (s *Service) handleMeGroupsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrNotAuthenticated)
		return
	}
	groups, err := s.svc.ListSubjectGroups(r.Context(), claims.UserID, core.SubjectKindUser)
	if err != nil {
		s.writeGroupOpError(w, err)
		return
	}
	data := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		data = append(data, map[string]any{"persona": g.Persona, "resource-id": g.ResourceRef, "role": g.Role})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"object": "list",
		"data":   data,
	})
}

// writeGroupOpError maps a core group-operation error to a wire response. An
// unknown group / unknown resource-id resolves to 404; an invalid role (not in
// the type catalog) to 400; everything else to a 500 database error.
func (s *Service) writeGroupOpError(w http.ResponseWriter, err error) {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "not assignable"):
		badRequest(w, ErrInvalidRequest)
	case strings.Contains(msg, "not found"):
		notFound(w, ErrNotFound)
	default:
		serverErr(w, ErrDatabaseError)
	}
}
