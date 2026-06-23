package authcore

// No-privilege-escalation enforcement for RUNTIME role assignment (#136).
//
// A runtime actor may grant or revoke a role in a group only if BOTH hold:
//  1. Capability — the actor holds the persona's role-management permission
//     (`<persona>:roles:manage`) in that group.
//  2. No step-up — the actor already holds every permission the target role
//     would confer: perms(targetRole) ⊆ perms(actor). So nobody can hand out
//     (or strip) authority above their own.
//
// This SUBSUMES the old "owner slug is reserved" hack: the owner role grants
// `<persona>:*`, and only an actor who itself holds `<persona>:*` can cover that
// grant — so "only an owner can mint/remove an owner" falls out of rule (2)
// instead of being a special case.
//
// The unchecked AssignGroupRole / assignRoleBySlug paths remain for GENESIS
// (bootstrap manifest, legacy migration) — the deploy-time trust root, which by
// design bypasses these runtime rules.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

var (
	// ErrInsufficientRoleAuthority: the actor lacks `<persona>:roles:manage` in
	// the group, so it may not change role assignments there at all.
	ErrInsufficientRoleAuthority = errors.New("insufficient_role_authority")
	// ErrRoleAssignmentEscalation: the target role confers a permission the actor
	// does not itself hold — assigning (or revoking) it would be privilege
	// escalation.
	ErrRoleAssignmentEscalation = errors.New("role_assignment_escalation")
)

// roleManagePerm is the role-management capability for a persona,
// e.g. "root:roles:manage".
func roleManagePerm(persona string) string {
	return persona + ":roles:manage"
}

// grantsCoverAll reports whether actorGrants cover EVERY permission in
// targetGrants under authkit's namespace-anchored glob semantics — i.e. the
// actor already holds everything the target role would confer (no escalation).
// Pure over resolved grant sets, so it is exhaustively unit-testable.
func grantsCoverAll(actorGrants, targetGrants []string) bool {
	for _, tp := range targetGrants {
		if !anyGrantCovers(actorGrants, tp) {
			return false
		}
	}
	return true
}

// authorizeRoleChange enforces the #136 capability + no-escalation rules for
// actorUserID changing (assign or unassign) targetRole in group gid of persona.
func (s *Service) authorizeRoleChange(ctx context.Context, st *PermissionGroupStore, sch *GroupSchema, persona, gid, actorUserID, targetRole string) error {
	actorUserID = strings.TrimSpace(actorUserID)
	if actorUserID == "" {
		return ErrInsufficientRoleAuthority
	}

	// Resolve the actor's effective grants in this group (additive walk-up union).
	asg, err := st.WalkAssignments(ctx, gid, actorUserID, SubjectKindUser)
	if err != nil {
		return err
	}
	ids := make([]string, 0, len(asg))
	for _, a := range asg {
		ids = append(ids, a.GroupID)
	}
	resolver, err := st.CustomRolesFor(ctx, ids)
	if err != nil {
		return err
	}
	actorGrants := sch.ResolveGrants(asg, resolver)

	// (1) capability: the actor must be able to manage roles in this persona.
	if !anyGrantCovers(actorGrants, roleManagePerm(persona)) {
		return ErrInsufficientRoleAuthority
	}
	// (2) no step-up: the actor must already hold every perm the target confers.
	targetGrants, err := s.roleGrantsForAuthz(sch, persona, gid, targetRole, resolver)
	if err != nil {
		return err
	}
	if !grantsCoverAll(actorGrants, targetGrants) {
		return ErrRoleAssignmentEscalation
	}
	return nil
}

// roleGrantsForAuthz returns the permission grants a role confers in a group: a
// catalog role's declared perms, or a custom role's stored grants.
func (s *Service) roleGrantsForAuthz(sch *GroupSchema, persona, gid, role string, resolver CustomRoleResolver) ([]string, error) {
	if r, ok := sch.Role(persona, role); ok {
		return r.Permissions, nil
	}
	if resolver != nil {
		if grants, ok := resolver(gid, role); ok {
			return grants, nil
		}
	}
	return nil, fmt.Errorf("role %q is not assignable in a %q group", role, persona)
}

// AssignGroupRoleAs is the actor-aware AssignGroupRole: it enforces the #136
// capability + no-escalation rules against actorUserID before assigning. Runtime
// callers (HTTP role-management endpoints) use this; genesis paths (bootstrap,
// migration) keep using the unchecked AssignGroupRole.
func (s *Service) AssignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error {
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group", role, persona)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	if err := s.authorizeRoleChange(ctx, st, sch, persona, gid, actorUserID, role); err != nil {
		return err
	}
	if err := s.requireMFAForRoleAssignment(ctx, db.ForSchema(s.pg, s.dbSchema()), persona, subjectID, subjectKind, role); err != nil {
		return err
	}
	return st.AssignRole(ctx, gid, subjectID, subjectKind, role)
}

// UnassignGroupRoleAs is the actor-aware UnassignGroupRole. Revoking is gated the
// same way (you cannot strip a role whose authority you do not hold — e.g. a
// non-owner cannot remove an owner).
func (s *Service) UnassignGroupRoleAs(ctx context.Context, actorUserID, persona, instanceSlug, subjectID, subjectKind, role string) error {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, persona, instanceSlug)
	if err != nil {
		return err
	}
	if err := s.authorizeRoleChange(ctx, st, sch, persona, gid, actorUserID, role); err != nil {
		return err
	}
	return st.UnassignRole(ctx, gid, subjectID, subjectKind, role)
}

// AssignRoleBySlugAs is the actor-aware root-group convenience (the runtime
// equivalent of assignRoleBySlug). "owner" is no longer a reserved special case:
// it is assignable only by an actor who already holds root:* (rule 2).
func (s *Service) AssignRoleBySlugAs(ctx context.Context, actorUserID, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	role := normalizeRootRoleSlug(slug)
	return s.AssignGroupRoleAs(ctx, actorUserID, RootPersona, "", strings.TrimSpace(userID), SubjectKindUser, role)
}

// RemoveRoleBySlugAs is the actor-aware root-group revoke.
func (s *Service) RemoveRoleBySlugAs(ctx context.Context, actorUserID, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	role := normalizeRootRoleSlug(slug)
	return s.UnassignGroupRoleAs(ctx, actorUserID, RootPersona, "", strings.TrimSpace(userID), SubjectKindUser, role)
}

// listRoleSlugsByUserErr is the error-PROPAGATING form of listRoleSlugsByUser:
// a failure resolving the user's root-group roles is returned, not swallowed
// into an empty slice, so authz callers can FAIL CLOSED instead of silently
// treating a backend outage as "this user has no roles" (#136). A missing root
// group is genuinely empty (not an error). Exposed via the facade as
// ListRoleSlugsByUserErr for consumers that must surface role-resolution
// failures (e.g. doujins #420 middleware).
func (s *Service) listRoleSlugsByUserErr(ctx context.Context, userID string) ([]string, error) {
	if s.pg == nil {
		return nil, nil
	}
	st := s.groupStore()
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		if errors.Is(err, ErrGroupNotFound) {
			return nil, nil // no root group yet ⇒ genuinely no roles
		}
		return nil, err
	}
	asg, err := st.WalkAssignments(ctx, gid, strings.TrimSpace(userID), SubjectKindUser)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, a := range asg {
		out = append(out, a.Roles...)
	}
	return out, nil
}
