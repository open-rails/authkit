package authkit

// No-privilege-escalation enforcement for RUNTIME role assignment (#136).
//
// A runtime actor may grant or revoke a role in a group only if BOTH hold:
//  1. Capability — the actor holds the persona's member-management permission
//     (`<persona>:members:manage`) in that group. The owner (`<persona>:*`) holds
//     it via the wildcard; a bounded admin that lacks it cannot promote anyone.
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

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/rbac"
	"github.com/open-rails/authkit/verify"
)

// grantsCoverAll reports whether actorGrants cover EVERY permission in
// targetGrants under authkit's namespace-anchored glob semantics — i.e. the
// actor already holds everything the target role would confer (no escalation).
// Pure over resolved grant sets, so it is exhaustively unit-testable.
func grantsCoverAll(actorGrants, targetGrants []string) bool {
	for _, tp := range targetGrants {
		if !iam.AnyGrantCovers(actorGrants, iam.Perm(tp)) {
			return false
		}
	}
	return true
}

// authorizeRoleChange enforces the #136 capability + no-escalation rules for
// actorUserID changing (assign or unassign) targetRole in group gid of persona.
func (s *engine) authorizeRoleChange(ctx context.Context, st *permissionGroupStore, sch *rbac.Schema, persona iam.Persona, gid, actorUserID string, targetRole iam.Role) error {
	return s.authorizeRoleGrant(ctx, st, sch, persona, gid, actorUserID, iam.PermMembersManage(persona), targetRole)
}

func (s *engine) authorizeRoleGrant(ctx context.Context, st *permissionGroupStore, sch *rbac.Schema, persona iam.Persona, gid, actorUserID string, capabilityPerm iam.Perm, targetRole iam.Role) error {
	return s.authorizeGroupActorRole(ctx, st, sch, persona, gid, groupMutationActor{userID: actorUserID}, capabilityPerm, targetRole)
}

func (s *engine) authorizeGroupActorRole(ctx context.Context, st *permissionGroupStore, sch *rbac.Schema, persona iam.Persona, gid string, actor groupMutationActor, capabilityPerm iam.Perm, targetRole iam.Role) error {
	subject, err := s.groupMutationSubject(ctx, st, persona, gid, actor)
	if err != nil {
		return err
	}
	// Resolve the actor's effective grants in this group (roles on the group and on root).
	asg, resolver, err := st.assignmentsWithCustomRoles(ctx, gid, subject, true)
	if err != nil {
		return err
	}
	actorGrants := sch.ResolveGrants(asg, resolver)

	// (1) capability: the actor must hold the operation's management permission.
	// owner (<persona>:*) holds it via the wildcard; a bounded admin without it
	// cannot grant authority through that operation.
	if !iam.AnyGrantCovers(actorGrants, capabilityPerm) || (actor.remote != nil && !actor.remote.HasPermission(capabilityPerm)) {
		return iam.ErrInsufficientRoleAuthority
	}
	// (2) no step-up: the actor must already hold every perm the target confers.
	if _, catalog := sch.Role(persona, targetRole); !catalog {
		targetResolver, err := st.CustomRolesFor(ctx, []string{gid})
		if err != nil {
			return err
		}
		resolver = targetResolver
	}
	targetGrants, err := s.roleGrantsForAuthz(sch, persona, gid, targetRole, resolver)
	if err != nil {
		return err
	}
	if !grantsCoverAll(actorGrants, targetGrants) || (actor.remote != nil && !grantsCoverAll(actor.remote.Permissions, targetGrants)) {
		return iam.ErrRoleAssignmentEscalation
	}
	return nil
}

// roleGrantsForAuthz returns the permission grants a role confers in a group: a
// catalog role's declared perms, or a custom role's stored grants.
func (s *engine) roleGrantsForAuthz(sch *rbac.Schema, persona iam.Persona, gid string, role iam.Role, resolver rbac.CustomRoleResolver) ([]string, error) {
	if r, ok := sch.Role(persona, role); ok {
		return r.Permissions, nil
	}
	if resolver != nil {
		if grants, ok := resolver(gid, role); ok {
			return grants, nil
		}
	}
	return nil, fmt.Errorf("role %q is not assignable in a %q group: %w", role, persona, iam.ErrRoleNotAssignable)
}

// authorizeCustomRoleChange enforces the #136/#247 capability + no-escalation
// rules for DEFINING (create/redefine) or DELETING a per-group custom role.
// Redefining a role's grants is a DEFERRED grant/revoke to EVERY subject
// currently holding it — same class as invite minting or a direct role
// assignment — so it needs the same gate: the actor must hold
// <persona>:roles:manage in the group AND already cover every permission in
// BOTH the role's CURRENT grant set (oldGrants — nil for a brand-new role) and
// its REQUESTED grant set (newGrants — nil for a delete), so nobody can widen
// (or narrow, silently stripping others while keeping their own coverage)
// authority they do not themselves hold. Unlike authorizeRoleGrant, the grant
// sets are supplied directly by the caller rather than resolved from a role
// name — DefineGroupCustomRole/DeleteGroupCustomRole already have both the
// stored old grants and the requested new ones in hand.
func (s *engine) authorizeCustomRoleChange(ctx context.Context, st *permissionGroupStore, sch *rbac.Schema, persona iam.Persona, gid, actorUserID string, oldGrants, newGrants []string) error {
	actorUserID = strings.TrimSpace(actorUserID)
	if actorUserID == "" {
		return iam.ErrInsufficientRoleAuthority
	}
	present, err := authorizationActorPresent(ctx, st.q, actorUserID)
	if err != nil {
		return err
	}
	if !present {
		return iam.ErrInsufficientRoleAuthority
	}
	asg, resolver, err := st.assignmentsWithCustomRoles(ctx, gid, iam.UserSubject(actorUserID), true)
	if err != nil {
		return err
	}
	actorGrants := sch.ResolveGrants(asg, resolver)
	if !iam.AnyGrantCovers(actorGrants, iam.PermRolesManage(persona)) {
		return iam.ErrInsufficientRoleAuthority
	}
	combined := make([]string, 0, len(oldGrants)+len(newGrants))
	combined = append(combined, oldGrants...)
	combined = append(combined, newGrants...)
	if !grantsCoverAll(actorGrants, combined) {
		return iam.ErrRoleAssignmentEscalation
	}
	return nil
}

// AssignGroupRoleAs is the actor-aware AssignGroupRole: it enforces the #136
// capability + no-escalation rules against actorUserID before assigning. engine
// callers (HTTP role-management endpoints) use this; genesis paths (bootstrap,
// migration) keep using the unchecked AssignGroupRole.
func (s *engine) AssignGroupRoleAs(ctx context.Context, actorUserID string, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return s.assignGroupRoleForActor(ctx, groupMutationActor{userID: actorUserID}, group, subject, role)
}

// AssignGroupRoleFromClaims is available only to the local HTTP transport. The
// transport must supply claims produced by its verifier, never request fields.
func (s *engine) AssignGroupRoleFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	actor, err := groupActorFromClaims(claims)
	if err != nil {
		return err
	}
	return s.assignGroupRoleForActor(ctx, actor, group, subject, role)
}

func (s *engine) assignGroupRoleForActor(ctx context.Context, actor groupMutationActor, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	role = iam.Role(strings.TrimSpace(string(role)))
	sch := s.groupSchemaOrDefault()
	if !s.validRoleForPersona(sch, group.Persona, role) {
		return fmt.Errorf("role %q is not assignable in a %q group: %w", role, group.Persona, iam.ErrRoleNotAssignable)
	}
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		if err := s.authorizeGroupActorRole(ctx, st, sch, group.Persona, gid, actor, iam.PermMembersManage(group.Persona), role); err != nil {
			return err
		}
		old, err := st.directRole(ctx, gid, subject)
		if err != nil {
			return err
		}
		if old != "" && old != role {
			if err := s.authorizeGroupActorRole(ctx, st, sch, group.Persona, gid, actor, iam.PermMembersManage(group.Persona), old); err != nil {
				return err
			}
			if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
				return err
			}
		}
		if err := s.requireMFAForRoleAssignment(ctx, st.q, gid, group.Persona, subject, role); err != nil {
			return err
		}
		return st.AssignRole(ctx, gid, subject, role)
	})
}

// UnassignGroupRoleAs is the actor-aware UnassignGroupRole. Revoking is gated the
// same way (you cannot strip a role whose authority you do not hold — e.g. a
// non-owner cannot remove an owner).
func (s *engine) UnassignGroupRoleAs(ctx context.Context, actorUserID string, group iam.GroupRef, subject iam.Subject, role iam.Role) error {
	role = iam.Role(strings.TrimSpace(string(role)))
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		if err := s.authorizeRoleChange(ctx, st, sch, group.Persona, gid, actorUserID, role); err != nil {
			return err
		}
		current, err := st.directRole(ctx, gid, subject)
		if err != nil {
			return err
		}
		if current != role {
			return nil
		}
		if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
			return err
		}
		return st.UnassignRole(ctx, gid, subject, role)
	})
}

// RemoveGroupSubjectAs strips every role a subject holds in a group. It enforces
// the #136 capability + no-escalation rules for EVERY role the subject currently
// holds before stripping them, so a bounded admin cannot remove a member whose
// authority it does not itself hold (e.g. a non-owner cannot remove an owner).
func (s *engine) RemoveGroupSubjectAs(ctx context.Context, actorUserID string, group iam.GroupRef, subject iam.Subject) error {
	return s.removeGroupSubjectForActor(ctx, groupMutationActor{userID: actorUserID}, group, subject)
}

func (s *engine) RemoveGroupSubjectFromClaims(ctx context.Context, claims verify.Claims, group iam.GroupRef, subject iam.Subject) error {
	actor, err := groupActorFromClaims(claims)
	if err != nil {
		return err
	}
	return s.removeGroupSubjectForActor(ctx, actor, group, subject)
}

func (s *engine) removeGroupSubjectForActor(ctx context.Context, actor groupMutationActor, group iam.GroupRef, subject iam.Subject) error {
	sch := s.groupSchemaOrDefault()
	st := s.groupStore()
	gid, err := s.resolveGroupID(ctx, st, group)
	if err != nil {
		return err
	}
	subject.ID = strings.TrimSpace(subject.ID)
	return s.withLockedGroup(ctx, gid, func(st *permissionGroupStore) error {
		role, err := st.directRole(ctx, gid, subject)
		if err != nil {
			return err
		}
		if role == "" {
			return nil
		}
		if err := s.authorizeGroupActorRole(ctx, st, sch, group.Persona, gid, actor, iam.PermMembersManage(group.Persona), role); err != nil {
			return err
		}
		if err := s.refuseOwnerLoss(ctx, st, gid, subject); err != nil {
			return err
		}
		return st.UnassignSubject(ctx, gid, subject)
	})
}

// AssignRoleBySlugAs is the actor-aware root-group convenience (the runtime
// equivalent of assignRoleBySlug). "owner" is no longer a reserved special case:
// it is assignable only by an actor who already holds root:* (rule 2).
func (s *engine) AssignRoleBySlugAs(ctx context.Context, actorUserID, userID string, role iam.Role) error {
	if s.pg == nil {
		return nil
	}
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	return s.AssignGroupRoleAs(ctx, actorUserID, iam.RootGroup(), iam.UserSubject(strings.TrimSpace(userID)), normalizeRootRoleSlug(role))
}

// RemoveRoleBySlugAs is the actor-aware root-group revoke.
func (s *engine) RemoveRoleBySlugAs(ctx context.Context, actorUserID, userID string, role iam.Role) error {
	if s.pg == nil {
		return nil
	}
	return s.UnassignGroupRoleAs(ctx, actorUserID, iam.RootGroup(), iam.UserSubject(strings.TrimSpace(userID)), normalizeRootRoleSlug(role))
}

// RoleSlugsByUsers returns each user's LIVE configured root permission-group
// role slugs in ONE call (#220 — replaces ListRoleSlugsByUser and the
// error-propagating ListRoleSlugsByUserErr). The map is keyed by user id;
// users holding no live roles are absent. A failure resolving roles is
// RETURNED, not swallowed into an empty result, so authz callers can FAIL
// CLOSED instead of treating a backend outage as "no roles" (#136). A missing
// root group is genuinely empty (not an error). Root has no parent groups, so
// direct root-group assignments ARE the effective set. Roles that have drifted
// out of the configured catalog are excluded (splitConfiguredRootRoles), which
// is also the correct authz reading: an unconfigured role confers nothing.
func (s *engine) RoleSlugsByUsers(ctx context.Context, userIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if s.pg == nil || len(userIDs) == 0 {
		return out, nil
	}
	st := s.groupStore()
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		if errors.Is(err, iam.ErrGroupNotFound) {
			return out, nil // no root group yet ⇒ genuinely no roles
		}
		return nil, err
	}
	raw, err := st.RootRolesForUsers(ctx, gid, userIDs)
	if err != nil {
		return nil, err
	}
	for id, roles := range raw {
		live, _ := s.splitConfiguredRootRoles(roles)
		if len(live) > 0 {
			out[id] = live
		}
	}
	return out, nil
}
