package embedded

import (
	"context"
	"fmt"
	"sort"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// Root permission-group role helpers. "Root roles" are a user's assignments in
// the RootPersona group; the catalog itself lives in Config (the GroupSchema),
// not the DB, so upsert is validation-only.

// ErrCannotRemoveLastAdminRole is returned by the permission-group last-owner
// guard (refuseOwnerLoss) and mapped to a stable HTTP code by the admin
// adapter. Aliased from the root package so core can return it unqualified.
var ErrCannotRemoveLastAdminRole = authkit.ErrCannotRemoveLastAdminRole

// normalizeRootRoleSlug canonicalises a root role slug. "admin" is not special:
// apps declare their own bounded `admin` catalog role when they need one.
func normalizeRootRoleSlug(role authkit.Role) authkit.Role {
	return authkit.Role(strings.ToLower(strings.TrimSpace(string(role))))
}

func (s *Client) splitConfiguredRootRoles(roles []string) (live []string, removed []string) {
	if len(roles) == 0 {
		return nil, nil
	}
	valid := map[string]struct{}{}
	if s.groupSchema != nil {
		if root, ok := s.groupSchema.types[RootPersona]; ok {
			for _, r := range root.Roles {
				valid[string(normalizeRootRoleSlug(r.Name))] = struct{}{}
			}
		}
	}
	if len(valid) == 0 {
		live = append([]string(nil), roles...)
		sort.Strings(live)
		return live, nil
	}
	liveSeen := map[string]struct{}{}
	removedSeen := map[string]struct{}{}
	for _, raw := range roles {
		role := string(normalizeRootRoleSlug(authkit.Role(raw)))
		if role == "" {
			continue
		}
		if _, ok := valid[role]; ok {
			liveSeen[role] = struct{}{}
			continue
		}
		removedSeen[role] = struct{}{}
	}
	for role := range liveSeen {
		live = append(live, role)
	}
	for role := range removedSeen {
		removed = append(removed, role)
	}
	sort.Strings(live)
	sort.Strings(removed)
	return live, removed
}

// rootRoleSlugsByUser returns a user's configured root permission-group roles
// and any stored roles removed from the current schema.
func (s *Client) rootRoleSlugsByUser(ctx context.Context, userID string) ([]string, []string) {
	if s.pg == nil {
		return nil, nil
	}
	st := s.groupStore()
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		return nil, nil
	}
	asg, err := st.WalkAssignments(ctx, gid, authkit.UserSubject(strings.TrimSpace(userID)))
	if err != nil {
		return nil, nil
	}
	var roles []string
	for _, a := range asg {
		if a.Role != "" {
			roles = append(roles, string(a.Role))
		}
	}
	return s.splitConfiguredRootRoles(roles)
}

// AssignRoleBySlug grants a user a role in the root permission-group (#111).
// This path skips actor-authz/no-escalation (genesis/bootstrap/migration);
// runtime callers use the actor-aware AssignRoleBySlugAs path. The
// MFA-required-role enrollment gate is a subject-state invariant and STILL
// applies — assigning an MFA-required role to a non-enrolled user fails closed
// with ErrTwoFAEnrollmentRequired.
func (s *Client) AssignRoleBySlug(ctx context.Context, userID string, role authkit.Role) error {
	if s.pg == nil {
		return nil
	}
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	return s.AssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(strings.TrimSpace(userID)), normalizeRootRoleSlug(role))
}

// UpsertRoleBySlug is a no-op under the permission-group model: catalog roles
// live in core.Config (the GroupSchema), not the DB, so there is nothing to
// "define" at runtime. name and description are ignored; it validates the slug
// is a known root catalog role, ensures the root group exists, and returns.
func (s *Client) UpsertRoleBySlug(ctx context.Context, name string, role authkit.Role, description *string) error {
	if s.pg == nil {
		return nil
	}
	role = normalizeRootRoleSlug(role)
	if role == "" {
		return fmt.Errorf("invalid_role")
	}
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	if !s.validRoleForPersona(s.groupSchemaOrDefault(), RootPersona, role) {
		return fmt.Errorf("invalid_role")
	}
	return nil
}

// RemoveRoleBySlug revokes a user's role in the root permission-group.
func (s *Client) RemoveRoleBySlug(ctx context.Context, userID string, role authkit.Role) error {
	if s.pg == nil {
		return nil
	}
	return s.UnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(strings.TrimSpace(userID)), normalizeRootRoleSlug(role))
}
