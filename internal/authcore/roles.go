package authcore

import (
	"context"
	"fmt"
	"sort"
	"strings"

	authkit "github.com/open-rails/authkit"
)

// Root permission-group role helpers. "Root roles" are a user's assignments in
// the RootPersona group; the catalog itself lives in Config (the GroupSchema),
// not the DB, so upsert is validation-only. The unexported helpers are the
// genesis/bootstrap path; the exported wrappers are what admin/HTTP adapters call.

// ErrCannotRemoveLastAdminRole is returned by the permission-group last-owner
// guard (refuseIfLastOwner) and mapped to a stable HTTP code by the admin
// adapter. Aliased from the root package so core can return it unqualified.
var ErrCannotRemoveLastAdminRole = authkit.ErrCannotRemoveLastAdminRole

// normalizeRootRoleSlug canonicalises a root role slug. "admin" is not special:
// apps declare their own bounded `admin` catalog role when they need one.
func normalizeRootRoleSlug(slug string) string {
	return strings.ToLower(strings.TrimSpace(slug))
}

func (s *Service) splitConfiguredRootRoles(roles []string) (live []string, removed []string) {
	if len(roles) == 0 {
		return nil, nil
	}
	valid := map[string]struct{}{}
	if s.groupSchema != nil {
		if root, ok := s.groupSchema.types[RootPersona]; ok {
			for _, r := range root.Roles {
				valid[normalizeRootRoleSlug(r.Name)] = struct{}{}
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
		role := normalizeRootRoleSlug(raw)
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
func (s *Service) rootRoleSlugsByUser(ctx context.Context, userID string) ([]string, []string) {
	if s.pg == nil {
		return nil, nil
	}
	st := s.groupStore()
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		return nil, nil
	}
	asg, err := st.WalkAssignments(ctx, gid, strings.TrimSpace(userID), SubjectKindUser)
	if err != nil {
		return nil, nil
	}
	var roles []string
	for _, a := range asg {
		roles = append(roles, a.Roles...)
	}
	return s.splitConfiguredRootRoles(roles)
}

// listRoleSlugsByUser returns a user's configured root permission-group roles.
// Operator authority is a root-group assignment.
func (s *Service) listRoleSlugsByUser(ctx context.Context, userID string) []string {
	live, _ := s.rootRoleSlugsByUser(ctx, userID)
	return live
}

// assignRoleBySlug grants a user a role in the root permission-group (#111).
// The unchecked path is for genesis/bootstrap/migration; runtime callers use the
// actor-aware AssignRoleBySlugAs path.
func (s *Service) assignRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	if _, err := s.EnsureRootGroup(ctx); err != nil {
		return err
	}
	role := normalizeRootRoleSlug(slug)
	return s.AssignGroupRole(ctx, RootPersona, "", strings.TrimSpace(userID), SubjectKindUser, role)
}

// upsertRoleBySlug is a no-op under the permission-group model: catalog roles
// live in core.Config (the GroupSchema), not the DB, so there is nothing to
// "define" at runtime. name and description are ignored; it validates the slug
// is a known root catalog role, ensures the root group exists, and returns.
func (s *Service) upsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	if s.pg == nil {
		return nil
	}
	role := normalizeRootRoleSlug(slug)
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

// removeRoleBySlug revokes a user's role in the root permission-group.
func (s *Service) removeRoleBySlug(ctx context.Context, userID, slug string) error {
	if s.pg == nil {
		return nil
	}
	role := normalizeRootRoleSlug(slug)
	if err := s.UnassignGroupRole(ctx, RootPersona, "", strings.TrimSpace(userID), SubjectKindUser, role); err != nil {
		return err
	}
	return nil
}

// Exported wrappers for admin/HTTP adapters.
func (s *Service) AssignRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.assignRoleBySlug(ctx, userID, slug)
}

func (s *Service) UpsertRoleBySlug(ctx context.Context, name, slug string, description *string) error {
	return s.upsertRoleBySlug(ctx, name, slug, description)
}

func (s *Service) RemoveRoleBySlug(ctx context.Context, userID, slug string) error {
	return s.removeRoleBySlug(ctx, userID, slug)
}

// (single-user role reads collapsed into RoleSlugsByUsers, #220; the unexported
// listRoleSlugsByUser stays for internal display callers.)
