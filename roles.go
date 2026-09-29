package authkit

import (
	"context"
	"sort"
	"strings"

	"github.com/open-rails/authkit/iam"
)

// Root permission-group role helpers. "Root roles" are a user's assignments in
// the RootPersona group; the catalog itself lives in Config.Roles,
// not the DB, so upsert is validation-only.

// normalizeRootRoleSlug canonicalises a root role slug. "admin" is not special:
// apps declare their own bounded `admin` catalog role when they need one.
func normalizeRootRoleSlug(role iam.Role) iam.Role {
	return iam.Role(strings.ToLower(strings.TrimSpace(string(role))))
}

func (s *engine) splitConfiguredRootRoles(roles []string) (live []string, removed []string) {
	if len(roles) == 0 {
		return nil, nil
	}
	valid := map[string]struct{}{}
	if s.groupSchema != nil {
		if root, ok := s.groupSchema.Persona(iam.RootPersona); ok {
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
		role := string(normalizeRootRoleSlug(iam.Role(raw)))
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
func (s *engine) rootRoleSlugsByUser(ctx context.Context, userID string) ([]string, []string) {
	if s.pg == nil {
		return nil, nil
	}
	st := s.groupStore()
	gid, err := st.RootGroupID(ctx)
	if err != nil {
		return nil, nil
	}
	asg, err := st.WalkAssignments(ctx, gid, iam.UserSubject(strings.TrimSpace(userID)))
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
