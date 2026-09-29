package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// rbacDriftReport counts orphaned authority rows — assigned group roles, custom
// roles, and API keys whose role definitions no longer exist.
type rbacDriftReport struct {
	GroupUserRoles int `json:"group_user_roles"`
	CustomRoles    int `json:"group_custom_roles"`
	APIKeys        int `json:"api_keys"`
}

func (r rbacDriftReport) Total() int {
	return r.GroupUserRoles + r.CustomRoles + r.APIKeys
}

func (s *Engine) driftReport(ctx context.Context) (rbacDriftReport, error) {
	if s == nil || s.pg == nil {
		return rbacDriftReport{}, nil
	}
	custom, err := s.driftCustomRoles(ctx)
	if err != nil {
		return rbacDriftReport{}, err
	}
	userRoles, err := s.driftAssignedRoles(ctx, "group_user_roles", "true")
	if err != nil {
		return rbacDriftReport{}, err
	}
	apiKeys, err := s.driftAssignedRoles(ctx, "api_keys", "revoked_at IS NULL")
	if err != nil {
		return rbacDriftReport{}, err
	}
	return rbacDriftReport{GroupUserRoles: userRoles, CustomRoles: custom, APIKeys: apiKeys}, nil
}

func (s *Engine) driftCustomRoles(ctx context.Context) (int, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT pg.persona, gcr.role, count(*)
		  FROM group_custom_roles gcr
		  JOIN permission_groups pg ON pg.id = gcr.permission_group_id
		 GROUP BY pg.persona, gcr.role`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var persona iam.Persona
		var name string
		var count int
		if err := rows.Scan(scanPersona(&persona), &name, &count); err != nil {
			return 0, err
		}
		if !s.customRolesLive(persona, ident.Role(persona, name)) {
			total += count
		}
	}
	return total, rows.Err()
}

func (s *Engine) driftAssignedRoles(ctx context.Context, table, where string) (int, error) {
	custom, err := s.liveCustomRoleSet(ctx)
	if err != nil {
		return 0, err
	}
	rows, err := s.pg.Query(ctx, `
		SELECT pg.id::text, pg.persona, r.role, count(*)
		  FROM `+table+` r
		  JOIN permission_groups pg ON pg.id = r.permission_group_id
		 WHERE `+where+`
		 GROUP BY pg.id, pg.persona, r.role`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var groupID, name string
		var persona iam.Persona
		var count int
		if err := rows.Scan(&groupID, scanPersona(&persona), &name, &count); err != nil {
			return 0, err
		}
		if !s.roleLive(persona, groupID, ident.Role(persona, name), custom) {
			total += count
		}
	}
	return total, rows.Err()
}

func (s *Engine) liveCustomRoleSet(ctx context.Context) (map[string]map[string]struct{}, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT pg.id::text, gcr.role
		  FROM group_custom_roles gcr
		  JOIN permission_groups pg ON pg.id = gcr.permission_group_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]map[string]struct{}{}
	for rows.Next() {
		var groupID, role string
		if err := rows.Scan(&groupID, &role); err != nil {
			return nil, err
		}
		if out[groupID] == nil {
			out[groupID] = map[string]struct{}{}
		}
		out[groupID][role] = struct{}{}
	}
	return out, rows.Err()
}

func (s *Engine) roleLive(persona iam.Persona, groupID string, role iam.Role, custom map[string]map[string]struct{}) bool {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return true
	}
	if !s.customRolesLive(persona, role) {
		return false
	}
	_, ok := custom[groupID][role.Name()]
	return ok
}

func (s *Engine) customRolesLive(persona iam.Persona, role iam.Role) bool {
	sch := s.groupSchemaOrDefault()
	td, ok := sch.Persona(persona)
	if !ok || !td.CustomRoles {
		return false
	}
	if _, catalog := sch.Role(persona, role); catalog {
		return true
	}
	return !role.IsZero()
}
