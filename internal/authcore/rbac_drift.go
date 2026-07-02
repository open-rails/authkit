package authcore

import (
	"context"

	"github.com/open-rails/authkit/internal/db"
)

// RBACDriftReport counts orphaned authority rows — assigned group roles, custom
// roles, and API keys whose role definitions no longer exist.
type RBACDriftReport struct {
	GroupUserRoles int `json:"group_user_roles"`
	CustomRoles    int `json:"group_custom_roles"`
	APIKeys        int `json:"api_keys"`
}

func (r RBACDriftReport) Total() int {
	return r.GroupUserRoles + r.CustomRoles + r.APIKeys
}

func (s *Service) RBACDriftReport(ctx context.Context) (RBACDriftReport, error) {
	if s == nil || s.pg == nil {
		return RBACDriftReport{}, nil
	}
	custom, err := s.driftCustomRoles(ctx)
	if err != nil {
		return RBACDriftReport{}, err
	}
	userRoles, err := s.driftAssignedRoles(ctx, "group_user_roles", "r.deleted_at IS NULL")
	if err != nil {
		return RBACDriftReport{}, err
	}
	apiKeys, err := s.driftAssignedRoles(ctx, "api_keys", "revoked_at IS NULL")
	if err != nil {
		return RBACDriftReport{}, err
	}
	return RBACDriftReport{GroupUserRoles: userRoles, CustomRoles: custom, APIKeys: apiKeys}, nil
}

func (s *Service) driftCustomRoles(ctx context.Context) (int, error) {
	rows, err := s.pg.Query(ctx, db.RewriteSQL(`
		SELECT pg.persona, gcr.role, count(*)
		  FROM profiles.group_custom_roles gcr
		  JOIN profiles.permission_groups pg ON pg.id = gcr.permission_group_id
		 WHERE pg.deleted_at IS NULL
		 GROUP BY pg.persona, gcr.role`, s.dbSchema()))
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var persona, role string
		var count int
		if err := rows.Scan(&persona, &role, &count); err != nil {
			return 0, err
		}
		if !s.customRolesLive(persona, role) {
			total += count
		}
	}
	return total, rows.Err()
}

func (s *Service) driftAssignedRoles(ctx context.Context, table, where string) (int, error) {
	custom, err := s.liveCustomRoleSet(ctx)
	if err != nil {
		return 0, err
	}
	rows, err := s.pg.Query(ctx, db.RewriteSQL(`
		SELECT pg.id::text, pg.persona, r.role, count(*)
		  FROM profiles.`+table+` r
		  JOIN profiles.permission_groups pg ON pg.id = r.permission_group_id
		 WHERE pg.deleted_at IS NULL AND `+where+`
		 GROUP BY pg.id, pg.persona, r.role`, s.dbSchema()))
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var groupID, persona, role string
		var count int
		if err := rows.Scan(&groupID, &persona, &role, &count); err != nil {
			return 0, err
		}
		if !s.roleLive(persona, groupID, role, custom) {
			total += count
		}
	}
	return total, rows.Err()
}

func (s *Service) liveCustomRoleSet(ctx context.Context) (map[string]map[string]struct{}, error) {
	rows, err := s.pg.Query(ctx, db.RewriteSQL(`
		SELECT pg.id::text, gcr.role
		  FROM profiles.group_custom_roles gcr
		  JOIN profiles.permission_groups pg ON pg.id = gcr.permission_group_id
		 WHERE pg.deleted_at IS NULL`, s.dbSchema()))
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

func (s *Service) roleLive(persona, groupID, role string, custom map[string]map[string]struct{}) bool {
	if _, ok := s.groupSchemaOrDefault().Role(persona, role); ok {
		return true
	}
	if !s.customRolesLive(persona, role) {
		return false
	}
	_, ok := custom[groupID][role]
	return ok
}

func (s *Service) customRolesLive(persona, role string) bool {
	sch := s.groupSchemaOrDefault()
	td, ok := sch.Persona(persona)
	if !ok || !td.Capabilities.CustomRoles {
		return false
	}
	if _, catalog := sch.Role(persona, role); catalog {
		return true
	}
	return role != ""
}
