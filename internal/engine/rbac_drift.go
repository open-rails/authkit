package engine

import (
	"context"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
)

// rbacDriftReport counts orphaned authority rows: assigned group roles and API
// keys whose role definitions no longer exist.
type rbacDriftReport struct {
	GroupUserRoles int `json:"group_user_roles"`
	APIKeys        int `json:"api_keys"`
}

func (r rbacDriftReport) Total() int {
	return r.GroupUserRoles + r.APIKeys
}

func (s *Engine) driftReport(ctx context.Context) (rbacDriftReport, error) {
	if s == nil || s.pg == nil {
		return rbacDriftReport{}, nil
	}
	userRoles, err := s.driftAssignedRoles(ctx, "group_user_roles", "true")
	if err != nil {
		return rbacDriftReport{}, err
	}
	apiKeys, err := s.driftAssignedRoles(ctx, "api_keys", "revoked_at IS NULL")
	if err != nil {
		return rbacDriftReport{}, err
	}
	return rbacDriftReport{GroupUserRoles: userRoles, APIKeys: apiKeys}, nil
}

func (s *Engine) driftAssignedRoles(ctx context.Context, table, where string) (int, error) {
	rows, err := s.pg.Query(ctx, `
		SELECT pg.persona, r.role, count(*)
		  FROM `+table+` r
		  JOIN permission_groups pg ON pg.id = r.permission_group_id
		 WHERE `+where+`
		 GROUP BY pg.persona, r.role`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	total := 0
	for rows.Next() {
		var name string
		var persona iam.Persona
		var count int
		if err := rows.Scan(scanPersona(&persona), &name, &count); err != nil {
			return 0, err
		}
		if _, ok := s.groupSchemaOrDefault().Role(persona, ident.Role(persona, name)); !ok {
			total += count
		}
	}
	return total, rows.Err()
}
