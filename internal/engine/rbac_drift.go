package engine

import (
	"context"

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
	userRoles, err := s.q.GroupUserRoleCounts(ctx)
	if err != nil {
		return rbacDriftReport{}, err
	}
	keyRoles, err := s.q.APIKeyRoleCounts(ctx)
	if err != nil {
		return rbacDriftReport{}, err
	}
	var report rbacDriftReport
	for _, r := range userRoles {
		report.GroupUserRoles += s.undefinedRoleCount(r.Persona, r.Role, r.N)
	}
	for _, r := range keyRoles {
		report.APIKeys += s.undefinedRoleCount(r.Persona, r.Role, r.N)
	}
	return report, nil
}

// undefinedRoleCount is n when the persona's role is no longer defined, else 0.
func (s *Engine) undefinedRoleCount(persona, role string, n int64) int {
	p := ident.Persona(persona)
	if _, ok := s.groupSchemaOrDefault().Role(p, ident.Role(p, role)); ok {
		return 0
	}
	return int(n)
}
