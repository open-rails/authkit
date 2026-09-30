package engine

import (
	"context"
	"slices"

	"github.com/open-rails/authkit/internal/ident"
)

// rbacDriftReport counts orphaned authority rows: assigned group roles no
// account issuer's catalog declares, and API keys this app judges whose role
// its catalog no longer declares.
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
	keyRoles, err := s.q.APIKeyRoleCounts(ctx, s.cfg.Token.Issuer)
	if err != nil {
		return rbacDriftReport{}, err
	}
	peerRoles, err := s.q.RoleCatalogsDeclaredRoles(ctx, s.accountIssuers()[1:])
	if err != nil {
		return rbacDriftReport{}, err
	}
	var report rbacDriftReport
	for _, r := range userRoles {
		if !slices.Contains(peerRoles, r.Role) {
			report.GroupUserRoles += s.undefinedRoleCount(r.Persona, r.Role, r.N)
		}
	}
	for _, r := range keyRoles {
		report.APIKeys += s.undefinedRoleCount(r.Persona, r.Role, r.N)
	}
	return report, nil
}

// undefinedRoleCount is n when the persona's role is no longer defined, else 0.
func (s *Engine) undefinedRoleCount(persona, role string, n int64) int {
	p := ident.Persona(persona)
	if _, ok := s.groupSchemaOrDefault().Role(p, ident.RoleText(role)); ok {
		return 0
	}
	return int(n)
}
