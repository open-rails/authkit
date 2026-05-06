package authhttp

import (
	"context"
	"strings"
)

func isPrivilegedOrgRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner":
		return true
	default:
		return false
	}
}

func (s *Service) requireOrgMember(ctx context.Context, userID, orgSlug string) (canonicalOrg string, ok bool, err error) {
	org, err := s.svc.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return "", false, err
	}
	canonicalOrg = org.Slug
	member, err := s.svc.IsOrgMember(ctx, canonicalOrg, userID)
	if err != nil {
		return canonicalOrg, false, err
	}
	return canonicalOrg, member, nil
}

func (s *Service) requireOrgOwner(ctx context.Context, userID, orgSlug string) (canonicalOrg string, roles []string, ok bool, err error) {
	org, err := s.svc.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return "", nil, false, err
	}
	canonicalOrg = org.Slug
	member, err := s.svc.IsOrgMember(ctx, canonicalOrg, userID)
	if err != nil || !member {
		return canonicalOrg, nil, false, err
	}
	roles, err = s.svc.ReadMemberRoles(ctx, canonicalOrg, userID)
	if err != nil {
		return canonicalOrg, nil, false, err
	}
	for _, r := range roles {
		if isPrivilegedOrgRole(r) {
			return canonicalOrg, roles, true, nil
		}
	}
	return canonicalOrg, roles, false, nil
}
