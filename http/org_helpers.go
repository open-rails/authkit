package authhttp

import (
	"context"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// CheckOrgAccess resolves orgSlug (slug or alias) to its canonical slug,
// verifies membership, and returns the member's org-scoped roles.
func CheckOrgAccess(ctx context.Context, svc *core.Service, userID, orgSlug string) (canonicalOrg string, memberRoles []string, isMember bool, err error) {
	if svc == nil {
		return "", nil, false, core.ErrOrgNotFound
	}
	org, err := svc.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return "", nil, false, err
	}
	canonicalOrg = org.Slug
	isMember, err = svc.IsOrgMember(ctx, canonicalOrg, userID)
	if err != nil || !isMember {
		return canonicalOrg, nil, isMember, err
	}
	memberRoles, err = svc.ReadMemberRoles(ctx, canonicalOrg, userID)
	return canonicalOrg, memberRoles, isMember, err
}

// HasAnyOrgRole returns true if roles contains any of want (case-insensitive).
func HasAnyOrgRole(roles []string, want ...string) bool {
	for _, r := range roles {
		for _, w := range want {
			if strings.EqualFold(strings.TrimSpace(r), strings.TrimSpace(w)) {
				return true
			}
		}
	}
	return false
}
