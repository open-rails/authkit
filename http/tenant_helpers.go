package authhttp

import (
	"context"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// CheckTenantAccess resolves tenantSlug (slug or alias) to its canonical slug,
// verifies membership, and returns the member's tenant-scoped roles.
func CheckTenantAccess(ctx context.Context, svc *core.Service, userID, tenantSlug string) (canonicalTenant string, memberRoles []string, isMember bool, err error) {
	if svc == nil {
		return "", nil, false, core.ErrTenantNotFound
	}
	tenant, err := svc.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return "", nil, false, err
	}
	canonicalTenant = tenant.Slug
	isMember, err = svc.IsTenantMember(ctx, canonicalTenant, userID)
	if err != nil || !isMember {
		return canonicalTenant, nil, isMember, err
	}
	memberRoles, err = svc.ReadMemberRoles(ctx, canonicalTenant, userID)
	return canonicalTenant, memberRoles, isMember, err
}

// HasAnyTenantRole returns true if roles contains any of want (case-insensitive).
func HasAnyTenantRole(roles []string, want ...string) bool {
	for _, r := range roles {
		for _, w := range want {
			if strings.EqualFold(strings.TrimSpace(r), strings.TrimSpace(w)) {
				return true
			}
		}
	}
	return false
}
