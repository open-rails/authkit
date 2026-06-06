package authhttp

import (
	"context"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// isPrivilegedTenantRole reports whether an tenant role may perform tenant management
// (members, roles, invites, service tokens). `owner` is the only role authkit
// hardcodes as privileged; any `admin` or finer-grained authority is the
// platform's concern, not authkit's.
func isPrivilegedTenantRole(role string) bool {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "owner":
		return true
	default:
		return false
	}
}

func (s *Service) requireTenantMember(ctx context.Context, userID, tenantSlug string) (canonicalTenant string, ok bool, err error) {
	tenant, err := s.svc.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return "", false, err
	}
	canonicalTenant = tenant.Slug
	member, err := s.svc.IsTenantMember(ctx, canonicalTenant, userID)
	if err != nil {
		return canonicalTenant, false, err
	}
	return canonicalTenant, member, nil
}

func (s *Service) requireTenantOwner(ctx context.Context, userID, tenantSlug string) (canonicalTenant string, roles []string, ok bool, err error) {
	tenant, err := s.svc.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return "", nil, false, err
	}
	canonicalTenant = tenant.Slug
	member, err := s.svc.IsTenantMember(ctx, canonicalTenant, userID)
	if err != nil || !member {
		return canonicalTenant, nil, false, err
	}
	roles, err = s.svc.ReadMemberRoles(ctx, canonicalTenant, userID)
	if err != nil {
		return canonicalTenant, nil, false, err
	}
	for _, r := range roles {
		if isPrivilegedTenantRole(r) {
			return canonicalTenant, roles, true, nil
		}
	}
	return canonicalTenant, roles, false, nil
}

// requireTenantPermission resolves the tenant and reports whether the caller holds the
// given permission there — via any role granted it (owner holds `*`), or a
// platform global-admin bypass. This is the permission-based gate for
// tenant-management endpoints (authkit #46), replacing the hardcoded owner check.
func (s *Service) requireTenantPermission(ctx context.Context, claims Claims, tenantSlug, perm string) (canonical string, allowed bool, err error) {
	tenant, err := s.svc.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return "", false, err
	}
	canonical = tenant.Slug
	if claimsHasGlobalAdmin(claims) {
		return canonical, true, nil
	}
	if strings.TrimSpace(claims.UserID) == "" {
		return canonical, false, nil
	}
	ok, err := s.svc.HasPermission(ctx, canonical, claims.UserID, perm)
	if err != nil {
		return canonical, false, err
	}
	return canonical, ok, nil
}

// requireTenantPermissionGin is the gin/handler wrapper: writes the standard error
// responses and returns ok=false when not permitted.
func (s *Service) requireTenantPermissionGin(w http.ResponseWriter, r *http.Request, claims Claims, tenantSlug, perm string) (canonical string, ok bool) {
	canonical, allowed, err := s.requireTenantPermission(r.Context(), claims, tenantSlug, perm)
	if err != nil {
		if err == core.ErrTenantNotFound {
			notFound(w, "tenant_not_found")
			return "", false
		}
		serverErr(w, "tenant_lookup_failed")
		return "", false
	}
	if !allowed {
		forbidden(w, "forbidden")
		return "", false
	}
	return canonical, true
}
