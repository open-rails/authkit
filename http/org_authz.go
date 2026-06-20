package authhttp

import (
	"context"
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// isPrivilegedOrgRole reports whether an org role may perform org management
// (members, roles, invites, API keys). `owner` is the only role authkit
// hardcodes as privileged; any `admin` or finer-grained authority is the
// platform's concern, not authkit's.
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

// requireOrgPermission resolves the org and reports whether the caller holds the
// given permission there — via any role granted it (owner holds `org:*`). This
// is the permission-based gate for org-management endpoints (authkit #46),
// replacing the hardcoded owner check. There is no global-admin bypass (#95).
func (s *Service) requireOrgPermission(ctx context.Context, claims Claims, orgSlug, perm string) (canonical string, allowed bool, err error) {
	org, err := s.svc.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return "", false, err
	}
	canonical = org.Slug
	// #95 disjoint model: org authority is ORG-membership only — there is no
	// global/platform-admin bypass into an org (a platform-admin manages orgs as
	// entities via /admin/orgs/*, never their internals).
	if strings.TrimSpace(claims.UserID) == "" {
		return canonical, false, nil
	}
	ok, err := s.svc.HasPermission(ctx, canonical, claims.UserID, perm)
	if err != nil {
		return canonical, false, err
	}
	return canonical, ok, nil
}

// requireOrgPermissionGin is the gin/handler wrapper: writes the standard error
// responses and returns ok=false when not permitted.
func (s *Service) requireOrgPermissionGin(w http.ResponseWriter, r *http.Request, claims Claims, orgSlug, perm string) (canonical string, ok bool) {
	canonical, allowed, err := s.requireOrgPermission(r.Context(), claims, orgSlug, perm)
	if err != nil {
		if err == core.ErrOrgNotFound {
			notFound(w, "org_not_found")
			return "", false
		}
		serverErr(w, "org_lookup_failed")
		return "", false
	}
	if !allowed {
		forbidden(w, "forbidden")
		return "", false
	}
	return canonical, true
}
