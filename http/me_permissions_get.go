package authhttp

import (
	"net/http"
	"strings"

	core "github.com/open-rails/authkit/core"
)

// handleMePermissionsGET is the "what are my permissions" introspection endpoint
// (#76 amendment): an authenticated principal reads its OWN GRANTED permission set
// — the CEILING — plus its identity/type. A caller uses this to discover its full
// grant before minting a down-scoped self-token (reject-on-over-claim is only
// ergonomic if a caller can look up its grant). For a JWKS-principal self-token it
// returns the STORED grant (direct ∪ role-derived) resolved by principal identity,
// NOT the possibly-narrowed Permissions of the presented token.
func (s *Service) handleMePermissionsGET(w http.ResponseWriter, r *http.Request) {
	claims, ok := ClaimsFromContext(r.Context())
	if !ok {
		unauthorized(w, "unauthorized")
		return
	}
	ctx := r.Context()

	switch {
	case claims.IsRemoteApplication():
		// JWKS principal: return the CEILING resolved by identity, not the
		// narrowed token claim, so the caller can discover its full grant.
		memberships, perms, err := s.svc.ResolveRemoteApplicationAuthority(ctx, claims.RemoteApplicationID)
		if err != nil {
			serverErr(w, "permissions_lookup_failed")
			return
		}
		tenant, roles := firstMembership(memberships)
		writeJSON(w, http.StatusOK, map[string]any{
			"principal_type": "remote_application",
			"id":             claims.RemoteApplicationID,
			"slug":           claims.RemoteApplicationSlug,
			"tenant":         tenant,
			"roles":          roles,
			"permissions":    nonNil(perms),
		})

	case claims.IsService():
		// Service token: stored permissions ride directly on the claims.
		writeJSON(w, http.StatusOK, map[string]any{
			"principal_type": "service",
			"tenant":         claims.Tenant,
			"roles":          nonNil(claims.TenantRoles),
			"permissions":    nonNil(claims.Permissions),
		})

	case strings.TrimSpace(claims.UserID) != "":
		// Native user: resolve effective permissions in the token's tenant.
		perms := claims.Permissions
		if t := strings.TrimSpace(claims.Tenant); t != "" {
			resolved, err := s.svc.EffectivePermissions(ctx, t, claims.UserID)
			if err != nil {
				serverErr(w, "permissions_lookup_failed")
				return
			}
			perms = resolved
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"principal_type": "user",
			"id":             claims.UserID,
			"tenant":         claims.Tenant,
			"roles":          nonNil(claims.TenantRoles),
			"permissions":    nonNil(perms),
		})

	default:
		unauthorized(w, "unauthorized")
	}
}

// firstMembership surfaces a principal's primary tenant + roles (a principal is
// typically a member of one tenant), mirroring resolveRemoteApplicationSelf.
func firstMembership(memberships []core.TenantMembership) (tenant string, roles []string) {
	roles = []string{}
	for _, m := range memberships {
		tenant = m.Tenant
		roles = append(roles, m.Roles...)
		break
	}
	return tenant, roles
}

// nonNil returns a non-nil slice so JSON renders [] not null.
func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
