package core

import (
	"context"
	"strings"

	"github.com/open-rails/authkit/internal/db"
)

// Direct-permission grants for a JWKS principal (#76). A remote_application's
// STORED authority is the union of these direct permissions and the permissions
// its assigned org roles expand to (RemoteApplicationOrgRoles ->
// org_role_permissions). Mirrors API-key permission storage: authority is what
// WE ASSIGNED, never what a self-signed token claims.

// AddRemoteApplicationPermission grants a direct permission to a
// remote_application. Idempotent (re-granting the same permission is a no-op).
func (s *Service) AddRemoteApplicationPermission(ctx context.Context, appID, permission string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	appID = strings.TrimSpace(appID)
	permission = strings.TrimSpace(permission)
	if appID == "" {
		return ErrInvalidRemoteApplication
	}
	if permission == "" {
		return ErrUnknownPermission
	}
	return s.q.RemoteApplicationPermissionInsert(ctx, db.RemoteApplicationPermissionInsertParams{
		RemoteApplicationID: appID,
		Permission:          permission,
	})
}

// RemoveRemoteApplicationPermission revokes a direct permission. Returns false
// when no such grant existed.
func (s *Service) RemoveRemoteApplicationPermission(ctx context.Context, appID, permission string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return false, ErrInvalidRemoteApplication
	}
	n, err := s.q.RemoteApplicationPermissionDelete(ctx, db.RemoteApplicationPermissionDeleteParams{
		RemoteApplicationID: appID,
		Permission:          strings.TrimSpace(permission),
	})
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListRemoteApplicationPermissions returns the direct permissions assigned to a
// remote_application (NOT including role-derived ones).
func (s *Service) ListRemoteApplicationPermissions(ctx context.Context, appID string) ([]string, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, ErrInvalidRemoteApplication
	}
	perms, err := s.q.RemoteApplicationPermissions(ctx, appID)
	if err != nil {
		return nil, err
	}
	if perms == nil {
		perms = []string{}
	}
	return perms, nil
}

// ResolveRemoteApplicationAuthority returns a JWKS principal's STORED authority:
// its org memberships (each a org slug + role names) and the effective
// permission set — the union of its DIRECT permissions and the permissions its
// org roles expand to against the catalog. This is the verifier's source of
// truth for "what may this remote_application do AS ITSELF" (#76); self-claimed
// authority on the token is ignored.
func (s *Service) ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (memberships []OrgMembership, permissions []string, err error) {
	if err := s.requirePG(); err != nil {
		return nil, nil, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, nil, ErrInvalidRemoteApplication
	}
	memberships, err = s.RemoteApplicationOrgRoles(ctx, appID)
	if err != nil {
		return nil, nil, err
	}
	catalog := s.knownPermissions()
	eff := map[string]bool{}
	for _, m := range memberships {
		for _, role := range m.Roles {
			toks, terr := s.GetRolePermissions(ctx, m.Org, role)
			if terr != nil {
				return nil, nil, terr
			}
			for p := range effectivePermsForTokens(toks, catalog) {
				eff[p] = true
			}
		}
	}
	direct, err := s.ListRemoteApplicationPermissions(ctx, appID)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range direct {
		eff[p] = true
	}
	return memberships, sortedKeys(eff), nil
}
