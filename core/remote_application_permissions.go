package core

import (
	"context"
	"strings"
)

// A remote_application's STORED authority is derived ENTIRELY from its org role
// membership (#95). There is no direct per-application permission list — a
// remote_application gets its permissions ONLY via org role membership
// (RemoteApplicationOrgRoles -> org_role_permissions). Authority is what WE
// ASSIGNED via roles, never what a role claims in a token assert.

// ResolveRemoteApplicationAuthority returns a remote application's STORED
// authority: its org memberships (each a org slug + role names) and the
// effective permission set — the permissions its org roles expand to against
// the catalog. This is the verifier's source of truth for "what may this
// remote_application do AS ITSELF" (#76/#95); role claims in the token are
// ignored.
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
	for _, d := range BasePlatformPermissions() {
		catalog[d.Name] = true
	}
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
	return memberships, sortedKeys(eff), nil
}
