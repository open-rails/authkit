package core

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// MemberKindRemoteApplication is the polymorphic org_memberships.member_kind
// for a remote_application principal. MemberKindUser is the user principal.
const (
	MemberKindUser              = "user"
	MemberKindRemoteApplication = "remote_application"
)

// AddRemoteApplicationMember makes a remote_application a member of a org with
// the given role, via the SAME polymorphic org_memberships machinery as
// users. role defaults to 'member'; the role must be defined on the org (or a
// materializable default). appID is the remote_application uuid.
// Deprecated: use s.Identity().AddRemoteApplicationMember.
func (s *Service) AddRemoteApplicationMember(ctx context.Context, orgSlug, appID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return ErrInvalidRemoteApplication
	}
	role = canonicalizeOrgRole(role)
	if err := validateOrgRole(role); err != nil {
		return err
	}
	// Materialize a default-role template the same way user assignment does, so
	// the org_roles row the membership FK requires exists.
	if err := s.materializeDefaultRole(ctx, org.ID, role); err != nil {
		return err
	}
	return s.q.OrgMembershipUpsertRolePrincipal(ctx, db.OrgMembershipUpsertRolePrincipalParams{
		OrgID:      org.ID,
		MemberID:   appID,
		MemberKind: MemberKindRemoteApplication,
		Role:       role,
	})
}

// RemoveRemoteApplicationMember soft-deletes a remote_application's membership in
// a org.
// Deprecated: use s.Identity().RemoveRemoteApplicationMember.
func (s *Service) RemoveRemoteApplicationMember(ctx context.Context, orgSlug, appID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return err
	}
	return s.q.OrgMemberSoftDeletePrincipal(ctx, db.OrgMemberSoftDeletePrincipalParams{
		OrgID:      org.ID,
		MemberID:   strings.TrimSpace(appID),
		MemberKind: MemberKindRemoteApplication,
	})
}

// RemoteApplicationOrgRole returns the role a remote_application holds in a
// org, or ErrNotOrgMember when it holds none.
// Deprecated: use s.Identity().RemoteApplicationOrgRole.
func (s *Service) RemoteApplicationOrgRole(ctx context.Context, orgSlug, appID string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	org, err := s.ResolveOrgBySlug(ctx, orgSlug)
	if err != nil {
		return "", err
	}
	role, err := s.q.OrgMemberRolePrincipal(ctx, db.OrgMemberRolePrincipalParams{
		OrgID:      org.ID,
		MemberID:   strings.TrimSpace(appID),
		MemberKind: MemberKindRemoteApplication,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotOrgMember
	}
	if err != nil {
		return "", err
	}
	return role, nil
}

// RemoteApplicationOrgRoles returns every (org slug, role) the
// remote_application principal holds — the verifier uses this to resolve a
// remote_app's org roles, the same way it would for a user principal.
// Deprecated: use s.Identity().RemoteApplicationOrgRoles.
func (s *Service) RemoteApplicationOrgRoles(ctx context.Context, appID string) ([]OrgMembership, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, ErrInvalidRemoteApplication
	}
	rows, err := s.q.OrgRolesForPrincipal(ctx, db.OrgRolesForPrincipalParams{
		MemberID:   appID,
		MemberKind: MemberKindRemoteApplication,
	})
	if err != nil {
		return nil, err
	}
	// Collapse to one OrgMembership per org with its roles.
	byOrg := map[string]int{}
	var out []OrgMembership
	for _, r := range rows {
		idx, ok := byOrg[r.Slug]
		if !ok {
			out = append(out, OrgMembership{Org: r.Slug})
			idx = len(out) - 1
			byOrg[r.Slug] = idx
		}
		out[idx].Roles = append(out[idx].Roles, r.Role)
	}
	return out, nil
}
