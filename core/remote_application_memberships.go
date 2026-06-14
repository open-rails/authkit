package core

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// MemberKindRemoteApplication is the polymorphic tenant_memberships.member_kind
// for a remote_application principal. MemberKindUser is the user principal.
const (
	MemberKindUser              = "user"
	MemberKindRemoteApplication = "remote_application"
)

// AddRemoteApplicationMember makes a remote_application a member of a tenant with
// the given role, via the SAME polymorphic tenant_memberships machinery as
// users. role defaults to 'member'; the role must be defined on the tenant (or a
// materializable default). appID is the remote_application uuid.
func (s *Service) AddRemoteApplicationMember(ctx context.Context, tenantSlug, appID, role string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return ErrInvalidRemoteApplication
	}
	role = canonicalizeTenantRole(role)
	if err := validateTenantRole(role); err != nil {
		return err
	}
	// Materialize a default-role template the same way user assignment does, so
	// the tenant_roles row the membership FK requires exists.
	if err := s.materializeDefaultRole(ctx, tenant.ID, role); err != nil {
		return err
	}
	return s.q.TenantMembershipUpsertRolePrincipal(ctx, db.TenantMembershipUpsertRolePrincipalParams{
		TenantID:   tenant.ID,
		MemberID:   appID,
		MemberKind: MemberKindRemoteApplication,
		Role:       role,
	})
}

// RemoveRemoteApplicationMember soft-deletes a remote_application's membership in
// a tenant.
func (s *Service) RemoveRemoteApplicationMember(ctx context.Context, tenantSlug, appID string) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return err
	}
	return s.q.TenantMemberSoftDeletePrincipal(ctx, db.TenantMemberSoftDeletePrincipalParams{
		TenantID:   tenant.ID,
		MemberID:   strings.TrimSpace(appID),
		MemberKind: MemberKindRemoteApplication,
	})
}

// RemoteApplicationTenantRole returns the role a remote_application holds in a
// tenant, or ErrNotTenantMember when it holds none.
func (s *Service) RemoteApplicationTenantRole(ctx context.Context, tenantSlug, appID string) (string, error) {
	if err := s.requirePG(); err != nil {
		return "", err
	}
	tenant, err := s.ResolveTenantBySlug(ctx, tenantSlug)
	if err != nil {
		return "", err
	}
	role, err := s.q.TenantMemberRolePrincipal(ctx, db.TenantMemberRolePrincipalParams{
		TenantID:   tenant.ID,
		MemberID:   strings.TrimSpace(appID),
		MemberKind: MemberKindRemoteApplication,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotTenantMember
	}
	if err != nil {
		return "", err
	}
	return role, nil
}

// RemoteApplicationTenantRoles returns every (tenant slug, role) the
// remote_application principal holds — the verifier uses this to resolve a
// remote_app's tenant roles, the same way it would for a user principal.
func (s *Service) RemoteApplicationTenantRoles(ctx context.Context, appID string) ([]TenantMembership, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	appID = strings.TrimSpace(appID)
	if appID == "" {
		return nil, ErrInvalidRemoteApplication
	}
	rows, err := s.q.TenantRolesForPrincipal(ctx, db.TenantRolesForPrincipalParams{
		MemberID:   appID,
		MemberKind: MemberKindRemoteApplication,
	})
	if err != nil {
		return nil, err
	}
	// Collapse to one TenantMembership per tenant with its roles.
	byTenant := map[string]int{}
	var out []TenantMembership
	for _, r := range rows {
		idx, ok := byTenant[r.Slug]
		if !ok {
			out = append(out, TenantMembership{Tenant: r.Slug})
			idx = len(out) - 1
			byTenant[r.Slug] = idx
		}
		out[idx].Roles = append(out[idx].Roles, r.Role)
	}
	return out, nil
}
