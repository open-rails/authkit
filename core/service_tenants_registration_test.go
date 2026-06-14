package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCreateTenantForUserCreatesOwnerAtomically(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	slug := fmt.Sprintf("user-owned-%d", time.Now().UnixNano())
	username := fmt.Sprintf("owner-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tenant, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: slug, OwnerUserID: user.ID})
	if err != nil {
		t.Fatalf("CreateTenantForUser: %v", err)
	}
	if tenant.Slug != slug || tenant.OwnerUserID != user.ID {
		t.Fatalf("tenant=%+v", tenant)
	}

	roles, err := svc.ReadMemberRoles(ctx, slug, user.ID)
	if err != nil {
		t.Fatalf("ReadMemberRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != tenantOwnerRole {
		t.Fatalf("roles=%v, want owner", roles)
	}
	perms, err := svc.GetRolePermissions(ctx, slug, tenantOwnerRole)
	if err != nil {
		t.Fatalf("GetRolePermissions: %v", err)
	}
	if len(perms) != 1 || perms[0] != PermWildcard {
		t.Fatalf("owner perms=%v, want *", perms)
	}
	defined, err := svc.ListTenantDefinedRoles(ctx, slug)
	if err != nil {
		t.Fatalf("ListTenantDefinedRoles: %v", err)
	}
	if !stringSliceContains(defined, tenantMemberRole) {
		t.Fatalf("defined roles=%v, want member role", defined)
	}
}

func TestCreateTenantForUserRejectsOwnerlessAndMissingUser(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: "no-owner"}); !errors.Is(err, ErrInvalidTenantOwner) {
		t.Fatalf("ownerless err=%v, want ErrInvalidTenantOwner", err)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{
		Slug: "missing-owner", OwnerUserID: "00000000-0000-0000-0000-000000000001",
	}); !errors.Is(err, ErrInvalidTenantOwner) {
		t.Fatalf("missing owner err=%v, want ErrInvalidTenantOwner", err)
	}
}

func TestCreateTenantForUserRejectsInvalidDuplicateBannedAndDeleted(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("owner-state-%d", time.Now().UnixNano())
	slug := fmt.Sprintf("owner-state-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug IN ($1, $2, $3)`, slug, slug+"-banned", slug+"-deleted")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username IN ($1, $2, $3)`, username, username+"-banned", username+"-deleted")
	})
	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: "-bad", OwnerUserID: user.ID}); !errors.Is(err, ErrInvalidTenantSlug) {
		t.Fatalf("invalid slug err=%v, want ErrInvalidTenantSlug", err)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: slug, OwnerUserID: user.ID}); err != nil {
		t.Fatalf("CreateTenantForUser first: %v", err)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: slug, OwnerUserID: user.ID}); !errors.Is(err, ErrOwnerSlugTaken) {
		t.Fatalf("duplicate slug err=%v, want ErrOwnerSlugTaken", err)
	}

	banned, err := svc.CreateUser(ctx, "", username+"-banned")
	if err != nil {
		t.Fatalf("CreateUser banned: %v", err)
	}
	if err := svc.BanUser(ctx, banned.ID, nil, nil, ""); err != nil {
		t.Fatalf("BanUser: %v", err)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: slug + "-banned", OwnerUserID: banned.ID}); !errors.Is(err, ErrInvalidTenantOwner) {
		t.Fatalf("banned owner err=%v, want ErrInvalidTenantOwner", err)
	}

	deleted, err := svc.CreateUser(ctx, "", username+"-deleted")
	if err != nil {
		t.Fatalf("CreateUser deleted: %v", err)
	}
	if err := svc.SoftDeleteUser(ctx, deleted.ID); err != nil {
		t.Fatalf("SoftDeleteUser: %v", err)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: slug + "-deleted", OwnerUserID: deleted.ID}); !errors.Is(err, ErrInvalidTenantOwner) {
		t.Fatalf("deleted owner err=%v, want ErrInvalidTenantOwner", err)
	}
}

func TestCreateTenantForUserRejectsTenantLimit(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("tenant-limit-owner-%d", time.Now().UnixNano())
	prefix := fmt.Sprintf("tenant-limit-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug LIKE $1`, prefix+"-%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for i := 0; i < maxTenantsPerUser; i++ {
		tenantID, err := newUUIDV7String()
		if err != nil {
			t.Fatalf("newUUIDV7String: %v", err)
		}
		slug := fmt.Sprintf("%s-%03d", prefix, i)
		if _, err := pool.Exec(ctx, `
			WITH tenant AS (
				INSERT INTO profiles.tenants (id, slug, metadata)
				VALUES ($1::uuid, $2, jsonb_build_object('namespace_state', 'registered_tenant', 'reserved', to_jsonb(false)))
				RETURNING id
			), roles AS (
				INSERT INTO profiles.tenant_roles (tenant_id, role)
				SELECT tenant.id, role_name
				FROM tenant
				CROSS JOIN (VALUES ('owner'), ('member')) AS role_defs(role_name)
				RETURNING tenant_id
			)
			INSERT INTO profiles.tenant_memberships (tenant_id, member_id, member_kind, role)
			SELECT tenant.id, $3::uuid, 'user', 'owner'
			FROM tenant
			WHERE (SELECT count(*) FROM roles) = 2
		`, tenantID, slug, user.ID); err != nil {
			t.Fatalf("seed tenant membership %d: %v", i, err)
		}
	}

	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{
		Slug: prefix + "-overflow", OwnerUserID: user.ID,
	}); !errors.Is(err, ErrTenantLimitExceeded) {
		t.Fatalf("tenant limit err=%v, want ErrTenantLimitExceeded", err)
	}
}

func TestCreateTenantForUserRejectsReservedAndParkedNamespace(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("namespace-owner-%d", time.Now().UnixNano())
	reservedSlug := fmt.Sprintf("reserved-tenant-%d", time.Now().UnixNano())
	parkedSlug := fmt.Sprintf("parked-tenant-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug IN ($1, $2)`, reservedSlug, parkedSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.owner_reserved_names WHERE slug IN ($1, $2)`, reservedSlug, parkedSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	restricted, _, err := svc.RestrictOwnerNamespaceSlugs(ctx, []string{reservedSlug})
	if err != nil {
		t.Fatalf("RestrictOwnerNamespaceSlugs: %v", err)
	}
	if len(restricted) != 1 || restricted[0] != reservedSlug {
		t.Fatalf("restricted=%v, want %q", restricted, reservedSlug)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: reservedSlug, OwnerUserID: user.ID}); !errors.Is(err, ErrOwnerSlugTaken) {
		t.Fatalf("reserved slug err=%v, want ErrOwnerSlugTaken", err)
	}

	if _, _, err := svc.ParkTenantNamespace(ctx, parkedSlug); err != nil {
		t.Fatalf("ParkTenantNamespace: %v", err)
	}
	state, err := svc.GetOwnerNamespaceStateBySlug(ctx, parkedSlug)
	if err != nil {
		t.Fatalf("GetOwnerNamespaceStateBySlug: %v", err)
	}
	if state != OwnerNamespaceStateParkedTenant {
		t.Fatalf("state=%q, want %q", state, OwnerNamespaceStateParkedTenant)
	}
	if _, err := svc.CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug: parkedSlug, OwnerUserID: user.ID}); !errors.Is(err, ErrOwnerSlugTaken) {
		t.Fatalf("parked slug err=%v, want ErrOwnerSlugTaken", err)
	}
}

func TestProvisionTenantBypassesPublicRegistrationMode(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{
		Issuer:                 "https://test",
		TenantRegistrationMode: RegistrationModeClosed,
	}, Keyset{}).WithPostgres(pool)

	slug := fmt.Sprintf("bootstrap-%d", time.Now().UnixNano())
	username := fmt.Sprintf("bootstrap-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})
	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	enabled := true
	result, err := svc.ProvisionTenant(ctx, TenantProvisionRequest{
		Slug: slug,
		Issuers: []TenantProvisionIssuer{{
			Issuer: "https://" + slug + ".example", JWKSURI: "https://" + slug + ".example/jwks", Audiences: []string{"openrails"}, Enabled: &enabled,
		}},
		Roles: []TenantProvisionRole{{Name: "admin", Permissions: []string{PermTenantRead}}},
		Memberships: []TenantProvisionMembership{{
			UserID: user.ID, Role: "admin",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("ProvisionTenant: %v", err)
	}
	if !result.Created || result.Issuers != 1 || result.Roles != 1 || result.Memberships != 1 {
		t.Fatalf("result=%+v", result)
	}
	roles, err := svc.ReadMemberRoles(ctx, slug, user.ID)
	if err != nil {
		t.Fatalf("ReadMemberRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("roles=%v, want admin", roles)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
