package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestCreateOrgForUserCreatesOwnerAtomically(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	slug := fmt.Sprintf("user-owned-%d", time.Now().UnixNano())
	username := fmt.Sprintf("owner-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	org, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: slug, OwnerUserID: user.ID})
	if err != nil {
		t.Fatalf("CreateOrgForUser: %v", err)
	}
	if org.Slug != slug || org.OwnerUserID != user.ID {
		t.Fatalf("org=%+v", org)
	}

	roles, err := svc.ReadMemberRoles(ctx, slug, user.ID)
	if err != nil {
		t.Fatalf("ReadMemberRoles: %v", err)
	}
	if len(roles) != 1 || roles[0] != orgOwnerRole {
		t.Fatalf("roles=%v, want owner", roles)
	}
	perms, err := svc.GetRolePermissions(ctx, slug, orgOwnerRole)
	if err != nil {
		t.Fatalf("GetRolePermissions: %v", err)
	}
	if len(perms) != 1 || perms[0] != PermWildcard {
		t.Fatalf("owner perms=%v, want *", perms)
	}
	defined, err := svc.ListOrgDefinedRoles(ctx, slug)
	if err != nil {
		t.Fatalf("ListOrgDefinedRoles: %v", err)
	}
	if !stringSliceContains(defined, orgMemberRole) {
		t.Fatalf("defined roles=%v, want member role", defined)
	}
}

func TestCreateOrgForUserRejectsOwnerlessAndMissingUser(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: "no-owner"}); !errors.Is(err, ErrInvalidOrgOwner) {
		t.Fatalf("ownerless err=%v, want ErrInvalidOrgOwner", err)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{
		Slug: "missing-owner", OwnerUserID: "00000000-0000-0000-0000-000000000001",
	}); !errors.Is(err, ErrInvalidOrgOwner) {
		t.Fatalf("missing owner err=%v, want ErrInvalidOrgOwner", err)
	}
}

func TestCreateOrgForUserRejectsInvalidDuplicateBannedAndDeleted(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("owner-state-%d", time.Now().UnixNano())
	slug := fmt.Sprintf("owner-state-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug IN ($1, $2, $3)`, slug, slug+"-banned", slug+"-deleted")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username IN ($1, $2, $3)`, username, username+"-banned", username+"-deleted")
	})
	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: "-bad", OwnerUserID: user.ID}); !errors.Is(err, ErrInvalidOrgSlug) {
		t.Fatalf("invalid slug err=%v, want ErrInvalidOrgSlug", err)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: slug, OwnerUserID: user.ID}); err != nil {
		t.Fatalf("CreateOrgForUser first: %v", err)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: slug, OwnerUserID: user.ID}); !errors.Is(err, ErrOwnerSlugTaken) {
		t.Fatalf("duplicate slug err=%v, want ErrOwnerSlugTaken", err)
	}

	banned, err := svc.CreateUser(ctx, "", username+"-banned")
	if err != nil {
		t.Fatalf("CreateUser banned: %v", err)
	}
	if err := svc.BanUser(ctx, banned.ID, nil, nil, ""); err != nil {
		t.Fatalf("BanUser: %v", err)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: slug + "-banned", OwnerUserID: banned.ID}); !errors.Is(err, ErrInvalidOrgOwner) {
		t.Fatalf("banned owner err=%v, want ErrInvalidOrgOwner", err)
	}

	deleted, err := svc.CreateUser(ctx, "", username+"-deleted")
	if err != nil {
		t.Fatalf("CreateUser deleted: %v", err)
	}
	if err := svc.SoftDeleteUser(ctx, deleted.ID); err != nil {
		t.Fatalf("SoftDeleteUser: %v", err)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: slug + "-deleted", OwnerUserID: deleted.ID}); !errors.Is(err, ErrInvalidOrgOwner) {
		t.Fatalf("deleted owner err=%v, want ErrInvalidOrgOwner", err)
	}
}

func TestCreateOrgForUserRejectsOrgLimit(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("org-limit-owner-%d", time.Now().UnixNano())
	prefix := fmt.Sprintf("org-limit-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug LIKE $1`, prefix+"-%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for i := 0; i < maxOrgsPerUser; i++ {
		orgID, err := newUUIDV7String()
		if err != nil {
			t.Fatalf("newUUIDV7String: %v", err)
		}
		slug := fmt.Sprintf("%s-%03d", prefix, i)
		if _, err := pool.Exec(ctx, `
			WITH org AS (
				INSERT INTO profiles.orgs (id, slug, metadata)
				VALUES ($1::uuid, $2, jsonb_build_object('namespace_state', 'registered_org', 'reserved', to_jsonb(false)))
				RETURNING id
			), roles AS (
				INSERT INTO profiles.org_roles (org_id, role)
				SELECT org.id, role_name
				FROM org
				CROSS JOIN (VALUES ('owner'), ('member')) AS role_defs(role_name)
				RETURNING org_id
			)
			INSERT INTO profiles.org_memberships (org_id, member_id, member_kind, role)
			SELECT org.id, $3::uuid, 'user', 'owner'
			FROM org
			WHERE (SELECT count(*) FROM roles) = 2
		`, orgID, slug, user.ID); err != nil {
			t.Fatalf("seed org membership %d: %v", i, err)
		}
	}

	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{
		Slug: prefix + "-overflow", OwnerUserID: user.ID,
	}); !errors.Is(err, ErrOrgLimitExceeded) {
		t.Fatalf("org limit err=%v, want ErrOrgLimitExceeded", err)
	}
}

func TestCreateOrgForUserRejectsReservedAndParkedNamespace(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("namespace-owner-%d", time.Now().UnixNano())
	reservedSlug := fmt.Sprintf("reserved-org-%d", time.Now().UnixNano())
	parkedSlug := fmt.Sprintf("parked-org-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug IN ($1, $2)`, reservedSlug, parkedSlug)
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
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: reservedSlug, OwnerUserID: user.ID}); !errors.Is(err, ErrOwnerSlugTaken) {
		t.Fatalf("reserved slug err=%v, want ErrOwnerSlugTaken", err)
	}
	org, err := svc.CreateOrg(ctx, reservedSlug)
	if err != nil {
		t.Fatalf("privileged CreateOrg reserved slug: %v", err)
	}
	if org.Slug != reservedSlug {
		t.Fatalf("created org slug=%q, want %q", org.Slug, reservedSlug)
	}
	state, err := svc.GetOwnerNamespaceStateBySlug(ctx, reservedSlug)
	if err != nil {
		t.Fatalf("GetOwnerNamespaceStateBySlug reserved-created org: %v", err)
	}
	if state != OwnerNamespaceStateRegistered {
		t.Fatalf("reserved-created state=%q, want %q", state, OwnerNamespaceStateRegistered)
	}

	if _, _, err := svc.ParkOrgNamespace(ctx, parkedSlug); err != nil {
		t.Fatalf("ParkOrgNamespace: %v", err)
	}
	state, err = svc.GetOwnerNamespaceStateBySlug(ctx, parkedSlug)
	if err != nil {
		t.Fatalf("GetOwnerNamespaceStateBySlug: %v", err)
	}
	if state != OwnerNamespaceStateParkedOrg {
		t.Fatalf("state=%q, want %q", state, OwnerNamespaceStateParkedOrg)
	}
	if _, err := svc.CreateOrgForUser(ctx, CreateOrgForUserRequest{Slug: parkedSlug, OwnerUserID: user.ID}); !errors.Is(err, ErrOwnerSlugTaken) {
		t.Fatalf("parked slug err=%v, want ErrOwnerSlugTaken", err)
	}
}

func TestProvisionOrgBypassesPublicRegistrationMode(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{
		Issuer:              "https://test",
		OrgRegistrationMode: RegistrationModeClosed,
	}, Keyset{}).WithPostgres(pool)

	slug := fmt.Sprintf("bootstrap-%d", time.Now().UnixNano())
	username := fmt.Sprintf("bootstrap-owner-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})
	user, err := svc.CreateUser(ctx, "", username)
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	enabled := true
	result, err := svc.ProvisionOrg(ctx, OrgProvisionRequest{
		Slug: slug,
		Issuers: []OrgProvisionIssuer{{
			Issuer: "https://" + slug + ".example", JWKSURI: "https://" + slug + ".example/jwks", Audiences: []string{"openrails"}, Enabled: &enabled,
		}},
		Roles: []OrgProvisionRole{{Name: "admin", Permissions: []string{PermOrgRead}}},
		Memberships: []OrgProvisionMembership{{
			UserID: user.ID, Role: "admin",
		}},
	}, nil)
	if err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
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
