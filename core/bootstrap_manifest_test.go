package core

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestParseBootstrapManifestYAMLRejectsUnknownFields(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
users:
  - username: bootstrap-admin
    surprise: true
`))
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestReconcileBootstrapManifestDryRunDoesNotMutate(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	username := fmt.Sprintf("bootstrap-dryrun-%d", time.Now().UnixNano())
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Ref:           "admin",
		Email:         username + "@example.com",
		Username:      username,
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
		GlobalRoles:   []string{"admin"},
	}}}

	result, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run reconcile: %v", err)
	}
	if !result.DryRun || result.UsersCreated != 1 || result.PasswordsSet != 1 || result.GlobalRoleAssignments != 1 {
		t.Fatalf("dry-run result=%+v", result)
	}
	if _, err := svc.getUserByUsername(ctx, username); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("dry-run user lookup err=%v, want no row", err)
	}
}

func TestReconcileBootstrapManifestSeedsUsersRolesAndOrgMemberships(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	suffix := time.Now().UnixNano()
	username := fmt.Sprintf("bootstrap-admin-%d", suffix)
	orgSlug := fmt.Sprintf("bootstrap-org-%d", suffix)
	roleSlug := fmt.Sprintf("bootstrap-role-%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.global_roles WHERE slug=$1`, roleSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	manifest := BootstrapManifest{
		GlobalRoles: []BootstrapManifestGlobalRole{{
			Name: "Bootstrap Role",
			Slug: roleSlug,
		}},
		Users: []BootstrapManifestUser{{
			Ref:           "admin",
			Email:         username + "@example.com",
			Username:      username,
			EmailVerified: true,
			Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
			GlobalRoles:   []string{roleSlug},
			Metadata:      map[string]any{"source": "bootstrap-test"},
		}},
		Orgs: []OrgManifestOrg{{
			Slug: orgSlug,
			Roles: []OrgManifestRole{{
				Name:        "operator",
				Permissions: []string{PermOrgSettingsRead},
			}},
			Memberships: []OrgManifestMembership{{
				UserRef: "admin",
				Role:    "operator",
			}},
		}},
	}

	first, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if first.UsersCreated != 1 || first.UsersUpdated != 0 || first.PasswordsSet != 1 || first.PasswordsKept != 0 || first.GlobalRoles != 1 || first.GlobalRoleAssignments != 1 {
		t.Fatalf("first result=%+v", first)
	}
	if first.OrgManifest.Orgs != 1 || first.OrgManifest.Roles != 1 || first.OrgManifest.Memberships != 1 {
		t.Fatalf("first org result=%+v", first.OrgManifest)
	}

	user, err := svc.getUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("lookup seeded user: %v", err)
	}
	if err := svc.CheckUserPassword(ctx, user.ID, "bootstrap-password-1"); err != nil {
		t.Fatalf("seeded password check: %v", err)
	}
	if roles := svc.ListRoleSlugsByUser(ctx, user.ID); !containsString(roles, roleSlug) {
		t.Fatalf("global roles=%v, want %q", roles, roleSlug)
	}
	if orgRoles, err := svc.ReadMemberRoles(ctx, orgSlug, user.ID); err != nil {
		t.Fatalf("list member roles: %v", err)
	} else if !containsString(orgRoles, "operator") {
		t.Fatalf("org roles=%v, want operator", orgRoles)
	}

	second, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.UsersCreated != 0 || second.UsersUpdated != 1 || second.PasswordsSet != 0 || second.PasswordsKept != 1 {
		t.Fatalf("second result=%+v", second)
	}
}

func TestReconcileBootstrapManifestIdempotentWithPersonalOrgAutoCreate(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{
		Issuer:                 "https://test",
		AutoCreatePersonalOrgs: true,
	}, Keyset{}).WithPostgres(pool)

	suffix := time.Now().UnixNano()
	username := fmt.Sprintf("bootstrap-personal-%d", suffix)
	orgSlug := fmt.Sprintf("bootstrap-personal-org-%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, orgSlug)
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	manifest := BootstrapManifest{
		Users: []BootstrapManifestUser{{
			Ref:           "admin",
			Email:         username + "@example.com",
			Username:      username,
			EmailVerified: true,
			Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
		}},
		Orgs: []OrgManifestOrg{{
			Slug: orgSlug,
			Memberships: []OrgManifestMembership{{
				UserRef: "admin",
				Role:    "owner",
			}},
		}},
	}

	if _, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	second, err := svc.ReconcileBootstrapManifest(ctx, manifest, nil, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.UsersCreated != 0 || second.UsersUpdated != 1 || second.PasswordsKept != 1 {
		t.Fatalf("second result=%+v", second)
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
