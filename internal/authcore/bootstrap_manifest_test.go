package authcore

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
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	username := fmt.Sprintf("bootstrap-dryrun-%d", time.Now().UnixNano())
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Ref:           "admin",
		Email:         username + "@example.com",
		Username:      username,
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
		RootRoles:     []string{"owner"},
	}}}

	result, err := svc.ReconcileBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry-run reconcile: %v", err)
	}
	if !result.DryRun || result.UsersCreated != 1 || result.PasswordsSet != 1 || result.RootRoleAssignments != 1 {
		t.Fatalf("dry-run result=%+v", result)
	}
	if _, err := svc.getUserByUsername(ctx, username); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("dry-run user lookup err=%v, want no row", err)
	}
}

// #136: the bootstrap apex is seeded as a root permission-group OWNER (root:*),
// seed-if-absent; reconcile is idempotent.
func TestReconcileBootstrapManifestSeedsRootOwner(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	suffix := time.Now().UnixNano()
	username := fmt.Sprintf("bootstrap-admin-%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	manifest := BootstrapManifest{
		Users: []BootstrapManifestUser{{
			Ref:           "admin",
			Email:         username + "@example.com",
			Username:      username,
			EmailVerified: true,
			Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
			RootRoles:     []string{"owner"},
			Metadata:      map[string]any{"source": "bootstrap-test"},
		}},
	}

	first, err := svc.ReconcileBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if first.UsersCreated != 1 || first.UsersUpdated != 0 || first.PasswordsSet != 1 || first.PasswordsKept != 0 || first.RootRoleAssignments != 1 {
		t.Fatalf("first result=%+v", first)
	}

	user, err := svc.getUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("lookup seeded user: %v", err)
	}
	if err := svc.CheckUserPassword(ctx, user.ID, "bootstrap-password-1"); err != nil {
		t.Fatalf("seeded password check: %v", err)
	}
	if roles := svc.ListRoleSlugsByUser(ctx, user.ID); !containsString(roles, OwnerRoleName) {
		t.Fatalf("root roles=%v, want %q", roles, OwnerRoleName)
	}

	second, err := svc.ReconcileBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.UsersCreated != 0 || second.UsersUpdated != 1 || second.PasswordsSet != 0 || second.PasswordsKept != 1 {
		t.Fatalf("second result=%+v", second)
	}
}

func TestReconcileBootstrapManifestOwnerSeedIfAbsentRecovery(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))

	suffix := time.Now().UnixNano()
	existingUsername := fmt.Sprintf("bootstrap-existing-owner-%d", suffix)
	recoveryUsername := fmt.Sprintf("bootstrap-recovery-owner-%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username IN ($1, $2)`, existingUsername, recoveryUsername)
	})

	existing, err := svc.CreateUser(ctx, existingUsername+"@example.com", existingUsername)
	if err != nil {
		t.Fatalf("create existing owner: %v", err)
	}
	if err := svc.AssignGroupRole(ctx, RootPersona, "", existing.ID, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("seed existing owner: %v", err)
	}

	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Ref:           "recovery",
		Email:         recoveryUsername + "@example.com",
		Username:      recoveryUsername,
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
		RootRoles:     []string{OwnerRoleName},
	}}}

	if _, err := svc.ReconcileBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("reconcile with existing owner: %v", err)
	}
	recovery, err := svc.getUserByUsername(ctx, recoveryUsername)
	if err != nil {
		t.Fatalf("lookup recovery user: %v", err)
	}
	if roles, err := svc.ListRoleSlugsByUserErr(ctx, recovery.ID); err != nil {
		t.Fatalf("list recovery roles: %v", err)
	} else if containsString(roles, OwnerRoleName) {
		t.Fatalf("bootstrap should not assign owner while another owner exists; roles=%v", roles)
	}

	if err := svc.UnassignGroupRole(ctx, RootPersona, "", existing.ID, SubjectKindUser, OwnerRoleName); err != nil {
		t.Fatalf("remove existing owner: %v", err)
	}
	if _, err := svc.ReconcileBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("reconcile after zero-owner state: %v", err)
	}
	if roles, err := svc.ListRoleSlugsByUserErr(ctx, recovery.ID); err != nil {
		t.Fatalf("list recovery roles after reseed: %v", err)
	} else if !containsString(roles, OwnerRoleName) {
		t.Fatalf("bootstrap should recover zero-owner state; roles=%v", roles)
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
