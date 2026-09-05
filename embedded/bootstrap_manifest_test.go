package embedded

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
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

func TestParseBootstrapManifestYAMLRejectsRBACSchema(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
rbac:
  personas:
    - name: root
users:
  - username: bootstrap-admin
`))
	if err == nil {
		t.Fatal("expected unknown rbac field error")
	}
}

func TestParseBootstrapManifestYAMLRejectsUserRef(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
users:
  - ref: operator
    username: bootstrap-admin
`))
	if err == nil {
		t.Fatal("expected unknown ref field error")
	}
}

func TestParseBootstrapManifestYAMLRejectsRootRoleDefinitions(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
root_roles:
  - slug: admin
    name: Admin
`))
	if err == nil {
		t.Fatal("expected unknown root_roles field error")
	}
}

func TestParseBootstrapManifestYAMLRejectsRemoteAppMode(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
remote_applications:
  - slug: cozy-creator
    issuer: https://cozy.art
    mode: jwks
    jwks_uri: https://cozy.art/.well-known/jwks.json
    enabled: true
`))
	if err == nil {
		t.Fatal("expected unknown mode field error")
	}
}

func TestParseBootstrapManifestYAMLRejectsRemoteAppAudiences(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
remote_applications:
  - slug: cozy-creator
    issuer: https://cozy.art
    jwks_uri: https://cozy.art/.well-known/jwks.json
    audiences: [authkit]
    enabled: true
`))
	if err == nil {
		t.Fatal("expected unknown audiences field error")
	}
}

func TestParseBootstrapManifestYAMLRejectsPluralUserRootRoles(t *testing.T) {
	_, err := ParseBootstrapManifestYAML([]byte(`
users:
  - username: bootstrap-admin
    root_roles:
      - owner
`))
	if err == nil {
		t.Fatal("expected unknown root_roles field error")
	}
}

func TestParseBootstrapManifestYAMLRejectsGroupRoleFields(t *testing.T) {
	for name, raw := range map[string]string{
		"group_roles": `
group_roles:
  - username: operator
    persona: merchant
    instance_slug: tensorhub
    role: admin
`,
		"assigned_roles": `
assigned_roles:
  - user: operator
    group: root
    role: admin
`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseBootstrapManifestYAML([]byte(raw)); err == nil {
				t.Fatal("expected unknown field error")
			}
		})
	}
}

func TestParseBootstrapManifestExample(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "bootstrap.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseBootstrapManifestYAML(raw); err != nil {
		t.Fatalf("parse example: %v", err)
	}
}

func TestApplyBootstrapManifestDryRunDoesNotMutate(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	username := fmt.Sprintf("bootstrap-dryrun-%d", time.Now().UnixNano())
	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Email:         username + "@example.com",
		Username:      username,
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
		RootRole:      "owner",
	}}}

	result, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{DryRun: true})
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

// The apply-once startup guard needs an empty users/remote-applications table,
// so this test runs on its own scratch database rather than the shared pool.
func TestApplyBootstrapManifestOnceOnlySkipsAfterFirstApply(t *testing.T) {
	pool := testdb.ScratchPostgres(t).Pool
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	username := "bootstrap-once"
	applyName := "bootstrap-once"

	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Email:         username + "@example.com",
		Username:      username,
		EmailVerified: true,
	}}}
	first, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true, Name: applyName})
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	if first.AlreadyApplied || first.UsersCreated != 1 {
		t.Fatalf("first result=%+v, want one created user", first)
	}
	second, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true, Name: applyName})
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if !second.AlreadyApplied || second.UsersCreated != 0 || second.UsersUpdated != 0 {
		t.Fatalf("second result=%+v, want already applied no-op", second)
	}
}

// #136: the bootstrap apex is seeded as a root permission-group OWNER (root:*),
// seed-if-absent; reconcile is idempotent.
func TestApplyBootstrapManifestSeedsRootOwner(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	suffix := time.Now().UnixNano()
	username := fmt.Sprintf("bootstrap-admin-%d", suffix)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	manifest := BootstrapManifest{
		Users: []BootstrapManifestUser{{
			Email:         username + "@example.com",
			Username:      username,
			EmailVerified: true,
			Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
			RootRole:      "owner",
			Metadata:      map[string]any{"source": "bootstrap-test"},
		}},
	}

	first, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
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
	if roles := svc.listRoleSlugsByUser(ctx, user.ID); !containsString(roles, string(OwnerRoleName)) {
		t.Fatalf("root roles=%v, want %q", roles, OwnerRoleName)
	}

	second, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if second.UsersCreated != 0 || second.UsersUpdated != 1 || second.PasswordsSet != 0 || second.PasswordsKept != 1 {
		t.Fatalf("second result=%+v", second)
	}
}

func TestApplyBootstrapManifestSeedsRemoteApplication(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://auth.example"}}, Keyset{}, WithPostgres(pool))

	suffix := time.Now().UnixNano()
	slug := fmt.Sprintf("bootstrap-remote-%d", suffix)
	issuer := fmt.Sprintf("https://remote-%d.example", suffix)
	enabled := true
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	})

	manifest := BootstrapManifest{RemoteApplications: []BootstrapManifestRemoteApplication{{
		Slug:     slug,
		Issuer:   issuer,
		JWKSURI:  issuer + "/.well-known/jwks.json",
		Enabled:  &enabled,
		RootRole: string(OwnerRoleName),
	}}}

	result, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if result.RemoteApplications != 1 || result.RemoteAppRootRoles != 1 {
		t.Fatalf("result=%+v, want one remote application and one role", result)
	}
	got, err := svc.GetRemoteApplication(ctx, issuer)
	if err != nil {
		t.Fatalf("lookup remote application: %v", err)
	}
	if got.Slug != slug || got.Mode != RemoteAppModeJWKS || got.JWKSURI != issuer+"/.well-known/jwks.json" || !got.Enabled {
		t.Fatalf("remote application=%+v", got)
	}
	roles, err := svc.remoteApplicationRoles(ctx, got.ID)
	if err != nil {
		t.Fatalf("remote application roles: %v", err)
	}
	if !containsString(roles, string(OwnerRoleName)) {
		t.Fatalf("remote application roles=%v, want %q", roles, OwnerRoleName)
	}
	authority, err := svc.ResolveRemoteApplicationAuthority(ctx, got.ID)
	if err != nil {
		t.Fatalf("remote application authority: %v", err)
	}
	if !containsString(authority.Permissions, string(authkit.Persona(RootPersona).OwnerGrant())) {
		t.Fatalf("remote application authority=%v, want %q", authority.Permissions, authkit.Persona(RootPersona).OwnerGrant())
	}
}

func TestApplyBootstrapManifestOwnerSeedIfAbsentRecovery(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

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
	if err := svc.AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(existing.ID), OwnerRoleName); err != nil {
		t.Fatalf("seed existing owner: %v", err)
	}

	manifest := BootstrapManifest{Users: []BootstrapManifestUser{{
		Email:         recoveryUsername + "@example.com",
		Username:      recoveryUsername,
		EmailVerified: true,
		Password:      &BootstrapUserPassword{Plaintext: "bootstrap-password-1"},
		RootRole:      string(OwnerRoleName),
	}}}

	if _, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("reconcile with existing owner: %v", err)
	}
	recovery, err := svc.getUserByUsername(ctx, recoveryUsername)
	if err != nil {
		t.Fatalf("lookup recovery user: %v", err)
	}
	if rolesByUser, err := svc.RoleSlugsByUsers(ctx, []string{recovery.ID}); err != nil {
		t.Fatalf("list recovery roles: %v", err)
	} else if containsString(rolesByUser[recovery.ID], string(OwnerRoleName)) {
		t.Fatalf("bootstrap should not assign owner while another owner exists; roles=%v", rolesByUser[recovery.ID])
	}

	if err := svc.UnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(existing.ID), OwnerRoleName); err != nil {
		t.Fatalf("remove existing owner: %v", err)
	}
	if _, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{}); err != nil {
		t.Fatalf("reconcile after zero-owner state: %v", err)
	}
	if rolesByUser, err := svc.RoleSlugsByUsers(ctx, []string{recovery.ID}); err != nil {
		t.Fatalf("list recovery roles after reseed: %v", err)
	} else if !containsString(rolesByUser[recovery.ID], string(OwnerRoleName)) {
		t.Fatalf("bootstrap should recover zero-owner state; roles=%v", rolesByUser[recovery.ID])
	}
}

func TestApplyBootstrapManifestFileLoadsAndAppliesYAML(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	username := fmt.Sprintf("bootstrap-file-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	if err := os.WriteFile(path, []byte(fmt.Sprintf(`
users:
  - email: %[1]s@example.com
    username: %[1]s
    email_verified: true
`, username)), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	manifest, err := LoadBootstrapManifestFile(path)
	if err != nil {
		t.Fatalf("load manifest file: %v", err)
	}
	result, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	if err != nil {
		t.Fatalf("apply file: %v", err)
	}
	if result.UsersCreated != 1 {
		t.Fatalf("users created=%d, want 1", result.UsersCreated)
	}
	if _, err := svc.getUserByUsername(ctx, username); err != nil {
		t.Fatalf("lookup user: %v", err)
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
