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
	"github.com/stretchr/testify/require"
)

func TestBootstrapManifestFormat(t *testing.T) {
	for name, raw := range map[string]string{
		"unknown user field": `users: [{username: bootstrap-admin, surprise: true}]`,
		"rbac schema": `users: [{username: bootstrap-admin}]
rbac: {personas: [{name: root}]}`,
		"user ref":              `users: [{username: bootstrap-admin, ref: operator}]`,
		"root role definitions": `root_roles: [{slug: admin, name: Admin}]`,
		"app mode":              `remote_applications: [{slug: test, issuer: 'https://app.test', jwks_uri: 'https://app.test/keys', enabled: true, mode: jwks}]`,
		"app audiences":         `remote_applications: [{slug: test, issuer: 'https://app.test', jwks_uri: 'https://app.test/keys', enabled: true, audiences: [authkit]}]`,
		"plural root roles":     `users: [{username: bootstrap-admin, root_roles: [owner]}]`,
		"group roles":           `group_roles: [{username: operator, persona: merchant, instance_slug: tensorhub, role: admin}]`,
		"assigned roles":        `assigned_roles: [{user: operator, group: root, role: admin}]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseBootstrapManifestYAML([]byte(raw))
			require.Error(t, err)
		})
	}
	raw, err := os.ReadFile(filepath.Join("..", "bootstrap.example.yaml"))
	require.NoError(t, err)
	_, err = ParseBootstrapManifestYAML(raw)
	require.NoError(t, err)
}

// One real-database workflow owns file loading, dry-run, initial authority,
// repeat names, password seed-once/enforcement, and remote application seeds.
func TestBootstrapWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://bootstrap.test"}}, Keyset{}, WithPostgres(pg.Pool))
	const seeded, rotated = "bootstrap-password-1", "rotated-password-2"
	path := filepath.Join(t.TempDir(), "bootstrap.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`users:
 - username: bootstrap-admin
   email: admin@example.test
   email_verified: true
   root_role: owner
   metadata: {source: bootstrap-test}
   password: {plaintext: bootstrap-password-1}
`), 0600))
	manifest, err := LoadBootstrapManifestFile(path)
	require.NoError(t, err)
	dry, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{DryRun: true})
	require.NoError(t, err)
	require.Equal(t, BootstrapManifestResult{DryRun: true, UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, dry)
	_, err = svc.GetUserByUsername(ctx, "bootstrap-admin")
	require.ErrorIs(t, err, pgx.ErrNoRows)

	first, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{StartupOnly: true, Name: "first"})
	require.NoError(t, err)
	require.Equal(t, BootstrapManifestResult{UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, first)
	user, err := svc.GetUserByUsername(ctx, "bootstrap-admin")
	require.NoError(t, err)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	roles, err := svc.RoleSlugsByUsers(ctx, []string{user.ID})
	require.NoError(t, err)
	require.Contains(t, roles[user.ID], string(OwnerRoleName))
	require.NoError(t, svc.AdminSetPassword(ctx, user.ID, rotated))

	// Neither the original name nor a different name can replay genesis, even
	// when the new manifest asks to enforce a password or create another owner.
	requested := manifest
	requested.Users = append([]BootstrapManifestUser(nil), manifest.Users...)
	requested.Users[0].Password = &BootstrapUserPassword{Plaintext: seeded, Enforce: true}
	requested.Users = append(requested.Users, BootstrapManifestUser{Username: "unexpected-owner", Email: "unexpected@example.test", RootRole: string(OwnerRoleName)})
	for _, name := range []string{"first", "second", "second"} {
		result, err := svc.ApplyBootstrapManifest(ctx, requested, BootstrapReconcileOptions{StartupOnly: true, Name: name})
		require.NoError(t, err)
		require.Equal(t, BootstrapManifestResult{AlreadyApplied: true}, result)
		require.NoError(t, svc.CheckUserPassword(ctx, user.ID, rotated))
	}
	_, err = svc.GetUserByUsername(ctx, "unexpected-owner")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	require.Equal(t, []string{"first", "second"}, bootstrapClaimNames(t, ctx, pg))

	result, err := svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, BootstrapManifestResult{UsersUpdated: 1, PasswordsKept: 1, RootRoleAssignments: 1}, result)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, rotated))
	require.Error(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	manifest.Users[0].Password.Enforce = true
	result, err = svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsSet)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	result, err = svc.ApplyBootstrapManifest(ctx, manifest, BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsKept)

	enabled := true
	app := BootstrapManifestRemoteApplication{Slug: "bootstrap-app", Issuer: "https://app.test", JWKSURI: "https://app.test/keys", Enabled: &enabled, RootRole: string(OwnerRoleName)}
	result, err = svc.ApplyBootstrapManifest(ctx, BootstrapManifest{RemoteApplications: []BootstrapManifestRemoteApplication{app}}, BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, BootstrapManifestResult{RemoteApplications: 1, RemoteAppRootRoles: 1}, result)
	stored, err := svc.GetRemoteApplication(ctx, app.Issuer)
	require.NoError(t, err)
	require.Equal(t, app.Slug, stored.Slug)
	require.Equal(t, app.JWKSURI, stored.JWKSURI)
	require.Equal(t, RemoteAppModeJWKS, stored.Mode)
	require.True(t, stored.Enabled)
	appRoles, err := svc.remoteApplicationRoles(ctx, stored.ID)
	require.NoError(t, err)
	require.Contains(t, appRoles, string(OwnerRoleName))
	authority, err := svc.ResolveRemoteApplicationAuthority(ctx, stored.ID)
	require.NoError(t, err)
	require.Contains(t, authority.Permissions, string(authkit.Persona(RootPersona).OwnerGrant()))
}

func TestValidateBootstrapUserPasswordEnforce(t *testing.T) {
	if err := validateBootstrapUserPassword(BootstrapUserPassword{ResetRequired: true, Enforce: true}); !errors.Is(err, ErrInvalidBootstrapManifest) {
		t.Fatalf("enforce+reset_required err=%v, want ErrInvalidBootstrapManifest", err)
	}
	if err := validateBootstrapUserPassword(BootstrapUserPassword{Plaintext: "bootstrap-password-1", Enforce: true}); err != nil {
		t.Fatalf("enforce+plaintext should be valid, got %v", err)
	}
	if err := validateBootstrapUserPassword(BootstrapUserPassword{ResetRequired: true}); err != nil {
		t.Fatalf("reset_required alone should be valid, got %v", err)
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

func containsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
