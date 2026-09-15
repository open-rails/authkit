package embedded

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

	// A repeated manifest cannot appoint another owner while one exists; the
	// same workflow can recover an explicitly emptied owner assignment set.
	recovery := BootstrapManifest{Users: []BootstrapManifestUser{{Username: "recovery-owner", Email: "recovery@example.test", RootRole: string(OwnerRoleName)}}}
	_, err = svc.ApplyBootstrapManifest(ctx, recovery, BootstrapReconcileOptions{})
	require.NoError(t, err)
	recoveryUser, err := svc.GetUserByUsername(ctx, "recovery-owner")
	require.NoError(t, err)
	roles, err = svc.RoleSlugsByUsers(ctx, []string{recoveryUser.ID})
	require.NoError(t, err)
	require.NotContains(t, roles[recoveryUser.ID], string(OwnerRoleName))
	require.ErrorIs(t, svc.UnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(user.ID), OwnerRoleName), ErrCannotRemoveLastAdminRole)
	// Only explicit out-of-band database repair can create this recovery state.
	_, err = pg.Pool.Exec(ctx, `DELETE FROM profiles.group_user_roles WHERE user_id=$1::uuid`, user.ID)
	require.NoError(t, err)
	_, err = svc.ApplyBootstrapManifest(ctx, recovery, BootstrapReconcileOptions{})
	require.NoError(t, err)
	roles, err = svc.RoleSlugsByUsers(ctx, []string{recoveryUser.ID})
	require.NoError(t, err)
	require.Contains(t, roles[recoveryUser.ID], string(OwnerRoleName))

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

func TestValidateBootstrapUserPassword(t *testing.T) {
	const phc = "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$YWJjZGVmZ2hpamtsbW5vcA"
	for name, tc := range map[string]struct {
		password BootstrapUserPassword
		valid    bool
	}{
		"plaintext enforcement":      {BootstrapUserPassword{Plaintext: "bootstrap-password-1", Enforce: true}, true},
		"reset flag":                 {BootstrapUserPassword{ResetRequired: true}, true},
		"reset flag enforcement":     {BootstrapUserPassword{ResetRequired: true, Enforce: true}, false},
		"explicit reset state":       {BootstrapUserPassword{Hash: "reset-required", HashAlgo: HashAlgoLegacyResetRequired}, true},
		"explicit reset enforcement": {BootstrapUserPassword{Hash: "reset-required", HashAlgo: HashAlgoLegacyResetRequired, Enforce: true}, false},
		"supported PHC":              {BootstrapUserPassword{Hash: phc, HashAlgo: "argon2id"}, true},
		"unsafe PHC":                 {BootstrapUserPassword{Hash: strings.Replace(phc, "t=1", "t=0", 1), HashAlgo: "argon2id"}, false},
		"unsupported algorithm":      {BootstrapUserPassword{Hash: "opaque", HashAlgo: "md5"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateBootstrapUserPassword(tc.password)
			if tc.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, ErrInvalidBootstrapManifest)
			}
		})
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
