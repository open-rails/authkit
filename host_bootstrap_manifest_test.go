package authkit

import (
	"context"
	"os"
	"path/filepath"

	"github.com/jackc/pgx/v5"

	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// One real-database workflow owns file loading, dry-run, initial authority,
// repeat names, password seed-once/enforcement, and remote application seeds.
func TestBootstrapWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := context.Background()
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://bootstrap.test"}}, keyset{}, Deps{Postgres: pg.Pool})
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
	dry, err := svc.OperatorApplyBootstrapManifest(ctx, manifest, iam.BootstrapReconcileOptions{DryRun: true})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapManifestResult{DryRun: true, UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, dry)
	_, err = svc.GetUserByUsername(ctx, "bootstrap-admin")
	require.ErrorIs(t, err, pgx.ErrNoRows)

	first, err := svc.OperatorApplyBootstrapManifest(ctx, manifest, iam.BootstrapReconcileOptions{StartupOnly: true, Name: "first"})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapManifestResult{UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, first)
	user, err := svc.GetUserByUsername(ctx, "bootstrap-admin")
	require.NoError(t, err)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	roles, err := svc.RoleSlugsByUsers(ctx, []string{user.ID})
	require.NoError(t, err)
	require.Contains(t, roles[user.ID], string(iam.OwnerRole))
	require.NoError(t, svc.AdminSetPassword(ctx, user.ID, rotated))

	// Neither the original name nor a different name can replay genesis, even
	// when the new manifest asks to enforce a password or create another owner.
	requested := manifest
	requested.Users = append([]iam.BootstrapManifestUser(nil), manifest.Users...)
	requested.Users[0].Password = &iam.BootstrapUserPassword{Plaintext: seeded, Enforce: true}
	requested.Users = append(requested.Users, iam.BootstrapManifestUser{Username: "unexpected-owner", Email: "unexpected@example.test", RootRole: string(iam.OwnerRole)})
	for _, name := range []string{"first", "second", "second"} {
		result, err := svc.OperatorApplyBootstrapManifest(ctx, requested, iam.BootstrapReconcileOptions{StartupOnly: true, Name: name})
		require.NoError(t, err)
		require.Equal(t, iam.BootstrapManifestResult{AlreadyApplied: true}, result)
		require.NoError(t, svc.CheckUserPassword(ctx, user.ID, rotated))
	}
	_, err = svc.GetUserByUsername(ctx, "unexpected-owner")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	require.Equal(t, []string{"first", "second"}, bootstrapClaimNames(t, ctx, pg))

	result, err := svc.OperatorApplyBootstrapManifest(ctx, manifest, iam.BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapManifestResult{UsersUpdated: 1, PasswordsKept: 1, RootRoleAssignments: 1}, result)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, rotated))
	require.Error(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	manifest.Users[0].Password.Enforce = true
	result, err = svc.OperatorApplyBootstrapManifest(ctx, manifest, iam.BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsSet)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	result, err = svc.OperatorApplyBootstrapManifest(ctx, manifest, iam.BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsKept)

	// A repeated manifest cannot appoint another owner while one exists; the
	// same workflow can recover an explicitly emptied owner assignment set.
	recovery := iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: "recovery-owner", Email: "recovery@example.test", RootRole: string(iam.OwnerRole)}}}
	_, err = svc.OperatorApplyBootstrapManifest(ctx, recovery, iam.BootstrapReconcileOptions{})
	require.NoError(t, err)
	recoveryUser, err := svc.GetUserByUsername(ctx, "recovery-owner")
	require.NoError(t, err)
	roles, err = svc.RoleSlugsByUsers(ctx, []string{recoveryUser.ID})
	require.NoError(t, err)
	require.NotContains(t, roles[recoveryUser.ID], string(iam.OwnerRole))
	require.ErrorIs(t, svc.UnassignGroupRole(ctx, iam.RootGroup(), iam.UserSubject(user.ID), iam.OwnerRole), iam.ErrCannotRemoveLastAdminRole)
	// Only explicit out-of-band database repair can create this recovery state.
	_, err = pg.Pool.Exec(ctx, `DELETE FROM group_user_roles WHERE user_id=$1::uuid`, user.ID)
	require.NoError(t, err)
	_, err = svc.OperatorApplyBootstrapManifest(ctx, recovery, iam.BootstrapReconcileOptions{})
	require.NoError(t, err)
	roles, err = svc.RoleSlugsByUsers(ctx, []string{recoveryUser.ID})
	require.NoError(t, err)
	require.Contains(t, roles[recoveryUser.ID], string(iam.OwnerRole))

	enabled := true
	app := iam.BootstrapManifestRemoteApplication{Slug: "bootstrap-app", Issuer: "https://app.test", JWKSURI: "https://app.test/keys", Enabled: &enabled, RootRole: string(iam.OwnerRole)}
	result, err = svc.OperatorApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{app}}, iam.BootstrapReconcileOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapManifestResult{RemoteApplications: 1, RemoteAppRootRoles: 1}, result)
	stored, err := svc.GetRemoteApplication(ctx, app.Issuer)
	require.NoError(t, err)
	require.Equal(t, app.Slug, stored.Slug)
	require.Equal(t, app.JWKSURI, stored.JWKSURI)
	require.Equal(t, iam.RemoteAppModeJWKS, stored.Mode)
	require.True(t, stored.Enabled)
	appRoles, err := svc.remoteApplicationRoles(ctx, stored.ID)
	require.NoError(t, err)
	require.Contains(t, appRoles, string(iam.OwnerRole))
	authority, err := svc.ResolveRemoteApplicationAuthority(ctx, stored.ID)
	require.NoError(t, err)
	require.Contains(t, authority.Permissions, string(iam.Persona(iam.RootPersona).OwnerGrant()))
}
