package engine

import (
	"context"

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
	manifest, err := ParseBootstrapManifestYAML([]byte(`users:
 - username: bootstrap-admin
   email: admin@example.test
   email_verified: true
   root_role: owner
   metadata: {source: bootstrap-test}
   password: {plaintext: bootstrap-password-1}
`))
	require.NoError(t, err)
	dry, err := svc.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{DryRun: true})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{DryRun: true, UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, dry)
	_, err = svc.getUserByUsername(ctx, "bootstrap-admin")
	require.ErrorIs(t, err, pgx.ErrNoRows)

	first, err := svc.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{StartupOnly: true, Name: "first"})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{UsersCreated: 1, PasswordsSet: 1, RootRoleAssignments: 1}, first)
	user, err := svc.getUserByUsername(ctx, "bootstrap-admin")
	require.NoError(t, err)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	roles, err := svc.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(user.ID)})
	require.NoError(t, err)
	require.Equal(t, iam.OwnerRole, roles[iam.UserSubject(user.ID)])
	require.NoError(t, svc.adminSetPassword(ctx, user.ID, rotated))

	// Neither the original name nor a different name can replay genesis, even
	// when the new manifest asks to enforce a password or create another owner.
	requested := manifest
	requested.Users = append([]iam.BootstrapManifestUser(nil), manifest.Users...)
	requested.Users[0].Password = &iam.BootstrapUserPassword{Plaintext: seeded, Enforce: true}
	requested.Users = append(requested.Users, iam.BootstrapManifestUser{Username: "unexpected-owner", Email: "unexpected@example.test", RootRole: iam.OwnerRole})
	for _, name := range []string{"first", "second", "second"} {
		result, err := svc.ApplyBootstrapManifest(ctx, requested, iam.BootstrapOptions{StartupOnly: true, Name: name})
		require.NoError(t, err)
		require.Equal(t, iam.BootstrapResult{AlreadyApplied: true}, result)
		require.NoError(t, svc.CheckUserPassword(ctx, user.ID, rotated))
	}
	_, err = svc.getUserByUsername(ctx, "unexpected-owner")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	require.Equal(t, []string{"first", "second"}, bootstrapClaimNames(t, ctx, pg))

	result, err := svc.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{UsersMatched: 1, PasswordsKept: 1, RootRoleAssignments: 1}, result)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, rotated))
	require.Error(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	manifest.Users[0].Password.Enforce = true
	result, err = svc.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsSet)
	require.NoError(t, svc.CheckUserPassword(ctx, user.ID, seeded))
	result, err = svc.ApplyBootstrapManifest(ctx, manifest, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, result.PasswordsKept)

	// A repeated manifest cannot appoint another owner while one exists.
	recovery := iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: "recovery-owner", Email: "recovery@example.test", EmailVerified: true, RootRole: iam.OwnerRole}}}
	_, err = svc.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.NoError(t, err)
	recoveryUser, err := svc.getUserByUsername(ctx, "recovery-owner")
	require.NoError(t, err)
	roles, err = svc.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(recoveryUser.ID)})
	require.NoError(t, err)
	require.NotEqual(t, iam.OwnerRole, roles[iam.UserSubject(recoveryUser.ID)])
	require.ErrorIs(t, unassignRole(ctx, svc, iam.SystemActor(), iam.RootGroup(), iam.UserSubject(user.ID), iam.OwnerRole), iam.ErrLastOwner)
	// Only explicit out-of-band database repair can empty the owner set. The
	// MFA-required owner role then goes to a new account, which must enroll at
	// its first sign-in; an existing account needs MFA first.
	_, err = pg.Pool.Exec(ctx, `DELETE FROM group_user_roles WHERE user_id=$1::uuid`, user.ID)
	require.NoError(t, err)
	_, err = svc.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	recovery.Users[0] = iam.BootstrapManifestUser{Username: "recovery-owner-2", Email: "recovery2@example.test", EmailVerified: true, RootRole: iam.OwnerRole}
	result, err = svc.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{UsersCreated: 1, RootRoleAssignments: 1}, result)
	recoveryUser, err = svc.getUserByUsername(ctx, "recovery-owner-2")
	require.NoError(t, err)
	roles, err = svc.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(recoveryUser.ID)})
	require.NoError(t, err)
	require.Equal(t, iam.OwnerRole, roles[iam.UserSubject(recoveryUser.ID)])

	enabled := true
	// An application can present no second factor: the MFA-required root
	// owner role is refused for it, like on every other assignment path.
	app := iam.BootstrapManifestRemoteApplication{Slug: "bootstrap-app", Issuer: "https://app.test", JWKSURI: "https://app.test/keys", Enabled: &enabled, RootRole: iam.OwnerRole}
	_, err = svc.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{app}}, iam.BootstrapOptions{})
	require.ErrorIs(t, err, iam.ErrRoleNotAssignable)
	app.RootRole = ""
	result, err = svc.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{RemoteApplications: []iam.BootstrapManifestRemoteApplication{app}}, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{RemoteApplications: 1}, result)
	stored, err := svc.GetRemoteApplication(ctx, app.Issuer)
	require.NoError(t, err)
	require.Equal(t, app.Slug, stored.Slug)
	require.Equal(t, app.JWKSURI, stored.JWKSURI)
	require.Equal(t, iam.RemoteApplicationModeJWKS, stored.Mode)
	require.True(t, stored.Enabled)
	appRoles, err := svc.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.RemoteApplicationSubject(stored.ID)})
	require.NoError(t, err)
	require.Empty(t, appRoles)
}
