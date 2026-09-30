package engine

import (
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Only out-of-band database repair can empty the root owner set (the rest of
// the bootstrap workflow is apitest's TestBootstrapWorkflow). Bootstrap then
// appoints the MFA-required owner role again, to a new account, which enrolls
// at its first sign-in; an existing account needs MFA first.
func TestBootstrapRepairsAnEmptyOwnerSet(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	cfg := maintenanceConfig()
	cfg.TwoFactor.Mode = iam.TwoFactorOptional
	svc := newTestEngine(t, cfg, config.Deps{Postgres: pg.Pool})
	owner := iam.RootPersona.OwnerRole()
	_, err := svc.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{
		{Username: "bootstrap-admin", Email: "admin@example.test", EmailVerified: true, RootRole: owner}}}, iam.BootstrapOptions{})
	require.NoError(t, err)
	user, err := svc.getUserByUsername(ctx, "bootstrap-admin")
	require.NoError(t, err)
	recovery := iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: "recovery-owner", Email: "recovery@example.test", EmailVerified: true, RootRole: owner}}}
	_, err = svc.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.NoError(t, err, "the account is created without the role while an owner exists")

	_, err = pg.Pool.Exec(ctx, `DELETE FROM group_user_roles WHERE user_id=$1::uuid`, user.ID)
	require.NoError(t, err)
	_, err = svc.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.ErrorIs(t, err, iam.ErrTwoFAEnrollmentRequired)
	recovery.Users[0] = iam.BootstrapManifestUser{Username: "recovery-owner-2", Email: "recovery2@example.test", EmailVerified: true, RootRole: owner}
	result, err := svc.ApplyBootstrapManifest(ctx, recovery, iam.BootstrapOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.BootstrapResult{UsersCreated: 1, RootRoleAssignments: 1}, result)
	recoveryUser, err := svc.getUserByUsername(ctx, "recovery-owner-2")
	require.NoError(t, err)
	roles, err := svc.GroupRoles(ctx, iam.RootGroup(), []iam.Subject{iam.UserSubject(recoveryUser.ID)})
	require.NoError(t, err)
	require.Equal(t, owner, roles[iam.UserSubject(recoveryUser.ID)])
}
