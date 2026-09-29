package authkit

import (
	"testing"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestClientOperatorRoleOperations(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	runtime := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://admin-client.test"},
		TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Roles: editorRoles()}, keyset{}, Deps{Postgres: pg.Pool})
	client := runtime
	ctx := t.Context()
	user, err := client.CreateUser(ctx, "operator@example.test", "operator")
	require.NoError(t, err)
	subject, group := iam.UserSubject(user.ID), iam.RootGroup()
	canEdit := func(want bool) {
		t.Helper()
		got, err := client.Can(ctx, subject, group, "root:posts:edit")
		require.NoError(t, err)
		require.Equal(t, want, got)
	}
	require.NoError(t, client.OperatorAssignGroupRole(ctx, group, subject, "editor"))
	canEdit(true)
	require.NoError(t, client.OperatorUnassignGroupRole(ctx, group, subject, "editor"))
	canEdit(false)
	require.Error(t, client.OperatorAssignGroupRole(ctx, group, iam.UserSubject(uuid.NewString()), "editor"))
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, subject, "unknown"), iam.ErrRoleNotAssignable)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, group, subject, iam.OwnerRole))
	require.ErrorIs(t, client.OperatorUnassignGroupRole(ctx, group, subject, iam.OwnerRole), iam.ErrCannotRemoveLastAdminRole)
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, subject, "editor"), iam.ErrCannotRemoveLastAdminRole)
	canEdit(true)
	// Host authority does not bypass subject-state MFA requirements.
	runtime.cfg.TwoFactor.Mode = iam.TwoFactorOptional
	mfaRoles := editorRoles()
	mfaRoles.Roles[0].RequiresMFA = true
	runtime.groupSchema, err = mfaRoles.schema()
	require.NoError(t, err)
	other, err := client.CreateUser(ctx, "unenrolled@example.test", "unenrolled")
	require.NoError(t, err)
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, iam.UserSubject(other.ID), "editor"), iam.ErrTwoFAEnrollmentRequired)
}
