package embedded

import (
	"testing"

	"github.com/google/uuid"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestClientOperatorRoleOperations(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	runtime := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://admin-client.test"},
		TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled}, RBAC: []PersonaDef{
			IntrinsicRootPersona(RoleDef{Name: "editor", Permissions: []string{"root:posts:edit"}}),
		}}, Keyset{}, Deps{Postgres: pg.Pool})
	client := runtime.Client()
	ctx := t.Context()
	user, err := client.CreateUser(ctx, "operator@example.test", "operator")
	require.NoError(t, err)
	subject, group := authkit.UserSubject(user.ID), authkit.RootGroup()
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
	require.Error(t, client.OperatorAssignGroupRole(ctx, group, authkit.UserSubject(uuid.NewString()), "editor"))
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, subject, "unknown"), ErrRoleNotAssignable)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, group, subject, authkit.OwnerRole))
	require.ErrorIs(t, client.OperatorUnassignGroupRole(ctx, group, subject, authkit.OwnerRole), ErrCannotRemoveLastAdminRole)
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, subject, "editor"), ErrCannotRemoveLastAdminRole)
	canEdit(true)
	// Host authority does not bypass subject-state MFA requirements.
	runtime.cfg.TwoFactor.Mode = TwoFactorOptional
	runtime.groupSchema, err = BuildSchema(IntrinsicRootPersona(RoleDef{Name: "editor", Permissions: []string{"root:posts:edit"}, RequiresMFA: true}))
	require.NoError(t, err)
	other, err := client.CreateUser(ctx, "unenrolled@example.test", "unenrolled")
	require.NoError(t, err)
	require.ErrorIs(t, client.OperatorAssignGroupRole(ctx, group, authkit.UserSubject(other.ID), "editor"), ErrTwoFAEnrollmentRequired)
}
