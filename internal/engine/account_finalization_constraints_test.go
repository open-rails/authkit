package engine

import (
	"context"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestAccountFinalizationPreservesForeignKeysAndCascadesMemberships(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := maintenanceConfig()
	cfg.Roles = RoleConfig{Roles: []Role{{Persona: "root", Name: "member"}}}
	runtime, err := New(context.Background(), cfg, Deps{Postgres: pg.Pool})
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	client := runtime
	user, err := client.createUser(t.Context(), "finalize-fk@example.test", "finalizefk")
	require.NoError(t, err)
	grantRole(t, client, iam.RootGroup(), iam.UserSubject(user.ID), "member")
	_, err = pg.Pool.Exec(t.Context(), "CREATE TABLE public.host_reference(user_id uuid REFERENCES profiles.users(id))")
	require.NoError(t, err)
	_, err = pg.Pool.Exec(t.Context(), "INSERT INTO public.host_reference VALUES ($1::uuid)", user.ID)
	require.NoError(t, err)
	generation := prepareExpiredDeletion(t, runtime, user.ID)
	require.ErrorIs(t, runtime.finalizeAccountDeletion(t.Context(), generation, true), errmodel.ErrUserReferenced)
	var count int
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid", user.ID).Scan(&count))
	require.Equal(t, 1, count, "failed purge rolls back every cascade")
	_, err = pg.Pool.Exec(t.Context(), "DELETE FROM public.host_reference WHERE user_id=$1::uuid", user.ID)
	require.NoError(t, err)
	require.NoError(t, runtime.finalizeAccountDeletion(t.Context(), generation, true))
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.group_user_roles WHERE user_id=$1::uuid", user.ID).Scan(&count))
	require.Zero(t, count)
	require.NoError(t, pg.Pool.QueryRow(t.Context(), "SELECT count(*) FROM profiles.users WHERE id=$1::uuid", user.ID).Scan(&count))
	require.Zero(t, count)
}
