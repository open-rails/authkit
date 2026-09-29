package engine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// One real-store workflow covers purge, its rollback and a grant waiting on it.
func TestGroupLifecycleWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config := pg.Pool.Config()
	config.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://lifecycle.test"}, TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Registration: RegistrationConfig{NativeUserMode: iam.RegistrationModeInviteOnly}, Roles: RoleConfig{
		Personas: map[string]Persona{"org": {Permissions: []string{"org:billing:read", "org:billing:write"}, APIKeys: true}},
	}}, keyset{}, Deps{Postgres: pool})
	_, err = svc.ensureRootGroup(ctx)
	require.NoError(t, err)
	owner, err := svc.createUser(ctx, "owner@lifecycle.test", "lifecycleowner")
	require.NoError(t, err)
	member, err := svc.createUser(ctx, "member@lifecycle.test", "lifecyclemember")
	require.NoError(t, err)
	create := func() string {
		id, err := seedGroup(ctx, svc, ident.Persona("org"), owner.ID)
		require.NoError(t, err)
		return id
	}
	t.Run("purge", func(t *testing.T) {
		group := create()
		require.NoError(t, svc.PurgeGroup(ctx, iam.GroupByID(group), nil))
		require.NoError(t, svc.PurgeGroup(ctx, iam.GroupByID(group), nil)) // captured-ID replay
		var remaining int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM permission_groups WHERE id=$1::uuid`, group).Scan(&remaining))
		require.Zero(t, remaining)
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM group_user_roles WHERE permission_group_id=$1::uuid`, group).Scan(&remaining))
		require.Zero(t, remaining, "authority rows cascade with the group")
	})
	t.Run("purge_rollback_and_concurrent_grant", func(t *testing.T) {
		group := create()
		_, err := pool.Exec(ctx, fmt.Sprintf(`CREATE FUNCTION lifecycle_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected lifecycle failure'; END $$;
  CREATE TRIGGER lifecycle_delete_failure BEFORE DELETE ON permission_groups FOR EACH ROW WHEN (OLD.id='%s'::uuid) EXECUTE FUNCTION lifecycle_delete_failure()`, group))
		require.NoError(t, err)
		require.ErrorContains(t, svc.PurgeGroup(ctx, iam.GroupByID(group), nil), "injected lifecycle failure")
		var owners int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM group_user_roles WHERE permission_group_id=$1::uuid`, group).Scan(&owners))
		require.Equal(t, 1, owners, "the group rolls back with the failed delete")
		_, err = pool.Exec(ctx, `DROP TRIGGER lifecycle_delete_failure ON permission_groups; DROP FUNCTION lifecycle_delete_failure()`)
		require.NoError(t, err)
		blocker, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer blocker.Rollback(ctx)
		_, err = blocker.Exec(ctx, `SELECT id FROM permission_groups WHERE id=$1 FOR KEY SHARE`, group)
		require.NoError(t, err)
		deleted := make(chan error, 1)
		go func() {
			deleted <- svc.PurgeGroup(ctx, iam.GroupByID(group), nil)
		}()
		require.Eventually(t, func() bool {
			var n int
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT persona FROM permission_groups WHERE id=$1::uuid FOR UPDATE%'`).Scan(&n)
			return err == nil && n == 1
		}, 5*time.Second, 10*time.Millisecond)
		granted := make(chan error, 1)
		go func() {
			granted <- assignRole(ctx, svc, iam.UserActor(owner.ID), iam.GroupByID(group), iam.UserSubject(member.ID), "owner")
		}()
		require.Eventually(t, func() bool {
			var n int
			// The grant waits for the authority lock the delete holds.
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND (query LIKE '%permission_groups%' OR query LIKE '%pg_advisory_xact_lock%')`).Scan(&n)
			return err == nil && n == 2
		}, 5*time.Second, 10*time.Millisecond)
		require.NoError(t, blocker.Commit(ctx))
		require.NoError(t, <-deleted)
		require.ErrorIs(t, <-granted, iam.ErrGroupNotFound, "a grant that waited on the delete finds no group")
	})
}
