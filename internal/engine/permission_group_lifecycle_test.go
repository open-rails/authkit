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

// One real-store workflow covers purge, its rollback, a grant waiting on it,
// and a delete that would strand another group without an owner.
func TestGroupLifecycleWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	config := pg.Pool.Config()
	config.MaxConns = 6
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cfg := maintenanceConfig()
	cfg.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	cfg.Roles = RoleConfig{Personas: map[string]Persona{"org": {Permissions: []string{"org:billing:read", "org:billing:write"}, APIKeys: true}}}
	svc := newTestEngine(t, cfg, Deps{Postgres: pool})
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
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%PermissionGroupForUpdate%'`).Scan(&n)
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
	t.Run("delete_rolls_back_external_owner_loss", func(t *testing.T) {
		controller := create()
		survivorID, err := seedGroup(ctx, svc, ident.Persona("org"), "")
		require.NoError(t, err)
		survivor := iam.GroupByID(survivorID)
		application, err := svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(controller), iam.RemoteApplication{Slug: "retained-app", Issuer: "https://retained-app.example", JWKSURI: "https://retained-app.example/jwks", Mode: iam.RemoteApplicationModeJWKS, Enabled: true})
		require.NoError(t, err)
		// A historical cross-control assignment that the assignment APIs
		// refuse: deleting its controller must not count the departing
		// application as the survivor's owner.
		_, err = pool.Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1::uuid,$2::uuid,'owner')`, survivorID, application.ID)
		require.NoError(t, err)
		require.ErrorIs(t, svc.DeleteGroup(ctx, iam.GroupByID(controller), nil), iam.ErrLastOwner)
		unchanged, err := svc.Group(ctx, iam.GroupByID(controller))
		require.NoError(t, err)
		require.Nil(t, unchanged.DeletedAt, "a refused delete is atomic")
		grantRole(t, svc, survivor, iam.UserSubject(owner.ID), "owner")
		require.NoError(t, svc.DeleteGroup(ctx, iam.GroupByID(controller), nil))
		_, err = svc.GetRemoteApplication(ctx, application.Issuer)
		require.Error(t, err)
		_, err = svc.ResolveRemoteApplicationAuthority(ctx, application.ID)
		require.Error(t, err)
		allowed, err := svc.Can(ctx, iam.RemoteApplicationActor(application.ID), survivor, ident.Perm("org:billing:read"))
		require.NoError(t, err)
		require.False(t, allowed)
		application.Enabled = false
		_, err = svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(application.PermissionGroupID), *application)
		require.ErrorIs(t, err, iam.ErrGroupNotFound, "retained application state cannot be rewritten")
	})
}
