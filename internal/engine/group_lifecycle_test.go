package engine

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type lifecycleReadKey struct{}
type lifecycleReadTrace struct{ swap atomic.Pointer[func()] }

func (tr *lifecycleReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "WITH targets AS") || strings.Contains(data.SQL, "WHERE k.key_id=") {
		return context.WithValue(ctx, lifecycleReadKey{}, true)
	}
	return ctx
}
func (tr *lifecycleReadTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryEndData) {
	if ctx.Value(lifecycleReadKey{}) == true {
		if fn := tr.swap.Swap(nil); fn != nil {
			(*fn)()
		}
	}
}

// One real-store workflow covers purge, its rollback and a grant waiting on it,
// and role edit/delete/recreate across members, applications, keys and
// deferred grants.
// Controlled query barriers also exercise writer and reader interleavings.
func TestGroupLifecycleWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	trace := &lifecycleReadTrace{}
	config := pg.Pool.Config()
	config.MaxConns = 6 // one controller plus five deliberately blocked writers
	config.ConnConfig.Tracer = trace
	pool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://lifecycle.test"}, TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Registration: RegistrationConfig{NativeUserMode: iam.RegistrationModeInviteOnly}, Roles: RoleConfig{
		Personas: map[string]Persona{"org": {Permissions: []string{"org:billing:read", "org:billing:write"}, CustomRoles: true, APIKeys: true}},
	}}, keyset{}, Deps{Postgres: pool})
	_, err = svc.ensureRootGroup(ctx)
	require.NoError(t, err)
	owner, err := svc.createUser(ctx, "owner@lifecycle.test", "lifecycleowner")
	require.NoError(t, err)
	member, err := svc.createUser(ctx, "member@lifecycle.test", "lifecyclemember")
	require.NoError(t, err)
	create := func() string {
		id, err := seedGroup(ctx, svc, "org", owner.ID)
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
			granted <- assignRole(ctx, svc, iam.UserActor(owner.ID), iam.GroupByID(group), iam.UserSubject(member.ID), iam.OwnerRole)
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

	gid := create()
	group := iam.GroupByID(gid)
	role := iam.Role("auditor")
	define := func(permission string) {
		require.NoError(t, svc.DefineGroupRole(ctx, iam.UserActor(owner.ID), group, iam.CustomRole{Name: role, Permissions: []string{permission}}))
	}
	define("org:billing:read")
	app, err := svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(gid), iam.RemoteApplication{Slug: "lifecycle-app", Issuer: "https://app.lifecycle.test", JWKSURI: "https://app.lifecycle.test/keys", Enabled: true})
	require.NoError(t, err)
	require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.UserSubject(member.ID), role))
	require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.RemoteApplicationSubject(app.ID), role))
	mint := func() string {
		_, token, err := svc.MintAPIKey(ctx, iam.UserActor(owner.ID), group, iam.NewAPIKey{Name: "lifecycle-key", Role: role})
		require.NoError(t, err)
		return token
	}
	token := mint()
	link, err := svc.CreateInviteLink(ctx, iam.UserActor(owner.ID), group, iam.NewInviteLink{Role: role})
	require.NoError(t, err)
	invite, err := svc.CreateAccountInvite(ctx, iam.UserActor(owner.ID), iam.NewAccountInvite{Email: "invitee@lifecycle.test", Group: group, Role: role})
	require.NoError(t, err)
	define("org:billing:write") // deliberate edits still update every holder
	allowed, err := svc.Can(ctx, iam.UserActor(member.ID), group, "org:billing:write")
	require.NoError(t, err)
	require.True(t, allowed)
	resolved, err := svc.ResolveAPIKey(ctx, token)
	require.NoError(t, err)
	require.Contains(t, resolved.Permissions, "org:billing:write")
	_, err = pool.Exec(ctx, `CREATE FUNCTION lifecycle_role_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected role failure'; END $$;
 CREATE TRIGGER lifecycle_role_failure BEFORE DELETE ON group_custom_roles FOR EACH ROW EXECUTE FUNCTION lifecycle_role_failure()`)
	require.NoError(t, err)
	require.ErrorContains(t, svc.DeleteGroupRole(ctx, iam.UserActor(owner.ID), group, role), "injected role failure")
	_, err = svc.ResolveAPIKey(ctx, token)
	require.NoError(t, err, "key deletion must roll back with definition deletion")
	_, err = pool.Exec(ctx, `DROP TRIGGER lifecycle_role_failure ON group_custom_roles; DROP FUNCTION lifecycle_role_failure()`)
	require.NoError(t, err)
	require.NoError(t, svc.DeleteGroupRole(ctx, iam.UserActor(owner.ID), group, role))
	define("org:billing:write")
	allowed, err = svc.Can(ctx, iam.UserActor(member.ID), group, "org:billing:write")
	require.NoError(t, err)
	require.False(t, allowed)
	authority, err := svc.ResolveRemoteApplicationAuthority(ctx, app.ID)
	require.NoError(t, err)
	require.Empty(t, authority.Permissions)
	_, err = svc.ResolveAPIKey(ctx, token)
	require.Error(t, err)
	_, err = svc.RedeemInviteLink(ctx, iam.UserActor(member.ID), link.Code)
	require.Error(t, err)
	require.Error(t, svc.consumeRegistrationInvite(ctx, "invitee@lifecycle.test", member.ID, invite.Code))

	// Deletion/recreation exactly between a first result and any subsequent
	// lookup cannot pair an old credential with replacement permissions.
	for _, reader := range []string{"member", "application", "key"} {
		t.Run("snapshot_"+reader, func(t *testing.T) {
			define("org:billing:read")
			require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.UserSubject(member.ID), role))
			require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.RemoteApplicationSubject(app.ID), role))
			token := mint()
			swap := func() {
				require.NoError(t, svc.DeleteGroupRole(ctx, iam.UserActor(owner.ID), group, role))
				define("org:billing:write")
			}
			trace.swap.Store(&swap)
			switch reader {
			case "member":
				allowed, err := svc.Can(ctx, iam.UserActor(member.ID), group, "org:billing:write")
				require.NoError(t, err)
				require.False(t, allowed)
			case "application":
				authority, err := svc.ResolveRemoteApplicationAuthority(ctx, app.ID)
				require.NoError(t, err)
				require.NotContains(t, authority.Permissions, "org:billing:write")
			case "key":
				resolved, err := svc.ResolveAPIKey(ctx, token)
				if err == nil {
					require.NotContains(t, resolved.Permissions, "org:billing:write")
				}
			}
			require.Nil(t, trace.swap.Load(), "the query boundary must actually fire")
		})
	}

	t.Run("waiting_grants_recheck_deleted_definition", func(t *testing.T) {
		define("org:billing:read")
		controller, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer controller.Rollback(ctx)
		q := controller
		require.NoError(t, svc.lockAuthority(ctx, q))
		require.NoError(t, lockPermissionGroup(ctx, q, gid))
		writers := []func() error{
			func() error {
				return assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.UserSubject(member.ID), role)
			},
			func() error {
				return assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.RemoteApplicationSubject(app.ID), role)
			},
			func() error {
				_, _, err := svc.MintAPIKey(ctx, iam.UserActor(owner.ID), group, iam.NewAPIKey{Name: "waiting", Role: role})
				return err
			},
			func() error {
				_, err := svc.CreateInviteLink(ctx, iam.UserActor(owner.ID), group, iam.NewInviteLink{Role: role})
				return err
			},
			func() error {
				_, err := svc.CreateAccountInvite(ctx, iam.UserActor(owner.ID), iam.NewAccountInvite{Email: "waiting@lifecycle.test", Group: group, Role: role})
				return err
			},
		}
		results := make(chan error, len(writers))
		for _, write := range writers {
			go func() { results <- write() }()
		}
		require.Eventually(t, func() bool {
			var n int
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%'`).Scan(&n)
			return err == nil && n == len(writers)
		}, 5*time.Second, 10*time.Millisecond)
		require.NoError(t, svc.groupStoreFor(q).DeleteCustomRole(ctx, gid, role))
		require.NoError(t, controller.Commit(ctx))
		for range writers {
			require.Error(t, <-results)
		}
		define("org:billing:write")
		allowed, err := svc.Can(ctx, iam.UserActor(member.ID), group, "org:billing:write")
		require.NoError(t, err)
		require.False(t, allowed)
	})
}
