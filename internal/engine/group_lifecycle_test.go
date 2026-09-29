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
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type lifecycleReadKey struct{}
type lifecycleReadTrace struct{ swap atomic.Pointer[func()] }

func (tr *lifecycleReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "WITH targets AS") || strings.Contains(data.SQL, "FROM api_keys t") {
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

// One real-store workflow covers name reservation/release/rollback and role
// edit/delete/recreate across members, applications, keys and deferred grants.
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
	owner, err := svc.CreateUser(ctx, "owner@lifecycle.test", "lifecycleowner")
	require.NoError(t, err)
	member, err := svc.CreateUser(ctx, "member@lifecycle.test", "lifecyclemember")
	require.NoError(t, err)
	create := func(name string) string {
		id, err := svc.CreatePermissionGroup(ctx, iam.CreatePermissionGroupRequest{Persona: "org", InstanceSlug: name, OwnerSubjectID: owner.ID})
		require.NoError(t, err)
		return id
	}
	for _, release := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete_release_%v", release), func(t *testing.T) {
			name := fmt.Sprintf("group-%v", release)
			group := create(name)
			renamed := name + "-renamed"
			_, err := svc.UpdateGroupInstanceAs(ctx, owner.ID, group, iam.GroupInstanceUpdate{Slug: &renamed})
			require.NoError(t, err)
			var deadline time.Time
			require.NoError(t, pool.QueryRow(ctx, `SELECT expires_at FROM name_claims WHERE owner_id=$1 AND name=$2`, group, name).Scan(&deadline))
			require.NoError(t, svc.DeleteGroupInstanceByID(ctx, group, iam.DeletePermissionGroupOptions{ReleaseSlug: release}))
			require.NoError(t, svc.DeleteGroupInstanceByID(ctx, group, iam.DeletePermissionGroupOptions{ReleaseSlug: release})) // captured-ID replay
			var remaining int
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM permission_groups WHERE id=$1::uuid`, group).Scan(&remaining))
			require.Zero(t, remaining)
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM group_user_roles WHERE permission_group_id=$1::uuid`, group).Scan(&remaining))
			require.Zero(t, remaining, "authority rows cascade with the group")
			available, err := svc.groupStore().InstanceSlugAvailable(ctx, iam.GroupBySlug("org", renamed))
			require.NoError(t, err)
			require.Equal(t, release, available)
			var retained time.Time
			require.NoError(t, pool.QueryRow(ctx, `SELECT expires_at FROM name_claims WHERE owner_id=$1 AND name=$2`, group, name).Scan(&retained))
			require.True(t, deadline.Equal(retained), "old aliases keep their issued deadlines")
		})
	}
	t.Run("delete_rollback_and_concurrent_rename", func(t *testing.T) {
		group := create("fault-group")
		_, err := pool.Exec(ctx, `CREATE FUNCTION lifecycle_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected lifecycle failure'; END $$;
  CREATE TRIGGER lifecycle_delete_failure BEFORE DELETE ON permission_groups FOR EACH ROW WHEN (OLD.instance_slug='fault-group') EXECUTE FUNCTION lifecycle_delete_failure()`)
		require.NoError(t, err)
		require.ErrorContains(t, svc.DeleteGroupInstanceByID(ctx, group, iam.DeletePermissionGroupOptions{}), "injected lifecycle failure")
		var canonical bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT canonical FROM name_claims WHERE owner_id=$1`, group).Scan(&canonical))
		require.True(t, canonical, "reservation rolls back with the failed delete")
		_, err = pool.Exec(ctx, `DROP TRIGGER lifecycle_delete_failure ON permission_groups; DROP FUNCTION lifecycle_delete_failure()`)
		require.NoError(t, err)
		blocker, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer blocker.Rollback(ctx)
		_, err = blocker.Exec(ctx, `SELECT id FROM permission_groups WHERE id=$1 FOR KEY SHARE`, group)
		require.NoError(t, err)
		deleted := make(chan error, 1)
		go func() { deleted <- svc.DeleteGroupInstanceByID(ctx, group, iam.DeletePermissionGroupOptions{}) }()
		require.Eventually(t, func() bool {
			var n int
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%SELECT persona FROM permission_groups WHERE id=$1::uuid FOR UPDATE%'`).Scan(&n)
			return err == nil && n == 1
		}, 5*time.Second, 10*time.Millisecond)
		renamed := make(chan error, 1)
		newName := "fault-group-renamed"
		go func() {
			_, err := svc.UpdateGroupInstanceAs(ctx, owner.ID, group, iam.GroupInstanceUpdate{Slug: &newName})
			renamed <- err
		}()
		require.Eventually(t, func() bool {
			var n int
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%permission_groups%'`).Scan(&n)
			return err == nil && n == 2
		}, 5*time.Second, 10*time.Millisecond)
		require.NoError(t, blocker.Commit(ctx))
		require.NoError(t, <-deleted)
		renameErr := <-renamed
		newAvailable, err := svc.groupStore().InstanceSlugAvailable(ctx, iam.GroupBySlug("org", newName))
		require.NoError(t, err)
		require.Equal(t, renameErr != nil, newAvailable, "a completed concurrent rename must be reserved; a losing rename leaves no claim")
	})

	gid := create("role-lifecycle")
	group := iam.GroupBySlug("org", "role-lifecycle")
	role := iam.Role("auditor")
	define := func(permission string) {
		require.NoError(t, svc.DefineGroupCustomRole(ctx, owner.ID, group, authflow.CustomRoleDef{Role: role, Permissions: []string{permission}}))
	}
	define("org:billing:read")
	app, err := svc.UpsertRemoteApplication(ctx, iam.RemoteApplication{Slug: "lifecycle-app", Issuer: "https://app.lifecycle.test", JWKSURI: "https://app.lifecycle.test/keys", PermissionGroupID: gid, Enabled: true})
	require.NoError(t, err)
	require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.UserSubject(member.ID), role))
	require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.RemoteApplicationSubject(app.ID), role))
	mint := func() (string, string) {
		_, token, err := svc.MintAPIKey(ctx, group, iam.APIKeyMintOptions{Name: "lifecycle-key", Role: role, CreatedBy: owner.ID})
		require.NoError(t, err)
		key, secret, ok := iam.ParseAPIKey(svc.cfg.APIKeys.Prefix, token)
		require.True(t, ok)
		return key, secret
	}
	key, secret := mint()
	link, err := svc.CreateGroupInviteLink(ctx, iam.CreateGroupInviteLinkRequest{Persona: group.Persona(), InstanceSlug: group.Slug(), Role: role, InvitedBy: owner.ID})
	require.NoError(t, err)
	invite, err := svc.CreateAccountRegistrationInvite(ctx, authflow.CreateAccountRegistrationInviteRequest{Email: "invitee@lifecycle.test", Persona: group.Persona(), InstanceSlug: group.Slug(), Role: role, InvitedBy: owner.ID})
	require.NoError(t, err)
	define("org:billing:write") // deliberate edits still update every holder
	allowed, err := svc.Can(ctx, iam.UserSubject(member.ID), group, "org:billing:write")
	require.NoError(t, err)
	require.True(t, allowed)
	resolved, err := svc.ResolveAPIKeyDetailed(ctx, key, secret)
	require.NoError(t, err)
	require.Contains(t, resolved.Permissions, "org:billing:write")
	_, err = pool.Exec(ctx, `CREATE FUNCTION lifecycle_role_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected role failure'; END $$;
 CREATE TRIGGER lifecycle_role_failure BEFORE DELETE ON group_custom_roles FOR EACH ROW EXECUTE FUNCTION lifecycle_role_failure()`)
	require.NoError(t, err)
	require.ErrorContains(t, svc.DeleteGroupCustomRole(ctx, owner.ID, group, role), "injected role failure")
	_, err = svc.ResolveAPIKeyDetailed(ctx, key, secret)
	require.NoError(t, err, "key deletion must roll back with definition deletion")
	_, err = pool.Exec(ctx, `DROP TRIGGER lifecycle_role_failure ON group_custom_roles; DROP FUNCTION lifecycle_role_failure()`)
	require.NoError(t, err)
	require.NoError(t, svc.DeleteGroupCustomRole(ctx, owner.ID, group, role))
	define("org:billing:write")
	allowed, err = svc.Can(ctx, iam.UserSubject(member.ID), group, "org:billing:write")
	require.NoError(t, err)
	require.False(t, allowed)
	authority, err := svc.ResolveRemoteApplicationAuthority(ctx, app.ID)
	require.NoError(t, err)
	require.Empty(t, authority.Permissions)
	_, err = svc.ResolveAPIKeyDetailed(ctx, key, secret)
	require.Error(t, err)
	_, err = svc.RedeemGroupInviteLink(ctx, link.Code, member.ID)
	require.Error(t, err)
	require.Error(t, svc.consumeRegistrationInvite(ctx, "invitee@lifecycle.test", member.ID, invite.Code))

	// Deletion/recreation exactly between a first result and any subsequent
	// lookup cannot pair an old credential with replacement permissions.
	for _, reader := range []string{"member", "application", "key"} {
		t.Run("snapshot_"+reader, func(t *testing.T) {
			define("org:billing:read")
			require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.UserSubject(member.ID), role))
			require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner.ID), group, iam.RemoteApplicationSubject(app.ID), role))
			key, secret := mint()
			swap := func() {
				require.NoError(t, svc.DeleteGroupCustomRole(ctx, owner.ID, group, role))
				define("org:billing:write")
			}
			trace.swap.Store(&swap)
			switch reader {
			case "member":
				allowed, err := svc.Can(ctx, iam.UserSubject(member.ID), group, "org:billing:write")
				require.NoError(t, err)
				require.False(t, allowed)
			case "application":
				authority, err := svc.ResolveRemoteApplicationAuthority(ctx, app.ID)
				require.NoError(t, err)
				require.NotContains(t, authority.Permissions, "org:billing:write")
			case "key":
				resolved, err := svc.ResolveAPIKeyDetailed(ctx, key, secret)
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
				_, _, err := svc.MintAPIKey(ctx, group, iam.APIKeyMintOptions{Name: "waiting", Role: role, CreatedBy: owner.ID})
				return err
			},
			func() error {
				_, err := svc.CreateGroupInviteLink(ctx, iam.CreateGroupInviteLinkRequest{Persona: group.Persona(), InstanceSlug: group.Slug(), Role: role, InvitedBy: owner.ID})
				return err
			},
			func() error {
				_, err := svc.CreateAccountRegistrationInvite(ctx, authflow.CreateAccountRegistrationInviteRequest{Email: "waiting@lifecycle.test", Persona: group.Persona(), InstanceSlug: group.Slug(), Role: role, InvitedBy: owner.ID})
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
		allowed, err := svc.Can(ctx, iam.UserSubject(member.ID), group, "org:billing:write")
		require.NoError(t, err)
		require.False(t, allowed)
	})
}
