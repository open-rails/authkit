package embedded

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type lifecycleReadKey struct{}
type lifecycleReadTrace struct{ swap atomic.Pointer[func()] }

func (tr *lifecycleReadTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "WITH RECURSIVE chain AS") || strings.Contains(data.SQL, "FROM api_keys t") {
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

// One real-store workflow covers subtree reservation/release/rollback and role
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
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://lifecycle.test"}, TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled}, Registration: RegistrationConfig{NativeUserMode: RegistrationModeInviteOnly}, RBAC: []PersonaDef{
		{Name: "org", Parent: RootPersona, Capabilities: PersonaCapabilities{CustomRoles: true, APIKeys: true}, Catalog: []string{"org:billing:read", "org:billing:write"}},
		{Name: "repo", Parent: "org"}, {Name: "leaf", Parent: "repo"},
	}}, Keyset{}, WithPostgres(pool))
	require.NoError(t, svc.SeedPermissionGroupContainment(ctx))
	_, err = svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	owner, err := svc.CreateUser(ctx, "owner@lifecycle.test", "lifecycleowner")
	require.NoError(t, err)
	member, err := svc.CreateUser(ctx, "member@lifecycle.test", "lifecyclemember")
	require.NoError(t, err)
	create := func(persona, name, parent string) string {
		id, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: authkit.Persona(persona), InstanceSlug: name, ParentInstanceSlug: parent, OwnerSubjectID: owner.ID})
		require.NoError(t, err)
		return id
	}
	for _, release := range []bool{false, true} {
		t.Run(fmt.Sprintf("subtree_release_%v", release), func(t *testing.T) {
			parentName := fmt.Sprintf("parent-%v", release)
			childName := fmt.Sprintf("child-%v", release)
			leafName := fmt.Sprintf("leaf-%v", release)
			parent := create("org", parentName, "")
			child := create("repo", childName, parentName)
			leaf := create("leaf", leafName, childName)
			renamed := childName + "-renamed"
			_, err := svc.UpdateGroupInstanceAs(ctx, owner.ID, child, authkit.GroupInstanceUpdate{Slug: &renamed})
			require.NoError(t, err)
			var deadline time.Time
			require.NoError(t, pool.QueryRow(ctx, `SELECT expires_at FROM name_claims WHERE owner_id=$1 AND name=$2`, child, childName).Scan(&deadline))
			require.NoError(t, svc.DeleteGroupInstanceByID(ctx, parent, DeletePermissionGroupOptions{ReleaseSlug: release}))
			require.NoError(t, svc.DeleteGroupInstanceByID(ctx, parent, DeletePermissionGroupOptions{ReleaseSlug: release})) // captured-ID replay
			var remaining int
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM permission_groups WHERE id=ANY($1::uuid[])`, []string{parent, child, leaf}).Scan(&remaining))
			require.Zero(t, remaining)
			require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM group_user_roles WHERE permission_group_id=ANY($1::uuid[])`, []string{parent, child, leaf}).Scan(&remaining))
			require.Zero(t, remaining, "descendant authority rows cascade with the subtree")
			for _, ref := range []authkit.GroupRef{{Persona: "org", Instance: parentName}, {Persona: "repo", Instance: renamed}, {Persona: "leaf", Instance: leafName}} {
				available, err := svc.groupStore().InstanceSlugAvailable(ctx, ref)
				require.NoError(t, err)
				require.Equal(t, release, available)
			}
			var retained time.Time
			require.NoError(t, pool.QueryRow(ctx, `SELECT expires_at FROM name_claims WHERE owner_id=$1 AND name=$2`, child, childName).Scan(&retained))
			require.True(t, deadline.Equal(retained), "old aliases keep their issued deadlines")
		})
	}
	t.Run("subtree_rollback_and_late_descendant", func(t *testing.T) {
		parent := create("org", "fault-parent", "")
		child := create("repo", "fault-child", "fault-parent")
		_, err := pool.Exec(ctx, `CREATE FUNCTION lifecycle_delete_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected lifecycle failure'; END $$;
  CREATE TRIGGER lifecycle_delete_failure BEFORE DELETE ON permission_groups FOR EACH ROW WHEN (OLD.instance_slug='fault-child') EXECUTE FUNCTION lifecycle_delete_failure()`)
		require.NoError(t, err)
		require.ErrorContains(t, svc.DeleteGroupInstanceByID(ctx, parent, DeletePermissionGroupOptions{}), "injected lifecycle failure")
		var canonical bool
		require.NoError(t, pool.QueryRow(ctx, `SELECT canonical FROM name_claims WHERE owner_id=$1`, child).Scan(&canonical))
		require.True(t, canonical, "reservation rolls back with the failed cascade")
		_, err = pool.Exec(ctx, `DROP TRIGGER lifecycle_delete_failure ON permission_groups; DROP FUNCTION lifecycle_delete_failure()`)
		require.NoError(t, err)
		blocker, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer blocker.Rollback(ctx)
		_, err = blocker.Exec(ctx, `SELECT id FROM permission_groups WHERE id=$1 FOR KEY SHARE`, child)
		require.NoError(t, err)
		deleted := make(chan error, 1)
		go func() { deleted <- svc.DeleteGroupInstanceByID(ctx, parent, DeletePermissionGroupOptions{}) }()
		require.Eventually(t, func() bool {
			var n int
			err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%WHERE parent_id=ANY%'`).Scan(&n)
			return err == nil && n == 1
		}, 5*time.Second, 10*time.Millisecond)
		// FK KEY SHARE is compatible with the blocker, so this descendant commits
		// after deletion began but before the child row can be locked/traversed.
		// Public creation queues behind the authority lock. This direct store
		// insertion still exercises the subtree traversal's FK race boundary.
		_, err = svc.groupStore().CreateGroup(ctx, authkit.GroupRef{Persona: "leaf", Instance: "late-leaf"}, child)
		require.NoError(t, err)
		renamed := make(chan error, 1)
		newName := "fault-child-renamed"
		go func() {
			_, err := svc.UpdateGroupInstanceAs(ctx, owner.ID, child, authkit.GroupInstanceUpdate{Slug: &newName})
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
		newAvailable, err := svc.groupStore().InstanceSlugAvailable(ctx, authkit.GroupRef{Persona: "repo", Instance: newName})
		require.NoError(t, err)
		require.Equal(t, renameErr != nil, newAvailable, "a completed concurrent rename must be reserved; a losing rename leaves no claim")
		available, err := svc.groupStore().InstanceSlugAvailable(ctx, authkit.GroupRef{Persona: "leaf", Instance: "late-leaf"})
		require.NoError(t, err)
		require.False(t, available, "late committed descendants must be reserved too")
	})

	gid := create("org", "role-lifecycle", "")
	group := authkit.GroupRef{Persona: "org", Instance: "role-lifecycle"}
	role := authkit.Role("auditor")
	define := func(permission string) {
		require.NoError(t, svc.DefineGroupCustomRole(ctx, owner.ID, group, authkit.CustomRoleDef{Role: role, Permissions: []string{permission}}))
	}
	define("org:billing:read")
	app, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: "lifecycle-app", Issuer: "https://app.lifecycle.test", JWKSURI: "https://app.lifecycle.test/keys", PermissionGroupID: gid, Enabled: true})
	require.NoError(t, err)
	require.NoError(t, svc.AssignGroupRoleAs(ctx, owner.ID, group, authkit.UserSubject(member.ID), role))
	require.NoError(t, svc.AssignRemoteApplicationRoleAs(ctx, owner.ID, group, app.Slug, role))
	mint := func() (string, string) {
		_, token, err := svc.MintAPIKeyWithOptions(ctx, group, APIKeyMintOptions{Name: "lifecycle-key", Role: role, CreatedBy: owner.ID})
		require.NoError(t, err)
		key, secret, ok := authkit.ParseAPIKey(svc.cfg.APIKeys.Prefix, token)
		require.True(t, ok)
		return key, secret
	}
	key, secret := mint()
	link, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: group.Persona, InstanceSlug: group.Instance, Role: role, InvitedBy: owner.ID})
	require.NoError(t, err)
	invite, err := svc.CreateAccountRegistrationInvite(ctx, CreateAccountRegistrationInviteRequest{Email: "invitee@lifecycle.test", Persona: group.Persona, InstanceSlug: group.Instance, Role: role, InvitedBy: owner.ID})
	require.NoError(t, err)
	define("org:billing:write") // deliberate edits still update every holder
	allowed, err := svc.Can(ctx, authkit.UserSubject(member.ID), group, "org:billing:write")
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
	allowed, err = svc.Can(ctx, authkit.UserSubject(member.ID), group, "org:billing:write")
	require.NoError(t, err)
	require.False(t, allowed)
	authority, err := svc.ResolveRemoteApplicationAuthority(ctx, app.ID)
	require.NoError(t, err)
	require.Empty(t, authority.Permissions)
	_, err = svc.ResolveAPIKeyDetailed(ctx, key, secret)
	require.Error(t, err)
	_, err = svc.RedeemGroupInviteLink(ctx, link.Code, member.ID)
	require.Error(t, err)
	require.Error(t, svc.ConsumeAccountRegistrationInvite(ctx, "invitee@lifecycle.test", member.ID, invite.Code))

	// Deletion/recreation exactly between a first result and any subsequent
	// lookup cannot pair an old credential with replacement permissions.
	for _, reader := range []string{"member", "application", "key"} {
		t.Run("snapshot_"+reader, func(t *testing.T) {
			define("org:billing:read")
			require.NoError(t, svc.AssignGroupRoleAs(ctx, owner.ID, group, authkit.UserSubject(member.ID), role))
			require.NoError(t, svc.AssignRemoteApplicationRoleAs(ctx, owner.ID, group, app.Slug, role))
			key, secret := mint()
			swap := func() {
				require.NoError(t, svc.DeleteGroupCustomRole(ctx, owner.ID, group, role))
				define("org:billing:write")
			}
			trace.swap.Store(&swap)
			switch reader {
			case "member":
				allowed, err := svc.Can(ctx, authkit.UserSubject(member.ID), group, "org:billing:write")
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
			func() error { return svc.AssignGroupRoleAs(ctx, owner.ID, group, authkit.UserSubject(member.ID), role) },
			func() error { return svc.AssignRemoteApplicationRoleAs(ctx, owner.ID, group, app.Slug, role) },
			func() error {
				_, _, err := svc.MintAPIKeyWithOptions(ctx, group, APIKeyMintOptions{Name: "waiting", Role: role, CreatedBy: owner.ID})
				return err
			},
			func() error {
				_, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: group.Persona, InstanceSlug: group.Instance, Role: role, InvitedBy: owner.ID})
				return err
			},
			func() error {
				_, err := svc.CreateAccountRegistrationInvite(ctx, CreateAccountRegistrationInviteRequest{Email: "waiting@lifecycle.test", Persona: group.Persona, InstanceSlug: group.Instance, Role: role, InvitedBy: owner.ID})
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
		allowed, err := svc.Can(ctx, authkit.UserSubject(member.ID), group, "org:billing:write")
		require.NoError(t, err)
		require.False(t, allowed)
	})
}
