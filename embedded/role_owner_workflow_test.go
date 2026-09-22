package embedded

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// Real-store role and account operations share this workflow. Raw SQL is used
// only to arrange pre-existing invalid states or pause a concurrent transaction.
func TestRoleOwnerWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	config := pg.Pool.Config()
	config.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	hostPool, err := pgxpool.NewWithConfig(ctx, config)
	require.NoError(t, err)
	t.Cleanup(hostPool.Close)
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://owners.test"}, TwoFactor: TwoFactorConfig{Mode: TwoFactorDisabled}, Registration: RegistrationConfig{NativeUserMode: RegistrationModeInviteOnly}, RBAC: []PersonaDef{
		{Name: RootPersona, Roles: []RoleDef{{Name: "manager", Permissions: []string{"root:members:manage", "root:credentials:manage", "root:users:ban"}}, {Name: "reader", Permissions: []string{"root:users:ban"}}}},
		{Name: "org", Parent: RootPersona, Capabilities: PersonaCapabilities{CustomRoles: true}, Catalog: []string{"org:records:read", "org:records:write", "org:members:manage", "org:credentials:manage"}, Roles: []RoleDef{{Name: "reader", Permissions: []string{"org:records:read"}}, {Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:records:read"}}}},
	}}, Keyset{}, Deps{Postgres: hostPool})
	require.NoError(t, svc.SeedPermissionGroupContainment(ctx))
	root, err := svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	n := 0
	user := func() string {
		n++
		u, err := svc.CreateUser(ctx, fmt.Sprintf("u%d@owners.test", n), fmt.Sprintf("owneruser%d", n))
		require.NoError(t, err)
		return u.ID
	}
	owner, manager, peer := user(), user(), user()
	require.NoError(t, svc.AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(owner), OwnerRoleName))
	require.NoError(t, svc.AssignRoleBySlugAs(ctx, owner, manager, "manager"))
	role := func(gid, uid string) authkit.Role {
		r, err := svc.groupStore().directRole(ctx, gid, authkit.UserSubject(uid))
		require.NoError(t, err)
		return r
	}
	t.Run("replacement_and_noop", func(t *testing.T) {
		require.ErrorIs(t, svc.AssignRoleBySlugAs(ctx, manager, owner, "reader"), ErrRoleAssignmentEscalation)
		require.ErrorIs(t, svc.RemoveRoleBySlugAs(ctx, owner, owner, OwnerRoleName), ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.AssignRoleBySlugAs(ctx, owner, owner, "reader"), ErrCannotRemoveLastAdminRole)
		require.NoError(t, svc.AssignRoleBySlugAs(ctx, owner, owner, OwnerRoleName))
		require.NoError(t, svc.AssignGroupRoleAs(ctx, owner, authkit.RootGroup(), authkit.UserSubject(owner), " owner "))
		require.NoError(t, svc.AssignGroupRoleGenesis(ctx, authkit.RootGroup(), authkit.UserSubject(owner), " owner "))
		require.ErrorIs(t, svc.UnassignGroupRoleAs(ctx, owner, authkit.RootGroup(), authkit.UserSubject(owner), " owner "), ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.UnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(owner), " owner "), ErrCannotRemoveLastAdminRole)
		require.NoError(t, svc.RemoveRoleBySlugAs(ctx, owner, owner, "reader")) // absent assignment
		require.NoError(t, svc.AssignRoleBySlugAs(ctx, owner, peer, OwnerRoleName))
		require.NoError(t, svc.AssignRoleBySlugAs(ctx, owner, peer, "reader"))
		require.Equal(t, OwnerRoleName, role(root, owner))
	})
	t.Run("bounded_invite_is_not_a_demotion", func(t *testing.T) {
		invite, err := svc.CreateGroupInviteLink(ctx, CreateGroupInviteLinkRequest{Persona: RootPersona, Role: "reader", InvitedBy: manager})
		require.NoError(t, err)
		_, err = svc.RedeemGroupInviteLink(ctx, invite.Code, owner)
		require.ErrorIs(t, err, ErrRoleAssignmentEscalation)
		require.NoError(t, svc.RemoveRoleBySlugAs(ctx, owner, manager, "manager"))
		recipient := user()
		_, err = svc.RedeemGroupInviteLink(ctx, invite.Code, recipient)
		require.NoError(t, err, "bearer grant survives inviter revocation")
		require.Equal(t, authkit.Role("reader"), role(root, recipient))
		require.Empty(t, role(root, manager))
		_, err = svc.RedeemGroupInviteLink(ctx, invite.Code, recipient)
		require.NoError(t, err, "same recipient is idempotent")
		_, err = svc.RedeemGroupInviteLink(ctx, invite.Code, user())
		require.ErrorIs(t, err, ErrInviteLinkNotFound)
		require.NoError(t, svc.AssignRoleBySlugAs(ctx, owner, manager, "manager"))
	})
	group := func(name, uid string) (authkit.GroupRef, string) {
		g := authkit.GroupRef{Persona: "org", Instance: name}
		id, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: g.Persona, InstanceSlug: g.Instance, OwnerSubjectID: uid})
		require.NoError(t, err)
		return g, id
	}
	app := func(gid string) *RemoteApplication {
		n++
		a, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{Slug: fmt.Sprintf("app%d", n), PermissionGroupID: gid, Issuer: fmt.Sprintf("https://app%d.owners.test", n), JWKSURI: "https://keys.owners.test/jwks", Mode: RemoteAppModeJWKS, Enabled: true})
		require.NoError(t, err)
		return a
	}
	t.Run("remote_application_replacement_and_lifecycle", func(t *testing.T) {
		human := user()
		g, gid := group("app-life", human)
		a := app(gid)
		require.NoError(t, svc.AssignRemoteApplicationRoleAs(ctx, human, g, a.Slug, OwnerRoleName))
		require.NoError(t, svc.AssignRemoteApplicationRoleAs(ctx, human, g, a.Slug, " owner "))
		bounded := user()
		require.NoError(t, svc.AssignGroupRoleAs(ctx, human, g, authkit.UserSubject(bounded), "manager"))
		require.ErrorIs(t, svc.AssignRemoteApplicationRoleAs(ctx, bounded, g, a.Slug, "reader"), ErrRoleAssignmentEscalation)
		require.NoError(t, svc.RemoveGroupSubjectAs(ctx, human, g, authkit.UserSubject(human)))
		a.Enabled = false
		_, err := svc.UpsertRemoteApplication(ctx, *a)
		require.ErrorIs(t, err, ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.DeleteRemoteApplication(ctx, a.Issuer), ErrCannotRemoveLastAdminRole)
		require.NoError(t, svc.AssignGroupRoleGenesis(ctx, g, authkit.UserSubject(human), OwnerRoleName))
		_, err = svc.UpsertRemoteApplication(ctx, *a)
		require.NoError(t, err)
		require.ErrorIs(t, svc.RemoveGroupSubjectAs(ctx, human, g, authkit.UserSubject(human)), ErrCannotRemoveLastAdminRole, "disabled app is not a recovery owner")
		a.Enabled = true
		_, err = svc.UpsertRemoteApplication(ctx, *a)
		require.NoError(t, err)
		require.NoError(t, svc.RemoveGroupSubjectAs(ctx, human, g, authkit.UserSubject(human)))
		require.NoError(t, svc.AssignGroupRoleGenesis(ctx, g, authkit.UserSubject(human), OwnerRoleName))
		require.NoError(t, svc.DeleteRemoteApplication(ctx, a.Issuer))
	})
	t.Run("subtree_cascade_cannot_count_cross_control_owners", func(t *testing.T) {
		human := user()
		_, controllerID := group("app-controller", human)
		survivor, survivorID := group("app-survivor", human)
		for range 2 {
			a := app(controllerID)
			require.ErrorIs(t, svc.AssignGroupRoleAs(ctx, human, survivor, authkit.RemoteAppSubject(a.ID), OwnerRoleName), ErrInsufficientRoleAuthority)
			// Historical invalid assignments are not operational owners. Even if
			// present, neither removal nor a concurrent subtree cascade may count them.
			_, err := svc.Postgres().Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,'owner')`, survivorID, a.ID)
			require.NoError(t, err)
		}
		require.ErrorIs(t, svc.RemoveGroupSubjectAs(ctx, human, survivor, authkit.UserSubject(human)), ErrCannotRemoveLastAdminRole)
		start := make(chan struct{})
		done := make(chan error, 2)
		go func() {
			<-start
			done <- svc.DeleteGroupInstanceByID(ctx, controllerID, DeletePermissionGroupOptions{})
		}()
		go func() { <-start; done <- svc.RemoveGroupSubjectAs(ctx, human, survivor, authkit.UserSubject(human)) }()
		close(start)
		success := 0
		for range 2 {
			err := <-done
			if err == nil {
				success++
			} else {
				require.ErrorIs(t, err, ErrCannotRemoveLastAdminRole)
			}
		}
		require.Equal(t, 1, success)
		count, err := svc.groupStore().OwnerCount(ctx, survivorID)
		require.NoError(t, err)
		require.Positive(t, count)
	})
	t.Run("account_lifecycle_and_import", func(t *testing.T) {
		sole := user()
		g, _ := group("account-life", sole)
		require.ErrorIs(t, svc.BanUser(ctx, sole, nil, nil, owner), ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.SoftDeleteUser(ctx, sole), ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.HardDeleteUserAs(ctx, sole, sole), ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.PatchUserMetadata(ctx, sole, map[string]any{"reserved": true}), ErrCannotRemoveLastAdminRole)
		require.ErrorIs(t, svc.PatchUserMetadata(ctx, sole, map[string]any{"reserved": json.RawMessage(`true`)}), ErrCannotRemoveLastAdminRole)
		_, err := svc.UpdateImportedUser(ctx, sole, ImportUserInput{Username: "reservedowner", Metadata: map[string]any{"reserved": json.RawMessage(`true`)}})
		require.ErrorIs(t, err, ErrCannotRemoveLastAdminRole)
		now := time.Now()
		_, err = svc.UpdateImportedUser(ctx, sole, ImportUserInput{Username: "importedowner", BannedAt: &now})
		require.ErrorIs(t, err, ErrCannotRemoveLastAdminRole)
		alternate := user()
		require.NoError(t, svc.AssignGroupRoleAs(ctx, sole, g, authkit.UserSubject(alternate), OwnerRoleName))
		require.NoError(t, svc.BanUser(ctx, alternate, nil, nil, owner))
		require.ErrorIs(t, svc.SoftDeleteUser(ctx, sole), ErrCannotRemoveLastAdminRole)
		require.NoError(t, svc.UnbanUser(ctx, alternate))
		require.NoError(t, svc.PatchUserMetadata(ctx, alternate, map[string]any{"reserved": true}))
		require.ErrorIs(t, svc.HardDeleteUser(ctx, sole), ErrCannotRemoveLastAdminRole)
		require.NoError(t, svc.PatchUserMetadata(ctx, alternate, map[string]any{"reserved": false}))
		require.NoError(t, svc.SoftDeleteUser(ctx, sole))
		require.NoError(t, svc.HardDeleteUser(ctx, sole), "already inactive owner can be cleaned up")
		require.ErrorIs(t, svc.HardDeleteUser(ctx, alternate), ErrCannotRemoveLastAdminRole)
	})
	t.Run("custom_role_is_not_recovery_owner", func(t *testing.T) {
		human := user()
		g, gid := group("custom-life", human)
		other := user()
		require.NoError(t, svc.DefineGroupCustomRole(ctx, human, g, authkit.CustomRoleDef{Role: "editor", Permissions: []string{"org:records:read", "org:records:write"}}))
		require.NoError(t, svc.AssignGroupRoleAs(ctx, human, g, authkit.UserSubject(other), "editor"))
		require.ErrorIs(t, svc.AssignGroupRoleAs(ctx, human, g, authkit.UserSubject(human), "editor"), ErrCannotRemoveLastAdminRole)
		require.NoError(t, svc.DefineGroupCustomRole(ctx, human, g, authkit.CustomRoleDef{Role: "editor", Permissions: []string{"org:records:read"}}))
		require.NoError(t, svc.DeleteGroupCustomRole(ctx, human, g, "editor"))
		require.Empty(t, role(gid, other))
		require.Equal(t, OwnerRoleName, role(gid, human))
	})
	t.Run("concurrent_owner_departures", func(t *testing.T) {
		for _, op := range []string{"remove", "unassign", "replace", "ban", "soft-delete", "hard-delete", "mfa", "mfa-factor"} {
			t.Run(op, func(t *testing.T) {
				one, two := user(), user()
				g, gid := group("race-"+op, one)
				require.NoError(t, svc.AssignGroupRoleAs(ctx, one, g, authkit.UserSubject(two), OwnerRoleName))
				raceSvc := svc
				if strings.HasPrefix(op, "mfa") {
					cfg := svc.cfg
					cfg.TwoFactor.Mode = TwoFactorOptional
					cfg.RBAC = []PersonaDef{{Name: "org", Parent: RootPersona, Roles: []RoleDef{{Name: OwnerRoleName, Permissions: []string{"org:*"}, RequiresMFA: true}}}}
					raceSvc = mustNewWithKeys(t, cfg, Keyset{}, Deps{Postgres: hostPool})
					_, err := raceSvc.Enable2FA(ctx, one, "email", nil, AllowAdditionalFactors)
					require.NoError(t, err)
					_, err = raceSvc.Enable2FA(ctx, two, "email", nil, AllowAdditionalFactors)
					require.NoError(t, err)
				}
				factors := map[string]string{}
				if op == "mfa-factor" {
					for _, uid := range []string{one, two} {
						settings, err := raceSvc.Get2FASettings(ctx, uid)
						require.NoError(t, err)
						require.Len(t, settings.Factors, 1)
						factors[uid] = settings.Factors[0].ID
					}
				}
				run := func(uid string) error {
					switch op {
					case "remove":
						return svc.RemoveGroupSubjectAs(ctx, uid, g, authkit.UserSubject(uid))
					case "unassign":
						return svc.UnassignGroupRoleAs(ctx, uid, g, authkit.UserSubject(uid), OwnerRoleName)
					case "replace":
						return svc.AssignGroupRoleAs(ctx, uid, g, authkit.UserSubject(uid), "reader")
					case "ban":
						return svc.BanUser(ctx, uid, nil, nil, uid)
					case "soft-delete":
						return svc.SoftDeleteUser(ctx, uid)
					case "hard-delete":
						return svc.HardDeleteUser(ctx, uid)
					case "mfa-factor":
						_, err := raceSvc.Disable2FAFactorWithRemovedRoles(ctx, uid, factors[uid])
						return err
					default:
						_, err := raceSvc.Disable2FAWithRemovedRoles(ctx, uid)
						return err
					}
				}
				start := make(chan struct{})
				results := make(chan error, 2)
				var wg sync.WaitGroup
				for _, uid := range []string{one, two} {
					wg.Add(1)
					go func(id string) { defer wg.Done(); <-start; results <- run(id) }(uid)
				}
				close(start)
				wg.Wait()
				close(results)
				success := 0
				for err := range results {
					if err == nil {
						success++
					} else {
						require.ErrorIs(t, err, ErrCannotRemoveLastAdminRole)
					}
				}
				require.Equal(t, 1, success)
				remaining, err := svc.groupStore().OwnerCount(ctx, gid)
				require.NoError(t, err)
				require.Equal(t, 1, remaining)
			})
		}
	})

	t.Run("queued_mutations_read_committed_authority", func(t *testing.T) {
		target := user()
		human := user()
		customGroup, customGID := group("queued-custom", human)
		customActor, customTarget := user(), user()
		require.NoError(t, svc.AssignGroupRoleAs(ctx, human, customGroup, authkit.UserSubject(customActor), "manager"))
		require.NoError(t, svc.DefineGroupCustomRole(ctx, human, customGroup, authkit.CustomRoleDef{Role: "auditor", Permissions: []string{"org:records:read"}}))
		require.NoError(t, svc.AssignGroupRoleAs(ctx, human, customGroup, authkit.UserSubject(customTarget), "auditor"))
		expiringActor := user()
		require.NoError(t, svc.AssignRoleBySlugAs(ctx, owner, expiringActor, "manager"))
		for _, tc := range []struct {
			name   string
			run    func() error
			mutate func(*PermissionGroupStore) error
			want   error
		}{
			{"target_promotion", func() error { return svc.AssignRoleBySlugAs(ctx, manager, target, "reader") }, func(st *PermissionGroupStore) error {
				return st.AssignRole(ctx, root, authkit.UserSubject(target), OwnerRoleName)
			}, ErrRoleAssignmentEscalation},
			{"custom_role_redefinition", func() error {
				return svc.AssignGroupRoleAs(ctx, customActor, customGroup, authkit.UserSubject(customTarget), "reader")
			}, func(st *PermissionGroupStore) error {
				return st.UpsertCustomRole(ctx, customGID, authkit.CustomRoleDef{Role: "auditor", Permissions: []string{"org:records:write"}})
			}, ErrRoleAssignmentEscalation},
			{"banned_actor_retains_current_permission", func() error { return svc.AssignRoleBySlugAs(ctx, expiringActor, peer, "reader") }, func(st *PermissionGroupStore) error {
				_, err := st.q.Exec(ctx, `UPDATE users SET banned_at=statement_timestamp(),banned_until=NULL WHERE id=$1::uuid`, expiringActor)
				return err
			}, nil},
			{"actor_revocation", func() error { return svc.AssignRoleBySlugAs(ctx, manager, peer, "reader") }, func(st *PermissionGroupStore) error {
				return st.UnassignSubject(ctx, root, authkit.UserSubject(manager))
			}, ErrInsufficientRoleAuthority},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tx, err := pg.Pool.Begin(ctx)
				require.NoError(t, err)
				defer tx.Rollback(ctx)
				raw := tx
				require.NoError(t, svc.lockAuthority(ctx, raw))
				done := make(chan error, 1)
				go func() { done <- tc.run() }()
				require.Eventually(t, func() bool {
					var waiting int
					err := pg.Pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND wait_event='advisory' AND query LIKE '%pg_advisory_xact_lock%'`).Scan(&waiting)
					return err == nil && waiting == 1
				}, 5*time.Second, 10*time.Millisecond, "public mutation must actually wait for authority lock")
				select {
				case err := <-done:
					t.Fatalf("mutation escaped held authority lock: %v", err)
				default:
				}
				require.NoError(t, tc.mutate(NewPermissionGroupStore(raw)))
				require.NoError(t, tx.Commit(ctx))
				if tc.want == nil {
					require.NoError(t, <-done)
				} else {
					require.ErrorIs(t, <-done, tc.want)
				}
				switch tc.name {
				case "target_promotion":
					require.Equal(t, OwnerRoleName, role(root, target))
				case "custom_role_redefinition":
					require.Equal(t, authkit.Role("auditor"), role(customGID, customTarget))
				case "actor_revocation":
					require.Empty(t, role(root, manager))
				case "ban_expiry_after_transaction_start":
					require.Equal(t, authkit.Role("reader"), role(root, peer))
				}
			})
		}
	})
}
