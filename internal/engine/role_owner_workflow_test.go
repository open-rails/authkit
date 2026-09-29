package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
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
	svc := mustNewWithKeys(t, Config{Token: TokenConfig{Issuer: "https://owners.test"}, TwoFactor: TwoFactorConfig{Mode: iam.TwoFactorDisabled}, Registration: RegistrationConfig{NativeUserMode: iam.RegistrationModeInviteOnly}, Roles: RoleConfig{
		Personas: map[string]Persona{"org": {Permissions: []string{"org:records:read", "org:records:write"}, CustomRoles: true, RemoteApplications: true}},
		Roles: []Role{
			{Persona: iam.RootPersona, Name: "manager", Permissions: []string{"root:members:manage", "root:users:ban"}},
			{Persona: iam.RootPersona, Name: "reader", Permissions: []string{"root:users:ban"}},
			{Persona: "org", Name: "reader", Permissions: []string{"org:records:read"}},
			{Persona: "org", Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:records:read"}},
		},
	}}, keyset{}, Deps{Postgres: hostPool})
	root, err := svc.ensureRootGroup(ctx)
	require.NoError(t, err)
	n := 0
	user := func() string {
		n++
		u, err := svc.createUser(ctx, fmt.Sprintf("u%d@owners.test", n), fmt.Sprintf("owneruser%d", n))
		require.NoError(t, err)
		return u.ID
	}
	owner, manager, peer := user(), user(), user()
	grantRole(t, svc, iam.RootGroup(), iam.UserSubject(owner), iam.OwnerRole)
	require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
	role := func(gid, uid string) iam.Role {
		r, err := svc.groupStore().directRole(ctx, gid, iam.UserSubject(uid))
		require.NoError(t, err)
		return r
	}
	t.Run("replacement_and_noop", func(t *testing.T) {
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(manager), iam.RootGroup(), iam.UserSubject(owner), "reader"), iam.ErrRoleAssignmentEscalation)
		require.ErrorIs(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), iam.OwnerRole), iam.ErrLastOwner)
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "reader"), iam.ErrLastOwner)
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), iam.OwnerRole))
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), " owner "))
		grantRole(t, svc, iam.RootGroup(), iam.UserSubject(owner), " owner ")
		require.ErrorIs(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), " owner "), iam.ErrLastOwner)
		require.ErrorIs(t, unassignRole(ctx, svc, iam.OperatorActor(), iam.RootGroup(), iam.UserSubject(owner), " owner "), iam.ErrLastOwner)
		require.NoError(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "reader")) // absent assignment
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(peer), iam.OwnerRole))
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(peer), "reader"))
		require.Equal(t, iam.OwnerRole, role(root, owner))
	})
	t.Run("bounded_invite_is_not_a_demotion", func(t *testing.T) {
		invite, err := svc.CreateInviteLink(ctx, iam.UserActor(manager), iam.RootGroup(), iam.NewInviteLink{Role: "reader"})
		require.NoError(t, err)
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(owner), invite.Code)
		require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
		recipient := user()
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(recipient), invite.Code)
		require.NoError(t, err)
		require.Equal(t, iam.Role("reader"), role(root, recipient))
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(recipient), invite.Code)
		require.NoError(t, err, "same recipient is idempotent")
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(user()), invite.Code)
		require.ErrorIs(t, err, iam.ErrInviteLinkNotFound)
		// A link never outlives its creator's authority (ak#394).
		pending, err := svc.CreateInviteLink(ctx, iam.UserActor(manager), iam.RootGroup(), iam.NewInviteLink{Role: "reader"})
		require.NoError(t, err)
		require.NoError(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
		require.Empty(t, role(root, manager))
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(user()), pending.Code)
		require.ErrorIs(t, err, errmodel.ErrInviteLinkRevoked)
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
	})
	group := func(name, uid string) (iam.GroupRef, string) {
		g := iam.GroupBySlug("org", name)
		id, err := seedGroup(ctx, svc, g.Persona(), g.Slug(), uid)
		require.NoError(t, err)
		return g, id
	}
	app := func(gid string) *iam.RemoteApplication {
		n++
		a, err := svc.UpsertRemoteApplication(ctx, iam.OperatorActor(), iam.GroupByID(gid), iam.RemoteApplication{Slug: fmt.Sprintf("app%d", n), Issuer: fmt.Sprintf("https://app%d.owners.test", n), JWKSURI: "https://keys.owners.test/jwks", Mode: iam.RemoteApplicationModeJWKS, Enabled: true})
		require.NoError(t, err)
		return a
	}
	t.Run("remote_application_replacement_and_lifecycle", func(t *testing.T) {
		human := user()
		g, gid := group("app-life", human)
		a := app(gid)
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.RemoteApplicationSubject(a.ID), iam.OwnerRole))
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.RemoteApplicationSubject(a.ID), " owner "))
		bounded := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.UserSubject(bounded), "manager"))
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(bounded), g, iam.RemoteApplicationSubject(a.ID), "reader"), iam.ErrRoleAssignmentEscalation)
		require.NoError(t, removeMember(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human)))
		a.Enabled = false
		_, err := svc.UpsertRemoteApplication(ctx, iam.OperatorActor(), iam.GroupByID(a.PermissionGroupID), *a)
		require.ErrorIs(t, err, iam.ErrLastOwner)
		require.ErrorIs(t, svc.DeleteRemoteApplication(ctx, iam.OperatorActor(), iam.GroupByID(a.PermissionGroupID), a.Slug), iam.ErrLastOwner)
		grantRole(t, svc, g, iam.UserSubject(human), iam.OwnerRole)
		_, err = svc.UpsertRemoteApplication(ctx, iam.OperatorActor(), iam.GroupByID(a.PermissionGroupID), *a)
		require.NoError(t, err)
		require.ErrorIs(t, removeMember(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human)), iam.ErrLastOwner, "disabled app is not a recovery owner")
		a.Enabled = true
		_, err = svc.UpsertRemoteApplication(ctx, iam.OperatorActor(), iam.GroupByID(a.PermissionGroupID), *a)
		require.NoError(t, err)
		require.NoError(t, removeMember(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human)))
		grantRole(t, svc, g, iam.UserSubject(human), iam.OwnerRole)
		require.NoError(t, svc.DeleteRemoteApplication(ctx, iam.OperatorActor(), iam.GroupByID(a.PermissionGroupID), a.Slug))
	})
	t.Run("subtree_cascade_cannot_count_cross_control_owners", func(t *testing.T) {
		human := user()
		_, controllerID := group("app-controller", human)
		survivor, survivorID := group("app-survivor", human)
		for range 2 {
			a := app(controllerID)
			require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(human), survivor, iam.RemoteApplicationSubject(a.ID), iam.OwnerRole), iam.ErrRemoteApplicationNotFound)
			// Historical invalid assignments are not operational owners. Even if
			// present, neither removal nor a concurrent subtree cascade may count them.
			_, err := svc.pg.Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,'owner')`, survivorID, a.ID)
			require.NoError(t, err)
		}
		require.ErrorIs(t, removeMember(ctx, svc, iam.UserActor(human), survivor, iam.UserSubject(human)), iam.ErrLastOwner)
		start := make(chan struct{})
		done := make(chan error, 2)
		go func() {
			<-start
			done <- svc.PurgeGroup(ctx, iam.OperatorActor(), iam.GroupByID(controllerID), iam.PurgeGroupOptions{})
		}()
		go func() {
			<-start
			done <- removeMember(ctx, svc, iam.UserActor(human), survivor, iam.UserSubject(human))
		}()
		close(start)
		success := 0
		for range 2 {
			err := <-done
			if err == nil {
				success++
			} else {
				require.ErrorIs(t, err, iam.ErrLastOwner)
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
		require.ErrorIs(t, svc.Ban(ctx, iam.OperatorActor(), sole, iam.Ban{}), iam.ErrLastOwner)
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.ErrorIs(t, itemErr(svc.DeleteUsers(ctx, iam.UserActor(sole), []string{sole})), iam.ErrLastOwner)
		require.ErrorIs(t, svc.PatchUserMetadata(ctx, iam.OperatorActor(), sole, map[string]any{"reserved": true}), errmodel.E(errmodel.CodeInvalidRequest), "reserved is AuthKit's key")
		_, err := svc.updateImportedUser(ctx, sole, newAccount{Username: "reservedowner", Metadata: map[string]any{"reserved": json.RawMessage(`true`)}})
		require.ErrorIs(t, err, iam.ErrLastOwner)
		now := time.Now()
		_, err = svc.updateImportedUser(ctx, sole, newAccount{Username: "importedowner", BannedAt: &now})
		require.ErrorIs(t, err, iam.ErrLastOwner)
		alternate := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(sole), g, iam.UserSubject(alternate), iam.OwnerRole))
		require.NoError(t, svc.Ban(ctx, iam.OperatorActor(), alternate, iam.Ban{}))
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.NoError(t, svc.Unban(ctx, iam.OperatorActor(), alternate))
		alternateRow, err := svc.getUserByID(ctx, alternate)
		require.NoError(t, err)
		reserve := func(reserved bool) error {
			_, err := svc.updateImportedUser(ctx, alternate, newAccount{Username: *alternateRow.Username, Metadata: map[string]any{"reserved": reserved}})
			return err
		}
		require.NoError(t, reserve(true))
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.NoError(t, reserve(false))
		require.NoError(t, svc.softDelete(ctx, sole))
		require.NoError(t, svc.softDelete(ctx, sole), "repeated deletion is idempotent")
		require.ErrorIs(t, svc.softDelete(ctx, alternate), iam.ErrLastOwner)
	})
	t.Run("custom_role_is_not_recovery_owner", func(t *testing.T) {
		human := user()
		g, gid := group("custom-life", human)
		other := user()
		require.NoError(t, svc.DefineGroupRole(ctx, iam.UserActor(human), g, iam.CustomRole{Name: "editor", Permissions: []string{"org:records:read", "org:records:write"}}))
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.UserSubject(other), "editor"))
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human), "editor"), iam.ErrLastOwner)
		require.NoError(t, svc.DefineGroupRole(ctx, iam.UserActor(human), g, iam.CustomRole{Name: "editor", Permissions: []string{"org:records:read"}}))
		require.NoError(t, svc.DeleteGroupRole(ctx, iam.UserActor(human), g, "editor"))
		require.Empty(t, role(gid, other))
		require.Equal(t, iam.OwnerRole, role(gid, human))
	})
	t.Run("concurrent_owner_departures", func(t *testing.T) {
		for _, op := range []string{"remove", "unassign", "replace", "ban", "soft-delete", "mfa", "mfa-factor"} {
			t.Run(op, func(t *testing.T) {
				one, two := user(), user()
				g, gid := group("race-"+op, one)
				require.NoError(t, assignRole(ctx, svc, iam.UserActor(one), g, iam.UserSubject(two), iam.OwnerRole))
				raceSvc := svc
				if strings.HasPrefix(op, "mfa") {
					cfg := svc.cfg
					cfg.TwoFactor.Mode = iam.TwoFactorOptional
					cfg.Roles = RoleConfig{
						Personas: map[string]Persona{"org": {RequireMFA: []string{"org:members:manage"}}},
						Roles:    []Role{{Persona: "org", Name: iam.OwnerRole, Permissions: []string{"org:*"}}},
					}
					raceSvc = mustNewWithKeys(t, cfg, keyset{}, Deps{Postgres: hostPool})
					_, err := raceSvc.enableFactor(ctx, one, "email", nil, authflow.AllowAdditionalFactors)
					require.NoError(t, err)
					_, err = raceSvc.enableFactor(ctx, two, "email", nil, authflow.AllowAdditionalFactors)
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
						return removeMember(ctx, svc, iam.UserActor(uid), g, iam.UserSubject(uid))
					case "unassign":
						return unassignRole(ctx, svc, iam.UserActor(uid), g, iam.UserSubject(uid), iam.OwnerRole)
					case "replace":
						return assignRole(ctx, svc, iam.UserActor(uid), g, iam.UserSubject(uid), "reader")
					case "ban":
						return svc.Ban(ctx, iam.OperatorActor(), uid, iam.Ban{})
					case "soft-delete":
						return svc.softDelete(ctx, uid)
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
						require.ErrorIs(t, err, iam.ErrLastOwner)
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
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), customGroup, iam.UserSubject(customActor), "manager"))
		require.NoError(t, svc.DefineGroupRole(ctx, iam.UserActor(human), customGroup, iam.CustomRole{Name: "auditor", Permissions: []string{"org:records:read"}}))
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), customGroup, iam.UserSubject(customTarget), "auditor"))
		expiringActor := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(expiringActor), "manager"))
		for _, tc := range []struct {
			name   string
			run    func() error
			mutate func(*permissionGroupStore) error
			want   error
		}{
			{"target_promotion", func() error {
				return assignRole(ctx, svc, iam.UserActor(manager), iam.RootGroup(), iam.UserSubject(target), "reader")
			}, func(st *permissionGroupStore) error {
				return st.AssignRole(ctx, root, iam.UserSubject(target), iam.OwnerRole)
			}, iam.ErrRoleAssignmentEscalation},
			{"custom_role_redefinition", func() error {
				return assignRole(ctx, svc, iam.UserActor(customActor), customGroup, iam.UserSubject(customTarget), "reader")
			}, func(st *permissionGroupStore) error {
				return st.UpsertCustomRole(ctx, customGID, "auditor", []string{"org:records:write"})
			}, iam.ErrRoleAssignmentEscalation},
			{"ban_while_queued_revokes_authority", func() error {
				return assignRole(ctx, svc, iam.UserActor(expiringActor), iam.RootGroup(), iam.UserSubject(peer), "reader")
			}, func(st *permissionGroupStore) error {
				_, err := st.q.Exec(ctx, `UPDATE users SET banned_at=statement_timestamp(),banned_until=NULL WHERE id=$1::uuid`, expiringActor)
				return err
			}, iam.ErrInsufficientAuthority},
			{"actor_revocation", func() error {
				return assignRole(ctx, svc, iam.UserActor(manager), iam.RootGroup(), iam.UserSubject(peer), "reader")
			}, func(st *permissionGroupStore) error {
				return st.UnassignSubject(ctx, root, iam.UserSubject(manager))
			}, iam.ErrInsufficientAuthority},
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
				require.NoError(t, tc.mutate(newPermissionGroupStore(raw)))
				require.NoError(t, tx.Commit(ctx))
				if tc.want == nil {
					require.NoError(t, <-done)
				} else {
					require.ErrorIs(t, <-done, tc.want)
				}
				switch tc.name {
				case "target_promotion":
					require.Equal(t, iam.OwnerRole, role(root, target))
				case "custom_role_redefinition":
					require.Equal(t, iam.Role("auditor"), role(customGID, customTarget))
				case "actor_revocation":
					require.Empty(t, role(root, manager))
				case "ban_expiry_after_transaction_start":
					require.Equal(t, iam.Role("reader"), role(root, peer))
				}
			})
		}
	})
}
