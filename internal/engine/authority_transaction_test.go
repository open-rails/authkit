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
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
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
	cfg := maintenanceConfig()
	cfg.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	cfg.Roles = RoleConfig{
		Personas: map[string]Persona{"org": {Permissions: []string{"org:records:read", "org:records:write"}, RemoteApplications: true}},
		Roles: []Role{
			{Persona: "root", Name: "manager", Permissions: []string{"root:members:manage", "root:users:ban"}},
			{Persona: "root", Name: "reader", Permissions: []string{"root:users:ban"}},
			{Persona: "org", Name: "reader", Permissions: []string{"org:records:read"}},
			{Persona: "org", Name: "editor", Permissions: []string{"org:records:read", "org:records:write"}},
			{Persona: "org", Name: "manager", Permissions: []string{"org:members:manage", "org:credentials:manage", "org:records:read"}},
		},
	}
	svc := newTestEngine(t, cfg, Deps{Postgres: hostPool})
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
	grantRole(t, svc, iam.RootGroup(), iam.UserSubject(owner), "owner")
	require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
	role := func(gid, uid string) string {
		r, err := svc.groupStore().directRoleName(ctx, gid, iam.UserSubject(uid))
		require.NoError(t, err)
		return r
	}
	t.Run("replacement_and_noop", func(t *testing.T) {
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(manager), iam.RootGroup(), iam.UserSubject(owner), "reader"), iam.ErrRoleAssignmentEscalation)
		require.ErrorIs(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "owner"), iam.ErrLastOwner)
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "reader"), iam.ErrLastOwner)
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "owner"))
		grantRole(t, svc, iam.RootGroup(), iam.UserSubject(owner), "owner")
		require.ErrorIs(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "owner"), iam.ErrLastOwner)
		require.ErrorIs(t, unassignRole(ctx, svc, iam.SystemActor(), iam.RootGroup(), iam.UserSubject(owner), "owner"), iam.ErrLastOwner)
		require.NoError(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(owner), "reader")) // absent assignment
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(peer), "owner"))
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(peer), "reader"))
		require.Equal(t, "owner", role(root, owner))
	})
	t.Run("bounded_invite_is_not_a_demotion", func(t *testing.T) {
		invite, err := svc.CreateInviteLink(ctx, iam.UserActor(manager), iam.RootGroup(), iam.NewInviteLink{Role: mustRole("root:reader")})
		require.NoError(t, err)
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(owner), invite.Code)
		require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
		recipient := user()
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(recipient), invite.Code)
		require.NoError(t, err)
		require.Equal(t, "reader", role(root, recipient))
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(recipient), invite.Code)
		require.NoError(t, err, "same recipient is idempotent")
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(user()), invite.Code)
		require.ErrorIs(t, err, iam.ErrInviteLinkNotFound)
		// A link never outlives its creator's authority (ak#394).
		pending, err := svc.CreateInviteLink(ctx, iam.UserActor(manager), iam.RootGroup(), iam.NewInviteLink{Role: mustRole("root:reader")})
		require.NoError(t, err)
		require.NoError(t, unassignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
		require.Empty(t, role(root, manager))
		_, err = svc.RedeemInviteLink(ctx, iam.UserActor(user()), pending.Code)
		require.ErrorIs(t, err, errmodel.ErrInviteLinkRevoked)
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
	})
	group := func(uid string) (iam.GroupRef, string) {
		id, err := seedGroup(ctx, svc, ident.Persona("org"), uid)
		require.NoError(t, err)
		return iam.GroupByID(id), id
	}
	app := func(gid string) *iam.RemoteApplication {
		n++
		a, err := svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(gid), iam.RemoteApplication{Slug: fmt.Sprintf("app%d", n), Issuer: fmt.Sprintf("https://app%d.owners.test", n), JWKSURI: "https://keys.owners.test/jwks", Mode: iam.RemoteApplicationModeJWKS, Enabled: true})
		require.NoError(t, err)
		return a
	}
	t.Run("remote_application_replacement_and_lifecycle", func(t *testing.T) {
		human := user()
		g, gid := group(human)
		a := app(gid)
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.RemoteApplicationSubject(a.ID), "owner"))
		bounded := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.UserSubject(bounded), "manager"))
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(bounded), g, iam.RemoteApplicationSubject(a.ID), "reader"), iam.ErrRoleAssignmentEscalation)
		require.NoError(t, removeMember(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human)))
		a.Enabled = false
		_, err := svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(a.PermissionGroupID), *a)
		require.ErrorIs(t, err, iam.ErrLastOwner)
		require.ErrorIs(t, svc.DeleteRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(a.PermissionGroupID), a.Slug), iam.ErrLastOwner)
		grantRole(t, svc, g, iam.UserSubject(human), "owner")
		_, err = svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(a.PermissionGroupID), *a)
		require.NoError(t, err)
		require.ErrorIs(t, removeMember(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human)), iam.ErrLastOwner, "disabled app is not a recovery owner")
		a.Enabled = true
		_, err = svc.UpsertRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(a.PermissionGroupID), *a)
		require.NoError(t, err)
		require.NoError(t, removeMember(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human)))
		grantRole(t, svc, g, iam.UserSubject(human), "owner")
		require.NoError(t, svc.DeleteRemoteApplication(ctx, iam.SystemActor(), iam.GroupByID(a.PermissionGroupID), a.Slug))
	})
	t.Run("subtree_cascade_cannot_count_cross_control_owners", func(t *testing.T) {
		human := user()
		_, controllerID := group(human)
		survivor, survivorID := group(human)
		for range 2 {
			a := app(controllerID)
			require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(human), survivor, iam.RemoteApplicationSubject(a.ID), "owner"), iam.ErrRemoteApplicationNotFound)
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
			done <- svc.PurgeGroup(ctx, iam.GroupByID(controllerID), nil)
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
		g, _ := group(sole)
		require.ErrorIs(t, svc.Ban(ctx, iam.SystemActor(), sole, iam.Ban{}), iam.ErrLastOwner)
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.ErrorIs(t, itemErr(svc.DeleteUsers(ctx, iam.UserActor(sole), []string{sole})), iam.ErrLastOwner)
		require.ErrorIs(t, svc.PatchUserMetadata(ctx, iam.SystemActor(), sole, map[string]any{"reserved": true}), errmodel.E(errmodel.CodeInvalidRequest), "reserved is AuthKit's key")
		_, err := svc.updateImportedUser(ctx, sole, newAccount{Username: "reservedowner", Metadata: map[string]any{"reserved": json.RawMessage(`true`)}})
		require.ErrorIs(t, err, iam.ErrLastOwner)
		now := time.Now()
		_, err = svc.updateImportedUser(ctx, sole, newAccount{Username: "importedowner", BannedAt: &now})
		require.ErrorIs(t, err, iam.ErrLastOwner)
		alternate := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(sole), g, iam.UserSubject(alternate), "owner"))
		require.NoError(t, svc.Ban(ctx, iam.SystemActor(), alternate, iam.Ban{}))
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.NoError(t, svc.Unban(ctx, iam.SystemActor(), alternate))
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
	t.Run("non_owner_role_is_not_recovery_owner", func(t *testing.T) {
		human := user()
		g, gid := group(human)
		other := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.UserSubject(other), "editor"))
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserActor(human), g, iam.UserSubject(human), "editor"), iam.ErrLastOwner)
		require.Equal(t, "editor", role(gid, other))
		require.Equal(t, "owner", role(gid, human))
	})
	t.Run("concurrent_owner_departures", func(t *testing.T) {
		for _, op := range []string{"remove", "unassign", "replace", "ban", "soft-delete", "mfa", "mfa-factor"} {
			t.Run(op, func(t *testing.T) {
				one, two := user(), user()
				g, gid := group(one)
				require.NoError(t, assignRole(ctx, svc, iam.UserActor(one), g, iam.UserSubject(two), "owner"))
				raceSvc := svc
				if strings.HasPrefix(op, "mfa") {
					cfg := svc.cfg
					cfg.TwoFactor.Mode = iam.TwoFactorOptional
					cfg.Roles = RoleConfig{
						Personas: map[string]Persona{"org": {RequireMFA: []string{"org:members:manage"}}},
						Roles:    []Role{{Persona: "org", Name: "owner", Permissions: []string{"org:*"}}},
					}
					// newEngine, not New: booting this catalog would sweep the
					// credentials the shared workflow still holds.
					var err error
					raceSvc, err = newEngine(cfg, Deps{Postgres: hostPool})
					require.NoError(t, err)
					t.Cleanup(raceSvc.Close)
					_, err = raceSvc.enableFactor(ctx, one, "email", nil, authflow.AllowAdditionalFactors)
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
						return unassignRole(ctx, svc, iam.UserActor(uid), g, iam.UserSubject(uid), "owner")
					case "replace":
						return assignRole(ctx, svc, iam.UserActor(uid), g, iam.UserSubject(uid), "reader")
					case "ban":
						return svc.Ban(ctx, iam.SystemActor(), uid, iam.Ban{})
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
				return st.AssignRole(ctx, root, iam.UserSubject(target), iam.RootPersona.OwnerRole())
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
				require.NoError(t, tc.mutate(svc.groupStoreFor(raw)))
				require.NoError(t, tx.Commit(ctx))
				if tc.want == nil {
					require.NoError(t, <-done)
				} else {
					require.ErrorIs(t, <-done, tc.want)
				}
				switch tc.name {
				case "target_promotion":
					require.Equal(t, "owner", role(root, target))
				case "actor_revocation":
					require.Empty(t, role(root, manager))
				}
			})
		}
	})
}

// updateImportedUser applies an import row to an existing account, as
// bootstrap does.
func (s *Engine) updateImportedUser(ctx context.Context, id string, input newAccount) (*db.User, error) {
	tx, err := s.beginAuthorityTransaction(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if err := s.lockAuthority(ctx, tx); err != nil {
		return nil, err
	}
	u, err := s.updateImportedUserTx(ctx, tx, id, input)
	if err != nil {
		return nil, err
	}
	return u, tx.Commit(ctx)
}
