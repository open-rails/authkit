package engine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
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
	poolCfg := pg.Pool.Config()
	poolCfg.ConnConfig.RuntimeParams["default_transaction_isolation"] = "repeatable read"
	hostPool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	require.NoError(t, err)
	t.Cleanup(hostPool.Close)
	cfg := maintenanceConfig()
	cfg.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
	roles := config.NewRoles()
	roles.Root.Role("manager", roles.Root.Members.Manage, roles.Root.Users.Ban)
	roles.Root.Role("reader", roles.Root.Users.Ban)
	org := roles.Persona("org", config.RemoteApplications)
	read, write := org.Permission("records", "read"), org.Permission("records", "write")
	org.Role("reader", read)
	org.Role("editor", read, write)
	org.Role("manager", org.Members.Manage, org.Credentials.Manage, read)
	cfg.Roles = roles
	svc := newTestEngine(t, cfg, config.Deps{Postgres: hostPool})
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
	require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
	role := func(gid, uid string) string {
		r, err := svc.groupStore().directRole(ctx, groupTarget{ID: gid}, iam.UserSubject(uid))
		require.NoError(t, err)
		return r.Name()
	}
	t.Run("replacement_and_noop", func(t *testing.T) {
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserIdentity(manager), iam.RootGroup(), iam.UserSubject(owner), "reader"), iam.ErrRoleAssignmentEscalation)
		require.ErrorIs(t, unassignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(owner), "owner"), iam.ErrLastOwner)
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(owner), "reader"), iam.ErrLastOwner)
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(owner), "owner"))
		grantRole(t, svc, iam.RootGroup(), iam.UserSubject(owner), "owner")
		require.ErrorIs(t, unassignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(owner), "owner"), iam.ErrLastOwner)
		require.ErrorIs(t, unassignRole(ctx, svc, iam.SystemIdentity(), iam.RootGroup(), iam.UserSubject(owner), "owner"), iam.ErrLastOwner)
		require.NoError(t, unassignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(owner), "reader")) // absent assignment
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(peer), "owner"))
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(peer), "reader"))
		require.Equal(t, "owner", role(root, owner))
	})
	t.Run("bounded_invite_is_not_a_demotion", func(t *testing.T) {
		invite, err := svc.CreateInvitation(ctx, iam.UserIdentity(manager), iam.RootGroup(), iam.NewInvitation{Role: mustRole("root:reader")})
		require.NoError(t, err)
		_, err = svc.RedeemInvitation(ctx, iam.UserIdentity(owner), invite.Code)
		require.ErrorIs(t, err, iam.ErrRoleAssignmentEscalation)
		recipient := user()
		_, err = svc.RedeemInvitation(ctx, iam.UserIdentity(recipient), invite.Code)
		require.NoError(t, err)
		require.Equal(t, "reader", role(root, recipient))
		_, err = svc.RedeemInvitation(ctx, iam.UserIdentity(recipient), invite.Code)
		require.NoError(t, err, "same recipient is idempotent")
		_, err = svc.RedeemInvitation(ctx, iam.UserIdentity(user()), invite.Code)
		require.ErrorIs(t, err, iam.ErrInvitationNotFound)
		// A link never outlives its creator's authority (ak#394).
		pending, err := svc.CreateInvitation(ctx, iam.UserIdentity(manager), iam.RootGroup(), iam.NewInvitation{Role: mustRole("root:reader")})
		require.NoError(t, err)
		require.NoError(t, unassignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
		require.Empty(t, role(root, manager))
		_, err = svc.RedeemInvitation(ctx, iam.UserIdentity(user()), pending.Code)
		require.ErrorIs(t, err, errmodel.ErrInvitationRevoked)
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(manager), "manager"))
	})
	group := func(uid string) (iam.GroupRef, string) {
		id, err := seedGroup(ctx, svc, ident.Persona("org"), uid)
		require.NoError(t, err)
		return iam.GroupByID(id), id
	}
	app := func(gid string) *iam.RemoteApplication {
		n++
		a, err := svc.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(gid), iam.RemoteApplication{Issuer: fmt.Sprintf("https://app%d.owners.test", n), JWKSURI: "https://keys.owners.test/jwks", Mode: iam.RemoteApplicationModeJWKS, Enabled: true})
		require.NoError(t, err)
		return &a
	}
	t.Run("remote_application_replacement_and_lifecycle", func(t *testing.T) {
		human := user()
		g, gid := group(human)
		a := app(gid)
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(human), g, iam.RemoteApplicationSubject(a.ID), "owner"))
		bounded := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(human), g, iam.UserSubject(bounded), "manager"))
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserIdentity(bounded), g, iam.RemoteApplicationSubject(a.ID), "reader"), iam.ErrRoleAssignmentEscalation)
		require.NoError(t, removeMember(ctx, svc, iam.UserIdentity(human), g, iam.UserSubject(human)))
		a.Enabled = false
		_, err := svc.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(a.GroupID), *a)
		require.ErrorIs(t, err, iam.ErrLastOwner)
		require.ErrorIs(t, svc.DeleteRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(a.GroupID), a.ID), iam.ErrLastOwner)
		grantRole(t, svc, g, iam.UserSubject(human), "owner")
		_, err = svc.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(a.GroupID), *a)
		require.NoError(t, err)
		require.ErrorIs(t, removeMember(ctx, svc, iam.UserIdentity(human), g, iam.UserSubject(human)), iam.ErrLastOwner, "disabled app is not a recovery owner")
		a.Enabled = true
		_, err = svc.UpsertRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(a.GroupID), *a)
		require.NoError(t, err)
		require.NoError(t, removeMember(ctx, svc, iam.UserIdentity(human), g, iam.UserSubject(human)))
		grantRole(t, svc, g, iam.UserSubject(human), "owner")
		require.NoError(t, svc.DeleteRemoteApplication(ctx, iam.SystemIdentity(), iam.GroupByID(a.GroupID), a.ID))
	})
	t.Run("subtree_cascade_cannot_count_cross_control_owners", func(t *testing.T) {
		human := user()
		_, controllerID := group(human)
		survivor, survivorID := group(human)
		for range 2 {
			a := app(controllerID)
			require.ErrorIs(t, assignRole(ctx, svc, iam.UserIdentity(human), survivor, iam.RemoteApplicationSubject(a.ID), "owner"), iam.ErrRemoteApplicationNotFound)
			// Historical invalid assignments are not operational owners. Even if
			// present, neither removal nor a concurrent subtree cascade may count them.
			_, err := svc.pg.Exec(ctx, `INSERT INTO group_remote_application_roles(permission_group_id,remote_application_id,role) VALUES($1,$2,'org:owner')`, survivorID, a.ID)
			require.NoError(t, err)
		}
		require.ErrorIs(t, removeMember(ctx, svc, iam.UserIdentity(human), survivor, iam.UserSubject(human)), iam.ErrLastOwner)
		start := make(chan struct{})
		done := make(chan error, 2)
		go func() {
			<-start
			done <- svc.PurgeGroup(ctx, iam.GroupByID(controllerID))
		}()
		go func() {
			<-start
			done <- removeMember(ctx, svc, iam.UserIdentity(human), survivor, iam.UserSubject(human))
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
	t.Run("account_lifecycle", func(t *testing.T) {
		sole := user()
		g, _ := group(sole)
		require.ErrorIs(t, svc.Ban(ctx, iam.SystemIdentity(), sole, iam.Ban{}), iam.ErrLastOwner)
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.ErrorIs(t, itemErr(svc.DeleteUsers(ctx, iam.UserIdentity(sole), []string{sole})), iam.ErrLastOwner)
		alternate := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(sole), g, iam.UserSubject(alternate), "owner"))
		require.NoError(t, svc.Ban(ctx, iam.SystemIdentity(), alternate, iam.Ban{}))
		require.ErrorIs(t, svc.softDelete(ctx, sole), iam.ErrLastOwner)
		require.NoError(t, svc.Unban(ctx, iam.SystemIdentity(), alternate))
		require.NoError(t, svc.softDelete(ctx, sole))
		require.NoError(t, svc.softDelete(ctx, sole), "repeated deletion is idempotent")
		require.ErrorIs(t, svc.softDelete(ctx, alternate), iam.ErrLastOwner)
	})
	t.Run("non_owner_role_is_not_recovery_owner", func(t *testing.T) {
		human := user()
		g, gid := group(human)
		other := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(human), g, iam.UserSubject(other), "editor"))
		require.ErrorIs(t, assignRole(ctx, svc, iam.UserIdentity(human), g, iam.UserSubject(human), "editor"), iam.ErrLastOwner)
		require.Equal(t, "editor", role(gid, other))
		require.Equal(t, "owner", role(gid, human))
	})
	t.Run("concurrent_owner_departures", func(t *testing.T) {
		for _, op := range []string{"remove", "unassign", "replace", "ban", "soft-delete", "mfa", "mfa-factor"} {
			t.Run(op, func(t *testing.T) {
				one, two := user(), user()
				g, gid := group(one)
				require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(one), g, iam.UserSubject(two), "owner"))
				raceSvc := svc
				if strings.HasPrefix(op, "mfa") {
					cfg := svc.cfg
					cfg.TwoFactor.Mode = iam.TwoFactorOptional
					mfaRoles := config.NewRoles()
					mfaOrg := mfaRoles.Persona("org")
					mfaOrg.RequireMFA(mfaOrg.Members.Manage)
					cfg.Roles = mfaRoles
					// A second app on the shared store: booting its catalog
					// sweeps only credentials it issued, never those the shared
					// workflow still holds.
					cfg.Token.Issuer = "https://mfa-race.test"
					cfg.Token.AccountIssuers = nil
					var err error
					raceSvc, err = New(ctx, cfg, config.Deps{Postgres: hostPool})
					require.NoError(t, err)
					t.Cleanup(func() { _ = raceSvc.Close(context.Background()) })
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
						return removeMember(ctx, svc, iam.UserIdentity(uid), g, iam.UserSubject(uid))
					case "unassign":
						return unassignRole(ctx, svc, iam.UserIdentity(uid), g, iam.UserSubject(uid), "owner")
					case "replace":
						return assignRole(ctx, svc, iam.UserIdentity(uid), g, iam.UserSubject(uid), "reader")
					case "ban":
						return svc.Ban(ctx, iam.SystemIdentity(), uid, iam.Ban{})
					case "soft-delete":
						return svc.softDelete(ctx, uid)
					case "mfa-factor":
						return raceSvc.Disable2FAFactor(ctx, uid, factors[uid])
					default:
						return raceSvc.Disable2FA(ctx, uid)
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
		expiring := user()
		require.NoError(t, assignRole(ctx, svc, iam.UserIdentity(owner), iam.RootGroup(), iam.UserSubject(expiring), "manager"))
		for _, tc := range []struct {
			name   string
			run    func() error
			mutate func(*permissionGroupStore) error
			want   error
		}{
			{"target_promotion", func() error {
				return assignRole(ctx, svc, iam.UserIdentity(manager), iam.RootGroup(), iam.UserSubject(target), "reader")
			}, func(st *permissionGroupStore) error {
				return st.AssignRole(ctx, root, iam.UserSubject(target), iam.RootPersona().OwnerRole())
			}, iam.ErrRoleAssignmentEscalation},
			{"ban_while_queued_revokes_authority", func() error {
				return assignRole(ctx, svc, iam.UserIdentity(expiring), iam.RootGroup(), iam.UserSubject(peer), "reader")
			}, func(st *permissionGroupStore) error {
				_, err := st.q.Exec(ctx, `UPDATE users SET banned_at=statement_timestamp(),banned_until=NULL WHERE id=$1::uuid`, expiring)
				return err
			}, iam.ErrInsufficientAuthority},
			{"identity_revocation", func() error {
				return assignRole(ctx, svc, iam.UserIdentity(manager), iam.RootGroup(), iam.UserSubject(peer), "reader")
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
				case "identity_revocation":
					require.Empty(t, role(root, manager))
				}
			})
		}
	})
}
