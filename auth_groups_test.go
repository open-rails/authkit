package authkit_test

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// teamRuntime is a Client whose app declares a team persona (member) and a
// club persona, on a scratch database the test can write to.
func teamRuntime(t *testing.T) (*authkit.Client, *testdb.Postgres, iam.Persona, iam.Role, iam.Persona) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	rbac := authkit.NewRoles()
	team, club := rbac.Persona("team"), rbac.Persona("club")
	member := team.Role("member", team.Permission("docs", "read"))
	cfg := testConfig(t)
	cfg.Roles = rbac
	auth := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(func() { _ = auth.Close(context.Background()) })
	return auth, pg, team.Persona, member, club.Persona
}

// NewGroup.ID keys a group by the host's own id, a user's id included:
// creating it again returns it unchanged, and one id never names two groups.
func TestCreateGroupByHostID(t *testing.T) {
	auth, _, team, member, club := teamRuntime(t)
	ctx := t.Context()
	customer, err := auth.CreateUser(ctx, iam.NewUser{Email: "customer@example.test", Username: "customer"})
	require.NoError(t, err)
	owner := iam.UserSubject(customer.ID)

	g, err := auth.CreateGroup(ctx, iam.NewGroup{ID: strings.ToUpper(customer.ID), Persona: team, Owner: &owner})
	require.NoError(t, err)
	require.Equal(t, customer.ID, g.ID, "the customer's own id keys its group")
	other, err := auth.CreateUser(ctx, iam.NewUser{Email: "other@example.test", Username: "other"})
	require.NoError(t, err)
	otherOwner := iam.UserSubject(other.ID)
	again, err := auth.CreateGroup(ctx, iam.NewGroup{ID: customer.ID, Persona: team, Owner: &otherOwner})
	require.NoError(t, err)
	require.Equal(t, g, again, "creating it again returns it unchanged")
	roles, err := auth.GroupRoles(ctx, iam.GroupByID(g.ID), []iam.Subject{owner, otherOwner})
	require.NoError(t, err)
	require.Equal(t, map[iam.Subject]iam.Role{owner: team.OwnerRole()}, roles, "Owner seeds only a new group")

	_, err = auth.CreateGroup(ctx, iam.NewGroup{ID: customer.ID, Persona: club})
	require.ErrorIs(t, err, iam.ErrGroupConflict, "another persona")
	root, err := auth.Group(ctx, iam.RootGroup())
	require.NoError(t, err)
	_, err = auth.CreateGroup(ctx, iam.NewGroup{ID: root.ID, Persona: team})
	require.ErrorIs(t, err, iam.ErrGroupConflict, "root's id")
	_, err = auth.CreateGroup(ctx, iam.NewGroup{ID: "not-a-uuid", Persona: team})
	e, ok := iam.AsError(err)
	require.True(t, ok, "%v", err)
	require.Equal(t, "invalid_request", e.Code())
	require.NoError(t, auth.DeleteGroup(ctx, iam.GroupByID(g.ID)))
	_, err = auth.CreateGroup(ctx, iam.NewGroup{ID: customer.ID, Persona: team})
	require.ErrorIs(t, err, iam.ErrGroupConflict, "a deleted group keeps its id")

	// Racing creators of one id get one group, with no resolve-then-create
	// loop.
	id := uuid.NewString()
	var wg sync.WaitGroup
	got, errs := make([]string, 8), make([]error, 8)
	for i := range got {
		wg.Go(func() {
			created, err := auth.CreateGroup(ctx, iam.NewGroup{ID: id, Persona: team})
			got[i], errs[i] = created.ID, err
		})
	}
	wg.Wait()
	for i := range got {
		require.NoError(t, errs[i])
		require.Equal(t, id, got[i])
	}
	_, err = auth.SetGroupRole(ctx, iam.SystemActor(), iam.GroupByID(id), iam.UserSubject(other.ID), member)
	require.NoError(t, err)
}

// InTx puts a group, an account and its seats in the host's transaction: they
// commit or roll back with the host's own rows. An option an operation does
// not take is refused, never ignored.
func TestOperationsJoinTheHostTransaction(t *testing.T) {
	auth, pg, team, member, _ := teamRuntime(t)
	ctx := t.Context()
	founder, err := auth.CreateUser(ctx, iam.NewUser{Email: "founder@example.test", Username: "founder"})
	require.NoError(t, err)
	owner := iam.UserSubject(founder.ID)
	seat := func(tx pgx.Tx, n string) (iam.Group, iam.User, iam.User) {
		t.Helper()
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: team, Owner: &owner}, authkit.InTx(tx))
		require.NoError(t, err)
		mod, err := auth.CreateUser(ctx, iam.NewUser{Email: n + "@example.test", Username: n}, authkit.InTx(tx))
		require.NoError(t, err)
		seated, err := auth.SetGroupRole(ctx, iam.UserActor(founder.ID), iam.GroupByID(g.ID), iam.UserSubject(mod.ID), member, authkit.InTx(tx))
		require.NoError(t, err)
		require.Equal(t, iam.GroupMember{Subject: iam.UserSubject(mod.ID), Role: member}, seated)
		invited, err := auth.EnsureUserRole(ctx, iam.GroupByID(g.ID), iam.UserByEmail(n+"-invited@example.test"), member, authkit.InTx(tx))
		require.NoError(t, err)
		require.Equal(t, n+"-invited@example.test", *invited.Email, "read inside the transaction")
		return g, mod, invited
	}

	tx, err := pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	g, mod, invited := seat(tx, "rolledback")
	require.NoError(t, tx.Rollback(ctx))
	_, err = auth.Group(ctx, iam.GroupByID(g.ID))
	require.ErrorIs(t, err, iam.ErrGroupNotFound)
	for _, id := range []string{mod.ID, invited.ID} {
		_, err = auth.User(ctx, iam.UserByID(id), authkit.IncludeDeleted())
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	}

	tx, err = pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	g, mod, invited = seat(tx, "committed")
	require.NoError(t, tx.Commit(ctx))
	roles, err := auth.GroupRoles(ctx, iam.GroupByID(g.ID), []iam.Subject{owner, iam.UserSubject(mod.ID), iam.UserSubject(invited.ID)})
	require.NoError(t, err)
	require.Equal(t, map[iam.Subject]iam.Role{owner: team.OwnerRole(), iam.UserSubject(mod.ID): member, iam.UserSubject(invited.ID): member}, roles)

	tx, err = pg.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	defer tx.Rollback(ctx)
	require.ErrorContains(t, auth.Ban(ctx, iam.SystemActor(), mod.ID, iam.Ban{}, authkit.InTx(tx)), "does not take InTx")
	_, err = auth.DeleteUsers(ctx, iam.SystemActor(), []string{mod.ID}, authkit.IfRole(member))
	require.ErrorContains(t, err, "does not take IfRole")
	_, err = auth.User(ctx, iam.UserByID(mod.ID), authkit.InTx(tx))
	require.ErrorContains(t, err, "does not take InTx")
	u, err := auth.User(ctx, iam.UserByID(mod.ID))
	require.NoError(t, err)
	require.Nil(t, u.Ban, "a refused option changes nothing")
}

// Batch reads take any number of ids, reading iam.MaxBatch at a time, and
// iam.All reads every page of a list.
func TestBatchReadsAndAllPages(t *testing.T) {
	auth, _, team, _, _ := teamRuntime(t)
	ctx := t.Context()
	alice, err := auth.CreateUser(ctx, iam.NewUser{Email: "batch-alice@example.test", Username: "batchalice"})
	require.NoError(t, err)
	owner := iam.UserSubject(alice.ID)
	ids := make([]string, iam.MaxBatch, iam.MaxBatch+1)
	subjects := make([]iam.Subject, 0, iam.MaxBatch+1)
	for i := range ids {
		ids[i] = uuid.NewString()
		subjects = append(subjects, iam.UserSubject(ids[i]))
	}
	ids, subjects = append(ids, alice.ID), append(subjects, owner) // the second batch

	users, err := auth.Users(ctx, ids)
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Equal(t, alice.ID, users[alice.ID].ID)
	public, err := auth.PublicUsers(ctx, ids)
	require.NoError(t, err)
	require.Len(t, public, 1)
	require.Equal(t, "batchalice", public[alice.ID].Username)

	var groups []string
	for range 3 {
		g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: team, Owner: &owner})
		require.NoError(t, err)
		groups = append(groups, g.ID)
	}
	roles, err := auth.GroupRoles(ctx, iam.GroupByID(groups[0]), subjects)
	require.NoError(t, err)
	require.Equal(t, map[iam.Subject]iam.Role{owner: team.OwnerRole()}, roles)

	pages := 0
	memberships := iam.All(func(p iam.PageRequest) (iam.ListPage[iam.Membership], error) {
		pages++
		require.Equal(t, iam.MaxPageLimit, p.Limit)
		p.Limit = 1
		return auth.ListMemberships(ctx, owner, p)
	})
	var listed []string
	for m, err := range memberships {
		require.NoError(t, err)
		listed = append(listed, m.Group.ID)
	}
	require.ElementsMatch(t, groups, listed)
	require.Equal(t, 3, pages)
	pages = 0
	for range memberships {
		break
	}
	require.Equal(t, 1, pages, "stopping early reads no further page")
}
