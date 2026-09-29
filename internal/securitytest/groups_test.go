package securitytest

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestSecurityGroupsJoinTheHostTransaction: with authkit.InTx a group, its
// owner role and their events commit or roll back with the host's own row, on
// a host pool whose search_path does not see AuthKit's schema. A refused
// operation leaves the host's transaction usable, and only READ COMMITTED
// transactions join.
func TestSecurityGroupsJoinTheHostTransaction(t *testing.T) {
	events := newEventLog()
	h := newHost(t, withHTTP(generousLimits), withEngine(withRBACNoMFA), withEvents(events))
	ctx := context.Background()
	require.NoError(t, h.auth.Start(ctx))
	cfg := h.pool.Config().Copy()
	cfg.ConnConfig.RuntimeParams["search_path"] = "public"
	app, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(app.Close)
	_, err = app.Exec(ctx, `CREATE TABLE channels (name text PRIMARY KEY, group_id uuid NOT NULL UNIQUE)`)
	require.NoError(t, err)

	owner := h.newAccount("txowner")
	subject := iam.UserSubject(owner.id)
	create := func(tx pgx.Tx, name string) iam.Group {
		t.Helper()
		g, err := h.auth.CreateGroup(ctx, iam.NewGroup{Persona: orgPersona, Owner: &subject}, authkit.InTx(tx))
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `INSERT INTO channels (name, group_id) VALUES ($1, $2)`, name, g.ID)
		require.NoError(t, err)
		return g
	}
	count := func(query string, args ...any) int {
		t.Helper()
		var n int
		require.NoError(t, h.pool.QueryRow(ctx, query, args...).Scan(&n))
		return n
	}
	delivered := func(kind iam.EventKind, groupID string) bool {
		for _, e := range events.drained(h) {
			if e.Kind == kind && e.GroupID == groupID {
				return true
			}
		}
		return false
	}

	t.Run("a rolled-back host transaction leaves no group, role or event", func(t *testing.T) {
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		g := create(tx, "rolledback")
		var path string
		require.NoError(t, tx.QueryRow(ctx, `SHOW search_path`).Scan(&path))
		require.Equal(t, "public", path, "InTx left AuthKit's search_path on the host transaction")
		require.NoError(t, tx.Rollback(ctx))
		_, err = h.auth.Group(ctx, iam.GroupByID(g.ID))
		require.ErrorIs(t, err, iam.ErrGroupNotFound)
		require.Zero(t, count(`SELECT count(*) FROM group_user_roles WHERE permission_group_id=$1::uuid`, g.ID))
		require.Zero(t, count(`SELECT count(*) FROM account_events WHERE group_id=$1::uuid`, g.ID))
		require.False(t, delivered(iam.EventGroupCreated, g.ID))
	})

	var kept iam.Group
	t.Run("a committed one keeps the group, its owner, the row and the events", func(t *testing.T) {
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		kept = create(tx, "committed")
		require.NoError(t, tx.Commit(ctx))
		g, err := h.auth.Group(ctx, iam.GroupByID(kept.ID))
		require.NoError(t, err)
		require.Equal(t, orgPersona, g.Persona)
		require.Equal(t, orgPersona.OwnerRole(), h.roleOf(iam.GroupByID(kept.ID), subject))
		require.Equal(t, 1, count(`SELECT count(*) FROM public.channels WHERE group_id=$1::uuid`, kept.ID))
		require.True(t, delivered(iam.EventGroupCreated, kept.ID))
		require.True(t, delivered(iam.EventRoleGranted, kept.ID))
	})

	t.Run("a refused operation leaves the host transaction usable", func(t *testing.T) {
		banned := h.newAccount("txbanned")
		require.NoError(t, h.auth.Ban(ctx, iam.SystemActor(), banned.id, iam.Ban{}))
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		bannedSubject := iam.UserSubject(banned.id)
		_, err = h.auth.CreateGroup(ctx, iam.NewGroup{Persona: orgPersona, Owner: &bannedSubject}, authkit.InTx(tx))
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
		g := create(tx, "afterrefusal")
		require.NoError(t, tx.Commit(ctx))
		_, err = h.auth.Group(ctx, iam.GroupByID(g.ID))
		require.NoError(t, err)
	})

	t.Run("only READ COMMITTED transactions join", func(t *testing.T) {
		tx, err := app.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
		require.NoError(t, err)
		defer tx.Rollback(ctx)
		_, err = h.auth.CreateGroup(ctx, iam.NewGroup{Persona: orgPersona}, authkit.InTx(tx))
		require.ErrorContains(t, err, "READ COMMITTED")
		var one int
		require.NoError(t, tx.QueryRow(ctx, `SELECT 1`).Scan(&one), "the refusal broke the host transaction")
	})

	t.Run("deleting joins the host transaction too", func(t *testing.T) {
		remove := func(tx pgx.Tx) {
			t.Helper()
			_, err := tx.Exec(ctx, `DELETE FROM channels WHERE group_id=$1`, kept.ID)
			require.NoError(t, err)
			require.NoError(t, h.auth.DeleteGroup(ctx, iam.GroupByID(kept.ID), authkit.InTx(tx)))
		}
		tx, err := app.Begin(ctx)
		require.NoError(t, err)
		remove(tx)
		require.NoError(t, tx.Rollback(ctx))
		g, err := h.auth.Group(ctx, iam.GroupByID(kept.ID))
		require.NoError(t, err)
		require.Nil(t, g.DeletedAt, "a rolled-back delete deleted the group")
		require.False(t, delivered(iam.EventGroupDeleted, kept.ID))

		require.NoError(t, pgx.BeginFunc(ctx, app, func(tx pgx.Tx) error { remove(tx); return nil }))
		g, err = h.auth.Group(ctx, iam.GroupByID(kept.ID))
		require.NoError(t, err)
		require.NotNil(t, g.DeletedAt)
		require.Zero(t, count(`SELECT count(*) FROM public.channels WHERE group_id=$1::uuid`, kept.ID))
		require.True(t, delivered(iam.EventGroupDeleted, kept.ID))
		ok, err := h.auth.Can(ctx, iam.UserActor(owner.id), iam.GroupByID(kept.ID), ownerOnly)
		require.NoError(t, err)
		require.False(t, ok, "a deleted group grants nothing")
	})
}
