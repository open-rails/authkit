package critical_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
)

// A host that holds the pool's only connection must be able to read its own
// uncommitted membership/user changes, without an accidental second checkout.
func TestCriticalGroupMembersHostTransaction(t *testing.T) {
	f := newFixture(t)
	cfg := f.pool.Config().Copy()
	cfg.MaxConns, cfg.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	noError(t, err)
	t.Cleanup(pool.Close)
	deps := f.deps
	deps.Postgres = pool
	client, err := authkit.New(t.Context(), f.cfg, deps)
	noError(t, err)
	t.Cleanup(func() { noError(t, client.Close(context.Background())) })
	user := f.user(t)
	for _, commit := range []bool{false, true} {
		t.Run(map[bool]string{false: "rollback", true: "commit"}[commit], func(t *testing.T) {
			group, err := f.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: f.shop.Persona})
			noError(t, err)
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			tx, err := pool.Begin(ctx)
			noError(t, err)
			defer tx.Rollback(context.Background())
			var before string
			noError(t, tx.QueryRow(ctx, "SHOW search_path").Scan(&before))
			_, err = client.EnsureUserRole(ctx, iam.GroupByID(group.ID), iam.UserByID(user.ID), f.writer, authkit.InTx(tx))
			noError(t, err)
			noError(t, client.PatchPublicMetadata(ctx, iam.SystemIdentity(), user.ID, map[string]any{"inside_tx": true}, authkit.InTx(tx)))
			page, err := client.ListGroupMembers(ctx, iam.GroupByID(group.ID), iam.MemberQuery{Roles: []iam.Role{f.writer}, WithUsers: true}, authkit.InTx(tx))
			noError(t, err)
			if len(page.Items) != 1 || page.Items[0].Subject.ID != user.ID || page.Items[0].User == nil || page.Items[0].User.PublicMetadata["inside_tx"] != true {
				t.Fatalf("transaction did not see its complete own writes: %+v", page)
			}
			var after string
			noError(t, tx.QueryRow(ctx, "SHOW search_path").Scan(&after))
			if before != after {
				t.Fatalf("read changed host search_path: %q -> %q", before, after)
			}
			outside, err := f.auth.ListGroupMembers(ctx, iam.GroupByID(group.ID), iam.MemberQuery{})
			noError(t, err)
			if len(outside.Items) != 0 {
				t.Fatal("uncommitted membership escaped transaction")
			}
			if commit {
				noError(t, tx.Commit(ctx))
			} else {
				noError(t, tx.Rollback(ctx))
			}
			outside, err = client.ListGroupMembers(ctx, iam.GroupByID(group.ID), iam.MemberQuery{})
			noError(t, err)
			want := 0
			if commit {
				want = 1
			}
			if len(outside.Items) != want {
				t.Fatalf("after transaction got %d members, want %d", len(outside.Items), want)
			}
		})
	}
	if _, err := client.ListGroupMembers(t.Context(), iam.RootGroup(), iam.MemberQuery{}, authkit.IncludeDeleted()); err == nil {
		t.Fatal("unsupported option accepted")
	}
}
