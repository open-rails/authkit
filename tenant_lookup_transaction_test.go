package authkit_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/tenancy"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestTenantLookupTransactionRetainsFixedView(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	authority := newPublicRuntime(t, testConfig(t), pg.Pool)
	t.Cleanup(func() { require.NoError(t, authority.Close(context.Background())) })
	other := iam.NewTenantID()
	require.NoError(t, authority.CreateTenant(t.Context(), iam.Tenant{ID: other}))
	a, err := authority.ForTenant(t.Context(), testdb.DefaultTenantID)
	require.NoError(t, err)
	b, err := authority.ForTenant(t.Context(), other)
	require.NoError(t, err)
	ua, err := a.CreateUser(t.Context(), iam.NewUser{Username: "usera"})
	require.NoError(t, err)
	ub, err := b.CreateUser(t.Context(), iam.NewUser{Username: "userb"})
	require.NoError(t, err)
	lookup, ok := a.UserInfo().(authkit.TransactionalUserInfo)
	require.True(t, ok)
	_, ok = a.RemoteUserInfo(iam.GroupByID(testdb.DefaultTenantID.String()), "https://remote.example.test").(authkit.TransactionalUserInfo)
	require.True(t, ok)
	tx, err := pg.Pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	// A source tenant in context never overrides an explicitly selected target.
	users, err := lookup.GetTx(tenancy.With(t.Context(), other), tx, []string{ua.ID, ub.ID})
	require.NoError(t, err)
	require.Len(t, users, 1)
	require.Contains(t, users, ua.ID)
	_, err = a.User(t.Context(), iam.UserByID(ua.ID), authkit.InTx(tx))
	require.ErrorContains(t, err, "does not take InTx")
}
