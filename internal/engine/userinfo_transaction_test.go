package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/ops"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestUserInfoTransactionUsesOnlyHostConnection(t *testing.T) {
	base := testdb.UnlockedPool(t)
	pc := base.Config().Copy()
	pc.MaxConns, pc.MinConns = 1, 0
	pool, err := pgxpool.NewWithConfig(t.Context(), pc)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	cfg := maintenanceConfig()
	cfg.Database.Schema = "userinfo_tx_" + uniqueSuffix()
	cfg.Database.RiverSchema = cfg.Database.Schema
	cfg.Roles = config.NewRoles()
	persona := cfg.Roles.Persona("directory", config.RemoteApplications)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, err := pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{cfg.Database.Schema}.Sanitize()+" CASCADE")
		require.NoError(t, err)
		_, err = pool.Exec(ctx, "DELETE FROM public.migrations WHERE app='authkit' AND schema=$1", cfg.Database.Schema)
		require.NoError(t, err)
	})
	e := newTestEngine(t, cfg, config.Deps{Postgres: pool})
	other := iam.NewTenantID()
	require.NoError(t, e.CreateTenant(t.Context(), iam.Tenant{ID: other}))
	a, b := WithTenant(t.Context(), cfg.DefaultTenantID), WithTenant(t.Context(), other)
	ua, err := e.CreateUser(a, iam.NewUser{Email: "a@example.test", Username: "usera", EmailVerified: true})
	require.NoError(t, err)
	ub, err := e.CreateUser(b, iam.NewUser{Email: "b@example.test", Username: "userb", EmailVerified: true})
	require.NoError(t, err)
	deleted, err := e.CreateUser(a, iam.NewUser{Email: "deleted@example.test", Username: "deleted"})
	require.NoError(t, err)
	results, err := e.DeleteUsers(a, iam.SystemIdentity(), []string{deleted.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	ga, err := e.CreateGroup(a, iam.NewGroup{Persona: persona.Persona})
	require.NoError(t, err)
	gb, err := e.CreateGroup(b, iam.NewGroup{Persona: persona.Persona})
	require.NoError(t, err)
	const issuer = "https://remote.example.test"
	require.NoError(t, e.RecordRemoteUserClaims(a, ga.ID, issuer, "same-subject", RemoteUserClaims{Name: "Tenant A"}))
	require.NoError(t, e.RecordRemoteUserClaims(b, gb.ID, issuer, "same-subject", RemoteUserClaims{Name: "Tenant B"}))
	root, err := e.Group(t.Context(), iam.RootGroup())
	require.NoError(t, err)
	require.NoError(t, e.RecordRemoteUserClaims(a, root.ID, issuer, "root-subject", RemoteUserClaims{Name: "Global"}))
	_, err = e.RemoteUserInfo(a, root.ID, issuer, []string{"root-subject"})
	require.ErrorIs(t, err, iam.ErrTenantMismatch)
	global, err := e.RemoteUserInfo(WithTenant(t.Context(), iam.TenantID{}), root.ID, issuer, []string{"root-subject"})
	require.NoError(t, err)
	require.Equal(t, "Global", global["root-subject"].Name)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tx, err := e.pg.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	require.NoError(t, err)
	defer tx.Rollback(context.Background())
	// This occupies the engine's only connection. Any accidental pool read in
	// GetTx (including remote-group resolution) would time out.
	require.NoError(t, db.New(tx).SetSearchPath(ctx, db.SetSearchPathParams{SearchPath: "public", IsLocal: true}))
	require.EqualValues(t, 1, e.pg.Stat().AcquiredConns())
	assertPath := func() {
		var path string
		require.NoError(t, tx.QueryRow(ctx, "SHOW search_path").Scan(&path))
		require.Equal(t, "public", path)
	}
	created, err := e.CreateUser(WithTenant(ctx, cfg.DefaultTenantID), iam.NewUser{Username: "uncommitted"}, ops.InTx(tx))
	require.NoError(t, err)
	native, err := e.UserInfoTx(WithTenant(ctx, cfg.DefaultTenantID), tx, []string{ua.ID, ub.ID, deleted.ID, created.ID, "malformed"})
	require.NoError(t, err)
	require.Len(t, native, 2)
	require.Contains(t, native, ua.ID)
	require.Contains(t, native, created.ID)
	assertPath()
	native, err = e.UserInfoTx(WithTenant(ctx, other), tx, []string{ua.ID, ub.ID})
	require.NoError(t, err)
	require.Len(t, native, 1)
	require.Contains(t, native, ub.ID)
	_, err = e.UserInfoTx(WithTenant(ctx, iam.TenantID{}), tx, []string{ua.ID})
	require.ErrorIs(t, err, iam.ErrTenantRequired)
	assertPath()
	_, err = e.UserInfoTx(ctx, nil, []string{ua.ID})
	require.ErrorContains(t, err, "requires a transaction")
	remote, err := e.RemoteUserInfoTx(WithTenant(ctx, cfg.DefaultTenantID), tx, iam.GroupByID(ga.ID), issuer, []string{"same-subject"})
	require.NoError(t, err)
	require.Equal(t, "Tenant A", remote["same-subject"].Name)
	assertPath()
	_, err = e.RemoteUserInfoTx(WithTenant(ctx, cfg.DefaultTenantID), tx, iam.RootGroup(), issuer, []string{"root-subject"})
	require.ErrorIs(t, err, iam.ErrTenantMismatch)
	assertPath()
	global, err = e.RemoteUserInfoTx(WithTenant(ctx, iam.TenantID{}), tx, iam.RootGroup(), issuer, []string{"root-subject"})
	require.NoError(t, err)
	require.Equal(t, "Global", global["root-subject"].Name)
	assertPath()

	_, err = e.RemoteUserInfoTx(WithTenant(ctx, cfg.DefaultTenantID), tx, iam.GroupByID(gb.ID), issuer, []string{"same-subject"})
	require.ErrorIs(t, err, iam.ErrTenantMismatch)
	assertPath()
	remote, err = e.RemoteUserInfoTx(WithTenant(ctx, other), tx, iam.GroupByID(gb.ID), "https://other.example.test", []string{"same-subject"})
	require.NoError(t, err)
	require.Empty(t, remote)
	remote, err = e.RemoteUserInfoTx(WithTenant(ctx, other), tx, iam.GroupByID(iam.NewTenantID().String()), issuer, []string{"same-subject"})
	require.NoError(t, err)
	require.Empty(t, remote)
	// A group deleted within this transaction is already absent, even though a
	// separate pool read would still see it until the outer commit.
	q := db.New(tx)
	require.NoError(t, q.SetSearchPath(ctx, db.SetSearchPathParams{SearchPath: pgx.Identifier{cfg.Database.Schema}.Sanitize() + ", public", IsLocal: true}))
	require.NoError(t, q.PermissionGroupDelete(ctx, gb.ID))
	require.NoError(t, q.SetSearchPath(ctx, db.SetSearchPathParams{SearchPath: "public", IsLocal: true}))
	remote, err = e.RemoteUserInfoTx(WithTenant(ctx, other), tx, iam.GroupByID(gb.ID), issuer, []string{"same-subject"})
	require.NoError(t, err)
	require.Empty(t, remote)
	assertPath()
	require.NoError(t, tx.Rollback(ctx))
	_, err = e.User(a, iam.UserByID(created.ID))
	require.ErrorIs(t, err, iam.ErrUserNotFound, "GetTx never commits the outer transaction")
}
