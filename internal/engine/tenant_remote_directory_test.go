package engine

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/scim"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestTenantRemoteDirectoryUsesGroupOwner(t *testing.T) {
	pool := testdb.UnlockedPool(t)
	cfg := maintenanceConfig()
	cfg.Database.Schema = "tenant_remote_" + uniqueSuffix()
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
	contexts := []context.Context{WithTenant(t.Context(), cfg.DefaultTenantID), WithTenant(t.Context(), other)}
	groups := make([]iam.Group, 2)
	for i, ctx := range contexts {
		var err error
		groups[i], err = e.CreateGroup(ctx, iam.NewGroup{Persona: persona.Persona})
		require.NoError(t, err)
		require.NoError(t, e.RecordRemoteUserClaims(ctx, groups[i].ID, "https://external.example.test", "same-subject", RemoteUserClaims{Email: "same@example.test", EmailVerified: true, Name: "Original"}))
	}
	for i, ctx := range contexts {
		own, err := e.RemoteUser(ctx, groups[i].ID, "https://external.example.test", "same-subject")
		require.NoError(t, err)
		_, err = e.RemoteUser(ctx, groups[1-i].ID, "https://external.example.test", "same-subject")
		require.ErrorIs(t, err, iam.ErrTenantMismatch)
		require.ErrorIs(t, e.RecordRemoteUserClaims(ctx, groups[1-i].ID, "https://external.example.test", "same-subject", RemoteUserClaims{Name: "Forbidden", UpdatedAt: time.Now()}), iam.ErrTenantMismatch)
		descriptor := scim.Tenant{GroupID: groups[i].ID, Persona: persona.Persona.String(), Issuer: "https://external.example.test"}
		created, err := e.CreateDirectoryUser(ctx, descriptor, scim.User{Schemas: []string{scim.SchemaUser}, ExternalID: "same-subject", UserName: "sameuser"})
		require.NoError(t, err)
		require.Equal(t, own.ID, created.ID)
		_, err = e.DirectoryUser(contexts[1-i], descriptor, created.ID)
		require.ErrorIs(t, err, iam.ErrTenantMismatch)
		current, err := e.RemoteUser(ctx, groups[i].ID, "https://external.example.test", "same-subject")
		require.NoError(t, err)
		require.NotEqual(t, "Forbidden", current.Name)
	}
	var native int
	require.NoError(t, e.pg.QueryRow(t.Context(), "SELECT count(*) FROM users").Scan(&native))
	require.Zero(t, native, "remote subjects are not native account registrations")
}
