package embedded

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestSchemaPoolIsolatesSearchPathFromHostPool(t *testing.T) {
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(testdb.URL(t))
	require.NoError(t, err)
	cfg.MinConns, cfg.MaxConns = 1, 1
	application := "authkit-pool-" + uuid.NewString()
	cfg.ConnConfig.RuntimeParams["application_name"] = application
	hostPath := cfg.ConnConfig.RuntimeParams["search_path"]
	host, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	defer host.Close()
	require.NoError(t, host.Ping(ctx))

	bound, err := schemaPool(host, "tenant_auth")
	require.NoError(t, err)
	defer bound.Close()
	require.Equal(t, hostPath, host.Config().ConnConfig.RuntimeParams["search_path"])
	require.Equal(t, `"tenant_auth", public`, bound.Config().ConnConfig.RuntimeParams["search_path"])
	bound.Close()
	require.NoError(t, host.Ping(ctx))

	settings := Config{
		Token:     TokenConfig{Issuer: "https://pool.test", IssuedAudiences: []string{"test"}},
		Keys:      KeysConfig{VerifyOnly: true},
		Ephemeral: EphemeralConfig{AllowMemory: true},
	}
	client, err := New(settings, Deps{Postgres: host})
	require.NoError(t, err)
	client.Close()
	require.NoError(t, host.Ping(ctx))
	directory, err := NewGroupDirectory(host, "profiles")
	require.NoError(t, err)
	directory.Close()
	require.NoError(t, host.Ping(ctx))

	connections := func() int {
		var count int
		require.NoError(t, host.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE application_name=$1`, application).Scan(&count))
		return count
	}
	for deadline := time.Now().Add(3 * time.Second); connections() != 1; {
		if time.Now().After(deadline) {
			t.Fatal("closed clients retained database connections")
		}
		time.Sleep(10 * time.Millisecond)
	}
	settings.Ephemeral.AllowMemory = false
	for range 3 {
		client, err := New(settings, Deps{Postgres: host})
		require.ErrorContains(t, err, "Ephemeral.AllowMemory")
		require.Nil(t, client)
	}
	// MinConns makes a discarded clone open a real connection asynchronously.
	// Observe the database long enough to catch startup after New returned.
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		require.Equal(t, 1, connections(), "rejected constructor retained a pool connection")
		time.Sleep(10 * time.Millisecond)
	}
	require.NoError(t, host.Ping(ctx))
}
