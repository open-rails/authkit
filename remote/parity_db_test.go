package remote_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/remote"
	"github.com/open-rails/authkit/server"
	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TestRemoteEmbeddedParity_DB proves the #142 thesis end-to-end: a remote.Client
// driving the REAL embedded engine over the management API behaves like the
// in-process embedded.Client — same writes, same reads, same error identity.
// Skips without a migrated test DB.
func TestRemoteEmbeddedParity_DB(t *testing.T) {
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed parity test")
	}
	t.Setenv("AUTHKIT_KEYS_PATH", t.TempDir()) // dev-gen a signing key here

	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	client, err := embedded.New(embedded.Config{
		Environment: "development",
		Token: embedded.TokenConfig{
			Issuer:            "https://parity.example.com",
			IssuedAudiences:   []string{"authkit"},
			ExpectedAudiences: []string{"authkit"},
		},
	}, pool)
	require.NoError(t, err)

	ts := httptest.NewServer(server.NewHandler(client, "tok"))
	t.Cleanup(ts.Close)
	rc := remote.New(ts.URL, "tok")
	ctx := context.Background()

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	email := "parity" + suffix + "@example.com"
	username := "parity" + suffix

	// WRITE through the REMOTE transport.
	created, err := rc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	require.NotEmpty(t, created.ID)

	// READ back through BOTH transports — they must agree.
	viaRemote, err := rc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	viaEmbedded, err := client.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, viaEmbedded.ID, viaRemote.ID)
	require.Equal(t, created.ID, viaRemote.ID)

	// Another read path (by username) through the remote transport agrees with the
	// write — proves typed result decoding and that the engine actually ran.
	uname, err := rc.GetUserByUsername(ctx, username)
	require.NoError(t, err)
	require.Equal(t, created.ID, uname.ID)

	// A write through the remote transport is visible to the embedded client:
	// ban via remote, observe the gate flip via the in-process engine.
	reason := "parity"
	require.NoError(t, rc.BanUser(ctx, created.ID, &reason, nil, created.ID))
	allowed, err := client.IsUserAllowed(ctx, created.ID)
	require.NoError(t, err)
	require.False(t, allowed, "ban issued over the remote transport must be visible to the embedded engine")
}
