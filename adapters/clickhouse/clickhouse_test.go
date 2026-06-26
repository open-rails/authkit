package clickhouse

import (
	"context"
	"os"
	"testing"
	"time"

	chgo "github.com/ClickHouse/clickhouse-go/v2"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/stretchr/testify/require"
)

// TestAdapter_LogAndList exercises the adapter end-to-end against a real ClickHouse
// (gated on AUTHKIT_TEST_CLICKHOUSE_URL; skipped otherwise). It creates a single-node
// table mirroring the bundled migration's columns — the adapter SQL is engine-agnostic,
// which avoids the Replicated/keeper setup the production migration needs.
func TestAdapter_LogAndList(t *testing.T) {
	dsn := os.Getenv("AUTHKIT_TEST_CLICKHOUSE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_CLICKHOUSE_URL not set; skipping ClickHouse adapter test")
	}
	opts, err := chgo.ParseDSN(dsn)
	require.NoError(t, err)
	conn, err := chgo.Open(opts)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	ctx := context.Background()

	require.NoError(t, conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS user_auth_session_events (
		occurred_at DateTime64(3,'UTC'), issuer LowCardinality(String), user_id String, session_id String,
		event LowCardinality(String), method LowCardinality(Nullable(String)), reason LowCardinality(Nullable(String)),
		ip_addr Nullable(String), user_agent Nullable(String), version DateTime64(3,'UTC') DEFAULT now64(3)
	) ENGINE = ReplacingMergeTree(version) ORDER BY (issuer, user_id, session_id, occurred_at, event)`))

	a := New(conn)
	uid := "user-" + time.Now().Format("150405.000000000")
	method := "password_login"
	require.NoError(t, a.LogSessionEvent(ctx, authcore.AuthSessionEvent{
		OccurredAt: time.Now().UTC(), Issuer: "https://test", UserID: uid, SessionID: "s1",
		Event: authcore.SessionEventCreated, Method: &method,
	}))
	require.NoError(t, a.LogSessionEvent(ctx, authcore.AuthSessionEvent{
		OccurredAt: time.Now().UTC().Add(time.Millisecond), Issuer: "https://test", UserID: uid, SessionID: "s1",
		Event: authcore.SessionEventRevoked,
	}))

	created, err := a.ListSessionEvents(ctx, uid, authcore.SessionEventCreated)
	require.NoError(t, err)
	require.Len(t, created, 1)
	require.Equal(t, authcore.SessionEventCreated, created[0].Event)
	require.NotNil(t, created[0].Method)
	require.Equal(t, "password_login", *created[0].Method)

	all, err := a.ListSessionEvents(ctx, uid)
	require.NoError(t, err)
	require.Len(t, all, 2)
}
