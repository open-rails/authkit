package authcore

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/stretchr/testify/require"
)

// testClickHouse returns a clickhouse.Conn bound to an isolated test database
// with the bundled user_auth_session_events table (rendered single-node), or
// skips when AUTHKIT_TEST_CLICKHOUSE_ADDR is unset. The native-protocol address
// is e.g. "127.0.0.1:9000".
func testClickHouse(t *testing.T) clickhouse.Conn {
	t.Helper()
	addr := os.Getenv("AUTHKIT_TEST_CLICKHOUSE_ADDR")
	if addr == "" {
		t.Skip("AUTHKIT_TEST_CLICKHOUSE_ADDR not set; skipping ClickHouse-backed test")
	}
	ctx := context.Background()

	admin, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: "default", Username: "default"},
	})
	require.NoError(t, err)
	require.NoError(t, admin.Exec(ctx, "CREATE DATABASE IF NOT EXISTS authkit_ch_test"))
	t.Cleanup(func() {
		_ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS authkit_ch_test")
		_ = admin.Close()
	})

	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: "authkit_ch_test", Username: "default"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	// Single-node render of migrations/clickhouse/001_auth_analytics.up.sql
	// (no {{ON_CLUSTER}} / Replicated engine): same columns + ORDER BY.
	require.NoError(t, conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS user_auth_session_events (
			occurred_at DateTime64(3, 'UTC'),
			issuer LowCardinality(String),
			user_id String,
			session_id String,
			event LowCardinality(String),
			method LowCardinality(Nullable(String)),
			reason LowCardinality(Nullable(String)),
			ip_addr Nullable(String),
			user_agent Nullable(String),
			version DateTime64(3, 'UTC') DEFAULT now64(3)
		) ENGINE = ReplacingMergeTree(version)
		ORDER BY (issuer, user_id, session_id, occurred_at, event)`))
	return conn
}

// TestClickHouseAuthLogRoundTrip proves WithClickHouse's concrete sink writes a
// session event AuthKit can read back — the whole point of the (de-abstracted)
// ClickHouse path: log directly, query directly.
func TestClickHouseAuthLogRoundTrip(t *testing.T) {
	conn := testClickHouse(t)
	log := newClickHouseAuthLog(conn)
	require.NotNil(t, log)

	ctx := context.Background()
	method := "password_login"
	reason := "logout"
	ip := "203.0.113.7"
	ua := "test-agent/1.0"

	created := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     "https://auth.example",
		UserID:     "user-1",
		SessionID:  "sess-1",
		Event:      SessionEventCreated,
		Method:     &method,
		IPAddr:     &ip,
		UserAgent:  &ua,
	}
	revoked := AuthSessionEvent{
		OccurredAt: time.Now().UTC().Add(time.Second),
		Issuer:     "https://auth.example",
		UserID:     "user-1",
		SessionID:  "sess-1",
		Event:      SessionEventRevoked,
		Reason:     &reason,
	}
	other := AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     "https://auth.example",
		UserID:     "user-2",
		SessionID:  "sess-2",
		Event:      SessionEventCreated,
		Method:     &method,
	}
	require.NoError(t, log.LogSessionEvent(ctx, created))
	require.NoError(t, log.LogSessionEvent(ctx, revoked))
	require.NoError(t, log.LogSessionEvent(ctx, other))

	// Scoped to user-1, created-only: exactly the one created event, fields intact.
	events, err := log.ListSessionEvents(ctx, "user-1", SessionEventCreated)
	require.NoError(t, err)
	require.Len(t, events, 1)
	got := events[0]
	require.Equal(t, "user-1", got.UserID)
	require.Equal(t, "sess-1", got.SessionID)
	require.Equal(t, SessionEventCreated, got.Event)
	require.NotNil(t, got.Method)
	require.Equal(t, "password_login", *got.Method)
	require.NotNil(t, got.IPAddr)
	require.Equal(t, "203.0.113.7", *got.IPAddr)
	require.Nil(t, got.Reason)

	// user-1 across both event types → 2 events; user-2 excluded.
	both, err := log.ListSessionEvents(ctx, "user-1", SessionEventCreated, SessionEventRevoked)
	require.NoError(t, err)
	require.Len(t, both, 2)

	// Empty userID → all users (3 events).
	all, err := log.ListSessionEvents(ctx, "")
	require.NoError(t, err)
	require.Len(t, all, 3)
}
