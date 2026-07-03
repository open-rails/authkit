package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// When ClickHouse is not wired, the admin sign-in history route reports
// unavailable (503 authlog_unavailable) rather than pretending to have data.
func TestAdminSignins_NoClickHouse_Returns503(t *testing.T) {
	s := newTestService(t) // engine built without WithClickHouse
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/users/u1/signins", nil)
	r.SetPathValue("user_id", "u1")
	s.handleAdminUserSigninsGET(w, r)
	require.Equal(t, http.StatusServiceUnavailable, w.Code)
	require.Contains(t, w.Body.String(), "authlog_unavailable")
}

// httpTestClickHouse mirrors the authcore CH helper but in its own database so
// the two integration tests never collide. Skips without
// AUTHKIT_TEST_CLICKHOUSE_ADDR (native-protocol addr, e.g. "127.0.0.1:9000").
func httpTestClickHouse(t *testing.T) clickhouse.Conn {
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
	require.NoError(t, admin.Exec(ctx, "CREATE DATABASE IF NOT EXISTS authkit_ch_http_test"))
	t.Cleanup(func() {
		_ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS authkit_ch_http_test")
		_ = admin.Close()
	})
	conn, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{Database: "authkit_ch_http_test", Username: "default"},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
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

// TestAdminSignins_EndToEnd_ClickHouse exercises the whole de-abstracted path in
// one shot: WithClickHouse wires the engine → an event is logged → the admin
// sign-ins HTTP handler reads it back from real ClickHouse and shapes the JSON,
// scoped to the requested user.
func TestAdminSignins_EndToEnd_ClickHouse(t *testing.T) {
	conn := httpTestClickHouse(t)

	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := authcore.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	engine := authcore.NewService(embedded.Config{Token: embedded.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}}, ks, authcore.WithClickHouse(conn))
	svc := &Service{svc: engine}

	ctx := context.Background()
	require.True(t, engine.SessionEventHistoryEnabled())
	engine.LogSessionCreated(ctx, "user-e2e", "password_login", "sess-e2e", nil, nil)
	engine.LogSessionFailed(ctx, "user-e2e", "sess-fail", nil, nil, nil)
	// A different user's event must not leak into user-e2e's history.
	engine.LogSessionCreated(ctx, "other-user", "password_login", "sess-other", nil, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/users/user-e2e/signins", nil)
	r.SetPathValue("user_id", "user-e2e")
	svc.handleAdminUserSigninsGET(w, r)

	require.Equal(t, http.StatusOK, w.Code, "body=%s", w.Body.String())
	var body struct {
		Data []struct {
			UserID    string `json:"user_id"`
			SessionID string `json:"session_id"`
			Event     string `json:"event"`
		} `json:"data"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	// Handler filters to created + failed events for this user → exactly 2, no leak.
	require.Len(t, body.Data, 2)
	events := map[string]string{}
	for _, e := range body.Data {
		require.Equal(t, "user-e2e", e.UserID)
		events[e.SessionID] = e.Event
	}
	require.Equal(t, "session_created", events["sess-e2e"])
	require.Equal(t, "session_failed", events["sess-fail"])
}
