package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

// Session-event history is always on (#245, Postgres-backed) — no longer gated
// on a ClickHouse option.
func TestAdminSignins_HistoryAlwaysEnabled(t *testing.T) {
	s := newTestService(t) // bare engine, no options at all
	require.True(t, s.svc.SessionEventHistoryEnabled())
}

// TestAdminSignins_EndToEnd exercises the whole path in one shot: events are
// logged through the engine → the admin sign-ins HTTP handler reads them back
// from Postgres and shapes the JSON, scoped to the requested user.
func TestAdminSignins_EndToEnd(t *testing.T) {
	pool := newServerTestPool(t) // skips when AUTHKIT_TEST_DATABASE_URL unset

	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	ks := authcore.Keyset{Active: signer, PublicKeys: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	issuer := "https://signins-e2e.test"
	engine := authcore.NewService(embedded.Config{Token: embedded.TokenConfig{Issuer: issuer, IssuedAudiences: []string{"test-app"}, ExpectedAudiences: []string{"test-app"}, AccessTokenDuration: time.Hour}}, ks, authcore.WithPostgres(pool))
	svc := &Service{svc: engine}

	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.session_events WHERE issuer = $1`, issuer)
	})
	uid := fmt.Sprintf("user-e2e-%d", time.Now().UnixNano())
	engine.LogSessionCreated(ctx, uid, "password_login", "sess-e2e", nil, nil)
	engine.LogSessionFailed(ctx, uid, "sess-fail", nil, nil, nil)
	// A different user's event must not leak into this user's history.
	engine.LogSessionCreated(ctx, uid+"-other", "password_login", "sess-other", nil, nil)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/admin/users/"+uid+"/signins", nil)
	r.SetPathValue("user_id", uid)
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
		require.Equal(t, uid, e.UserID)
		events[e.SessionID] = e.Event
	}
	require.Equal(t, "session_created", events["sess-e2e"])
	require.Equal(t, "session_failed", events["sess-fail"])
}
