package authhttp

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRefreshFamilyHistory_OldReplayRevokesHTTP(t *testing.T) {
	g := newGraceHarness(t, 30*time.Second)
	uid, original := g.login(t, "oldreplay")
	ctx := context.Background()
	// A different login's family must remain valid for the same user.
	_, other, _, err := g.srv.svc.IssueRefreshSession(ctx, uid, "other-device", nil)
	require.NoError(t, err)
	current := original
	var predecessor string
	for range 3 {
		code, body, err := g.refresh(current)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code, body)
		predecessor = current
		current = body["refresh_token"].(string)
	}
	// Only the immediate predecessor can re-deliver the current token.
	code, body, err := g.refresh(predecessor)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	require.Equal(t, current, body["refresh_token"])

	code, body, err = g.refresh(original)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)
	live, revoked := g.sessionCounts(t, uid)
	require.Equal(t, 1, live, "old replay must kill the stolen family, preserving the other login")
	require.Equal(t, 1, revoked)
	code, body, err = g.refresh(current)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)
	code, body, err = g.refresh(other)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	var events int
	require.NoError(t, g.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.session_events WHERE user_id=$1 AND event='session_revoked' AND reason='refresh_reuse_detected'`, uid).Scan(&events))
	require.Equal(t, 1, events)
}
