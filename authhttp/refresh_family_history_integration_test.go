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

func TestRefreshFamilyHistory_ReplayRacingRotationHTTP(t *testing.T) {
	g := newGraceHarness(t, 30*time.Second)
	uid, original := g.login(t, "replayrace")
	current := original
	for range 2 {
		code, body, err := g.refresh(current)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code, body)
		current = body["refresh_token"].(string)
	}
	type result struct {
		code int
		body map[string]any
		err  error
	}
	start := make(chan struct{})
	replay := make(chan result, 1)
	rotation := make(chan result, 1)
	for token, out := range map[string]chan result{original: replay, current: rotation} {
		go func() { <-start; code, body, err := g.refresh(token); out <- result{code, body, err} }()
	}
	close(start)
	replayed, rotated := <-replay, <-rotation
	require.NoError(t, replayed.err)
	require.NoError(t, rotated.err)
	require.Equal(t, http.StatusUnauthorized, replayed.code, replayed.body)
	require.Contains(t, []int{http.StatusOK, http.StatusUnauthorized}, rotated.code)
	live, revoked := g.sessionCounts(t, uid)
	require.Zero(t, live)
	require.Equal(t, 1, revoked)
	if rotated.code == http.StatusOK {
		code, body, err := g.refresh(rotated.body["refresh_token"].(string))
		require.NoError(t, err)
		require.Equal(t, http.StatusUnauthorized, code, body)
	}
}

func TestRefreshFamilyHistory_UnknownTokenAuditHTTP(t *testing.T) {
	g := newGraceHarness(t, 30*time.Second)
	var before, after int
	ctx := context.Background()
	query := `SELECT count(*) FROM profiles.session_events WHERE event='session_failed' AND reason='refresh_token_unknown' AND user_id='' AND session_id=''`
	require.NoError(t, g.pool.QueryRow(ctx, query).Scan(&before))
	code, body, err := g.refresh("unknown-refresh-token")
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)
	require.NoError(t, g.pool.QueryRow(ctx, query).Scan(&after))
	require.Equal(t, before+1, after)
}
