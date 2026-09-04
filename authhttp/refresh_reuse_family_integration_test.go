package authhttp

// ak#285 — refresh-token reuse detection across the whole family, end to end over
// the mounted handler and a real Postgres.
//
// Before this, a session row remembered exactly ONE demoted hash. An attacker who
// stole RT0 and rotated it twice (RT0→RT1→RT2) left RT0 two generations old:
// neither current nor previous, so the victim's next refresh was "invalid" — a
// silent logout — while the attacker kept RT2 and nothing was revoked or logged.
//
// Skips without AUTHKIT_TEST_DATABASE_URL.

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func (g *graceHarness) sessionEventCounts(t *testing.T, userID, event, reason string) (n int, withIP int) {
	t.Helper()
	require.NoError(t, g.pool.QueryRow(context.Background(), `
		SELECT count(*), count(ip_addr)
		FROM profiles.session_events
		WHERE user_id = $1 AND event = $2 AND reason = $3`, userID, event, reason).Scan(&n, &withIP))
	return n, withIP
}

// TestRefreshReuse_StolenTokenRotatedTwiceRevokesFamily is the pin. The attacker
// walks the chain two steps ahead of the victim, all inside the grace window (so
// this is not the ak#274 expiry case). The victim's RT0 must still be recognised
// as a demoted member of a live family, the family must die, and the attacker's
// RT2 must die with it.
func TestRefreshReuse_StolenTokenRotatedTwiceRevokesFamily(t *testing.T) {
	g := newGraceHarness(t, 30*time.Second)
	uid, rt0 := g.login(t, "reusefamily")

	code, body, err := g.refresh(rt0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	rt1, _ := body["refresh_token"].(string)
	require.NotEmpty(t, rt1)

	code, body, err = g.refresh(rt1)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	rt2, _ := body["refresh_token"].(string)
	require.NotEmpty(t, rt2)
	require.NotEqual(t, rt1, rt2)

	// The victim comes back with the token that was stolen from them.
	code, body, err = g.refresh(rt0)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)
	wire, _ := body["error"].(map[string]any)
	require.Equal(t, "invalid_refresh_token", wire["code"])

	live, revoked := g.sessionCounts(t, uid)
	require.Zero(t, live, "a two-generations-old token must revoke the family")
	require.Equal(t, 1, revoked)

	// The attacker's live credential is gone with the family.
	code, body, err = g.refresh(rt2)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)

	n, _ := g.sessionEventCounts(t, uid, "session_revoked", "refresh_reuse_detected")
	require.Equal(t, 1, n, "the family revoke must be recorded")
	n, withIP := g.sessionEventCounts(t, uid, "session_failed", "refresh_reuse_detected")
	require.Equal(t, 1, n, "the presenter of the reused token must be recorded")
	require.Equal(t, 1, withIP, "with the presenter's IP")
}

// TestRefreshReuse_GracePredecessorStillReDelivers pins that history-based lookup
// did not narrow the ak#274 grace path: the immediate predecessor inside the
// window is re-delivered its own successor, nothing is revoked, and the chain
// continues from that successor.
func TestRefreshReuse_GracePredecessorStillReDelivers(t *testing.T) {
	g := newGraceHarness(t, 30*time.Second)
	uid, rt0 := g.login(t, "reusegrace")

	code, body, err := g.refresh(rt0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	rt1, _ := body["refresh_token"].(string)
	require.NotEmpty(t, rt1)

	code, body, err = g.refresh(rt0)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	again, _ := body["refresh_token"].(string)
	require.Equal(t, rt1, again, "the grace predecessor is handed its own successor")

	live, revoked := g.sessionCounts(t, uid)
	require.Equal(t, 1, live)
	require.Zero(t, revoked)
	n, _ := g.sessionEventCounts(t, uid, "session_failed", "refresh_reuse_detected")
	require.Zero(t, n, "grace re-delivery is not reuse")

	code, body, err = g.refresh(rt1)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
}
