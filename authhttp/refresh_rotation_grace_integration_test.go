package authhttp

// ak#274 — the refresh-rotation grace window, end to end: a real HTTP server over
// the mounted handler, a real Postgres, real concurrent clients, no fakes.
//
// The incident this pins (tensorhub th#1817 / cozy-local cl#50): several agent
// processes on one box share ~/.cozy/config.json and therefore share ONE refresh
// token. Whoever refreshes first demotes that token to `previous`; every sibling
// then presents a token the server reads as REUSE and answers by revoking the
// family. Eight profiles and 737 of 740 sessions died that way in a single event.
// No client-side write discipline can fix it — the credential is consumed
// server-side before any file is written.
//
// Skips without AUTHKIT_TEST_DATABASE_URL.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testclock"
	"github.com/stretchr/testify/require"
)

// graceRacers is the shape that matters. Two racers can be survived by handing the
// loser a brand-new token; three cannot, because `previous` holds exactly one hash
// and the second re-mint would push the first racer's token out of both slots. The
// box in the incident routinely ran five concurrent publishers.
const graceRacers = 5

type graceHarness struct {
	url  string
	pool *pgxpool.Pool
	srv  *Service
	clk  *testclock.Clock
}

func newGraceHarness(t *testing.T, grace time.Duration) *graceHarness {
	t.Helper()
	pool := newServerTestPool(t)
	cfg := newServerTestConfig()
	cfg.Token.RefreshRotationGrace = grace
	// Wall-following: the rotation timestamp the window is measured against is
	// written by Postgres, so a frozen clock would sit behind it forever.
	clk := testclock.Wall()
	srv, err := NewServer(newServerClient(t, cfg, pool, embedded.WithClock(clk.Now)), WithoutRateLimiter())
	require.NoError(t, err)
	h, err := MountHandler(srv, MountOptions{})
	require.NoError(t, err)
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	return &graceHarness{url: ts.URL, pool: pool, srv: srv, clk: clk}
}

// postJSON is error-returning rather than assert-on-failure because the racers
// call it from goroutines, where a testify FailNow would not be sound.
func (g *graceHarness) postJSON(path, body string) (int, map[string]any, error) {
	resp, err := http.Post(g.url+path, "application/json", bytes.NewReader([]byte(body)))
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	out := map[string]any{}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, nil
}

// login returns the refresh token a fresh CLI login would write to its config file.
func (g *graceHarness) login(t *testing.T, prefix string) (userID, refreshToken string) {
	t.Helper()
	email, pass := newCookieTestUser(t, g.pool, g.srv, prefix)
	code, body, err := g.postJSON("/api/v1/password/login", `{"identifier":"`+email+`","password":"`+pass+`"}`)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	rt, _ := body["refresh_token"].(string)
	require.NotEmpty(t, rt)
	var uid string
	require.NoError(t, g.pool.QueryRow(context.Background(),
		`SELECT id::text FROM profiles.users WHERE email = $1`, email).Scan(&uid))
	return uid, rt
}

func (g *graceHarness) refresh(rt string) (int, map[string]any, error) {
	return g.postJSON("/api/v1/token", `{"grant_type":"refresh_token","refresh_token":"`+rt+`"}`)
}

// sessionCounts reports live and revoked session rows for a user — the number that
// went 3-live / 737-revoked in the incident.
func (g *graceHarness) sessionCounts(t *testing.T, userID string) (live, revoked int) {
	t.Helper()
	require.NoError(t, g.pool.QueryRow(context.Background(), `
		SELECT count(*) FILTER (WHERE revoked_at IS NULL),
		       count(*) FILTER (WHERE revoked_at IS NOT NULL)
		FROM profiles.refresh_sessions WHERE user_id = $1::uuid`, userID).Scan(&live, &revoked))
	return live, revoked
}

// TestRefreshRotationGrace_ConcurrentHoldersConverge is the pin. Five clients
// refresh ONE token at the same instant, as five agent processes sharing one
// credential file do. Every one of them must come back holding the SAME live
// credential, and nothing may be revoked.
//
// Against pre-ak#274 code this fails on the first assertion: the racers that lose
// find their token in previous_token_hash, which is read as reuse, and the family
// is revoked out from under all five.
func TestRefreshRotationGrace_ConcurrentHoldersConverge(t *testing.T) {
	g := newGraceHarness(t, 30*time.Second)
	uid, rt := g.login(t, "gracerace")

	type outcome struct {
		code int
		body map[string]any
		err  error
	}
	results := make([]outcome, graceRacers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(graceRacers)
	for i := range results {
		go func(i int) {
			defer wg.Done()
			<-start
			code, body, err := g.refresh(rt)
			results[i] = outcome{code, body, err}
		}(i)
	}
	close(start)
	wg.Wait()

	converged := ""
	for i, r := range results {
		require.NoErrorf(t, r.err, "racer %d transport error", i)
		require.Equalf(t, http.StatusOK, r.code, "racer %d was refused: %v", i, r.body)
		tok, _ := r.body["refresh_token"].(string)
		require.NotEmptyf(t, tok, "racer %d got no refresh token", i)
		require.NotEqualf(t, rt, tok, "racer %d was handed back the consumed token", i)
		access, _ := r.body["access_token"].(string)
		require.NotEmptyf(t, access, "racer %d got no access token", i)
		if converged == "" {
			converged = tok
		}
		require.Equalf(t, converged, tok, "racer %d was forked onto a second credential chain", i)
	}

	live, revoked := g.sessionCounts(t, uid)
	require.Equal(t, 1, live, "the session must survive the race")
	require.Zero(t, revoked, "a lost race must revoke nothing")

	// The credential they all converged on is real, and using it rotates normally.
	code, body, err := g.refresh(converged)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)
	next, _ := body["refresh_token"].(string)
	require.NotEqual(t, converged, next, "a serial refresh must still rotate")
}

// TestRefreshRotationGrace_ExpiredReplayStillRevokes proves the window is a bounded
// delay in reuse detection and not an exemption from it: the same replay that the
// test above tolerates inside the window revokes the family outside it.
func TestRefreshRotationGrace_ExpiredReplayStillRevokes(t *testing.T) {
	t.Run("clock advance", func(t *testing.T) {
		g := newGraceHarness(t, 150*time.Millisecond)
		expiredReplayRevokes(t, g, func() { g.clk.Advance(400 * time.Millisecond) })
	})
	// One wall-clock run keeps the seam honest against the DB's own rotation timestamp.
	t.Run("wall clock smoke", func(t *testing.T) {
		g := newGraceHarness(t, 20*time.Millisecond)
		expiredReplayRevokes(t, g, func() { time.Sleep(50 * time.Millisecond) })
	})
}

func expiredReplayRevokes(t *testing.T, g *graceHarness, elapse func()) {
	t.Helper()
	uid, rt := g.login(t, "graceexpiry")

	code, body, err := g.refresh(rt)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)

	elapse()

	code, body, err = g.refresh(rt)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)
	live, revoked := g.sessionCounts(t, uid)
	require.Zero(t, live, "a replay past the window must still revoke the family")
	require.Equal(t, 1, revoked)
}

// TestRefreshRotationGrace_DisabledIsStrictlySingleUse pins the opt-out: a negative
// window restores pre-ak#274 behaviour exactly, so an operator who wants strict
// single-use rotation can have it.
func TestRefreshRotationGrace_DisabledIsStrictlySingleUse(t *testing.T) {
	g := newGraceHarness(t, -1)
	uid, rt := g.login(t, "gracedisabled")

	code, body, err := g.refresh(rt)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code, body)

	code, body, err = g.refresh(rt)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, code, body)
	live, revoked := g.sessionCounts(t, uid)
	require.Zero(t, live)
	require.Equal(t, 1, revoked)
}
