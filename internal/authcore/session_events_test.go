package authcore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/db"
	"github.com/stretchr/testify/require"
)

const testSessionEventIssuer = "https://session-events.test"

func newSessionEventsService(t *testing.T) *Service {
	t.Helper()
	pool := testPG(t)
	svc := NewService(Config{Token: TokenConfig{Issuer: testSessionEventIssuer}}, Keyset{}, WithPostgres(pool))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.session_events WHERE issuer = $1`, testSessionEventIssuer)
	})
	return svc
}

// TestSessionEventsRoundTrip proves the PG session-event path end to end:
// best-effort writes land, the reader returns them newest-first with field
// fidelity, event-type filtering works, and other users never leak in.
func TestSessionEventsRoundTrip(t *testing.T) {
	svc := newSessionEventsService(t)
	ctx := context.Background()
	uid := fmt.Sprintf("se-user-%d", time.Now().UnixNano())
	other := uid + "-other"
	ip := "203.0.113.7"
	ua := "test-agent/1.0"
	reason := "logout"

	svc.LogSessionCreated(ctx, uid, "password_login", "sess-1", &ip, &ua)
	svc.logSessionRevoked(ctx, uid, "sess-1", &reason)
	svc.LogSessionFailed(ctx, uid, "sess-2", &reason, &ip, &ua)
	svc.LogSessionCreated(ctx, other, "password_login", "sess-other", nil, nil)

	// Created-only: exactly one event, fields intact.
	events, err := svc.ListSessionEvents(ctx, uid, SessionEventCreated)
	require.NoError(t, err)
	require.Len(t, events, 1)
	got := events[0]
	require.Equal(t, uid, got.UserID)
	require.Equal(t, "sess-1", got.SessionID)
	require.Equal(t, testSessionEventIssuer, got.Issuer)
	require.Equal(t, SessionEventCreated, got.Event)
	require.NotNil(t, got.Method)
	require.Equal(t, "password_login", *got.Method)
	require.NotNil(t, got.IPAddr)
	require.Equal(t, ip, *got.IPAddr)
	require.Nil(t, got.Reason)

	// No filter: all three of the user's events, other user excluded.
	all, err := svc.ListSessionEvents(ctx, uid)
	require.NoError(t, err)
	require.Len(t, all, 3)
	for _, e := range all {
		require.Equal(t, uid, e.UserID)
	}

	// Newest-first ordering — the last-login shape: seed a strictly older
	// created event, then the first created row must still be sess-1.
	old := AuthSessionEvent{
		OccurredAt: time.Now().UTC().Add(-time.Hour),
		Issuer:     testSessionEventIssuer,
		UserID:     uid,
		SessionID:  "sess-earlier",
		Event:      SessionEventCreated,
	}
	svc.logSessionEvent(ctx, old)
	created, err := svc.ListSessionEvents(ctx, uid, SessionEventCreated)
	require.NoError(t, err)
	require.Len(t, created, 2)
	require.Equal(t, "sess-1", created[0].SessionID) // most recent sign-in first
	require.Equal(t, "sess-earlier", created[1].SessionID)
	require.True(t, !created[0].OccurredAt.Before(created[1].OccurredAt))

	// Blank user id is rejected, not "all users".
	_, err = svc.ListSessionEvents(ctx, "  ")
	require.Error(t, err)
}

// TestSessionEventsHistoryAlwaysEnabled pins #245: history is no longer
// config-gated — even a bare service (no options at all) reports it enabled.
func TestSessionEventsHistoryAlwaysEnabled(t *testing.T) {
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://bare.test"}}, Keyset{})
	require.True(t, svc.SessionEventHistoryEnabled())
}

// TestSessionEventsBestEffortWrite pins the best-effort contract: a failing
// insert (canceled context) must not panic or surface — the auth operation
// that triggered it already succeeded. A service with no Postgres no-ops.
func TestSessionEventsBestEffortWrite(t *testing.T) {
	svc := newSessionEventsService(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	svc.LogSessionCreated(canceled, "se-best-effort", "password_login", "sess-x", nil, nil) // must not panic
	events, err := svc.ListSessionEvents(context.Background(), "se-best-effort")
	require.NoError(t, err)
	require.Empty(t, events)

	bare := NewService(Config{Token: TokenConfig{Issuer: "https://bare.test"}}, Keyset{})
	bare.LogSessionCreated(context.Background(), "se-no-pg", "password_login", "sess-y", nil, nil) // no-op
}

func seedSessionEvent(t *testing.T, svc *Service, uid, sid string, at time.Time) {
	t.Helper()
	require.NoError(t, svc.q.SessionEventInsert(context.Background(), db.SessionEventInsertParams{
		OccurredAt: at.UTC(),
		Issuer:     testSessionEventIssuer,
		UserID:     uid,
		SessionID:  sid,
		Event:      string(SessionEventCreated),
	}))
}

// TestSessionEventsPruneBatched proves the retention sweep: bounded batches
// loop until done, the cutoff boundary is exact (occurred_at < cutoff — a row
// AT the cutoff survives), and newer rows are untouched.
func TestSessionEventsPruneBatched(t *testing.T) {
	svc := newSessionEventsService(t)
	ctx := context.Background()
	uid := fmt.Sprintf("se-prune-%d", time.Now().UnixNano())
	cutoff := time.Now().UTC().Add(-24 * time.Hour)

	for i := range 5 {
		seedSessionEvent(t, svc, uid, fmt.Sprintf("old-%d", i), cutoff.Add(-time.Duration(i+1)*time.Hour))
	}
	seedSessionEvent(t, svc, uid, "at-cutoff", cutoff)
	seedSessionEvent(t, svc, uid, "new", time.Now().UTC())

	// batchSize 2 forces the loop: 5 old rows => 3 batches (2+2+1).
	require.NoError(t, svc.pruneSessionEventsBatched(ctx, cutoff, 2))

	events, err := svc.ListSessionEvents(ctx, uid)
	require.NoError(t, err)
	require.Len(t, events, 2)
	require.Equal(t, "new", events[0].SessionID)
	require.Equal(t, "at-cutoff", events[1].SessionID) // occurred_at == cutoff is KEPT
}

// TestCleanupPrunesSessionEvents drives retention through the public sweep:
// with the default 365d retention, a >1y-old event dies and a fresh one lives.
// A negative retention (keep forever) prunes nothing.
func TestCleanupPrunesSessionEvents(t *testing.T) {
	svc := newSessionEventsService(t)
	require.Equal(t, 365*24*time.Hour, svc.cfg.SessionEventRetention) // normalized default
	ctx := context.Background()
	uid := fmt.Sprintf("se-cleanup-%d", time.Now().UnixNano())

	seedSessionEvent(t, svc, uid, "ancient", time.Now().UTC().Add(-2*365*24*time.Hour))
	seedSessionEvent(t, svc, uid, "fresh", time.Now().UTC())
	require.NoError(t, svc.CleanupExpiredAuthState(ctx))

	events, err := svc.ListSessionEvents(ctx, uid)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "fresh", events[0].SessionID)

	// Keep-forever: negative retention leaves even ancient rows alone.
	forever := NewService(Config{
		Token:                 TokenConfig{Issuer: testSessionEventIssuer},
		SessionEventRetention: -1,
	}, Keyset{}, WithPostgres(svc.pg))
	seedSessionEvent(t, forever, uid, "ancient-2", time.Now().UTC().Add(-2*365*24*time.Hour))
	require.NoError(t, forever.CleanupExpiredAuthState(ctx))
	events, err = forever.ListSessionEvents(ctx, uid)
	require.NoError(t, err)
	require.Len(t, events, 2)
}
