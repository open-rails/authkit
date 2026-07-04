package authcore

import (
	"context"
	"errors"
	stdlog "log"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// Session-event history (#245): sign-ins, revocations, password changes are
// recorded in profiles.session_events (Postgres; formerly ClickHouse). Writes
// are best-effort — a failed insert is logged loudly but NEVER fails the auth
// operation (login availability > forensics completeness). All call sites log
// post-commit, so inserts go straight to the pool.

// listSessionEventsLimit caps per-user history reads (newest-first).
const listSessionEventsLimit = 500

// sessionEventsPruneBatchSize bounds each retention DELETE batch.
const sessionEventsPruneBatchSize = 5000

// SessionEventHistoryEnabled reports whether session-event history is
// available. Always true since #245: history is Postgres-backed and every
// deployment has Postgres — the feature is no longer config-gated.
func (s *Service) SessionEventHistoryEnabled() bool { return true }

// ListSessionEvents returns a user's recent session events, most recent first
// (capped at listSessionEventsLimit). No eventTypes means all event types.
func (s *Service) ListSessionEvents(ctx context.Context, userID string, eventTypes ...SessionEventType) ([]AuthSessionEvent, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if userID = strings.TrimSpace(userID); userID == "" {
		return nil, errors.New("user id required")
	}
	events := make([]string, 0, len(eventTypes))
	for _, et := range eventTypes {
		if et != "" {
			events = append(events, string(et))
		}
	}
	rows, err := s.q.SessionEventsListByUser(ctx, db.SessionEventsListByUserParams{
		UserID:   userID,
		Events:   events,
		RowLimit: listSessionEventsLimit,
	})
	if err != nil {
		return nil, err
	}
	out := make([]AuthSessionEvent, 0, len(rows))
	for _, r := range rows {
		out = append(out, AuthSessionEvent{
			OccurredAt: r.OccurredAt,
			Issuer:     r.Issuer,
			UserID:     r.UserID,
			SessionID:  r.SessionID,
			Event:      SessionEventType(r.Event),
			Method:     r.Method,
			Reason:     r.Reason,
			IPAddr:     r.IpAddr,
			UserAgent:  r.UserAgent,
		})
	}
	return out, nil
}

// logSessionEvent is the single best-effort sink. No Postgres (verify-only
// construction) means no history; an insert failure is loud but non-fatal.
func (s *Service) logSessionEvent(ctx context.Context, e AuthSessionEvent) {
	if s.pg == nil {
		return
	}
	occurredAt := e.OccurredAt.UTC()
	if occurredAt.IsZero() {
		occurredAt = time.Now().UTC()
	}
	err := s.q.SessionEventInsert(ctx, db.SessionEventInsertParams{
		OccurredAt: occurredAt,
		Issuer:     e.Issuer,
		UserID:     e.UserID,
		SessionID:  e.SessionID,
		Event:      string(e.Event),
		Method:     e.Method,
		Reason:     e.Reason,
		IpAddr:     e.IPAddr,
		UserAgent:  e.UserAgent,
	})
	if err != nil {
		stdlog.Printf("authkit: error: failed to record session event %s for user %s: %v", e.Event, e.UserID, err)
	}
}

// LogSessionCreated records a session creation event (best-effort).
func (s *Service) LogSessionCreated(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string) {
	m := strings.TrimSpace(method)
	var mPtr *string
	if m != "" {
		mPtr = &m
	}
	s.logSessionEvent(ctx, AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventCreated,
		Method:     mPtr,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

func (s *Service) logSessionRevoked(ctx context.Context, userID string, sessionID string, reason *string) {
	s.logSessionEvent(ctx, AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventRevoked,
		Reason:     reason,
	})
}

// LogPasswordChanged records a password change event for a user (best-effort).
func (s *Service) LogPasswordChanged(ctx context.Context, userID string, sessionID string, ip *string, ua *string) {
	s.logSessionEvent(ctx, AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventPasswordChange,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

// LogPasswordRecovery records a password recovery event for a user (best-effort).
func (s *Service) LogPasswordRecovery(ctx context.Context, userID string, method, sessionID string, ip *string, ua *string) {
	s.logSessionEvent(ctx, AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventPasswordRecovery,
		Method:     &method,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

// LogSessionFailed records a failed session event for a user (best-effort).
func (s *Service) LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string) {
	s.logSessionEvent(ctx, AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      SessionEventFailed,
		Reason:     reason,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

// pruneSessionEvents enforces Config.SessionEventRetention: bounded DELETE
// batches walking the occurred_at index until a short batch, so one sweep never
// runs an unbounded statement. Negative retention keeps events forever.
// Invoked from CleanupExpiredAuthState (host-scheduled, daily-ish cadence).
func (s *Service) pruneSessionEvents(ctx context.Context) error {
	if s.cfg.SessionEventRetention < 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-s.cfg.SessionEventRetention)
	return s.pruneSessionEventsBatched(ctx, cutoff, sessionEventsPruneBatchSize)
}

func (s *Service) pruneSessionEventsBatched(ctx context.Context, cutoff time.Time, batchSize int64) error {
	for {
		n, err := s.q.SessionEventsPruneBatch(ctx, db.SessionEventsPruneBatchParams{Cutoff: cutoff, BatchSize: batchSize})
		if err != nil {
			return err
		}
		if n < batchSize {
			return nil
		}
	}
}
