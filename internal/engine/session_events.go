package engine

import (
	"context"
	"errors"
	stdlog "log"
	"strconv"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/db"
	"github.com/open-rails/authkit/internal/errmodel"
)

// Session-event history (#245): sign-ins, revocations, password changes are
// recorded in session_events (Postgres; formerly ClickHouse). Writes
// are best-effort — a failed insert is logged loudly but NEVER fails the auth
// operation (login availability > forensics completeness). All call sites log
// post-commit, so inserts go straight to the pool.

// sessionEventsPruneBatchSize bounds each retention DELETE batch.
const sessionEventsPruneBatchSize = 5000

// SessionEvents pages an account's session history, newest first.
func (s *Engine) SessionEvents(ctx context.Context, userID string, q iam.SessionEventQuery) (iam.ListPage[iam.SessionEvent], error) {
	out := iam.ListPage[iam.SessionEvent]{Items: []iam.SessionEvent{}}
	userID, ok := canonicalUUID(userID)
	if !ok {
		return out, iam.ErrUserNotFound
	}
	if err := s.requirePG(); err != nil {
		return out, err
	}
	after, err := decodePageCursor(q.Page.Cursor, 2)
	if err != nil {
		return out, err
	}
	var at *time.Time
	var id int64
	if after[0] != "" {
		t, terr := time.Parse(time.RFC3339Nano, after[0])
		n, nerr := strconv.ParseInt(after[1], 10, 64)
		if terr != nil || nerr != nil {
			return out, errmodel.E(errmodel.CodeInvalidRequest, errmodel.WithCause(errors.New("invalid page cursor")))
		}
		at, id = &t, n
	}
	kinds := make([]string, 0, len(q.Kinds))
	for _, k := range q.Kinds {
		kinds = append(kinds, string(k))
	}
	limit := q.Page.PageLimit()
	rows, err := s.pg.Query(ctx, `SELECT id, occurred_at, issuer, session_id, event, COALESCE(method,''), COALESCE(reason,''), COALESCE(ip_addr,''), COALESCE(user_agent,'')
 FROM session_events WHERE user_id=$1 AND (cardinality($2::text[])=0 OR event=ANY($2::text[]))
 AND ($3::timestamptz IS NULL OR (occurred_at,id)<($3,$4))
 ORDER BY occurred_at DESC, id DESC LIMIT $5`, userID, kinds, at, id, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var e iam.SessionEvent
		var rowID int64
		if err := rows.Scan(&rowID, &e.OccurredAt, &e.Issuer, &e.SessionID, &e.Kind, &e.Method, &e.Reason, &e.IP, &e.UserAgent); err != nil {
			return out, err
		}
		out.Items = append(out.Items, e)
		ids = append(ids, rowID)
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > limit {
		out.Items = out.Items[:limit]
		out.Next = encodePageCursor(out.Items[limit-1].OccurredAt.UTC().Format(time.RFC3339Nano), strconv.FormatInt(ids[limit-1], 10))
	}
	return out, nil
}

// logSessionEvent is the single best-effort sink. No Postgres (verify-only
// construction) means no history; an insert failure is loud but non-fatal.
func (s *Engine) logSessionEvent(ctx context.Context, e authflow.AuthSessionEvent) {
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
		stdlog.Printf("authkit: error: failed to record session event %s for user %q: %v", e.Event, e.UserID, err)
	}
}

// logSessionCreated records a session creation event (best-effort).
func (s *Engine) logSessionCreated(ctx context.Context, userID string, method string, sessionID string, ip *string, ua *string) {
	m := strings.TrimSpace(method)
	var mPtr *string
	if m != "" {
		mPtr = &m
	}
	s.logSessionEvent(ctx, authflow.AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      iam.SessionEventCreated,
		Method:     mPtr,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

func (s *Engine) logSessionRevoked(ctx context.Context, userID string, sessionID string, reason *string) {
	s.logSessionEvent(ctx, authflow.AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      iam.SessionEventRevoked,
		Reason:     reason,
	})
}

// logPasswordChanged records a password change event for a user (best-effort).
func (s *Engine) logPasswordChanged(ctx context.Context, userID string, sessionID string, ip *string, ua *string) {
	s.logSessionEvent(ctx, authflow.AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      iam.SessionEventPasswordChange,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

// logPasswordRecovery records a password recovery event for a user (best-effort).
func (s *Engine) logPasswordRecovery(ctx context.Context, userID string, method, sessionID string, ip *string, ua *string) {
	s.logSessionEvent(ctx, authflow.AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      iam.SessionEventPasswordRecovery,
		Method:     &method,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

// LogSessionFailed records a failed session event for a user (best-effort).
func (s *Engine) LogSessionFailed(ctx context.Context, userID string, sessionID string, reason *string, ip *string, ua *string) {
	s.logSessionEvent(ctx, authflow.AuthSessionEvent{
		OccurredAt: time.Now().UTC(),
		Issuer:     s.cfg.Token.Issuer,
		UserID:     userID,
		SessionID:  sessionID,
		Event:      iam.SessionEventFailed,
		Reason:     reason,
		IPAddr:     ip,
		UserAgent:  ua,
	})
}

// pruneSessionEvents enforces Config.SessionEventRetention: bounded DELETE
// batches walking the occurred_at index until a short batch, so one sweep never
// runs an unbounded statement. Negative retention keeps events forever.
// Invoked from cleanupExpiredAuthState (host-scheduled, daily-ish cadence).
func (s *Engine) pruneSessionEvents(ctx context.Context) error {
	if s.cfg.SessionEventRetention < 0 {
		return nil
	}
	cutoff := time.Now().UTC().Add(-s.cfg.SessionEventRetention)
	return s.pruneSessionEventsBatched(ctx, cutoff, sessionEventsPruneBatchSize)
}

func (s *Engine) pruneSessionEventsBatched(ctx context.Context, cutoff time.Time, batchSize int64) error {
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
