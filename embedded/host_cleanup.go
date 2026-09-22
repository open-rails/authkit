package embedded

import (
	"context"
	"fmt"
	"time"
)

// terminalRetention keeps revoked/expired keys and invitations available for
// host inspection for 90 days. Live credentials have no cleanup deadline.
const terminalRetention = 90 * 24 * time.Hour

// sessionsGCBatchSize bounds one dead-session DELETE (#325): never an
// unbounded statement, same rule as session_events (#245).
const sessionsGCBatchSize int64 = 5000

// gcDeadSessions removes revoked/expired refresh sessions (history cascades)
// in bounded batches until a short batch; it reports the batches issued.
func (s *engine) gcDeadSessions(ctx context.Context, batchSize int64) (int, error) {
	batches := 0
	for {
		n, err := s.q.SessionsDeleteRevokedOrExpiredBatch(ctx, batchSize)
		if err != nil {
			return batches, err
		}
		batches++
		if n < batchSize {
			return batches, nil
		}
	}
}

// CleanupExpiredAuthState removes expired transient AuthKit state that lives in
// postgres. Short-lived verification state — pending registrations, pending
// email/phone changes, email/phone verifications, and password resets — now
// lives entirely in the ephemeral store (Redis when multi-instance, in-memory
// otherwise) and expires automatically by TTL, so no database sweep is needed
// for it. The postgres sweep covers revoked/expired refresh sessions and their
// consumed-token history,
// terminal keys/invites (retained terminalRetention after their first terminal event),
// and session-event history past Config.SessionEventRetention (#245).
func (s *engine) CleanupExpiredAuthState(ctx context.Context) error {
	if err := s.requirePG(); err != nil {
		return err
	}

	if _, err := s.gcDeadSessions(ctx, sessionsGCBatchSize); err != nil {
		return err
	}

	// One bounded alias batch per maintenance tick. Request-time expiry is the
	// authority regardless of whether this best-effort storage cleanup has run.
	if _, err := s.q.NameClaimsDeleteExpired(ctx, s.namingNow()); err != nil {
		return err
	}

	cutoff := time.Now().UTC().Add(-terminalRetention)
	q := s.pg
	for _, target := range []struct{ table, terminal string }{
		{"group_invite_links", "LEAST(redeemed_at, revoked_at, expires_at)"},
		{"account_registration_invites", "LEAST(consumed_at, revoked_at, expires_at)"},
		{"api_keys", "LEAST(revoked_at, expires_at)"},
	} {
		// Table/expressions are fixed above. Lock only this batch; another worker
		// can make progress without waiting, and each call has bounded work.
		stmt := fmt.Sprintf(`WITH batch AS (
 SELECT id FROM %s WHERE %s < $1 ORDER BY %s, id
 LIMIT $2 FOR UPDATE SKIP LOCKED)
 DELETE FROM %s WHERE id IN (SELECT id FROM batch)`, target.table, target.terminal, target.terminal, target.table)
		if _, err := q.Exec(ctx, stmt, cutoff, sessionsGCBatchSize); err != nil {
			return err
		}
	}
	return s.pruneSessionEvents(ctx)
}
