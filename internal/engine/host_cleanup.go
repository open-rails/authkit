package engine

import (
	"context"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// terminalRetention keeps revoked/expired keys and invitations available for
// host inspection for 90 days. Live credentials have no cleanup deadline.
const terminalRetention = 90 * 24 * time.Hour

// sessionsGCBatchSize bounds one dead-session DELETE (#325): never an
// unbounded statement, same rule as session_events (#245).
const sessionsGCBatchSize int64 = 5000

// gcDeadSessions removes revoked/expired refresh sessions (history cascades)
// in bounded batches until a short batch; it reports the batches issued.
func (s *Engine) gcDeadSessions(ctx context.Context, batchSize int64) (int, error) {
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

// cleanupExpiredAuthState is the periodic maintenance sweep: expired
// ephemeral rows (codes, ceremonies, counters) and rate-limit budgets,
// revoked/expired refresh sessions and their consumed-token history, terminal
// keys/invites (retained terminalRetention after their first terminal event),
// and session-event history past Config.SessionEventRetention (#245).
func (s *Engine) cleanupExpiredAuthState(ctx context.Context) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if _, err := s.purgeExpiredEphemeral(ctx); err != nil {
		return err
	}
	if _, err := s.purgeExpiredRateLimits(ctx); err != nil {
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
	if _, err := s.gcTerminalAccountDeletions(ctx, cutoff, sessionsGCBatchSize); err != nil {
		return err
	}
	// One bounded batch per table; each locks only its batch, so another
	// worker can make progress without waiting.
	if err := s.q.InviteLinksDeleteExpiredBatch(ctx, db.InviteLinksDeleteExpiredBatchParams{Cutoff: cutoff, BatchSize: sessionsGCBatchSize}); err != nil {
		return err
	}
	if err := s.q.AccountInvitesDeleteExpiredBatch(ctx, db.AccountInvitesDeleteExpiredBatchParams{Cutoff: cutoff, BatchSize: sessionsGCBatchSize}); err != nil {
		return err
	}
	if err := s.q.APIKeysDeleteExpiredBatch(ctx, db.APIKeysDeleteExpiredBatchParams{Cutoff: cutoff, BatchSize: sessionsGCBatchSize}); err != nil {
		return err
	}
	return s.pruneSessionEvents(ctx)
}

// Lifecycle history shares the existing private 90-day terminal retention.
// Pending callbacks and active generations are never eligible. One bounded
// batch per maintenance tick deletes completed receipts through their FK;
// old River retries safely no-op when the generation or receipt is absent.
func (s *Engine) gcTerminalAccountDeletions(ctx context.Context, cutoff time.Time, batchSize int64) (int64, error) {
	return s.q.AccountDeletionsDeleteTerminalBatch(ctx, db.AccountDeletionsDeleteTerminalBatchParams{Cutoff: cutoff, BatchSize: batchSize})
}
