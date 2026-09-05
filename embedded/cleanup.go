package embedded

import (
	"context"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// inviteRetention is how long dead invite rows (expired, consumed/redeemed,
// declined, or revoked) are kept for audit before the cleanup sweep purges them
// (#235). Pending, unexpired rows are never touched.
const inviteRetention = 90 * 24 * time.Hour

// sessionsGCBatchSize bounds one dead-session DELETE (#325): never an
// unbounded statement, same rule as session_events (#245).
const sessionsGCBatchSize int64 = 5000

// gcDeadSessions removes revoked/expired refresh sessions (history cascades)
// in bounded batches until a short batch; it reports the batches issued.
func (s *Client) gcDeadSessions(ctx context.Context, batchSize int64) (int, error) {
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
// long-dead invite rows (retained inviteRetention past their terminal moment),
// and session-event history past Config.SessionEventRetention (#245).
func (s *Client) CleanupExpiredAuthState(ctx context.Context) error {
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

	cutoff := time.Now().UTC().Add(-inviteRetention)
	q := db.ForSchema(s.pg, s.dbSchema())
	for _, stmt := range []string{
		`DELETE FROM profiles.group_invite_links
		  WHERE redeemed_at < $1 OR revoked_at < $1 OR expires_at < $1`,
		`DELETE FROM profiles.account_registration_invites
		  WHERE consumed_at < $1 OR revoked_at < $1 OR expires_at < $1`,
	} {
		if _, err := q.Exec(ctx, stmt, cutoff); err != nil {
			return err
		}
	}
	return s.pruneSessionEvents(ctx)
}
