package authcore

import (
	"context"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// inviteRetention is how long dead invite rows (expired, consumed/redeemed,
// declined, or revoked) are kept for audit before the cleanup sweep purges them
// (#235). Pending, unexpired rows are never touched.
const inviteRetention = 90 * 24 * time.Hour

// CleanupExpiredAuthState removes expired transient AuthKit state that lives in
// postgres. Short-lived verification state — pending registrations, pending
// email/phone changes, email/phone verifications, and password resets — now
// lives entirely in the ephemeral store (Redis when multi-instance, in-memory
// otherwise) and expires automatically by TTL, so no database sweep is needed
// for it. The postgres sweep covers revoked/expired refresh sessions,
// long-dead invite rows (retained inviteRetention past their terminal moment),
// and session-event history past Config.SessionEventRetention (#245).
func (s *Service) CleanupExpiredAuthState(ctx context.Context) error {
	if err := s.requirePG(); err != nil {
		return err
	}

	if err := s.q.SessionsDeleteRevokedOrExpired(ctx); err != nil {
		return err
	}

	cutoff := time.Now().UTC().Add(-inviteRetention)
	q := db.ForSchema(s.pg, s.dbSchema())
	for _, stmt := range []string{
		`DELETE FROM profiles.group_invite_links
		  WHERE redeemed_at < $1 OR revoked_at < $1 OR expires_at < $1`,
		`DELETE FROM profiles.account_registration_invites
		  WHERE consumed_at < $1 OR revoked_at < $1 OR expires_at < $1`,
		`DELETE FROM profiles.group_membership_invites
		  WHERE accepted_at < $1 OR declined_at < $1 OR revoked_at < $1 OR expires_at < $1`,
	} {
		if _, err := q.Exec(ctx, stmt, cutoff); err != nil {
			return err
		}
	}
	return s.pruneSessionEvents(ctx)
}
