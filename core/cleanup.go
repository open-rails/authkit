package core

import "context"

// CleanupExpiredAuthState removes expired transient AuthKit state that lives in
// postgres. Short-lived verification state — pending registrations, pending
// email/phone changes, email/phone verifications, and password resets — now
// lives entirely in the ephemeral store (Redis when multi-instance, in-memory
// otherwise) and expires automatically by TTL, so no database sweep is needed
// for it. The only persistent auth state requiring a sweep is revoked/expired
// refresh sessions.
func (s *Service) CleanupExpiredAuthState(ctx context.Context) error {
	if err := s.requirePG(); err != nil {
		return err
	}

	if _, err := s.pg.Exec(ctx, `
		DELETE FROM profiles.refresh_sessions
		WHERE revoked_at IS NOT NULL
		   OR (expires_at IS NOT NULL AND expires_at <= NOW())
	`); err != nil {
		return err
	}

	return nil
}
