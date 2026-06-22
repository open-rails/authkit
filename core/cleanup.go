package core

import "context"

// CleanupExpiredAuthState removes expired transient AuthKit state that lives in
// postgres. Short-lived verification state — pending registrations, pending
// email/phone changes, email/phone verifications, and password resets — now
// lives entirely in the ephemeral store (Redis when multi-instance, in-memory
// otherwise) and expires automatically by TTL, so no database sweep is needed
// for it. The only persistent auth state requiring a sweep is revoked/expired
// refresh sessions.
// Deprecated: use s.Sessions().CleanupExpiredAuthState.
func (s *Service) CleanupExpiredAuthState(ctx context.Context) error {
	if err := s.requirePG(); err != nil {
		return err
	}

	return s.q.SessionsDeleteRevokedOrExpired(ctx)
}
