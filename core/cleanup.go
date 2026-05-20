package core

import "context"

// CleanupExpiredAuthState removes expired transient AuthKit state.
func (s *Service) CleanupExpiredAuthState(ctx context.Context) error {
	if err := s.requirePG(); err != nil {
		return err
	}

	if _, err := s.pg.Exec(ctx, `DELETE FROM profiles.email_verifications WHERE expires_at <= NOW()`); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `DELETE FROM profiles.password_resets WHERE expires_at <= NOW()`); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `
		DELETE FROM profiles.refresh_sessions
		WHERE revoked_at IS NOT NULL
		   OR (expires_at IS NOT NULL AND expires_at <= NOW())
	`); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `DELETE FROM profiles.pending_registrations WHERE expires_at <= NOW()`); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `DELETE FROM profiles.pending_phone_registrations WHERE expires_at <= NOW()`); err != nil {
		return err
	}
	if _, err := s.pg.Exec(ctx, `DELETE FROM profiles.phone_verifications WHERE expires_at <= NOW() OR used_at IS NOT NULL`); err != nil {
		return err
	}

	return nil
}
