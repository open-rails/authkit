package engine

import (
	"context"

	"github.com/open-rails/authkit/internal/authflow"
)

// Setup shortcuts over engine internals that production reaches only
// through the HTTP flows.

func (s *Engine) enableFactor(ctx context.Context, userID, method string, phone *string, mode authflow.FactorEnrollmentMode) ([]string, error) {
	codes, _, err := s.enable2FA(ctx, factorEnable{UserID: userID, Method: method, Phone: phone, Email: s.fixtureFactorEmail(ctx, userID), Mode: mode})
	return codes, err
}

func (s *Engine) enableDefaultFactor(ctx context.Context, userID, method string, phone *string, mode authflow.FactorEnrollmentMode) ([]string, error) {
	codes, _, err := s.enable2FA(ctx, factorEnable{UserID: userID, Method: method, Phone: phone, Email: s.fixtureFactorEmail(ctx, userID), MakeDefault: true, Mode: mode})
	return codes, err
}

// fixtureFactorEmail is the account's current address, which a real email
// factor enrollment proves before pinning it.
func (s *Engine) fixtureFactorEmail(ctx context.Context, userID string) *string {
	var email *string
	_ = s.pg.QueryRow(ctx, `SELECT email::text FROM users WHERE id=$1::uuid`, userID).Scan(&email)
	return email
}

func (s *Engine) enableTOTPFactor(ctx context.Context, in totpEnrollment) ([]string, error) {
	codes, _, err := s.enableTOTP2FA(ctx, in, "")
	return codes, err
}

func (s *Engine) consumeRegistrationInvite(ctx context.Context, email, userID, token string) error {
	return s.consumeAccountRegistrationInvite(contextWithAccountRegistrationInviteToken(ctx, token), email, userID)
}
