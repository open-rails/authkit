package engine

import (
	"context"

	"github.com/open-rails/authkit/internal/authflow"
)

// Setup shortcuts over engine internals that production reaches only
// through the HTTP flows.

func (s *Engine) enableFactor(ctx context.Context, userID, method string, phone *string, mode authflow.FactorEnrollmentMode) ([]string, error) {
	codes, _, err := s.enable2FA(ctx, factorEnable{UserID: userID, Method: method, Phone: phone, Mode: mode})
	return codes, err
}

func (s *Engine) enableDefaultFactor(ctx context.Context, userID, method string, phone *string, mode authflow.FactorEnrollmentMode) ([]string, error) {
	codes, _, err := s.enable2FA(ctx, factorEnable{UserID: userID, Method: method, Phone: phone, MakeDefault: true, Mode: mode})
	return codes, err
}

func (s *Engine) enableTOTPFactor(ctx context.Context, in totpEnrollment) ([]string, error) {
	codes, _, err := s.enableTOTP2FA(ctx, in, "")
	return codes, err
}

func (s *Engine) consumeRegistrationInvite(ctx context.Context, email, userID, token string) error {
	return s.consumeAccountRegistrationInvite(contextWithAccountRegistrationInviteToken(ctx, token), email, userID)
}
