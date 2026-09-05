package authcore

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// IsUserReserved reports whether a user is a reserved, non-loginable placeholder
// (the `reserved` metadata flag). The login gate (ensureUserAccess) consults it
// so reserved placeholders cannot authenticate. The owner-namespace reservation
// FLOW that set this flag was removed in the permission-group hard cut (#111);
// the read gate stays as defense-in-depth for any externally-set flag.
func (s *Service) IsUserReserved(ctx context.Context, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	if strings.TrimSpace(userID) == "" {
		return false, fmt.Errorf("invalid_user")
	}
	reserved, err := s.q.UserIsReserved(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrUserNotFound
		}
		return false, err
	}
	return reserved, nil
}
