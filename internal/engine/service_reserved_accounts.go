package engine

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit/iam"
)

// isUserReserved reports whether a user is a reserved, non-loginable placeholder
// (the `reserved` metadata flag). The login gate (ensureUserAccess) consults it
// so reserved placeholders cannot authenticate. The owner-namespace reservation
// FLOW that set this flag was removed in the permission-group hard cut (#111);
// the read gate stays as defense-in-depth for any externally-set flag.
func (s *Engine) isUserReserved(ctx context.Context, userID string) (bool, error) {
	if err := s.requirePG(); err != nil {
		return false, err
	}
	if strings.TrimSpace(userID) == "" {
		return false, fmt.Errorf("invalid_user")
	}
	reserved, err := s.q.UserIsReserved(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, iam.ErrUserNotFound
		}
		return false, err
	}
	return reserved, nil
}

// Inspect the exact normalized JSON written to PostgreSQL, including values
// supplied through json.RawMessage or a host's custom JSON marshaler.
func metadataMarksReserved(raw []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	return strings.TrimSpace(string(fields["reserved"])) == "true"
}
