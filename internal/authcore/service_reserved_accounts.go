package authcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/open-rails/authkit/internal/db"
)

// GetUserMetadata returns a user's arbitrary metadata (internal/admin flags).
func (s *Service) GetUserMetadata(ctx context.Context, userID string) (map[string]any, error) {
	if err := s.requirePG(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(userID) == "" {
		return nil, fmt.Errorf("invalid_user")
	}
	raw, err := s.q.UserMetadata(ctx, userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PatchUserMetadata merges patch into a user's metadata.
func (s *Service) PatchUserMetadata(ctx context.Context, userID string, patch map[string]any) error {
	if err := s.requirePG(); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" {
		return fmt.Errorf("invalid_user")
	}
	if len(patch) == 0 {
		return nil
	}
	raw, err := json.Marshal(patch)
	if err != nil {
		return err
	}
	n, err := s.q.UserMetadataPatch(ctx, db.UserMetadataPatchParams{ID: userID, Patch: raw})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrUserNotFound
	}
	return nil
}

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
