package core

import (
	"context"
	"time"

	"github.com/open-rails/authkit/internal/db"
)

// ListUsersDeletedBefore returns user IDs for users soft-deleted before the cutoff.
// It is intended for retention/purge workflows in the host application.
func (s *Service) ListUsersDeletedBefore(ctx context.Context, cutoff time.Time, limit int) ([]string, error) {
	if s.pg == nil {
		return nil, nil
	}
	if limit <= 0 {
		limit = 500
	}
	out, err := s.q.UsersPurgeCandidates(ctx, db.UsersPurgeCandidatesParams{Cutoff: &cutoff, MaxRows: int64(limit)})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// HardDeleteUser permanently deletes the user row and dependent AuthKit rows via ON DELETE CASCADE.
func (s *Service) HardDeleteUser(ctx context.Context, userID string) error {
	return s.AdminDeleteUser(ctx, userID)
}
