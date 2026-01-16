package core

import (
	"context"
	"time"
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
	rows, err := s.pg.Query(ctx, `
		SELECT id::text
		FROM profiles.users
		WHERE deleted_at IS NOT NULL AND deleted_at < $1
		ORDER BY deleted_at ASC
		LIMIT $2
	`, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// HardDeleteUser permanently deletes the user row and dependent AuthKit rows via ON DELETE CASCADE.
func (s *Service) HardDeleteUser(ctx context.Context, userID string) error {
	return s.AdminDeleteUser(ctx, userID)
}

