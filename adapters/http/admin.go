package authhttp

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IsAdmin checks whether the given user has the admin role in Postgres.
func IsAdmin(ctx context.Context, pg *pgxpool.Pool, userID string) (bool, error) {
	if pg == nil {
		return false, errors.New("admin_check_unavailable")
	}
	if strings.TrimSpace(userID) == "" {
		return false, errors.New("missing_user_id")
	}
	var isAdmin bool
	err := pg.QueryRow(ctx, `
            SELECT EXISTS (
              SELECT 1 FROM profiles.user_roles ur
              JOIN profiles.roles r ON ur.role_id = r.id
              WHERE ur.user_id = $1 AND r.slug = 'admin'
                AND r.deleted_at IS NULL
                AND EXISTS (
                  SELECT 1 FROM profiles.users u
                  WHERE u.id = $1 AND u.deleted_at IS NULL AND u.banned_at IS NULL
                )
            )
        `, userID).Scan(&isAdmin)
	if err != nil {
		return false, err
	}
	return isAdmin, nil
}
