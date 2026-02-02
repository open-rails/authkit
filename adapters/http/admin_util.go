package authhttp

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IsAdmin checks whether the given user has the admin role in Postgres.
func IsAdmin(ctx context.Context, pg *pgxpool.Pool, userID string) (bool, error) {
	return HasRoleDBCheck(ctx, pg, userID, "admin")
}

// HasRoleDBCheck checks whether the given user has the provided role slug in Postgres.
// It also verifies the user is not deleted or banned.
func HasRoleDBCheck(ctx context.Context, pg *pgxpool.Pool, userID, role string) (bool, error) {
	if pg == nil {
		return false, errors.New("role_check_unavailable")
	}
	if strings.TrimSpace(userID) == "" {
		return false, errors.New("missing_user_id")
	}
	if strings.TrimSpace(role) == "" {
		return false, errors.New("missing_role")
	}
	var hasRole bool
	err := pg.QueryRow(ctx, `
            SELECT EXISTS (
              SELECT 1 FROM profiles.user_roles ur
              JOIN profiles.roles r ON ur.role_id = r.id
              WHERE ur.user_id = $1 AND r.slug = $2
                AND r.deleted_at IS NULL
                AND EXISTS (
                  SELECT 1 FROM profiles.users u
                  WHERE u.id = $1 AND u.deleted_at IS NULL AND u.banned_at IS NULL
                )
            )
        `, userID, role).Scan(&hasRole)
	if err != nil {
		return false, err
	}
	return hasRole, nil
}
