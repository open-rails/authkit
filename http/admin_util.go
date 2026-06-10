package authhttp

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
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
	return db.New(pg).GlobalUserHasActiveRole(ctx, db.GlobalUserHasActiveRoleParams{UserID: userID, Slug: role})
}
