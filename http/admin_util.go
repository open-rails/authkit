package authhttp

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/db"
)

// IsAdmin checks whether the given user has the admin role in Postgres.
// It assumes the default "profiles" schema; hosts that configure
// core.Config.Schema should use IsAdminInSchema with svc.Schema().
func IsAdmin(ctx context.Context, pg *pgxpool.Pool, userID string) (bool, error) {
	return IsAdminInSchema(ctx, pg, db.DefaultSchema, userID)
}

// IsAdminInSchema is IsAdmin against AuthKit tables in the given schema.
func IsAdminInSchema(ctx context.Context, pg *pgxpool.Pool, schema, userID string) (bool, error) {
	return HasRoleDBCheckInSchema(ctx, pg, schema, userID, "admin")
}

// HasRoleDBCheck checks whether the given user has the provided role slug in Postgres.
// It also verifies the user is not deleted or banned.
// It assumes the default "profiles" schema; hosts that configure
// core.Config.Schema should use HasRoleDBCheckInSchema with svc.Schema().
func HasRoleDBCheck(ctx context.Context, pg *pgxpool.Pool, userID, role string) (bool, error) {
	return HasRoleDBCheckInSchema(ctx, pg, db.DefaultSchema, userID, role)
}

// HasRoleDBCheckInSchema is HasRoleDBCheck against AuthKit tables in the given schema.
func HasRoleDBCheckInSchema(ctx context.Context, pg *pgxpool.Pool, schema, userID, role string) (bool, error) {
	if pg == nil {
		return false, errors.New("role_check_unavailable")
	}
	if strings.TrimSpace(userID) == "" {
		return false, errors.New("missing_user_id")
	}
	if strings.TrimSpace(role) == "" {
		return false, errors.New("missing_role")
	}
	if schema != "" && !db.ValidSchemaName(schema) {
		return false, errors.New("invalid_schema")
	}
	q := db.New(db.ForSchema(pg, schema))
	return q.GlobalUserHasActiveRole(ctx, db.GlobalUserHasActiveRoleParams{UserID: userID, Slug: role})
}
