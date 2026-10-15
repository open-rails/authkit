package authkit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/engine"
)

// ErrMigrationsRequired means New could not confirm the required database
// migrations. The underlying validation failure remains available to errors.Is
// and errors.As. Run Migrate explicitly before starting the application.
var ErrMigrationsRequired = engine.ErrMigrationsRequired

// Migrate explicitly prepares AuthKit's and River's schemas without building
// an AuthKit runtime. It applies migrations even when SkipMigrations is true;
// that setting controls automatic application startup only.
func Migrate(ctx context.Context, pool *pgxpool.Pool, database DatabaseConfig) error {
	return engine.Migrate(ctx, pool, database)
}
