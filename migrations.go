package authkit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/engine"
)

// MigrateOptions configures Migrate beyond what Config declares.
type MigrateOptions = config.MigrateOptions

// Migrate applies AuthKit's PostgreSQL migrations to cfg.Schema through a
// privileged pool, and River's to cfg.River.Schema unless cfg.River.HostOwned.
// New and Start never run DDL, so runtime credentials can be restricted.
// Migrate creates the schemas; callers must not.
func Migrate(ctx context.Context, pool *pgxpool.Pool, cfg Config, opts MigrateOptions) error {
	return engine.Migrate(ctx, pool, cfg, opts)
}
