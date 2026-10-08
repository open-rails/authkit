package authkit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/engine"
)

// MigrateOptions configures Migrate beyond what Config declares.
type MigrateOptions = config.MigrateOptions

// Migrate applies AuthKit's PostgreSQL migrations to cfg.Schema and River's to
// cfg.RiverSchema through a privileged pool, whether Start will run AuthKit's
// own River client or a host fleet in that schema (River's migrations are
// idempotent and serialized with the host's). New and Start never run DDL, so
// runtime credentials can be restricted. Migrate creates the schemas; callers
// must not.
func Migrate(ctx context.Context, pool *pgxpool.Pool, cfg Config, opts MigrateOptions) error {
	return engine.Migrate(ctx, pool, cfg, opts)
}
