package authkit

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit/internal/engine"
)

// MigrateOptions configures Migrate. Schema is AuthKit's PostgreSQL schema
// ("" selects "profiles"); it must match Config.Schema. River uses the same
// declaration as Deps.River: nil owns River initialization, RiverFromHost
// skips it. RiverSchema defaults to public, matching Config.River.
type MigrateOptions struct {
	Schema      string
	River       *RiverOwnership
	RiverSchema string
	// RuntimePool identifies the existing database user that will run AuthKit.
	// When supplied, initialization grants that user runtime access directly.
	// Both pools must connect to the same database and remain host-owned.
	// Nil applies migrations without provisioning runtime privileges.
	RuntimePool *pgxpool.Pool
}

// Migrate applies AuthKit's PostgreSQL migrations to a privileged pool. It
// also initializes managed River unless RiverFromHost is declared. New and
// Start never run DDL, so runtime credentials can be separately restricted.
//
// AuthKit owns its migration source and runner; the host supplies the pool,
// then calls New once Migrate succeeds. Migrate creates the schema; callers
// must not create it separately.
func Migrate(ctx context.Context, pool *pgxpool.Pool, opts MigrateOptions) error {
	return engine.Migrate(ctx, pool, opts.engine())
}
