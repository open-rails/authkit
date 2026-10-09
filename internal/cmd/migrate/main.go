// Command migrate creates or upgrades AuthKit's tables in a database for the
// repository's own tooling (scripts/check.sh: sqlc's live checks and the
// shared test schema). Applications never run it: authkit.New migrates.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/engine"
)

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL connection string")
	schema := flag.String("schema", "profiles", "AuthKit PostgreSQL schema")
	riverSchema := flag.String("river-schema", "public", "River PostgreSQL schema")
	flag.Parse()
	if *dsn == "" {
		log.Fatal("-dsn is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		log.Fatalf("connect to PostgreSQL: %v", err)
	}
	defer pool.Close()
	if err := engine.Migrate(ctx, pool, config.DatabaseConfig{Schema: *schema, RiverSchema: *riverSchema}); err != nil {
		log.Fatalf("migrate: %v", err)
	}
}
