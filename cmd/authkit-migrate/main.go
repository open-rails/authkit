// Command authkit-migrate is AuthKit's repository-owned migration runner.
// Consumers should call embedded.ApplyMigrations from their application
// startup instead of importing this command or AuthKit's private source.
package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
)

func main() {
	dsn := flag.String("dsn", "", "PostgreSQL connection string")
	schema := flag.String("schema", "profiles", "AuthKit PostgreSQL schema")
	riverSchema := flag.String("river-schema", "public", "Managed River PostgreSQL schema")
	hostRiver := flag.Bool("host-river", false, "Host owns River migrations; initialize only AuthKit")
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
	if err := pool.Ping(ctx); err != nil {
		log.Fatalf("ping PostgreSQL: %v", err)
	}
	opts := embedded.MigrationOptions{RiverSchema: *riverSchema}
	if *hostRiver {
		opts.River = embedded.RiverFromHost()
	}
	if err := embedded.ApplyMigrations(ctx, pool, *schema, opts); err != nil {
		log.Fatalf("apply AuthKit migrations: %v", err)
	}
}
