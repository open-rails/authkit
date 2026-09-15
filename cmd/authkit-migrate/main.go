// authkit-migrate prepares a database for local development and CI. Applications
// normally call authkitmigrate directly during their own startup.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authkitmigrate"
)

func main() {
	schema := flag.String("schema", "profiles", "AuthKit database schema")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected arguments; use --schema to select a schema")
	}
	dsn := os.Getenv("AUTHKIT_DATABASE_URL")
	if dsn == "" {
		log.Fatal("AUTHKIT_DATABASE_URL is required")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		log.Fatal("invalid AUTHKIT_DATABASE_URL")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	if err := authkitmigrate.New(pool, &authkitmigrate.Config{Schema: *schema}).Migrate(ctx); err != nil {
		log.Fatal(err)
	}
	log.Print("AuthKit schema ready")
}
