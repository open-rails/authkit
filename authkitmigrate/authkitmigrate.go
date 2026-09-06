// Package authkitmigrate applies AuthKit's embedded Postgres migrations from
// host code, mirroring rivermigrate's shape:
//
//	migrator := authkitmigrate.New(pool, &authkitmigrate.Config{Schema: cfg.Schema})
//	res, err := migrator.Migrate(ctx)
//
// It is up-only (AuthKit ships no down migrations) and idempotent: tracking is
// name-based in public.migrations under the canonical "authkit" app key via
// migratekit, advisory-locked so concurrent replicas are safe. A non-default
// schema is stamped into the tracking rows, so multiple apps may embed AuthKit
// in the same database under different schemas without colliding.
package authkitmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/open-rails/migratekit"

	migrations "github.com/open-rails/authkit/migrations/postgres"
)

// trackingApp is the canonical migratekit app key AuthKit's migrations have
// always been recorded under.
const trackingApp = "authkit"

// defaultSchema mirrors internal/db.DefaultSchema and the schema the embedded
// DDL is authored against.
const defaultSchema = "profiles"

var schemaNameRE = regexp.MustCompile(`^[a-z_][a-z0-9_]*$`)

// Config configures a Migrator.
type Config struct {
	// Schema is the Postgres schema AuthKit's tables live in; it must match
	// embedded.Config.Schema. Empty defaults to "profiles".
	Schema string
}

// Migrator applies AuthKit's Postgres migrations. Construct with New.
type Migrator struct {
	pool   *pgxpool.Pool
	schema string
}

// New returns a Migrator over the same pool the host passes to embedded.New.
// A nil config targets the default "profiles" schema.
func New(pool *pgxpool.Pool, config *Config) *Migrator {
	m := &Migrator{pool: pool}
	if config != nil {
		m.schema = strings.TrimSpace(config.Schema)
	}
	return m
}

// MigrateResult reports what a Migrate call did.
type MigrateResult struct {
	// Applied is the migration names applied by THIS call, in order; empty
	// when the database was already current.
	Applied []string
}

// Migrate applies all pending AuthKit migrations and reports what it applied.
func (m *Migrator) Migrate(ctx context.Context) (*MigrateResult, error) {
	p, ms, db, err := m.open()
	if err != nil {
		return nil, err
	}
	defer db.Close()

	if err := setup(ctx, p); err != nil {
		return nil, fmt.Errorf("authkitmigrate: ensure tracking table: %w", err)
	}
	before, err := p.Applied(ctx)
	if err != nil {
		return nil, fmt.Errorf("authkitmigrate: read applied migrations: %w", err)
	}
	if err := p.ApplyMigrations(ctx, ms); err != nil {
		return nil, fmt.Errorf("authkitmigrate: apply migrations: %w", err)
	}
	after, err := p.Applied(ctx)
	if err != nil {
		return nil, fmt.Errorf("authkitmigrate: read applied migrations: %w", err)
	}

	seen := make(map[string]bool, len(before))
	for _, name := range before {
		seen[name] = true
	}
	res := &MigrateResult{}
	for _, name := range after {
		if !seen[name] {
			res.Applied = append(res.Applied, name)
		}
	}
	return res, nil
}

// setupAttempts bounds the Setup retry loop; a loser that keeps colliding
// past this is not racing, it is broken.
const setupAttempts = 8

// setup ensures the tracking table exists. Migrators racing a fresh database
// (a host's Postgres and ClickHouse migration groups both track in
// public.migrations) hit Postgres's concurrent-create race on each idempotent
// DDL statement behind Setup — CREATE TABLE / ADD COLUMN / CREATE INDEX ... IF
// NOT EXISTS — and the loser fails with a duplicate key on a catalog index or
// a duplicate object. Every statement is a no-op once the winner has
// committed, so the loser retries with a short backoff (migratekit's own
// ApplyMigrations retries once, which covers a single lost statement; two
// migrators in lockstep lose several in a row).
func setup(ctx context.Context, p *migratekit.Postgres) error {
	for attempt := 1; ; attempt++ {
		err := p.Setup(ctx)
		if err == nil || attempt == setupAttempts || !isConcurrentDDL(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(attempt) * 10 * time.Millisecond):
		}
	}
}

// isConcurrentDDL reports the SQLSTATEs a lost "... IF NOT EXISTS" race
// surfaces as: unique_violation on a catalog index, duplicate_table,
// duplicate_object, duplicate_column.
func isConcurrentDDL(err error) bool {
	var state interface{ SQLState() string }
	if !errors.As(err, &state) {
		return false
	}
	switch state.SQLState() {
	case "23505", "42P07", "42710", "42701":
		return true
	}
	return false
}

// Validate returns nil when every AuthKit migration has been applied, and an
// error naming the pending ones otherwise. Intended for host startup checks.
func (m *Migrator) Validate(ctx context.Context) error {
	p, ms, db, err := m.open()
	if err != nil {
		return err
	}
	defer db.Close()
	return p.ValidateAllApplied(ctx, ms)
}

// open builds the migratekit migrator over dedicated sessions opened from the
// host pool's connection config (its connect hooks included) and closed by the
// caller: migration session state (a plain SET, a leaked lock_timeout) must
// never be released back into the host's pool (#302). migratekit pins one
// session for the advisory lock and applies on another, so two are needed.
// The default schema deliberately uses NO WithSchema so tracking rows keep the
// historical schema-less stamp existing deployments already have.
func (m *Migrator) open() (*migratekit.Postgres, []migratekit.Migration, *sql.DB, error) {
	if m == nil || m.pool == nil {
		return nil, nil, nil, fmt.Errorf("authkitmigrate: a non-nil *pgxpool.Pool is required")
	}
	if m.schema != "" && (len(m.schema) > 63 || !schemaNameRE.MatchString(m.schema)) {
		return nil, nil, nil, fmt.Errorf("authkitmigrate: invalid schema %q (want lowercase identifier matching ^[a-z_][a-z0-9_]*$, max 63 bytes)", m.schema)
	}
	ms, err := migratekit.LoadFromFS(migrations.FS)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("authkitmigrate: load embedded migrations: %w", err)
	}
	cfg := m.pool.Config()
	var opts []stdlib.OptionOpenDB
	if cfg.BeforeConnect != nil {
		opts = append(opts, stdlib.OptionBeforeConnect(cfg.BeforeConnect))
	}
	if cfg.AfterConnect != nil {
		opts = append(opts, stdlib.OptionAfterConnect(cfg.AfterConnect))
	}
	db := stdlib.OpenDB(*cfg.ConnConfig.Copy(), opts...)
	db.SetMaxOpenConns(2)
	p := migratekit.NewPostgres(db, trackingApp)
	if m.schema != "" && m.schema != defaultSchema {
		p = p.WithSchema(m.schema, defaultSchema)
	}
	return p, ms, db, nil
}
