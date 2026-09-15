// Package authkitmigrate installs AuthKit's schema using the host's PostgreSQL
// connection configuration. Migrate is idempotent and returns only an error;
// Validate requires exact identity and content of every installed migration.
package authkitmigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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

// Migrate applies the fresh baseline and pending migrations. Earlier prerelease
// schemas or unknown/drifted ledger identities are refused without deleting data.
func (m *Migrator) Migrate(ctx context.Context) error {
	p, ms, db, err := m.open()
	if err != nil {
		return err
	}
	defer db.Close()
	if err := setup(ctx, p); err != nil {
		return fmt.Errorf("authkitmigrate: ensure tracking table: %w", err)
	}
	if err := validateLedger(ctx, p, ms, false); err != nil {
		return err
	}
	if err := p.ApplyMigrations(ctx, ms); err != nil {
		return fmt.Errorf("authkitmigrate: apply migrations: %w", err)
	}
	return validateLedger(ctx, p, ms, true)
}

// Validate the actual filename and digest, not just a reused numeric prefix.
// A fresh database may have no records; startup validation also requires every
// expected migration. migratekit continues to own locking and atomic apply.
func validateLedger(ctx context.Context, p *migratekit.Postgres, ms []migratekit.Migration, complete bool) error {
	records, err := p.AppliedRecords(ctx)
	if err != nil {
		return fmt.Errorf("authkitmigrate: schema ledger unavailable; migrate a fresh AuthKit schema: %w", err)
	}
	expected := make(map[string]migratekit.Migration, len(ms))
	for _, migration := range ms {
		expected[migratekit.Prefix(migration.Name)] = migration
	}
	for key, record := range records {
		migration, known := expected[key]
		if !known || record.Filename != migration.Name || record.Digest != migratekit.ContentDigest(migration.Content) || record.SemanticDigest != migratekit.SemanticContentDigest(migration.Content) || record.Status != migratekit.StatusApplied {
			return fmt.Errorf("authkitmigrate: unsupported schema ledger entry %q; use a fresh AuthKit schema and reset only its scoped migration ledger", key)
		}
	}
	if complete {
		for key, migration := range expected {
			if _, ok := records[key]; !ok {
				return fmt.Errorf("authkitmigrate: required migration %s is not applied", migration.Name)
			}
		}
	}
	return nil
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

// Validate requires every current migration with exact identity, digests and
// applied status. It performs no migration or repair.
func (m *Migrator) Validate(ctx context.Context) error {
	p, ms, db, err := m.open()
	if err != nil {
		return err
	}
	defer db.Close()
	return validateLedger(ctx, p, ms, true)
}

// open builds the migratekit migrator over dedicated sessions opened from the
// host pool's connection config (its connect hooks included) and closed by the
// caller: migration session state (a plain SET, a leaked lock_timeout) must
// never be released back into the host's pool (#302). migratekit pins one
// session for the advisory lock and applies on another, so two are needed.
// The default schema deliberately uses NO WithSchema so tracking rows keep the
// canonical schema-less stamp shared with default raw-FS runners.
func (m *Migrator) open() (*migratekit.Postgres, []migratekit.Migration, *sql.DB, error) {
	if m == nil || m.pool == nil {
		return nil, nil, nil, fmt.Errorf("authkitmigrate: a non-nil *pgxpool.Pool is required")
	}
	fsys, err := migrations.FSForSchema(m.schema)
	if err != nil {
		return nil, nil, nil, err
	}
	ms, err := migratekit.LoadFromFS(fsys)
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
