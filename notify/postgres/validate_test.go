package postgres

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/migratekit"
)

func TestValidateInboxReadOnlyAndDoesNotCreateMissingSchema(t *testing.T) {
	_, pool, schema := database(t)
	ctx := t.Context()
	cfg := pool.Config()
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	read, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	if err := Validate(ctx, read, schema); err != nil {
		t.Fatal(err)
	}
	missing := schema + "_missing"
	if err := Validate(ctx, read, missing); err == nil {
		t.Fatal("missing schema accepted")
	}
	var exists bool
	if err := pool.QueryRow(ctx, `SELECT to_regnamespace($1) IS NOT NULL`, missing).Scan(&exists); err != nil || exists {
		t.Fatalf("validation created missing schema: %t %v", exists, err)
	}
	// An inbox that ran its migration with other content, as one built before
	// AuthKit v1.58.0 did, is refused by both; nothing is applied.
	if _, err := pool.Exec(ctx, `UPDATE public.migrations SET content_sha256 = md5(content_sha256) WHERE app = $1 AND schema = $2`, app, schema); err != nil {
		t.Fatal(err)
	}
	if err := Validate(ctx, read, schema); !errors.Is(err, migratekit.ErrMigrationEdited) {
		t.Fatalf("edited inbox migration accepted: %v", err)
	}
	if err := Migrate(ctx, pool, schema); !errors.Is(err, migratekit.ErrMigrationEdited) {
		t.Fatalf("edited inbox migration migrated: %v", err)
	}
	if _, err := pool.Exec(ctx, `DELETE FROM public.migrations WHERE app = $1 AND schema = $2`, app, schema); err != nil {
		t.Fatal(err)
	}
	if err := Validate(ctx, read, schema); err == nil {
		t.Fatal("missing inbox migration accepted")
	}
}
