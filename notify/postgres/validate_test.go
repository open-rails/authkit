package postgres

import (
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
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
	if _, err := pool.Exec(ctx, `DELETE FROM `+schema+`.notify_migrations WHERE version=4`); err != nil {
		t.Fatal(err)
	}
	if err := Validate(ctx, read, schema); err == nil {
		t.Fatal("pending visibility migration accepted")
	}
}
