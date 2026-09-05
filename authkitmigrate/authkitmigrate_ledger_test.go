package authkitmigrate_test

import (
	"bytes"
	"context"
	"database/sql"
	"log/slog"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/open-rails/migratekit"

	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/internal/testdb"
	migrations "github.com/open-rails/authkit/migrations/postgres"
)

const (
	migration0001 = "0001_auth_schema.up.sql"
	migration0002 = "0002_session_events.up.sql"
)

// #302 edited 0001 in place (SET -> SET LOCAL) because migratekit v1.4.0
// tracked by name alone. migratekit >= v1.5 records a content digest and
// >= v1.8 a token digest, so a database that applied the OLD 0001 must keep
// migrating cleanly under the new ledger: never re-run, never refused.
func TestMigrateOverLedgerThatAppliedOld0001(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	t.Run("v1.5-v1.7 ledger records the old digest; drift is warning-only", func(t *testing.T) {
		pg := testdb.EmptyScratchPostgres(t)
		applyChainWithOld0001(t, ctx, pg.URL)
		// v1.5-v1.7 wrote no token digest.
		if _, err := pg.Pool.Exec(ctx, `UPDATE public.migrations SET semantic_sha256 = NULL`); err != nil {
			t.Fatal(err)
		}
		logs := captureSlog(t)

		m := authkitmigrate.New(pg.Pool, nil)
		res, err := m.Migrate(ctx)
		if err != nil {
			t.Fatalf("Migrate over old-0001 ledger: %v", err)
		}
		if len(res.Applied) != 0 {
			t.Fatalf("nothing may re-run, applied %v", res.Applied)
		}
		if err := m.Validate(ctx); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if out := logs.String(); !strings.Contains(out, migration0001+" was EDITED") {
			t.Fatalf("expected a content-drift warning for 0001, got logs:\n%s", out)
		}

		// 0001 keeps the digest of the bytes that actually ran; unchanged rows
		// get their token digest backfilled.
		var semantic0001, semantic0002 sql.NullString
		if err := pg.Pool.QueryRow(ctx, `SELECT semantic_sha256 FROM public.migrations WHERE app='authkit' AND name=$1`,
			migratekit.Prefix(migration0001)).Scan(&semantic0001); err != nil {
			t.Fatal(err)
		}
		if err := pg.Pool.QueryRow(ctx, `SELECT semantic_sha256 FROM public.migrations WHERE app='authkit' AND name=$1`,
			migratekit.Prefix(migration0002)).Scan(&semantic0002); err != nil {
			t.Fatal(err)
		}
		if semantic0001.Valid {
			t.Fatalf("0001 drifted, its token digest must not be re-stamped silently: %q", semantic0001.String)
		}
		if !semantic0002.Valid {
			t.Fatal("0002 is unchanged, its token digest should be backfilled")
		}
	})

	t.Run("v1.4.0 ledger has no identity columns", func(t *testing.T) {
		pg := testdb.EmptyScratchPostgres(t)
		applyChainWithOld0001(t, ctx, pg.URL)
		// Rows written by <= v1.4.0 carry no filename, digest or status.
		if _, err := pg.Pool.Exec(ctx, `ALTER TABLE public.migrations
			DROP COLUMN filename, DROP COLUMN content_sha256, DROP COLUMN semantic_sha256, DROP COLUMN status, DROP COLUMN "error"`); err != nil {
			t.Fatal(err)
		}
		if _, err := pg.Pool.Exec(ctx, `DROP TABLE public.migration_repairs`); err != nil {
			t.Fatal(err)
		}
		logs := captureSlog(t)

		m := authkitmigrate.New(pg.Pool, nil)
		res, err := m.Migrate(ctx)
		if err != nil {
			t.Fatalf("Migrate over v1.4.0 ledger: %v", err)
		}
		if len(res.Applied) != 0 {
			t.Fatalf("nothing may re-run, applied %v", res.Applied)
		}
		if err := m.Validate(ctx); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if out := logs.String(); out != "" {
			t.Fatalf("a legacy row has nothing to compare, expected no warnings:\n%s", out)
		}

		// The identity columns are back and 0001 stays unknown: nothing may
		// invent a digest for bytes it never saw.
		var digest, semantic sql.NullString
		if err := pg.Pool.QueryRow(ctx, `SELECT content_sha256, semantic_sha256 FROM public.migrations WHERE app='authkit' AND name=$1`,
			migratekit.Prefix(migration0001)).Scan(&digest, &semantic); err != nil {
			t.Fatal(err)
		}
		if digest.Valid || semantic.Valid {
			t.Fatalf("legacy 0001 row was stamped: content=%q semantic=%q", digest.String, semantic.String)
		}
	})
}

// applyChainWithOld0001 applies the full chain as a pre-#302 build did: the
// same files, but 0001 with its plain SET statements.
func applyChainWithOld0001(t *testing.T, ctx context.Context, dbURL string) {
	t.Helper()
	ms, err := migratekit.LoadFromFS(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for i := range ms {
		if ms[i].Name != migration0001 {
			continue
		}
		old := strings.ReplaceAll(ms[i].Content, "SET LOCAL ", "SET ")
		if old == ms[i].Content {
			t.Fatalf("%s no longer carries SET LOCAL; this test models the pre-#302 file", migration0001)
		}
		ms[i].Content = old
		found = true
	}
	if !found {
		t.Fatalf("%s not in the embedded chain", migration0001)
	}
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatal(err)
	}
	defer sqlDB.Close()
	if err := migratekit.NewPostgres(sqlDB, "authkit").ApplyMigrations(ctx, ms); err != nil {
		t.Fatalf("apply chain with old 0001: %v", err)
	}
}

// captureSlog routes slog.Default, migratekit's warning sink, into a buffer
// for the rest of the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}
