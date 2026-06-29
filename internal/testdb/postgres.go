// Package testdb owns AuthKit's Postgres integration-test harness.
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	pgmigrations "github.com/open-rails/authkit/migrations/postgres"
	"github.com/open-rails/migratekit"
)

// Postgres is an isolated migrated database for integration tests.
type Postgres struct {
	Pool     *pgxpool.Pool
	URL      string
	Database string
}

// ScratchPostgres creates, migrates, and cleans up a scratch database on the
// server named by QUERY_TEST_DATABASE_URL, AUTHKIT_TEST_DATABASE_URL, or
// SQLC_DATABASE_URL. It skips when no URL is provided so ordinary go test runs do
// not start integration infrastructure by accident.
func ScratchPostgres(t testing.TB) *Postgres {
	t.Helper()
	baseURL := firstEnv("QUERY_TEST_DATABASE_URL", "AUTHKIT_TEST_DATABASE_URL", "SQLC_DATABASE_URL")
	if baseURL == "" {
		t.Skip("QUERY_TEST_DATABASE_URL/AUTHKIT_TEST_DATABASE_URL/SQLC_DATABASE_URL not set; skipping DB-backed test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	dbName := scratchDBName()
	adminURL, err := withDatabase(baseURL, "postgres")
	if err != nil {
		t.Fatalf("parse postgres URL: %v", err)
	}
	testURL, err := withDatabase(baseURL, dbName)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect postgres admin database: %v", err)
	}
	defer admin.Close()

	if _, err := admin.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{dbName}.Sanitize()); err != nil {
		t.Fatalf("create scratch database %s: %v", dbName, err)
	}

	pool, err := pgxpool.New(ctx, testURL)
	if err != nil {
		dropDatabase(context.Background(), adminURL, dbName)
		t.Fatalf("connect scratch database: %v", err)
	}

	pg := &Postgres{Pool: pool, URL: testURL, Database: dbName}
	t.Cleanup(func() {
		pool.Close()
		if os.Getenv("QUERY_TEST_KEEP_DB") == "" {
			dropDatabase(context.Background(), adminURL, dbName)
		} else {
			t.Logf("kept scratch database %s", dbName)
		}
	})

	ApplyMigrations(t, ctx, testURL)
	return pg
}

// ApplyMigrations applies AuthKit's embedded Postgres migrations to dbURL.
func ApplyMigrations(t testing.TB, ctx context.Context, dbURL string) {
	t.Helper()
	sqlDB, err := sql.Open("pgx", dbURL)
	if err != nil {
		t.Fatalf("open sql db: %v", err)
	}
	defer sqlDB.Close()

	ms, err := migratekit.LoadFromFS(pgmigrations.FS)
	if err != nil {
		t.Fatalf("load authkit migrations: %v", err)
	}
	if err := migratekit.NewPostgres(sqlDB, "authkit").ApplyMigrations(ctx, ms); err != nil {
		t.Fatalf("apply authkit migrations: %v", err)
	}
}

func firstEnv(keys ...string) string {
	for _, key := range keys {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return ""
}

func scratchDBName() string {
	return "authkit_qtest_" + strconv.Itoa(os.Getpid()) + "_" + strconv.FormatInt(time.Now().UnixNano(), 36)
}

func withDatabase(raw, database string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("expected postgres URL, got %q", raw)
	}
	u.Path = "/" + database
	return u.String(), nil
}

func dropDatabase(ctx context.Context, adminURL, dbName string) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		return
	}
	defer admin.Close()
	_, _ = admin.Exec(ctx, `SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, dbName)
	_, _ = admin.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{dbName}.Sanitize())
}
