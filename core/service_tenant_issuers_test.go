package core

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// testPG returns a pool against AUTHKIT_TEST_DATABASE_URL, or skips. The
// Postgres migrations in migrations/postgres must already be applied.
func testPG(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestTenantIssuerRoundTrip(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()

	iss := "https://cozy.example/roundtrip"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, "cozy-art")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, "cozy-art") })
	if _, err := svc.CreateTenant(ctx, "cozy-art"); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() { _ = svc.DeleteTenantIssuer(ctx, iss) })

	// Upsert (insert).
	fi, err := svc.UpsertTenantIssuer(ctx, TenantIssuer{
		TenantSlug: "cozy-art",
		Issuer:     iss,
		JWKSURI:    "https://cozy.example/.well-known/jwks.json",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if !fi.Enabled || fi.TenantSlug != "cozy-art" {
		t.Fatalf("unexpected row: %+v", fi)
	}

	// Get.
	got, err := svc.GetTenantIssuer(ctx, iss)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Issuer != iss || got.JWKSURI != fi.JWKSURI {
		t.Fatalf("get mismatch: %+v", got)
	}

	// Upsert (update jwks + Enabled).
	upd, err := svc.UpsertTenantIssuer(ctx, TenantIssuer{
		TenantSlug: "cozy-art",
		Issuer:     iss,
		JWKSURI:    "https://cozy.example/v2/jwks.json",
		Enabled:    false,
	})
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if upd.JWKSURI != "https://cozy.example/v2/jwks.json" || upd.Enabled {
		t.Fatalf("update did not apply: %+v", upd)
	}

	// List enabledOnly should exclude the now-disabled issuer.
	enabled, err := svc.ListTenantIssuers(ctx, true)
	if err != nil {
		t.Fatalf("list enabled: %v", err)
	}
	for _, a := range enabled {
		if a.Issuer == iss {
			t.Fatalf("disabled issuer should not appear in enabled list")
		}
	}

	// Delete.
	if err := svc.DeleteTenantIssuer(ctx, iss); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetTenantIssuer(ctx, iss); !errors.Is(err, ErrTenantIssuerNotFound) {
		t.Fatalf("expected not-found after delete, got %v", err)
	}
	if err := svc.DeleteTenantIssuer(ctx, iss); !errors.Is(err, ErrTenantIssuerNotFound) {
		t.Fatalf("expected not-found on second delete, got %v", err)
	}
}

func TestUpsertTenantIssuerValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}) // no PG
	_, err := svc.UpsertTenantIssuer(context.Background(), TenantIssuer{})
	if err == nil {
		t.Fatal("expected error without PG / with empty fields")
	}
}
