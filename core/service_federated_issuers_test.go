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

func TestFederatedOrgIssuerRoundTrip(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()

	iss := "https://cozy.example/roundtrip"
	t.Cleanup(func() { _ = svc.DeleteFederatedOrgIssuer(ctx, iss) })

	// Upsert (insert).
	fi, err := svc.UpsertFederatedOrgIssuer(ctx, FederatedOrgIssuer{
		OrgSlug:  "cozy-art",
		IssuerID: iss,
		JWKSURL:  "https://cozy.example/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if fi.Status != "active" || fi.OrgSlug != "cozy-art" {
		t.Fatalf("unexpected row: %+v", fi)
	}

	// Get.
	got, err := svc.GetFederatedOrgIssuer(ctx, iss)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.IssuerID != iss || got.JWKSURL != fi.JWKSURL {
		t.Fatalf("get mismatch: %+v", got)
	}

	// Upsert (update jwks + status).
	upd, err := svc.UpsertFederatedOrgIssuer(ctx, FederatedOrgIssuer{
		OrgSlug:  "cozy-art",
		IssuerID: iss,
		JWKSURL:  "https://cozy.example/v2/jwks.json",
		Status:   "inactive",
	})
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if upd.JWKSURL != "https://cozy.example/v2/jwks.json" || upd.Status != "inactive" {
		t.Fatalf("update did not apply: %+v", upd)
	}

	// List activeOnly should exclude the now-inactive issuer.
	active, err := svc.ListFederatedOrgIssuers(ctx, true)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	for _, a := range active {
		if a.IssuerID == iss {
			t.Fatalf("inactive issuer should not appear in active list")
		}
	}

	// Delete.
	if err := svc.DeleteFederatedOrgIssuer(ctx, iss); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetFederatedOrgIssuer(ctx, iss); !errors.Is(err, ErrFederatedIssuerNotFound) {
		t.Fatalf("expected not-found after delete, got %v", err)
	}
	if err := svc.DeleteFederatedOrgIssuer(ctx, iss); !errors.Is(err, ErrFederatedIssuerNotFound) {
		t.Fatalf("expected not-found on second delete, got %v", err)
	}
}

func TestUpsertFederatedOrgIssuerValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}) // no PG
	_, err := svc.UpsertFederatedOrgIssuer(context.Background(), FederatedOrgIssuer{})
	if err == nil {
		t.Fatal("expected error without PG / with empty fields")
	}
}
