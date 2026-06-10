package core

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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

func testPublicKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// TestNormalizeTenantIssuerTrustSource locks the #465 XOR rule: one trust
// source per issuer binding, never both, never neither.
func TestNormalizeTenantIssuerTrustSource(t *testing.T) {
	pemKey := testPublicKeyPEM(t)
	cases := []struct {
		name     string
		jwksURI  string
		mode     string
		keys     []TenantIssuerKey
		wantMode string
		wantErr  bool
	}{
		{name: "jwks inferred", jwksURI: "https://p.example/jwks.json", wantMode: TenantIssuerModeJWKS},
		{name: "jwks explicit", jwksURI: "https://p.example/jwks.json", mode: "jwks", wantMode: TenantIssuerModeJWKS},
		{name: "static inferred", keys: []TenantIssuerKey{{KID: "k1", PublicKeyPEM: pemKey}}, wantMode: TenantIssuerModeStatic},
		{name: "static explicit", mode: "static", keys: []TenantIssuerKey{{PublicKeyPEM: pemKey}}, wantMode: TenantIssuerModeStatic},
		{name: "BOTH rejected", jwksURI: "https://p.example/jwks.json", keys: []TenantIssuerKey{{PublicKeyPEM: pemKey}}, wantErr: true},
		{name: "both with jwks mode rejected", jwksURI: "https://p.example/jwks.json", mode: "jwks", keys: []TenantIssuerKey{{PublicKeyPEM: pemKey}}, wantErr: true},
		{name: "both with static mode rejected", jwksURI: "https://p.example/jwks.json", mode: "static", keys: []TenantIssuerKey{{PublicKeyPEM: pemKey}}, wantErr: true},
		{name: "neither rejected", wantErr: true},
		{name: "static empty list rejected", mode: "static", wantErr: true},
		{name: "bad PEM rejected", keys: []TenantIssuerKey{{PublicKeyPEM: "not a key"}}, wantErr: true},
		{name: "unknown mode rejected", jwksURI: "https://p.example/jwks.json", mode: "magic", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := NormalizeTenantIssuerTrustSource(tc.jwksURI, tc.mode, tc.keys)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %q", mode)
				}
				if !errors.Is(err, ErrInvalidTenantIssuer) {
					t.Fatalf("expected ErrInvalidTenantIssuer, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != tc.wantMode {
				t.Fatalf("mode = %q, want %q", mode, tc.wantMode)
			}
		})
	}
}

// TestTenantIssuerStaticRoundTrip: static-mode (authorized_keys-style) issuer
// persists its key list, round-trips through Get/List, and mode switches
// atomically clear the other trust source (#465).
func TestTenantIssuerStaticRoundTrip(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()
	pemKey := testPublicKeyPEM(t)

	iss := "https://static.example/issuer"
	slug := "static-keys-tenant"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.tenants WHERE slug=$1`, slug) })
	if _, err := svc.CreateTenant(ctx, slug); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() { _ = svc.DeleteTenantIssuer(ctx, iss) })

	// Static insert.
	fi, err := svc.UpsertTenantIssuer(ctx, TenantIssuer{
		TenantSlug: slug,
		Issuer:     iss,
		PublicKeys: []TenantIssuerKey{{KID: "k1", PublicKeyPEM: pemKey}},
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("static upsert: %v", err)
	}
	if fi.Mode != TenantIssuerModeStatic || len(fi.PublicKeys) != 1 || fi.PublicKeys[0].KID != "k1" || fi.JWKSURI != "" {
		t.Fatalf("unexpected static row: %+v", fi)
	}

	got, err := svc.GetTenantIssuer(ctx, iss)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Mode != TenantIssuerModeStatic || len(got.PublicKeys) != 1 || got.PublicKeys[0].PublicKeyPEM != pemKey {
		t.Fatalf("static keys did not round-trip: %+v", got)
	}

	// BOTH trust sources on the same row must be rejected by the upsert.
	if _, err := svc.UpsertTenantIssuer(ctx, TenantIssuer{
		TenantSlug: slug,
		Issuer:     iss,
		JWKSURI:    "https://static.example/jwks.json",
		PublicKeys: []TenantIssuerKey{{PublicKeyPEM: pemKey}},
		Enabled:    true,
	}); !errors.Is(err, ErrInvalidTenantIssuer) {
		t.Fatalf("expected ErrInvalidTenantIssuer for dual trust source, got %v", err)
	}

	// Mode switch static -> jwks (human console action): atomically clears keys.
	fi2, err := svc.UpsertTenantIssuer(ctx, TenantIssuer{
		TenantSlug: slug,
		Issuer:     iss,
		JWKSURI:    "https://static.example/jwks.json",
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("mode switch: %v", err)
	}
	if fi2.Mode != TenantIssuerModeJWKS || len(fi2.PublicKeys) != 0 || fi2.JWKSURI == "" {
		t.Fatalf("mode switch did not clear the other side: %+v", fi2)
	}
}
