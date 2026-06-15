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

// createTestOrg makes a fresh org for a remote_application fixture and returns
// its id (org_id is OPTIONAL since #80; fixtures still bind one). Cleanup runs
// after the RA cleanup (LIFO).
func createTestOrg(t *testing.T, ctx context.Context, svc *Service, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.orgs WHERE slug=$1`, slug) })
	org, err := svc.CreateOrg(ctx, slug)
	if err != nil {
		t.Fatalf("create org %q: %v", slug, err)
	}
	return org.ID
}

func TestRemoteApplicationRoundTrip(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()

	iss := "https://cozy.example/roundtrip"
	orgID := createTestOrg(t, ctx, svc, pool, "cozy-art-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "cozy-art")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "cozy-art") })

	// Upsert (insert).
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:    "cozy-art",
		OrgID:   orgID,
		Issuer:  iss,
		JWKSURI: "https://cozy.example/.well-known/jwks.json",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if !ra.Enabled || ra.Slug != "cozy-art" {
		t.Fatalf("unexpected row: %+v", ra)
	}

	// Get.
	got, err := svc.GetRemoteApplication(ctx, iss)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Issuer != iss || got.JWKSURI != ra.JWKSURI {
		t.Fatalf("get mismatch: %+v", got)
	}

	// GetBySlug.
	bySlug, err := svc.GetRemoteApplicationBySlug(ctx, "cozy-art")
	if err != nil || bySlug.Issuer != iss {
		t.Fatalf("get by slug mismatch: %+v err=%v", bySlug, err)
	}

	// Upsert (update jwks + Enabled).
	upd, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:    "cozy-art",
		OrgID:   orgID,
		Issuer:  iss,
		JWKSURI: "https://cozy.example/v2/jwks.json",
		Enabled: false,
	})
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if upd.JWKSURI != "https://cozy.example/v2/jwks.json" || upd.Enabled {
		t.Fatalf("update did not apply: %+v", upd)
	}

	// List enabledOnly should exclude the now-disabled principal.
	enabled, err := svc.ListRemoteApplications(ctx, true)
	if err != nil {
		t.Fatalf("list enabled: %v", err)
	}
	for _, a := range enabled {
		if a.Issuer == iss {
			t.Fatalf("disabled principal should not appear in enabled list")
		}
	}

	// Delete.
	if err := svc.DeleteRemoteApplication(ctx, iss); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := svc.GetRemoteApplication(ctx, iss); !errors.Is(err, ErrRemoteApplicationNotFound) {
		t.Fatalf("expected not-found after delete, got %v", err)
	}
	if err := svc.DeleteRemoteApplication(ctx, iss); !errors.Is(err, ErrRemoteApplicationNotFound) {
		t.Fatalf("expected not-found on second delete, got %v", err)
	}
}

func TestUpsertRemoteApplicationValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}) // no PG
	_, err := svc.UpsertRemoteApplication(context.Background(), RemoteApplication{})
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

// TestNormalizeRemoteAppTrustSource locks the XOR rule: one trust source per
// remote_application, never both, never neither (#74).
func TestNormalizeRemoteAppTrustSource(t *testing.T) {
	pemKey := testPublicKeyPEM(t)
	cases := []struct {
		name     string
		jwksURI  string
		mode     string
		keys     []RemoteAppKey
		wantMode string
		wantErr  bool
	}{
		{name: "jwks inferred", jwksURI: "https://p.example/jwks.json", wantMode: RemoteAppModeJWKS},
		{name: "jwks explicit", jwksURI: "https://p.example/jwks.json", mode: "jwks", wantMode: RemoteAppModeJWKS},
		{name: "static inferred", keys: []RemoteAppKey{{KID: "k1", PublicKeyPEM: pemKey}}, wantMode: RemoteAppModeStatic},
		{name: "static explicit", mode: "static", keys: []RemoteAppKey{{PublicKeyPEM: pemKey}}, wantMode: RemoteAppModeStatic},
		{name: "BOTH rejected", jwksURI: "https://p.example/jwks.json", keys: []RemoteAppKey{{PublicKeyPEM: pemKey}}, wantErr: true},
		{name: "both with jwks mode rejected", jwksURI: "https://p.example/jwks.json", mode: "jwks", keys: []RemoteAppKey{{PublicKeyPEM: pemKey}}, wantErr: true},
		{name: "both with static mode rejected", jwksURI: "https://p.example/jwks.json", mode: "static", keys: []RemoteAppKey{{PublicKeyPEM: pemKey}}, wantErr: true},
		{name: "neither rejected", wantErr: true},
		{name: "static empty list rejected", mode: "static", wantErr: true},
		{name: "bad PEM rejected", keys: []RemoteAppKey{{PublicKeyPEM: "not a key"}}, wantErr: true},
		{name: "unknown mode rejected", jwksURI: "https://p.example/jwks.json", mode: "magic", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, err := NormalizeRemoteAppTrustSource(tc.jwksURI, tc.mode, tc.keys)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %q", mode)
				}
				if !errors.Is(err, ErrInvalidRemoteApplication) {
					t.Fatalf("expected ErrInvalidRemoteApplication, got %v", err)
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

// TestRemoteApplicationStaticRoundTrip: static-mode (authorized_keys-style)
// principal persists its key list, round-trips through Get, and mode switches
// atomically clear the other trust source (#74).
func TestRemoteApplicationStaticRoundTrip(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()
	pemKey := testPublicKeyPEM(t)

	iss := "https://static.example/issuer"
	slug := "static-keys-app"
	orgID := createTestOrg(t, ctx, svc, pool, "static-keys-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, slug) })

	// Static insert.
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:       slug,
		OrgID:      orgID,
		Issuer:     iss,
		PublicKeys: []RemoteAppKey{{KID: "k1", PublicKeyPEM: pemKey}},
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("static upsert: %v", err)
	}
	if ra.Mode != RemoteAppModeStatic || len(ra.PublicKeys) != 1 || ra.PublicKeys[0].KID != "k1" || ra.JWKSURI != "" {
		t.Fatalf("unexpected static row: %+v", ra)
	}

	got, err := svc.GetRemoteApplication(ctx, iss)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Mode != RemoteAppModeStatic || len(got.PublicKeys) != 1 || got.PublicKeys[0].PublicKeyPEM != pemKey {
		t.Fatalf("static keys did not round-trip: %+v", got)
	}

	// BOTH trust sources on the same row must be rejected by the upsert.
	if _, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:       slug,
		Issuer:     iss,
		JWKSURI:    "https://static.example/jwks.json",
		PublicKeys: []RemoteAppKey{{PublicKeyPEM: pemKey}},
		Enabled:    true,
	}); !errors.Is(err, ErrInvalidRemoteApplication) {
		t.Fatalf("expected ErrInvalidRemoteApplication for dual trust source, got %v", err)
	}

	// Mode switch static -> jwks (human console action): atomically clears keys.
	ra2, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:    slug,
		OrgID:   orgID,
		Issuer:  iss,
		JWKSURI: "https://static.example/jwks.json",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("mode switch: %v", err)
	}
	if ra2.Mode != RemoteAppModeJWKS || len(ra2.PublicKeys) != 0 || ra2.JWKSURI == "" {
		t.Fatalf("mode switch did not clear the other side: %+v", ra2)
	}
}
