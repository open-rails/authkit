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
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire test db lock connection: %v", err)
	}
	if _, err := conn.Exec(context.Background(), `SELECT pg_advisory_lock(638476116)`); err != nil {
		conn.Release()
		t.Fatalf("acquire test db lock: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), `SELECT pg_advisory_unlock(638476116)`)
		conn.Release()
	})
	return pool
}

// createTestGroup ensures the root permission-group exists and returns its id
// for a remote_application fixture (#111: remote-apps are group-nested; their
// permission_group_id FK just needs to point at a live group). The slug arg is
// unused now but kept for call-site stability.
func createTestGroup(t *testing.T, ctx context.Context, svc *Service, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	_ = slug
	gid, err := svc.EnsureRootGroup(ctx)
	if err != nil {
		t.Fatalf("ensure root group: %v", err)
	}
	return gid
}

func TestRemoteApplicationRoundTrip(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	ctx := context.Background()

	iss := "https://cozy.example/roundtrip"
	orgID := createTestGroup(t, ctx, svc, pool, "cozy-art-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "cozy-art")
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "cozy-art") })

	// Upsert (insert).
	ra, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:           "cozy-art",
		OrgID:          orgID,
		Issuer:         iss,
		JWKSURI:        "https://cozy.example/.well-known/jwks.json",
		AllowedOrigins: []string{"https://Cozy.example", "https://cozy.example"},
		Enabled:        true,
	})
	if err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	if !ra.Enabled || ra.Slug != "cozy-art" {
		t.Fatalf("unexpected row: %+v", ra)
	}
	if got, want := ra.AllowedOrigins, []string{"https://cozy.example"}; len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("allowed origins = %#v, want %#v", got, want)
	}

	// Get.
	got, err := svc.GetRemoteApplication(ctx, iss)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Issuer != iss || got.JWKSURI != ra.JWKSURI {
		t.Fatalf("get mismatch: %+v", got)
	}
	if got.AllowedOrigins[0] != "https://cozy.example" {
		t.Fatalf("get allowed origins = %#v", got.AllowedOrigins)
	}

	// GetBySlug.
	bySlug, err := svc.GetRemoteApplicationBySlug(ctx, "cozy-art")
	if err != nil || bySlug.Issuer != iss {
		t.Fatalf("get by slug mismatch: %+v err=%v", bySlug, err)
	}

	// Upsert (update jwks + Enabled).
	upd, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:           "cozy-art",
		OrgID:          orgID,
		Issuer:         iss,
		JWKSURI:        "https://cozy.example/v2/jwks.json",
		AllowedOrigins: []string{"https://billing.cozy.example"},
		Enabled:        false,
	})
	if err != nil {
		t.Fatalf("upsert update: %v", err)
	}
	if upd.JWKSURI != "https://cozy.example/v2/jwks.json" || upd.Enabled {
		t.Fatalf("update did not apply: %+v", upd)
	}
	if upd.AllowedOrigins[0] != "https://billing.cozy.example" {
		t.Fatalf("update allowed origins = %#v", upd.AllowedOrigins)
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

func TestRemoteApplicationOrgOptionalOwnerUserRemoved(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	ctx := context.Background()

	var ownerUserColumnCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM information_schema.columns
		WHERE table_schema='profiles'
		  AND table_name='remote_applications'
		  AND column_name='owner_user_id'
	`).Scan(&ownerUserColumnCount); err != nil {
		t.Fatalf("inspect remote_applications columns: %v", err)
	}
	if ownerUserColumnCount != 0 {
		t.Fatalf("remote_applications.owner_user_id should not exist after migration")
	}

	// #111: permission_group_id is now REQUIRED. A group-less
	// ("bootstrap/operator-managed") remote application is REJECTED — every issuer
	// must map to exactly one controlling permission-group (no orphan issuers).
	_, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:    "bootstrap-issuer",
		Issuer:  "https://bootstrap.example/issuer",
		JWKSURI: "https://bootstrap.example/jwks.json",
		Enabled: true,
	})
	if !errors.Is(err, ErrInvalidRemoteApplication) {
		t.Fatalf("org-less remote application should be rejected with ErrInvalidRemoteApplication, got %v", err)
	}
}

func TestUpsertRemoteApplicationValidation(t *testing.T) {
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}) // no PG
	_, err := svc.UpsertRemoteApplication(context.Background(), RemoteApplication{})
	if err == nil {
		t.Fatal("expected error without PG / with empty fields")
	}
}

func TestNormalizeAllowedOrigins(t *testing.T) {
	got, err := NormalizeAllowedOrigins([]string{
		" https://Doujins.com ",
		"https://doujins.com",
		"http://localhost:5173",
		"",
	})
	if err != nil {
		t.Fatalf("NormalizeAllowedOrigins: %v", err)
	}
	want := []string{"https://doujins.com", "http://localhost:5173"}
	if len(got) != len(want) {
		t.Fatalf("origins = %#v, want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("origins = %#v, want %#v", got, want)
		}
	}
	if !OriginAllowed("https://DOUJINS.com", got) {
		t.Fatal("expected exact normalized origin to be allowed")
	}
	for _, bad := range []string{"null", "https://doujins.com/path", "https://*.doujins.com", "ftp://doujins.com"} {
		if _, err := NormalizeAllowedOrigins([]string{bad}); !errors.Is(err, ErrInvalidRemoteApplication) {
			t.Fatalf("origin %q error = %v, want ErrInvalidRemoteApplication", bad, err)
		}
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
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}, WithPostgres(pool))
	ctx := context.Background()
	pemKey := testPublicKeyPEM(t)

	iss := "https://static.example/issuer"
	slug := "static-keys-app"
	orgID := createTestGroup(t, ctx, svc, pool, "static-keys-org")
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
