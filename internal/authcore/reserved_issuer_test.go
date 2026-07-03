package authcore

// AK-AUTH-01: UpsertRemoteApplication must reject any registration whose issuer
// equals the platform's own issuer string (case-insensitively). This is the
// authoritative guard covering every caller, including bootstrap/provisioning.

import (
	"context"
	"errors"
	"testing"
)

func TestUpsertRemoteApplicationRejectsPlatformIssuer(t *testing.T) {
	pool := testPG(t)
	const platformIssuer = "https://platform.example"
	svc := NewService(Config{Token: TokenConfig{Issuer: platformIssuer}}, Keyset{}, WithPostgres(pool))
	ctx := context.Background()

	orgID := createTestGroup(t, ctx, svc, pool, "reserved-issuer-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "reserved-issuer-ra")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "reserved-issuer-ra")
	})

	cases := []struct {
		name   string
		issuer string
	}{
		{"exact", platformIssuer},
		{"case_variant_host", "https://PLATFORM.example"},
		{"surrounding_whitespace", "  https://platform.example  "},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
				Slug:              "reserved-issuer-ra",
				PermissionGroupID: orgID,
				Issuer:            tc.issuer,
				JWKSURI:           "https://platform.example/.well-known/jwks.json",
				Enabled:           true,
				PublicKeys:        nil,
			})
			if !errors.Is(err, ErrReservedIssuer) {
				t.Fatalf("AK-AUTH-01: expected ErrReservedIssuer for issuer %q, got %v", tc.issuer, err)
			}
		})
	}
}

func TestUpsertRemoteApplicationAllowsNonPlatformIssuer(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://platform.example"}}, Keyset{}, WithPostgres(pool))
	ctx := context.Background()

	orgID := createTestGroup(t, ctx, svc, pool, "ok-issuer-org")
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "ok-issuer-ra")
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.remote_applications WHERE slug=$1`, "ok-issuer-ra")
	})

	if _, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:              "ok-issuer-ra",
		PermissionGroupID: orgID,
		Issuer:            "https://merchant-app.example",
		JWKSURI:           "https://merchant-app.example/.well-known/jwks.json",
		Enabled:           true,
	}); err != nil {
		t.Fatalf("legitimate remote_application registration was rejected: %v", err)
	}
}
