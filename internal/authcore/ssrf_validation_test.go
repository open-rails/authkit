package authcore

// AK-C2 / SSRF: validateJWKSURI must reject non-HTTPS schemes, private/reserved
// IP literals, and well-known internal hostnames before a jwks_uri is accepted
// at registration time.

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidateJWKSURI_Accepted(t *testing.T) {
	valid := []string{
		"https://auth.example.com/.well-known/jwks.json",
		"https://auth.example.com:8443/jwks",
		"https://1.2.3.4/jwks", // public IP literal (ARIN/APNIC range)
		"https://8.8.8.8/jwks", // Google DNS — clearly public
		"https://sub.domain.example.com/path/to/jwks",
	}
	for _, u := range valid {
		if err := validateJWKSURI(u, false); err != nil {
			t.Errorf("validateJWKSURI(%q) returned unexpected error: %v", u, err)
		}
	}
}

func TestValidateJWKSURI_RejectedScheme(t *testing.T) {
	cases := []string{
		"http://example.com/jwks",
		"ftp://example.com/jwks",
		"//example.com/jwks",
		"example.com/jwks",
		"",
	}
	for _, u := range cases {
		if err := validateJWKSURI(u, false); err == nil {
			t.Errorf("validateJWKSURI(%q): expected error for non-HTTPS scheme, got nil", u)
		}
	}
}

func TestValidateJWKSURI_RejectedPrivateIPs(t *testing.T) {
	cases := []string{
		"https://127.0.0.1/jwks",
		"https://127.0.0.2/jwks",
		"https://10.0.0.1/jwks",
		"https://10.255.255.255/jwks",
		"https://172.16.0.1/jwks",
		"https://172.31.255.255/jwks",
		"https://192.168.1.1/jwks",
		"https://169.254.169.254/latest/meta-data/", // AWS metadata
		"https://169.254.169.254/computeMetadata/",  // GCP metadata (same range)
		"https://100.64.0.1/jwks",                   // carrier-grade NAT
		"https://[::1]/jwks",                        // IPv6 loopback
		"https://[fe80::1]/jwks",                    // IPv6 link-local
		"https://[fc00::1]/jwks",                    // IPv6 unique local
	}
	for _, u := range cases {
		if err := validateJWKSURI(u, false); err == nil {
			t.Errorf("validateJWKSURI(%q): expected error for private/reserved IP, got nil", u)
		}
	}
}

func TestValidateJWKSURI_RejectedInternalHostnames(t *testing.T) {
	cases := []string{
		// localhost variants
		"https://localhost/jwks",
		"https://localhost:8080/jwks",
		"https://foo.localhost/jwks",
		// cloud metadata
		"https://metadata/jwks",
		"https://metadata.google.internal/computeMetadata/v1/",
		// Docker Desktop / Docker Engine
		"https://host.docker.internal/jwks",
		"https://gateway.docker.internal/jwks",
		"https://kubernetes.docker.internal/jwks",
		"https://host-gateway/jwks",
		"https://custom.docker.internal/jwks",
		// Podman / OCI runtimes
		"https://host.containers.internal/jwks",
		"https://custom.containers.internal/jwks",
	}
	for _, u := range cases {
		if err := validateJWKSURI(u, false); err == nil {
			t.Errorf("validateJWKSURI(%q): expected error for internal hostname, got nil", u)
		}
	}
}

func TestNormalizeRemoteAppTrustSource_RejectsPrivateJWKSURI(t *testing.T) {
	_, err := NormalizeRemoteAppTrustSource("http://169.254.169.254/jwks", "jwks", nil, false)
	if err == nil {
		t.Fatal("NormalizeRemoteAppTrustSource: expected error for private jwks_uri, got nil")
	}
}

// #257: dev environments accept non-HTTPS and loopback/private jwks_uri values.
func TestValidateJWKSURI_DevAcceptsInsecure(t *testing.T) {
	valid := []string{
		"http://127.0.0.1:31550/.well-known/jwks.json",
		"http://localhost:8080/jwks",
		"https://192.168.1.10/jwks",
		"http://host.docker.internal/jwks",
		"https://auth.example.com/.well-known/jwks.json",
	}
	for _, u := range valid {
		if err := validateJWKSURI(u, true); err != nil {
			t.Errorf("validateJWKSURI(%q, dev): unexpected error: %v", u, err)
		}
	}
}

// #257: even in dev, a jwks_uri must be a parseable http(s) URL with a host.
func TestValidateJWKSURI_DevStillRejectsNonHTTP(t *testing.T) {
	cases := []string{
		"ftp://example.com/jwks",
		"file:///etc/passwd",
		"//example.com/jwks",
		"example.com/jwks",
		"",
	}
	for _, u := range cases {
		if err := validateJWKSURI(u, true); err == nil {
			t.Errorf("validateJWKSURI(%q, dev): expected error, got nil", u)
		}
	}
}

// #257: the jwks/public_keys XOR rule holds regardless of environment.
func TestNormalizeRemoteAppTrustSource_DevKeepsXORRule(t *testing.T) {
	keys := []RemoteAppKey{{KID: "k1", PublicKeyPEM: "irrelevant"}}
	if _, err := NormalizeRemoteAppTrustSource("http://127.0.0.1/jwks", "jwks", keys, true); err == nil {
		t.Fatal("dev: jwks_uri + public_keys must stay mutually exclusive")
	}
	if _, err := NormalizeRemoteAppTrustSource("http://127.0.0.1/jwks", "", nil, true); err != nil {
		t.Fatalf("dev: loopback http jwks_uri should be accepted: %v", err)
	}
	if _, err := NormalizeRemoteAppTrustSource("http://127.0.0.1/jwks", "", nil, false); err == nil {
		t.Fatal("non-dev: loopback http jwks_uri must stay rejected")
	}
}

// #257 (DB): registration accepts a loopback http jwks_uri only in dev
// environments; staging/production reject with the unchanged messages.
func TestUpsertRemoteApplication_DevLoopbackJWKS(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()

	dev := NewService(Config{Environment: "dev", Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	gid := createTestGroup(t, ctx, dev, pool, "")
	slug := fmt.Sprintf("dev-fed-%d", time.Now().UnixNano())
	ra, err := dev.UpsertRemoteApplication(ctx, RemoteApplication{
		Slug:              slug,
		PermissionGroupID: gid,
		Issuer:            "http://127.0.0.1:31550",
		JWKSURI:           "http://127.0.0.1:31550/.well-known/jwks.json",
		Enabled:           true,
	})
	if err != nil {
		t.Fatalf("dev registration with loopback http jwks_uri: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM profiles.remote_applications WHERE id=$1::uuid`, ra.ID)
	})

	for _, env := range []string{"staging", "production"} {
		svc := NewService(Config{Environment: env, Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
		_, err := svc.UpsertRemoteApplication(ctx, RemoteApplication{
			Slug: slug + "-x", PermissionGroupID: gid,
			Issuer: "http://127.0.0.1:31551", JWKSURI: "http://127.0.0.1:31551/jwks", Enabled: true,
		})
		if err == nil || !strings.Contains(err.Error(), `jwks_uri must use https`) {
			t.Fatalf("%s: expected https rejection, got %v", env, err)
		}
		_, err = svc.UpsertRemoteApplication(ctx, RemoteApplication{
			Slug: slug + "-y", PermissionGroupID: gid,
			Issuer: "https://127.0.0.1:31551", JWKSURI: "https://127.0.0.1:31551/jwks", Enabled: true,
		})
		if err == nil || !strings.Contains(err.Error(), "private/reserved IP — not allowed") {
			t.Fatalf("%s: expected loopback rejection message, got %v", env, err)
		}
	}
}
