package authcore

// AK-C2 / SSRF: validateJWKSURI must reject non-HTTPS schemes, private/reserved
// IP literals, and well-known internal hostnames before a jwks_uri is accepted
// at registration time.

import "testing"

func TestValidateJWKSURI_Accepted(t *testing.T) {
	valid := []string{
		"https://auth.example.com/.well-known/jwks.json",
		"https://auth.example.com:8443/jwks",
		"https://1.2.3.4/jwks", // public IP literal (ARIN/APNIC range)
		"https://8.8.8.8/jwks", // Google DNS — clearly public
		"https://sub.domain.example.com/path/to/jwks",
	}
	for _, u := range valid {
		if err := validateJWKSURI(u); err != nil {
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
		if err := validateJWKSURI(u); err == nil {
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
		if err := validateJWKSURI(u); err == nil {
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
		if err := validateJWKSURI(u); err == nil {
			t.Errorf("validateJWKSURI(%q): expected error for internal hostname, got nil", u)
		}
	}
}

func TestNormalizeRemoteAppTrustSource_RejectsPrivateJWKSURI(t *testing.T) {
	_, err := NormalizeRemoteAppTrustSource("http://169.254.169.254/jwks", "jwks", nil)
	if err == nil {
		t.Fatal("NormalizeRemoteAppTrustSource: expected error for private jwks_uri, got nil")
	}
}
