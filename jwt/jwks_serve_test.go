package jwtkit

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
)

func testJWKS(t *testing.T) JWKS {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return JWKS{Keys: []JWK{PublicToJWK(pub, "k1", "")}}
}

func TestServeJWKS_SetsSecurityAndCacheHeaders(t *testing.T) {
	ks := testJWKS(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)

	ServeJWKS(rec, req, ks)

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("nosniff header = %q, want nosniff", got)
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatal("missing ETag")
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Fatal("missing Cache-Control")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestServeJWKS_NotModifiedKeepsValidators(t *testing.T) {
	ks := testJWKS(t)

	// First request to learn the ETag.
	rec := httptest.NewRecorder()
	ServeJWKS(rec, httptest.NewRequest(http.MethodGet, "/jwks", nil), ks)
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on first response")
	}

	// Conditional request with the matching ETag -> 304, still carrying the
	// validator and freshness headers (RFC 7232).
	rec2 := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	req.Header.Set("If-None-Match", etag)
	ServeJWKS(rec2, req, ks)

	if rec2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec2.Code)
	}
	if rec2.Header().Get("ETag") != etag {
		t.Fatalf("304 ETag = %q, want %q", rec2.Header().Get("ETag"), etag)
	}
	if rec2.Header().Get("Cache-Control") == "" {
		t.Fatal("304 missing Cache-Control")
	}
	if rec2.Body.Len() != 0 {
		t.Fatalf("304 must have empty body, got %d bytes", rec2.Body.Len())
	}
}

func TestServeJWKS_IfNoneMatchWildcardAndWeak(t *testing.T) {
	ks := testJWKS(t)
	rec := httptest.NewRecorder()
	ServeJWKS(rec, httptest.NewRequest(http.MethodGet, "/jwks", nil), ks)
	etag := rec.Header().Get("ETag")

	for _, inm := range []string{"*", "W/" + etag, `"x", ` + etag} {
		r := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/jwks", nil)
		req.Header.Set("If-None-Match", inm)
		ServeJWKS(r, req, ks)
		if r.Code != http.StatusNotModified {
			t.Fatalf("If-None-Match %q: status = %d, want 304", inm, r.Code)
		}
	}
}
