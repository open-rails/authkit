package jose

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit/keys"
)

// ak#275 (ae/jwks-serve-headers): ServeJWKS is a public integration surface
// fetched constantly by verifiers and normally cached by an intermediary.

func TestServeJWKS_HeadersAndConditional(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks := keys.JWKS{Keys: []keys.JWK{keys.PublicJWK(priv.Public().(ed25519.PublicKey), "k1", "")}}

	serve := func(ifNoneMatch string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
		if ifNoneMatch != "" {
			req.Header.Set("If-None-Match", ifNoneMatch)
		}
		ServeJWKS(rec, req, ks)
		return rec
	}

	full := serve("")
	if full.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", full.Code)
	}
	etag := full.Header().Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag on the full response")
	}
	if got := full.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if full.Header().Get("Cache-Control") == "" {
		t.Fatal("missing Cache-Control on the full response")
	}
	if full.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", full.Header().Get("Content-Type"))
	}

	// Every If-None-Match form RFC 7232 defines must produce a 304 that still
	// carries the validator and the freshness directive.
	for _, inm := range []string{etag, "*", "W/" + etag, `"other", ` + etag, " " + etag + " "} {
		rec := serve(inm)
		if rec.Code != http.StatusNotModified {
			t.Fatalf("If-None-Match %q: status = %d, want 304", inm, rec.Code)
		}
		if got := rec.Header().Get("ETag"); got != etag {
			t.Fatalf("If-None-Match %q: 304 ETag = %q, want %q", inm, got, etag)
		}
		if rec.Header().Get("Cache-Control") == "" {
			t.Fatalf("If-None-Match %q: 304 dropped Cache-Control", inm)
		}
		if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
			t.Fatalf("If-None-Match %q: 304 dropped nosniff", inm)
		}
		if rec.Body.Len() != 0 {
			t.Fatalf("If-None-Match %q: 304 must have an empty body, got %d bytes", inm, rec.Body.Len())
		}
	}

	// A non-matching validator must still serve the document.
	for _, inm := range []string{`"stale"`, `"a", "b"`, "W/\"stale\""} {
		if rec := serve(inm); rec.Code != http.StatusOK {
			t.Fatalf("If-None-Match %q: status = %d, want 200", inm, rec.Code)
		}
	}
}
