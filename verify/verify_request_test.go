package verify

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// VerifyRequest's happy path + enrichment/ban gates are exercised through the
// Required middleware tests (Required now delegates to VerifyRequest). This pins
// the direct entry point's fail-closed contract: no bearer token → error, no
// claims, without driving the middleware.
func TestVerifyRequest_MissingToken(t *testing.T) {
	v := NewVerifier()
	cl, err := v.VerifyRequest(httptest.NewRequest(http.MethodGet, "/x", nil))
	if err == nil {
		t.Fatal("expected error for a request with no bearer token")
	}
	if cl.UserID != "" {
		t.Fatalf("expected zero claims on failure, got UserID=%q", cl.UserID)
	}
}
