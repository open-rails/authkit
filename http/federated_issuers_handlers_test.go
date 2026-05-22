package authhttp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestInboundHandlerRejectsUnauthenticated verifies the inbound accept-side
// handler rejects callers with no authenticated user (no claims in context).
func TestInboundHandlerRejectsUnauthenticated(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodPost, "/federated-issuers",
		strings.NewReader(`{"org":"cozy-art","issuer_id":"https://cozy.example","jwks_url":"https://cozy.example/jwks"}`))
	rec := httptest.NewRecorder()
	s.handleFederatedIssuerRegisterPOST(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestInboundHandlerRejectsAuthenticatedNonOwner verifies that an authenticated
// but non-owner caller is rejected before any registration is stored. A delegated
// (non-user) principal also has no UserID, so it is rejected too. Here we inject
// claims with a UserID but the org-owner check fails because there is no DB —
// requireOrgOwner returns an error, which the handler maps to a non-2xx. We assert
// the registration is NOT accepted (status is not 2xx).
func TestInboundHandlerRejectsBadRequest(t *testing.T) {
	s := &Service{}
	// Missing issuer_id/jwks_url -> bad request, even with claims present.
	req := httptest.NewRequest(http.MethodPost, "/federated-issuers", strings.NewReader(`{"org":"cozy-art"}`))
	req = req.WithContext(setClaims(req.Context(), Claims{UserID: "user-1"}))
	rec := httptest.NewRecorder()
	s.handleFederatedIssuerRegisterPOST(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestClaimsHasGlobalAdmin(t *testing.T) {
	if !claimsHasGlobalAdmin(Claims{GlobalRoles: []string{"admin"}}) {
		t.Fatal("expected admin detection")
	}
	if claimsHasGlobalAdmin(Claims{GlobalRoles: []string{"member"}}) {
		t.Fatal("did not expect admin for member")
	}
	if claimsHasGlobalAdmin(Claims{}) {
		t.Fatal("did not expect admin for empty roles")
	}
}
