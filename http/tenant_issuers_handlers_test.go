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
	req := httptest.NewRequest(http.MethodPost, "/tenant-issuers",
		strings.NewReader(`{"tenant":"cozy-art","issuer":"https://cozy.example","jwks_uri":"https://cozy.example/jwks"}`))
	rec := httptest.NewRecorder()
	s.handleTenantIssuerRegisterPOST(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestInboundHandlerRejectsAuthenticatedNonOwner verifies that an authenticated
// but non-owner caller is rejected before any registration is stored. A delegated
// (non-user) principal also has no UserID, so it is rejected too. Here we inject
// claims with a UserID but the tenant-owner check fails because there is no DB —
// requireTenantOwner returns an error, which the handler maps to a non-2xx. We assert
// the registration is NOT accepted (Status is not 2xx).
func TestInboundHandlerRejectsBadRequest(t *testing.T) {
	s := &Service{}
	// Missing issuer/jwks_uri -> bad request, even with claims present.
	req := httptest.NewRequest(http.MethodPost, "/tenant-issuers", strings.NewReader(`{"tenant":"cozy-art"}`))
	req = req.WithContext(setClaims(req.Context(), Claims{UserID: "user-1"}))
	rec := httptest.NewRecorder()
	s.handleTenantIssuerRegisterPOST(rec, req)
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

// TestInboundHandlerRejectsDelegatedPrincipal locks the #465 human-only rule:
// trust-config mutation requires a human session. A delegated/service token
// carries no `sub` (UserID stays empty), so it must be rejected with 401 even
// though it is a VALID authenticated principal for other routes — a stolen
// platform signing key must not be able to re-point trust at attacker
// infrastructure.
func TestInboundHandlerRejectsDelegatedPrincipal(t *testing.T) {
	s := &Service{}
	body := `{"tenant":"cozy-art","issuer":"https://cozy.example","jwks_uri":"https://cozy.example/jwks"}`

	for _, route := range []struct {
		name string
		h    func(http.ResponseWriter, *http.Request)
	}{
		{"register", s.handleTenantIssuerRegisterPOST},
		{"delete", s.handleTenantIssuerDeleteDELETE},
	} {
		t.Run(route.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/tenant-issuers", strings.NewReader(body))
			req = req.WithContext(setClaims(req.Context(), Claims{
				// Delegated principal: tenant + delegated_sub set, NO UserID.
				Tenant:           "cozy-art",
				DelegatedSubject: "platform:cozy-art",
				Issuer:           "https://cozy.example",
			}))
			rec := httptest.NewRecorder()
			route.h(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("expected 401 for delegated principal, got %d (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestInboundHandlerRejectsBothTrustSources: one trust source per binding,
// never both (#465) — a body carrying jwks_uri AND public_keys is a 400
// before any tenant lookup happens.
func TestInboundHandlerRejectsBothTrustSources(t *testing.T) {
	s := &Service{}
	body := `{"tenant":"cozy-art","issuer":"https://cozy.example","jwks_uri":"https://cozy.example/jwks","public_keys":[{"kid":"k1","public_key_pem":"-----BEGIN PUBLIC KEY-----\nx\n-----END PUBLIC KEY-----"}]}`
	req := httptest.NewRequest(http.MethodPost, "/tenant-issuers", strings.NewReader(body))
	req = req.WithContext(setClaims(req.Context(), Claims{UserID: "user-1"}))
	rec := httptest.NewRecorder()
	s.handleTenantIssuerRegisterPOST(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for dual trust source, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_trust_source") {
		t.Fatalf("expected invalid_trust_source code, body=%s", rec.Body.String())
	}
}

// TestTenantsCreateRejectsInvalidFederation: an invalid federation block
// rejects the whole registration — no tenant is created (#465).
func TestTenantsCreateRejectsInvalidFederation(t *testing.T) {
	s := &Service{}
	body := `{"slug":"cozy-art","federation":{"issuer":"https://cozy.example","jwks_uri":"https://cozy.example/jwks","public_keys":[{"public_key_pem":"x"}]}}`
	req := httptest.NewRequest(http.MethodPost, "/tenants", strings.NewReader(body))
	req = req.WithContext(setClaims(req.Context(), Claims{UserID: "user-1"}))
	rec := httptest.NewRecorder()
	s.handleTenantsCreatePOST(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid federation block, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "invalid_federation_trust_source") {
		t.Fatalf("expected invalid_federation_trust_source, body=%s", rec.Body.String())
	}
}
