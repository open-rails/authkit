package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// memFederatedSource is an in-memory FederatedIssuerSource for tests, so the
// Verifier-load path can be exercised without a Postgres-backed core.Service.
type memFederatedSource struct {
	items []core.FederatedOrgIssuer
}

func (m *memFederatedSource) ListFederatedOrgIssuers(_ context.Context, activeOnly bool) ([]core.FederatedOrgIssuer, error) {
	if !activeOnly {
		return m.items, nil
	}
	var out []core.FederatedOrgIssuer
	for _, i := range m.items {
		if i.Status == "active" {
			out = append(out, i)
		}
	}
	return out, nil
}

func (m *memFederatedSource) GetFederatedOrgIssuer(_ context.Context, issuerID string) (*core.FederatedOrgIssuer, error) {
	for i := range m.items {
		if m.items[i].IssuerID == issuerID {
			fi := m.items[i]
			return &fi, nil
		}
	}
	return nil, core.ErrFederatedIssuerNotFound
}

// jwksServer serves a single signer's JWKS, returning its base URL.
func jwksServer(t *testing.T, signer *jwtkit.RSASigner) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk := jwtkit.RSAPublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())
		jwtkit.ServeJWKS(w, r, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	return httptest.NewServer(mux)
}

// TestOutboundClientPostsRegistration verifies the outbound FederationClient
// posts the correct body and auth header to a resource server's accept endpoint.
func TestOutboundClientPostsRegistration(t *testing.T) {
	var got federatedIssuerRegistration
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fc := NewFederationClient(WithFederationAuthToken("owner-token"))
	err := fc.RegisterIssuer(context.Background(), srv.URL+"/api/v1/federated-issuers", FederationRegistration{
		Org:      "cozy-art",
		IssuerID: "https://cozy.example",
		JWKSURL:  "https://cozy.example/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	if got.Org != "cozy-art" || got.IssuerID != "https://cozy.example" || got.JWKSURL != "https://cozy.example/.well-known/jwks.json" {
		t.Fatalf("body mismatch: %+v", got)
	}
	if gotAuth != "Bearer owner-token" {
		t.Fatalf("auth header=%q", gotAuth)
	}
}

func TestOutboundClientPropagatesError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer srv.Close()
	fc := NewFederationClient()
	err := fc.RegisterIssuer(context.Background(), srv.URL, FederationRegistration{
		Org: "cozy-art", IssuerID: "https://cozy.example", JWKSURL: "https://cozy.example/jwks",
	})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
}

func TestOutboundClientValidatesInput(t *testing.T) {
	fc := NewFederationClient()
	if err := fc.RegisterIssuer(context.Background(), "", FederationRegistration{Org: "a", IssuerID: "b", JWKSURL: "c"}); err == nil {
		t.Fatal("expected error for empty accept URL")
	}
	if err := fc.RegisterIssuer(context.Background(), "http://x", FederationRegistration{Org: "a"}); err == nil {
		t.Fatal("expected error for missing issuer/jwks")
	}
}

// TestVerifierLoadsFederatedIssuerAndValidates is the end-to-end mint -> register
// (in store) -> load-into-verifier -> validate path. The platform mints a
// delegated token; the resource server loads the federated issuer from its
// store and validates the token against the issuer's JWKS.
func TestVerifierLoadsFederatedIssuerAndValidates(t *testing.T) {
	// Platform signer + its JWKS endpoint.
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	// Resource server's store has the federated issuer registered, pointing at
	// the platform's JWKS endpoint.
	src := &memFederatedSource{items: []core.FederatedOrgIssuer{{
		OrgSlug:  "cozy-art",
		IssuerID: iss,
		JWKSURL:  jwks.URL + "/.well-known/jwks.json",
		Status:   "active",
	}}}

	// Resource server's verifier loads federated issuers from the store.
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadFederatedIssuers: %v", err)
	}

	// Platform mints a delegated token.
	tok, err := MintDelegatedToken(context.Background(), signer, DelegatedTokenParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "ext-user-1",
		Tenant:           "cozy-art",
		UserTier:         "cozy_pro",
		Roles:            []string{"member"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	// Resource server validates it (JWKS fetched in-house from the platform).
	cl, err := ver.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	dp, ok := cl.Delegated()
	if !ok {
		t.Fatal("expected delegated principal")
	}
	if dp.Tenant != "cozy-art" || dp.DelegatedSubject != "ext-user-1" || dp.UserTier != "cozy_pro" {
		t.Fatalf("principal=%+v", dp)
	}
}

// TestVerifierRejectsUnregisteredIssuer confirms an unregistered issuer's token
// is rejected even though the JWKS is reachable.
func TestVerifierRejectsUnregisteredIssuer(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	src := &memFederatedSource{} // empty store
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), src, []string{"tensorhub"}); err != nil {
		t.Fatalf("LoadFederatedIssuers: %v", err)
	}
	tok, _ := MintDelegatedToken(context.Background(), signer, DelegatedTokenParams{
		Issuer: "https://rogue.example", Audiences: []string{"tensorhub"},
		DelegatedSubject: "x", Tenant: "rogue", TTL: time.Minute,
	})
	if _, err := ver.Verify(tok); err == nil {
		t.Fatal("expected rejection of unregistered issuer")
	}
}
