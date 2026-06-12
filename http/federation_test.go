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

// memFederatedSource is an in-memory TenantIssuerSource for tests, so the
// Verifier-load path can be exercised without a Postgres-backed core.Service.
type memFederatedSource struct {
	items []core.TenantIssuer
}

func (m *memFederatedSource) ListTenantIssuers(_ context.Context, enabledOnly bool) ([]core.TenantIssuer, error) {
	if !enabledOnly {
		return m.items, nil
	}
	var out []core.TenantIssuer
	for _, i := range m.items {
		if i.Enabled {
			out = append(out, i)
		}
	}
	return out, nil
}

func (m *memFederatedSource) GetTenantIssuer(_ context.Context, issuerID string) (*core.TenantIssuer, error) {
	for i := range m.items {
		if m.items[i].Issuer == issuerID {
			fi := m.items[i]
			return &fi, nil
		}
	}
	return nil, core.ErrTenantIssuerNotFound
}

// jwksServer serves a single signer's JWKS, returning its base URL.
func jwksServer(t *testing.T, signer *jwtkit.RSASigner) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		jwk := jwtkit.PublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())
		jwtkit.ServeJWKS(w, r, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	return httptest.NewServer(mux)
}

// TestOutboundClientPostsRegistration verifies the outbound TenantIssuersClient
// posts the correct body and auth header to a resource server's accept endpoint.
func TestOutboundClientPostsRegistration(t *testing.T) {
	var got tenantIssuerRegistration
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fc := NewTenantIssuersClient(WithTenantIssuersAuthToken("owner-token"))
	err := fc.RegisterIssuer(context.Background(), srv.URL+"/api/v1/tenant-issuers", TenantIssuersRegistration{
		Tenant:  "cozy-art",
		Issuer:  "https://cozy.example",
		JWKSURI: "https://cozy.example/.well-known/jwks.json",
	})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	if got.Tenant != "cozy-art" || got.Issuer != "https://cozy.example" || got.JWKSURI != "https://cozy.example/.well-known/jwks.json" {
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
	fc := NewTenantIssuersClient()
	err := fc.RegisterIssuer(context.Background(), srv.URL, TenantIssuersRegistration{
		Tenant: "cozy-art", Issuer: "https://cozy.example", JWKSURI: "https://cozy.example/jwks",
	})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
}

func TestOutboundClientValidatesInput(t *testing.T) {
	fc := NewTenantIssuersClient()
	if err := fc.RegisterIssuer(context.Background(), "", TenantIssuersRegistration{Tenant: "a", Issuer: "b", JWKSURI: "c"}); err == nil {
		t.Fatal("expected error for empty accept URL")
	}
	if err := fc.RegisterIssuer(context.Background(), "http://x", TenantIssuersRegistration{Tenant: "a"}); err == nil {
		t.Fatal("expected error for missing issuer/jwks")
	}
}

// TestVerifierLoadsTenantIssuerAndValidates is the end-to-end mint -> register
// (in store) -> load-into-verifier -> validate path. The platform mints a
// delegated token; the resource server loads the tenant issuer from its
// store and validates the token against the issuer's JWKS.
func TestVerifierLoadsTenantIssuerAndValidates(t *testing.T) {
	// Platform signer + its JWKS endpoint.
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	// Resource server's store has the tenant issuer registered, pointing at
	// the platform's JWKS endpoint.
	src := &memFederatedSource{items: []core.TenantIssuer{{
		TenantSlug: "cozy-art",
		Issuer:     iss,
		JWKSURI:    jwks.URL + "/.well-known/jwks.json",
		Enabled:    true,
	}}}

	// Resource server's verifier loads tenant issuers from the store.
	ver := NewVerifier(WithTenantMode("multi"))
	if err := ver.LoadTenantIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadTenantIssuers: %v", err)
	}

	// Platform mints a delegated service token.
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "ext-user-1",
		Attributes:       map[string]any{"tier": "cozy_pro"},
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
	if dp.DelegatedSubject != "ext-user-1" || dp.UserTier != "cozy_pro" {
		t.Fatalf("principal=%+v", dp)
	}
}

// TestVerifierRejectsTenantIssuerMismatch proves the resource server binds a
// tenant issuer to the tenant/resource account it was registered for.
// (Hard cut: tokens carry no tenant claims, so "claiming another resource
// account" is structurally impossible — the issuer registration alone decides
// the tenant. These tests now assert the registry-loaded issuer's token simply
// verifies.)
func TestVerifierAcceptsRegistryLoadedTenantIssuerToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://doujins.example"
	aud := []string{"openrails"}
	src := newCountingSource(core.TenantIssuer{
		TenantSlug: "doujins",
		Issuer:     iss,
		JWKSURI:    jwks.URL + "/.well-known/jwks.json",
		Enabled:    true,
	})

	ver := NewVerifier(WithTenantMode("multi"))
	if err := ver.LoadTenantIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadTenantIssuers: %v", err)
	}

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "paul-fidika",
		Permissions:      []string{"openrails:tenant:admin"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, _, err = ver.VerifyDelegatedAccess(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifierAcceptsLazyLoadedTenantIssuerToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://doujins.example"
	aud := []string{"openrails"}
	src := newCountingSource(core.TenantIssuer{
		TenantSlug: "doujins",
		Issuer:     iss,
		JWKSURI:    jwks.URL + "/.well-known/jwks.json",
		Enabled:    true,
	})

	// Load only the source/audience; the List path returns nothing so the token
	// must exercise lazy-load-on-miss.
	ver := NewVerifier(WithTenantMode("multi"))
	if err := ver.LoadTenantIssuers(context.Background(), &listEmptyGetFull{src}, aud); err != nil {
		t.Fatalf("LoadTenantIssuers: %v", err)
	}

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "paul-fidika",
		Permissions:      []string{"openrails:tenant:admin"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, _, err = ver.VerifyDelegatedAccess(tok); err != nil {
		t.Fatalf("verify (lazy-load): %v", err)
	}
}

// TestVerifierRejectsUnregisteredIssuer confirms an unregistered issuer's token
// is rejected even though the JWKS is reachable.
func TestVerifierRejectsUnregisteredIssuer(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	src := &memFederatedSource{} // empty store
	ver := NewVerifier(WithTenantMode("multi"))
	if err := ver.LoadTenantIssuers(context.Background(), src, []string{"tensorhub"}); err != nil {
		t.Fatalf("LoadTenantIssuers: %v", err)
	}
	tok, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: "https://rogue.example", Audiences: []string{"tensorhub"},
		DelegatedSubject: "x", TTL: time.Minute,
	})
	if _, err := ver.Verify(tok); err == nil {
		t.Fatal("expected rejection of unregistered issuer")
	}
}
