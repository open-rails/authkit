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

// memFederatedSource is an in-memory OrgIssuerSource for tests, so the
// Verifier-load path can be exercised without a Postgres-backed core.Service.
type memFederatedSource struct {
	items []core.RemoteApplication
}

func (m *memFederatedSource) ListRemoteApplications(_ context.Context, enabledOnly bool) ([]core.RemoteApplication, error) {
	if !enabledOnly {
		return m.items, nil
	}
	var out []core.RemoteApplication
	for _, i := range m.items {
		if i.Enabled {
			out = append(out, i)
		}
	}
	return out, nil
}

func (m *memFederatedSource) GetRemoteApplication(_ context.Context, issuerID string) (*core.RemoteApplication, error) {
	for i := range m.items {
		if m.items[i].Issuer == issuerID {
			fi := m.items[i]
			return &fi, nil
		}
	}
	return nil, core.ErrRemoteApplicationNotFound
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

// TestOutboundClientPostsRegistration verifies the outbound OrgIssuersClient
// posts the correct body and auth header to a resource server's accept endpoint.
func TestOutboundClientPostsRegistration(t *testing.T) {
	var got remoteApplicationRegistration
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	fc := NewOrgIssuersClient(WithOrgIssuersAuthToken("owner-token"))
	err := fc.RegisterIssuer(context.Background(), srv.URL+"/api/v1/remote-applications", OrgIssuersRegistration{
		Slug:           "cozy-art",
		Issuer:         "https://cozy.example",
		JWKSURI:        "https://cozy.example/.well-known/jwks.json",
		AllowedOrigins: []string{"https://Cozy.example"},
	})
	if err != nil {
		t.Fatalf("RegisterIssuer: %v", err)
	}
	if got.Slug != "cozy-art" || got.Issuer != "https://cozy.example" || got.JWKSURI != "https://cozy.example/.well-known/jwks.json" {
		t.Fatalf("body mismatch: %+v", got)
	}
	if len(got.AllowedOrigins) != 1 || got.AllowedOrigins[0] != "https://cozy.example" {
		t.Fatalf("allowed_origins mismatch: %#v", got.AllowedOrigins)
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
	fc := NewOrgIssuersClient()
	err := fc.RegisterIssuer(context.Background(), srv.URL, OrgIssuersRegistration{
		Slug: "cozy-art", Issuer: "https://cozy.example", JWKSURI: "https://cozy.example/jwks",
	})
	if err == nil {
		t.Fatal("expected error for non-2xx response")
	}
}

func TestOutboundClientValidatesInput(t *testing.T) {
	fc := NewOrgIssuersClient()
	if err := fc.RegisterIssuer(context.Background(), "", OrgIssuersRegistration{Slug: "a", Issuer: "b", JWKSURI: "c"}); err == nil {
		t.Fatal("expected error for empty accept URL")
	}
	if err := fc.RegisterIssuer(context.Background(), "http://x", OrgIssuersRegistration{Slug: "a"}); err == nil {
		t.Fatal("expected error for missing issuer/jwks")
	}
	if err := fc.RegisterIssuer(context.Background(), "http://x", OrgIssuersRegistration{
		Slug: "a", Issuer: "https://issuer.example", JWKSURI: "https://issuer.example/jwks",
		AllowedOrigins: []string{"https://issuer.example/path"},
	}); err == nil {
		t.Fatal("expected error for invalid allowed_origins")
	}
}

func TestRemoteApplicationCORSUsesEnabledOriginUnion(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	src := &memFederatedSource{items: []core.RemoteApplication{
		{Slug: "doujins", Issuer: "https://auth.doujins.com", JWKSURI: jwks.URL + "/.well-known/jwks.json", AllowedOrigins: []string{"https://doujins.com"}, Enabled: true},
		{Slug: "hentai0", Issuer: "https://auth.hentai0.com", JWKSURI: jwks.URL + "/.well-known/jwks.json", AllowedOrigins: []string{"https://hentai0.com"}, Enabled: false},
	}}
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadRemoteApplications(context.Background(), src, []string{"openrails"}); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}
	handler := RemoteApplicationCORS(ver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	allowed := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/memberships/cancel", nil)
	req.Header.Set("Origin", "https://doujins.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d body=%s", allowed.Code, allowed.Body.String())
	}
	if got := allowed.Header().Get("Access-Control-Allow-Origin"); got != "https://doujins.com" {
		t.Fatalf("Access-Control-Allow-Origin = %q", got)
	}

	disabled := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodOptions, "/memberships/cancel", nil)
	req.Header.Set("Origin", "https://hentai0.com")
	handler.ServeHTTP(disabled, req)
	if disabled.Code != http.StatusForbidden {
		t.Fatalf("disabled origin preflight status = %d body=%s", disabled.Code, disabled.Body.String())
	}
}

func TestRequireDelegatedOriginChecksVerifiedIssuer(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://auth.doujins.com"
	aud := []string{"openrails"}
	src := &memFederatedSource{items: []core.RemoteApplication{{
		Slug:           "doujins",
		Issuer:         iss,
		JWKSURI:        jwks.URL + "/.well-known/jwks.json",
		AllowedOrigins: []string{"https://doujins.com"},
		Enabled:        true,
	}}}
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadRemoteApplications(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "external-user-1",
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	handler := Required(ver)(RequireDelegatedOrigin(ver, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})))

	for _, tc := range []struct {
		name   string
		origin string
		want   int
	}{
		{name: "matching origin", origin: "https://doujins.com", want: http.StatusOK},
		{name: "no origin server to server", origin: "", want: http.StatusOK},
		{name: "other merchant origin", origin: "https://hentai0.com", want: http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/memberships/cancel", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

// TestVerifierLoadsOrgIssuerAndValidates is the end-to-end mint -> register
// (in store) -> load-into-verifier -> validate path. The platform mints a
// delegated token; the resource server loads the org issuer from its
// store and validates the token against the issuer's JWKS.
func TestVerifierLoadsOrgIssuerAndValidates(t *testing.T) {
	// Platform signer + its JWKS endpoint.
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://cozy.example"
	aud := []string{"tensorhub"}

	// Resource server's store has the org issuer registered, pointing at
	// the platform's JWKS endpoint.
	src := &memFederatedSource{items: []core.RemoteApplication{{
		Slug:    "cozy-art",
		Issuer:  iss,
		JWKSURI: jwks.URL + "/.well-known/jwks.json",
		Enabled: true,
	}}}

	// Resource server's verifier loads org issuers from the store.
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadRemoteApplications(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}

	// Platform mints a delegated access token.
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

// TestVerifierRejectsOrgIssuerMismatch proves the resource server binds a
// org issuer to the org/resource account it was registered for.
// (Hard cut: tokens carry no org claims, so "claiming another resource
// account" is structurally impossible — the issuer registration alone decides
// the org. These tests now assert the registry-loaded issuer's token simply
// verifies.)
func TestVerifierAcceptsRegistryLoadedOrgIssuerToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://doujins.example"
	aud := []string{"openrails"}
	src := newCountingSource(core.RemoteApplication{
		Slug:    "doujins",
		Issuer:  iss,
		JWKSURI: jwks.URL + "/.well-known/jwks.json",
		Enabled: true,
	})

	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadRemoteApplications(context.Background(), src, aud); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "paul-fidika",
		Permissions:      []string{"openrails:merchant:admin"},
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if _, _, err = ver.VerifyDelegatedAccess(tok); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifierAcceptsLazyLoadedOrgIssuerToken(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	jwks := jwksServer(t, signer)
	defer jwks.Close()

	iss := "https://doujins.example"
	aud := []string{"openrails"}
	src := newCountingSource(core.RemoteApplication{
		Slug:    "doujins",
		Issuer:  iss,
		JWKSURI: jwks.URL + "/.well-known/jwks.json",
		Enabled: true,
	})

	// Load only the source/audience; the List path returns nothing so the token
	// must exercise lazy-load-on-miss.
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadRemoteApplications(context.Background(), &listEmptyGetFull{src}, aud); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}

	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "paul-fidika",
		Permissions:      []string{"openrails:merchant:admin"},
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
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadRemoteApplications(context.Background(), src, []string{"tensorhub"}); err != nil {
		t.Fatalf("LoadRemoteApplications: %v", err)
	}
	tok, _ := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer: "https://rogue.example", Audiences: []string{"tensorhub"},
		DelegatedSubject: "x", TTL: time.Minute,
	})
	if _, err := ver.Verify(tok); err == nil {
		t.Fatal("expected rejection of unregistered issuer")
	}
}
