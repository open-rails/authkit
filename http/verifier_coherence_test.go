package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// countingSource wraps an in-memory federated store and counts how many times
// each lookup method is called, so tests can assert single-DB-hit behavior and
// negative caching.
type countingSource struct {
	mu        sync.Mutex
	items     []core.FederatedOrgIssuer
	listCalls int32
	getCalls  map[string]int32
}

func newCountingSource(items ...core.FederatedOrgIssuer) *countingSource {
	return &countingSource{items: items, getCalls: map[string]int32{}}
}

func (c *countingSource) setItems(items []core.FederatedOrgIssuer) {
	c.mu.Lock()
	c.items = items
	c.mu.Unlock()
}

func (c *countingSource) ListFederatedOrgIssuers(_ context.Context, activeOnly bool) ([]core.FederatedOrgIssuer, error) {
	atomic.AddInt32(&c.listCalls, 1)
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []core.FederatedOrgIssuer
	for _, i := range c.items {
		if !activeOnly || i.Status == "active" {
			out = append(out, i)
		}
	}
	return out, nil
}

func (c *countingSource) GetFederatedOrgIssuer(_ context.Context, issuerID string) (*core.FederatedOrgIssuer, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.getCalls[issuerID]++
	for i := range c.items {
		if c.items[i].IssuerID == issuerID {
			fi := c.items[i]
			return &fi, nil
		}
	}
	return nil, core.ErrFederatedIssuerNotFound
}

func (c *countingSource) getCount(issuerID string) int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.getCalls[issuerID]
}

// rotatableJWKS serves a JWKS whose key set can be swapped at runtime, and
// counts fetches so rotation/single-flight behavior can be asserted.
type rotatableJWKS struct {
	mu      sync.Mutex
	signer  *jwtkit.RSASigner
	fetches int32
	srv     *httptest.Server
}

func newRotatableJWKS(t *testing.T, signer *jwtkit.RSASigner) *rotatableJWKS {
	t.Helper()
	r := &rotatableJWKS{signer: signer}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, req *http.Request) {
		atomic.AddInt32(&r.fetches, 1)
		r.mu.Lock()
		s := r.signer
		r.mu.Unlock()
		jwk := jwtkit.PublicToJWK(s.PublicKey(), s.KID(), s.Algorithm())
		jwtkit.ServeJWKS(w, req, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	r.srv = httptest.NewServer(mux)
	t.Cleanup(r.srv.Close)
	return r
}

func (r *rotatableJWKS) rotate(s *jwtkit.RSASigner) {
	r.mu.Lock()
	r.signer = s
	r.mu.Unlock()
}

func (r *rotatableJWKS) url() string { return r.srv.URL + "/.well-known/jwks.json" }

func mintFor(t *testing.T, signer *jwtkit.RSASigner, iss string, aud []string) string {
	t.Helper()
	tok, err := MintDelegatedAccessToken(context.Background(), signer, DelegatedAccessParams{
		Issuer:           iss,
		Audiences:        aud,
		DelegatedSubject: "ext-user",
		Tenant:           "cozy-art",
		TTL:              time.Minute,
	})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return tok
}

// (a) Lazy-load a not-pre-loaded issuer succeeds, and a second Verify hits the
// in-memory cache (source GET + JWKS fetch each happen exactly once).
func TestLazyLoadOnMissThenCached(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-1")
	jwks := newRotatableJWKS(t, signer)
	iss := "https://lazy.example"
	aud := []string{"tensorhub"}

	src := newCountingSource(core.FederatedOrgIssuer{
		OrgSlug: "cozy-art", IssuerID: iss, JWKSURL: jwks.url(), Status: "active",
	})

	ver := NewVerifier(WithOrgMode("multi"))
	// Thread fedSource + audiences via LoadFederatedIssuers using a source whose
	// List is EMPTY (nothing pre-loaded) but whose Get knows the issuer. This
	// isolates the lazy-load-on-miss path from the bulk load.
	if err := ver.LoadFederatedIssuers(context.Background(), &listEmptyGetFull{src}, aud); err != nil {
		t.Fatalf("LoadFederatedIssuers: %v", err)
	}

	tok := mintFor(t, signer, iss, aud)
	if _, err := ver.Verify(tok); err != nil {
		t.Fatalf("first verify (lazy-load): %v", err)
	}
	if got := src.getCount(iss); got != 1 {
		t.Fatalf("expected 1 GET on first use, got %d", got)
	}
	if f := atomic.LoadInt32(&jwks.fetches); f != 1 {
		t.Fatalf("expected 1 JWKS fetch on first use, got %d", f)
	}

	// Second verify must hit cache: no new GET, no new JWKS fetch.
	if _, err := ver.Verify(tok); err != nil {
		t.Fatalf("second verify (cached): %v", err)
	}
	if got := src.getCount(iss); got != 1 {
		t.Fatalf("expected GET still 1 on cached use, got %d", got)
	}
	if f := atomic.LoadInt32(&jwks.fetches); f != 1 {
		t.Fatalf("expected JWKS fetch still 1 on cached use, got %d", f)
	}
}

// listEmptyGetFull lists nothing (so nothing is bulk-loaded) but Get returns the
// underlying source's issuers, isolating the lazy-load path.
type listEmptyGetFull struct{ inner *countingSource }

func (l *listEmptyGetFull) ListFederatedOrgIssuers(context.Context, bool) ([]core.FederatedOrgIssuer, error) {
	return nil, nil
}
func (l *listEmptyGetFull) GetFederatedOrgIssuer(ctx context.Context, issuerID string) (*core.FederatedOrgIssuer, error) {
	return l.inner.GetFederatedOrgIssuer(ctx, issuerID)
}

// (b) Unknown issuer fails AND is negatively cached: the source is not consulted
// again on an immediate retry.
func TestUnknownIssuerNegativeCached(t *testing.T) {
	src := newCountingSource() // empty: GET always returns not-found
	signer, _ := jwtkit.NewRSASigner(2048, "k")
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), src, []string{"tensorhub"}); err != nil {
		t.Fatalf("LoadFederatedIssuers: %v", err)
	}
	iss := "https://rogue.example"
	tok := mintFor(t, signer, iss, []string{"tensorhub"})

	if _, err := ver.Verify(tok); err == nil {
		t.Fatal("expected unknown issuer to be rejected")
	}
	if got := src.getCount(iss); got != 1 {
		t.Fatalf("expected 1 GET for unknown issuer, got %d", got)
	}
	// Immediate retry must be served from the negative cache (no new GET).
	if _, err := ver.Verify(tok); err == nil {
		t.Fatal("expected unknown issuer still rejected")
	}
	if got := src.getCount(iss); got != 1 {
		t.Fatalf("expected GET still 1 (negative cache), got %d", got)
	}
}

// (c) Reconciling reload evicts a now-inactive issuer so its token stops
// validating.
func TestReconcilingReloadEvicts(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-1")
	jwks := newRotatableJWKS(t, signer)
	iss := "https://evict.example"
	aud := []string{"tensorhub"}

	src := newCountingSource(core.FederatedOrgIssuer{
		OrgSlug: "cozy-art", IssuerID: iss, JWKSURL: jwks.url(), Status: "active",
	})
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("initial load: %v", err)
	}

	tok := mintFor(t, signer, iss, aud)
	if _, err := ver.Verify(tok); err != nil {
		t.Fatalf("verify before eviction: %v", err)
	}

	// Deactivate the issuer in the store and reconcile.
	src.setItems([]core.FederatedOrgIssuer{{
		OrgSlug: "cozy-art", IssuerID: iss, JWKSURL: jwks.url(), Status: "inactive",
	}})
	if err := ver.LoadFederatedIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("reconcile load: %v", err)
	}

	// The token must now be rejected. The lazy-load path won't re-add it because
	// GET returns a non-active status.
	if _, err := ver.Verify(tok); err == nil {
		t.Fatal("expected token to be rejected after eviction")
	}
}

// Static issuers (added via AddIssuer directly) must NOT be evicted by a
// reconciling reload — only federated issuers are eligible.
func TestReconcileDoesNotEvictStaticIssuer(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-1")
	jwks := newRotatableJWKS(t, signer)
	staticIss := "https://static.example"
	aud := []string{"tensorhub"}

	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.AddIssuer(staticIss, aud, IssuerOptions{JWKSURL: jwks.url()}); err != nil {
		t.Fatalf("AddIssuer static: %v", err)
	}

	// A reconciling reload with an empty federated set must leave the static
	// issuer intact.
	src := newCountingSource()
	if err := ver.LoadFederatedIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("reconcile: %v", err)
	}

	tok := mintFor(t, signer, staticIss, aud)
	if _, err := ver.Verify(tok); err != nil {
		t.Fatalf("static issuer should still validate after reconcile: %v", err)
	}
}

// (d) A rotated kid arriving mid-TTL triggers a single bounded JWKS refetch and
// then validates.
func TestRotatedKidRefetch(t *testing.T) {
	signer1, _ := jwtkit.NewRSASigner(2048, "kid-old")
	jwks := newRotatableJWKS(t, signer1)
	iss := "https://rotate.example"
	aud := []string{"tensorhub"}

	src := newCountingSource(core.FederatedOrgIssuer{
		OrgSlug: "cozy-art", IssuerID: iss, JWKSURL: jwks.url(), Status: "active",
	})
	// Long TTL so the normal TTL refresh does not fire — only the unknown-kid
	// fall-through can pick up the rotation.
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("load: %v", err)
	}
	// Force a long cacheTTL on the registered issuer.
	if err := ver.AddIssuer(iss, aud, IssuerOptions{JWKSURL: jwks.url(), CacheTTL: time.Hour}); err != nil {
		t.Fatalf("re-add with long TTL: %v", err)
	}

	// Prime the cache with kid-old.
	tokOld := mintFor(t, signer1, iss, aud)
	if _, err := ver.Verify(tokOld); err != nil {
		t.Fatalf("verify with old kid: %v", err)
	}
	fetchesAfterPrime := atomic.LoadInt32(&jwks.fetches)

	// Rotate the signer/JWKS to a new kid.
	signer2, _ := jwtkit.NewRSASigner(2048, "kid-new")
	jwks.rotate(signer2)
	tokNew := mintFor(t, signer2, iss, aud)

	// Mid-TTL token with the new kid must trigger a forced refetch and validate.
	if _, err := ver.Verify(tokNew); err != nil {
		t.Fatalf("verify with rotated kid (should refetch): %v", err)
	}
	if atomic.LoadInt32(&jwks.fetches) <= fetchesAfterPrime {
		t.Fatal("expected a forced JWKS refetch on unknown kid")
	}
}

// Single-flight guard: a storm of unknown-kid tokens must not hammer the JWKS
// endpoint — at most one forced refetch within the min-interval window.
func TestUnknownKidStormSingleFlight(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-known")
	jwks := newRotatableJWKS(t, signer)
	iss := "https://storm.example"
	aud := []string{"tensorhub"}

	src := newCountingSource(core.FederatedOrgIssuer{
		OrgSlug: "cozy-art", IssuerID: iss, JWKSURL: jwks.url(), Status: "active",
	})
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), src, aud); err != nil {
		t.Fatalf("load: %v", err)
	}
	if err := ver.AddIssuer(iss, aud, IssuerOptions{JWKSURL: jwks.url(), CacheTTL: time.Hour}); err != nil {
		t.Fatalf("re-add: %v", err)
	}
	// Prime cache.
	if _, err := ver.Verify(mintFor(t, signer, iss, aud)); err != nil {
		t.Fatalf("prime: %v", err)
	}
	fetchesAfterPrime := atomic.LoadInt32(&jwks.fetches)

	// A token signed by an UNRELATED signer (unknown kid, never in this JWKS).
	bad, _ := jwtkit.NewRSASigner(2048, "kid-bad")
	tok := mintFor(t, bad, iss, aud)

	for i := 0; i < 10; i++ {
		_, _ = ver.Verify(tok) // all fail, but should refetch at most once
	}
	delta := atomic.LoadInt32(&jwks.fetches) - fetchesAfterPrime
	if delta > 1 {
		t.Fatalf("expected at most 1 forced refetch within min-interval, got %d", delta)
	}
}

// (e) No deadlock and correctness under concurrent first-use of the same issuer:
// many goroutines verify simultaneously; the source GET coalesces.
func TestConcurrentFirstUseNoDeadlock(t *testing.T) {
	signer, _ := jwtkit.NewRSASigner(2048, "kid-1")
	jwks := newRotatableJWKS(t, signer)
	iss := "https://concurrent.example"
	aud := []string{"tensorhub"}

	src := newCountingSource(core.FederatedOrgIssuer{
		OrgSlug: "cozy-art", IssuerID: iss, JWKSURL: jwks.url(), Status: "active",
	})
	ver := NewVerifier(WithOrgMode("multi"))
	if err := ver.LoadFederatedIssuers(context.Background(), &listEmptyGetFull{src}, aud); err != nil {
		t.Fatalf("load: %v", err)
	}

	tok := mintFor(t, signer, iss, aud)

	done := make(chan error, 50)
	for i := 0; i < 50; i++ {
		go func() {
			_, err := ver.Verify(tok)
			done <- err
		}()
	}
	timeout := time.After(10 * time.Second)
	for i := 0; i < 50; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("concurrent verify failed: %v", err)
			}
		case <-timeout:
			t.Fatal("deadlock/timeout under concurrent first-use")
		}
	}
	// Single-flight should keep the source GET count low (not 50).
	if got := src.getCount(iss); got > 5 {
		t.Fatalf("single-flight failed: %d GETs for concurrent first-use", got)
	}
}
