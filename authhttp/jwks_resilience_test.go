package authhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
)

// TestVerifierJWKSFetchResilience proves the JWKS fetcher tolerates a
// momentarily-unreachable endpoint (a peer still starting / transient 5xx):
// the first two JWKS fetches fail, but token verification still succeeds because
// refreshIssuerKeys retries with backoff instead of failing on the first blip.
func TestVerifierJWKSFetchResilience(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "platform-kid")
	if err != nil {
		t.Fatal(err)
	}
	var calls int32
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable) // transient: peer "starting"
			return
		}
		jwk := jwtkit.PublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())
		jwtkit.ServeJWKS(w, r, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	iss := "https://flaky.example"
	aud := []string{"tensorhub"}
	ver := NewVerifier()
	if err := ver.AddIssuer(iss, aud, IssuerOptions{JWKSURI: srv.URL + "/.well-known/jwks.json"}); err != nil {
		t.Fatal(err)
	}
	tok, err := embedded.MintDelegatedAccessToken(context.Background(), signer, authkit.DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ver.Verify(tok); err != nil {
		t.Fatalf("verify should succeed after JWKS retries (calls=%d): %v", atomic.LoadInt32(&calls), err)
	}
	if got := atomic.LoadInt32(&calls); got < 3 {
		t.Fatalf("expected the fetcher to retry past the transient 503s, calls=%d", got)
	}
}

// TestVerifierRefetchesOnVerifyFailure proves the "refetch-on-reject" path: a
// signing key rotates under the SAME kid while the cached JWKS is still fresh.
// The first verify of a token signed by the NEW key fails against the cached
// (old) key; VerifyClaims then force-refreshes the issuer's JWKS and retries,
// so the verification ultimately succeeds without waiting for the TTL.
func TestVerifierRefetchesOnVerifyFailure(t *testing.T) {
	const kid = "rotating-kid"
	oldSigner, err := jwtkit.NewRSASigner(2048, kid)
	if err != nil {
		t.Fatal(err)
	}
	newSigner, err := jwtkit.NewRSASigner(2048, kid)
	if err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[jwtkit.RSASigner]
	current.Store(oldSigner)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		s := current.Load()
		jwk := jwtkit.PublicToJWK(s.PublicKey(), s.KID(), s.Algorithm())
		jwtkit.ServeJWKS(w, r, jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	iss := "https://rotate.example"
	aud := []string{"tensorhub"}
	ver := NewVerifier()
	if err := ver.AddIssuer(iss, aud, IssuerOptions{JWKSURI: srv.URL + "/.well-known/jwks.json"}); err != nil {
		t.Fatal(err)
	}

	// Prime the cache with the OLD key (verify a token it signed).
	t1, _ := embedded.MintDelegatedAccessToken(context.Background(), oldSigner, authkit.DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u1", TTL: time.Minute,
	})
	if _, err := ver.Verify(t1); err != nil {
		t.Fatalf("prime verify: %v", err)
	}

	// Rotate the signing key (same kid), cache still fresh, mint with the NEW key.
	current.Store(newSigner)
	t2, _ := embedded.MintDelegatedAccessToken(context.Background(), newSigner, authkit.DelegatedAccessParams{
		Issuer: iss, Audiences: aud, DelegatedSubject: "u2", TTL: time.Minute,
	})
	if _, err := ver.Verify(t2); err != nil {
		t.Fatalf("verify should succeed after refetch-on-reject (key rotated under same kid): %v", err)
	}
}
