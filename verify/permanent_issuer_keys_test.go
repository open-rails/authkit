package verify

// #239 regression coverage: an issuer registered with pre-provided keys
// (RawKeys/Keys) and NO JWKS URI — including every IsLocal issuer, since a
// co-located authkit.Service always registers itself this way — must be
// PERMANENT. It must never synthesize a `<issuer>/.well-known/jwks.json`
// fetch, no matter how much time passes or what kid a token names. Only an
// issuer registered WITH a JWKS URI may ever refetch.
//
// There is no injectable clock in Verifier (time.Now() throughout), so
// "simulate 25h/49h past" is done by reaching into the unexported issuerKeys
// cache entry directly (white-box, package verify) and setting expiresAt/
// staleUntil deep in the past — proving the fix does not merely raise the
// TTL, but makes a permanent entry's expiry fields irrelevant regardless of
// their value. A counting HTTP transport that errors on every call proves
// zero network attempts across all of: normal verification, a
// deep-in-the-past cache entry, an unknown kid, and a bad signature (the
// verify-failure retry path).

import (
	"crypto"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/jwtkit"
)

// neverDialTransport fails every request instantly (no real network I/O) and
// counts how many times it was invoked, so a test can assert "zero fetch
// attempts" even though the issuer string looks like a fetchable URL.
type neverDialTransport struct {
	calls atomic.Int64
}

func (rt *neverDialTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls.Add(1)
	return nil, fmt.Errorf("test: unexpected outbound request to %s (permanent issuer must never fetch)", req.URL)
}

func TestPermanentIssuerKeys_NeverExpireNeverFetch(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid-permanent")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}

	// A DNS-plausible issuer/host: if the pre-fix well-known synthesis fired,
	// this transport would see the request instead of erroring on an
	// obviously-fake hostname (which could be mistaken for a config error
	// rather than a proven fetch attempt).
	const iss = "https://permanent-issuer.example"
	const aud = "my-api"

	transport := &neverDialTransport{}
	v := NewVerifier(WithAlgorithms("RS256"), WithHTTPClient(&http.Client{Transport: transport}))
	if err := v.AddIssuer(iss, []string{aud}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		IsLocal: true,
	}); err != nil {
		t.Fatalf("add issuer: %v", err)
	}

	tok := mintStatelessAccess(t, signer, iss, aud, "user-123")

	// 1) Verifies immediately, no fetch.
	if _, err := v.VerifyClaims(tok); err != nil {
		t.Fatalf("verify immediately after AddIssuer: %v", err)
	}
	if n := transport.calls.Load(); n != 0 {
		t.Fatalf("unexpected %d outbound request(s) on first verify", n)
	}

	// 2) Simulate 25h/49h having passed: force the cached entry's expiresAt/
	// staleUntil deep into the past. Under the pre-#239 24h/48h synthetic TTL
	// this would trigger a forced refetch; under the fix it must be a no-op
	// because permanence is keyed on the ABSENCE of a JWKS URI, not on these
	// timestamps.
	longAgo := time.Now().Add(-1000 * time.Hour)
	v.mu.Lock()
	c := v.byIss[iss]
	if c == nil {
		v.mu.Unlock()
		t.Fatal("expected a seeded issuerKeys cache entry after AddIssuer(RawKeys)")
	}
	c.expiresAt = longAgo
	c.staleUntil = longAgo
	v.mu.Unlock()

	if _, err := v.VerifyClaims(tok); err != nil {
		t.Fatalf("verify after simulated 25h/49h expiry: %v", err)
	}
	if n := transport.calls.Load(); n != 0 {
		t.Fatalf("unexpected %d outbound request(s) after simulated expiry", n)
	}

	// 3) Unknown kid for this KNOWN, permanent issuer must fail closed
	// (unknown_kid) WITHOUT a forced JWKS refetch (publicKeyFor's guard).
	otherSigner, err := jwtkit.NewRSASigner(2048, "kid-not-registered")
	if err != nil {
		t.Fatalf("other signer: %v", err)
	}
	unknownKidTok := mintStatelessAccess(t, otherSigner, iss, aud, "user-123")
	if _, err := v.VerifyClaims(unknownKidTok); err == nil {
		t.Fatal("expected verification to fail for an unregistered kid")
	}
	if n := transport.calls.Load(); n != 0 {
		t.Fatalf("unexpected %d outbound request(s) after unknown-kid verify", n)
	}

	// 4) A KNOWN kid with a BAD signature (wrong private key) fails the
	// cryptographic check, which drives the verify-failure retry path
	// (forceRefreshForToken). That path must also refuse to fetch for a
	// permanent, URI-less issuer.
	wrongKeySameKID, err := jwtkit.NewRSASigner(2048, "kid-permanent") // same kid, different key
	if err != nil {
		t.Fatalf("wrong-key signer: %v", err)
	}
	badSigTok := mintStatelessAccess(t, wrongKeySameKID, iss, aud, "user-123")
	if _, err := v.VerifyClaims(badSigTok); err == nil {
		t.Fatal("expected verification to fail for a mismatched-key signature")
	}
	if n := transport.calls.Load(); n != 0 {
		t.Fatalf("unexpected %d outbound request(s) after bad-signature verify (forceRefreshForToken should have refused to fetch)", n)
	}
}
