package verify_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// ak#316: the caller's context reaches the JWKS fetch. A verifier whose issuer
// keys must be fetched from a stalled endpoint returns as soon as the caller's
// deadline passes, and the endpoint observes the request being cancelled —
// nothing waits on context.Background() inside the key lookup path.
func TestVerify_ContextCancellationReachesJWKSFetch(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "cancel-kid")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	const iss = "https://stalled-issuer.example"
	const aud = "my-api"

	sawCancel := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			close(sawCancel)
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	v := verify.NewVerifier(verify.WithAlgorithms("RS256"))
	if err := v.AddIssuer(iss, []string{aud}, verify.IssuerOptions{JWKSURI: srv.URL}); err != nil {
		t.Fatalf("add issuer: %v", err)
	}
	tok := mintAccess(t, signer, iss, aud, "user-1")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := v.Verify(ctx, tok); err == nil {
		t.Fatal("verify succeeded without any JWKS")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("verify took %v: the caller's deadline did not bound the JWKS fetch", elapsed)
	}
	select {
	case <-sawCancel:
	case <-time.After(5 * time.Second):
		t.Fatal("JWKS endpoint never observed the cancelled request")
	}
}
