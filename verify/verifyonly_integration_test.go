package verify_test

// Integration test for the verify-only consumer story (#110): this file is in an
// EXTERNAL test package and imports ONLY the verify package + jwtkit + stdlib —
// never core, pgx, or redis. It therefore both exercises the end-to-end verify
// path (mint → verify → middleware-gate) AND serves as a compile-time proof that
// token verification works without authkit's storage stack.

import (
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/open-rails/authkit/verify"
)

func mintAccess(t *testing.T, signer jwtkit.Signer, iss, aud, sub string) string {
	t.Helper()
	hs, ok := any(signer).(jwtkit.HeaderSigner)
	if !ok {
		t.Fatal("test signer must support JOSE headers")
	}
	now := time.Now()
	tok, err := hs.SignWithHeaders(context.Background(), map[string]any{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}, map[string]any{"typ": verify.AccessTokenType})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

func TestVerifyOnlyConsumer_EndToEnd(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	const iss = "https://issuer.example"
	const aud = "my-api"

	v := verify.NewVerifier(verify.WithAlgorithms("RS256"))
	if err := v.AddIssuer(iss, []string{aud}, verify.IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
		IsLocal: true,
	}); err != nil {
		t.Fatalf("add issuer: %v", err)
	}

	tok := mintAccess(t, signer, iss, aud, "user-123")

	// 1) Direct verification yields the expected claims.
	cl, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if cl.UserID != "user-123" {
		t.Fatalf("UserID = %q, want user-123", cl.UserID)
	}
	if cl.Issuer != iss {
		t.Fatalf("Issuer = %q, want %q", cl.Issuer, iss)
	}

	// 2) Required middleware admits a valid token and exposes claims in context —
	//    with NO enricher set (the native-user path is stateless — no DB work; #215).
	var sawUser string
	h := verify.Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, ok := verify.ClaimsFromContext(r.Context())
		if !ok {
			t.Error("claims missing from request context")
		}
		sawUser = c.UserID
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("protected route status = %d, want 200", rec.Code)
	}
	if sawUser != "user-123" {
		t.Fatalf("handler saw UserID = %q, want user-123", sawUser)
	}

	// 3) Missing Authorization → 401.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/protected", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", rec.Code)
	}

	// 4) A token signed by an unknown key under the same issuer must NOT verify.
	attacker, err := jwtkit.NewRSASigner(2048, "attacker-kid")
	if err != nil {
		t.Fatalf("new attacker signer: %v", err)
	}
	bad := mintAccess(t, attacker, iss, aud, "user-123")
	if _, err := v.Verify(bad); err == nil {
		t.Fatal("token signed with an unknown key must not verify")
	}
}
