package testing

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	authhttp "github.com/open-rails/authkit/adapters/http"
	jwtkit "github.com/open-rails/authkit/jwt"
)

func TestTestIssuer_ServesJWKS(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	// Fetch JWKS from the test server
	resp, err := http.Get(issuer.URL() + "/.well-known/jwks.json")
	if err != nil {
		t.Fatalf("failed to fetch JWKS: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var ks jwtkit.JWKS
	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		t.Fatalf("failed to decode JWKS: %v", err)
	}

	if len(ks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(ks.Keys))
	}

	key := ks.Keys[0]
	if key.Kty != "RSA" {
		t.Errorf("expected kty=RSA, got %s", key.Kty)
	}
	if key.Alg != "RS256" {
		t.Errorf("expected alg=RS256, got %s", key.Alg)
	}
	if key.Kid == "" {
		t.Error("expected kid to be set")
	}
}

func TestTestIssuer_CreateToken(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	token := issuer.CreateToken("user-123", "test@example.com")
	if token == "" {
		t.Fatal("expected non-empty token")
	}

	// Token should have 3 parts (header.payload.signature)
	parts := 0
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected 2 dots in JWT, got %d", parts)
	}
}

func TestTestIssuer_TokenValidatesWithVerifier(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	token := issuer.CreateToken("user-123", "test@example.com")

	verifier := authhttp.NewVerifier(
		authhttp.WithAlgorithms("RS256"),
		authhttp.WithSkew(60*time.Second),
	)
	_ = verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, authhttp.IssuerOptions{
		JWKSURL: issuer.URL() + "/.well-known/jwks.json",
	})

	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	if claims.UserID != "user-123" {
		t.Errorf("expected UserID=user-123, got %s", claims.UserID)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("expected Email=test@example.com, got %s", claims.Email)
	}
	if claims.Issuer != issuer.URL() {
		t.Errorf("expected Issuer=%s, got %s", issuer.URL(), claims.Issuer)
	}
}

func TestTestIssuer_TokenWithRoles(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	roles := []string{"admin", "moderator"}
	token := issuer.CreateTokenWithRoles("user-123", "test@example.com", roles)

	verifier := authhttp.NewVerifier(authhttp.WithAlgorithms("RS256"))
	_ = verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, authhttp.IssuerOptions{
		JWKSURL: issuer.URL() + "/.well-known/jwks.json",
	})

	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	if len(claims.Roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(claims.Roles))
	}
}

func TestTestIssuer_ExpiredToken(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	token := issuer.CreateExpiredToken("user-123", "test@example.com")

	verifier := authhttp.NewVerifier(
		authhttp.WithAlgorithms("RS256"),
		authhttp.WithSkew(0),
	)
	_ = verifier.AddIssuer(issuer.URL(), []string{issuer.Audience()}, authhttp.IssuerOptions{
		JWKSURL: issuer.URL() + "/.well-known/jwks.json",
	})

	_, err := verifier.Verify(token)
	if err == nil {
		t.Error("expected expired token to fail verification")
	}
}

func TestTestIssuer_CustomAudience(t *testing.T) {
	issuer := NewTestIssuerWithAudience("billing-service")
	defer issuer.Close()

	if issuer.Audience() != "billing-service" {
		t.Errorf("expected audience=billing-service, got %s", issuer.Audience())
	}

	token := issuer.CreateToken("user-123", "test@example.com")

	verifier := authhttp.NewVerifier(authhttp.WithAlgorithms("RS256"))
	_ = verifier.AddIssuer(issuer.URL(), []string{"billing-service"}, authhttp.IssuerOptions{
		JWKSURL: issuer.URL() + "/.well-known/jwks.json",
	})

	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	// aud is extracted into Claims but not as a field — verified via the issuer audience check.
	// Just confirm the token verified successfully with the right issuer.
	if claims.Issuer != issuer.URL() {
		t.Errorf("expected Issuer=%s, got %s", issuer.URL(), claims.Issuer)
	}
}
