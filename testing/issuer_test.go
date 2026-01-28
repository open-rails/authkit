package testing

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	authhttp "github.com/PaulFidika/authkit/adapters/http"
	"github.com/PaulFidika/authkit/core"
	jwtkit "github.com/PaulFidika/authkit/jwt"
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

	// Create a token
	token := issuer.CreateToken("user-123", "test@example.com")

	// Create a verifier configured to accept tokens from our test issuer
	accept := core.AcceptConfig{
		Issuers: []core.IssuerAccept{
			{
				Issuer:   issuer.URL(),
				Audience: issuer.Audience(),
			},
		},
		Algorithms: []string{"RS256"},
		Skew:       60 * time.Second,
	}

	verifier := authhttp.NewVerifier(accept)

	// Verify the token
	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	// Check claims
	if sub, _ := claims["sub"].(string); sub != "user-123" {
		t.Errorf("expected sub=user-123, got %s", sub)
	}
	if email, _ := claims["email"].(string); email != "test@example.com" {
		t.Errorf("expected email=test@example.com, got %s", email)
	}
	if iss, _ := claims["iss"].(string); iss != issuer.URL() {
		t.Errorf("expected iss=%s, got %s", issuer.URL(), iss)
	}
}

func TestTestIssuer_TokenWithRoles(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	roles := []string{"admin", "moderator"}
	token := issuer.CreateTokenWithRoles("user-123", "test@example.com", roles)

	accept := core.AcceptConfig{
		Issuers: []core.IssuerAccept{
			{Issuer: issuer.URL(), Audience: issuer.Audience()},
		},
		Algorithms: []string{"RS256"},
	}

	verifier := authhttp.NewVerifier(accept)
	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	claimRoles, ok := claims["roles"].([]any)
	if !ok {
		t.Fatal("expected roles claim to be present")
	}
	if len(claimRoles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(claimRoles))
	}
}

func TestTestIssuer_ExpiredToken(t *testing.T) {
	issuer := NewTestIssuer()
	defer issuer.Close()

	// Create an expired token
	token := issuer.CreateExpiredToken("user-123", "test@example.com")

	accept := core.AcceptConfig{
		Issuers: []core.IssuerAccept{
			{Issuer: issuer.URL(), Audience: issuer.Audience()},
		},
		Algorithms: []string{"RS256"},
		Skew:       0, // No skew - strict expiry checking
	}

	verifier := authhttp.NewVerifier(accept)
	_, err := verifier.Verify(token)

	// Token should fail verification due to expiry
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

	accept := core.AcceptConfig{
		Issuers: []core.IssuerAccept{
			{Issuer: issuer.URL(), Audience: "billing-service"},
		},
		Algorithms: []string{"RS256"},
	}

	verifier := authhttp.NewVerifier(accept)
	claims, err := verifier.Verify(token)
	if err != nil {
		t.Fatalf("token verification failed: %v", err)
	}

	if aud, _ := claims["aud"].(string); aud != "billing-service" {
		t.Errorf("expected aud=billing-service, got %s", aud)
	}
}
