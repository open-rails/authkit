// Package testing provides utilities for testing applications that use authkit.
// It provides a mock issuer that serves JWKS and can sign tokens, enabling
// integration tests without needing a real auth server.
//
// Example usage:
//
//	issuer := testing.NewTestIssuer()
//	defer issuer.Close()
//
//	// Configure your app to use the test issuer
//	cfg.Auth.Issuers = []string{issuer.URL()}
//
//	// Create tokens for testing
//	token := issuer.CreateToken("user-123", "test@example.com")
package testing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// TestIssuer provides a complete mock authentication setup for testing.
// It runs an HTTP server that serves JWKS at /.well-known/jwks.json
// and can sign JWT tokens that will validate against the JWKS.
type TestIssuer struct {
	server   *httptest.Server
	signer   *jwtkit.RSASigner
	audience string
}

// NewTestIssuer creates a new test issuer with a JWKS endpoint.
// The issuer generates a new RSA key pair and serves the public key as JWKS.
// Call Close() when done to shut down the test server.
func NewTestIssuer() *TestIssuer {
	return NewTestIssuerWithAudience("test-app")
}

// NewTestIssuerWithAudience creates a test issuer with a specific audience claim.
func NewTestIssuerWithAudience(audience string) *TestIssuer {
	signer, err := jwtkit.NewRSASigner(2048, "test-key-1")
	if err != nil {
		panic("failed to create RSA signer: " + err.Error())
	}

	ti := &TestIssuer{
		signer:   signer,
		audience: audience,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", ti.handleJWKS)

	ti.server = httptest.NewServer(mux)
	return ti
}

// URL returns the base URL of the test issuer server.
// Use this as the issuer in your auth configuration.
func (ti *TestIssuer) URL() string {
	return ti.server.URL
}

// Audience returns the audience configured for this test issuer.
func (ti *TestIssuer) Audience() string {
	return ti.audience
}

// Close shuts down the test server.
func (ti *TestIssuer) Close() {
	if ti.server != nil {
		ti.server.Close()
	}
}

// handleJWKS serves the JWKS document containing the public key.
func (ti *TestIssuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jwk := jwtkit.RSAPublicToJWK(ti.signer.PublicKey(), ti.signer.KID(), ti.signer.Algorithm())
	ks := jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}}
	jwtkit.ServeJWKS(w, r, ks)
}

// CreateToken creates a signed JWT token for testing.
// The token is signed with the test issuer's private key and will validate
// against the JWKS served by this issuer.
func (ti *TestIssuer) CreateToken(userID, email string) string {
	return ti.CreateTokenWithClaims(userID, email, nil)
}

// CreateTokenWithClaims creates a signed JWT token with additional custom claims.
// The custom claims are merged with the standard claims (sub, email, iss, aud, exp, iat).
func (ti *TestIssuer) CreateTokenWithClaims(userID, email string, extraClaims map[string]any) string {
	now := time.Now()

	claims := jwt.MapClaims{
		"sub":   userID,
		"email": email,
		"iss":   ti.URL(),
		"aud":   ti.audience,
		"exp":   now.Add(time.Hour).Unix(),
		"iat":   now.Unix(),
	}

	// Merge extra claims
	for k, v := range extraClaims {
		claims[k] = v
	}

	token, err := ti.signer.Sign(context.Background(), claims)
	if err != nil {
		panic("failed to sign token: " + err.Error())
	}
	return token
}

// CreateTokenWithRoles creates a signed JWT token with role claims.
func (ti *TestIssuer) CreateTokenWithRoles(userID, email string, roles []string) string {
	return ti.CreateTokenWithClaims(userID, email, map[string]any{
		"roles": roles,
	})
}

// CreateTokenWithExpiry creates a signed JWT token with a custom expiry time.
func (ti *TestIssuer) CreateTokenWithExpiry(userID, email string, expiry time.Time) string {
	return ti.CreateTokenWithClaims(userID, email, map[string]any{
		"exp": expiry.Unix(),
	})
}

// CreateExpiredToken creates a token that has already expired.
// Useful for testing token expiration handling.
func (ti *TestIssuer) CreateExpiredToken(userID, email string) string {
	return ti.CreateTokenWithExpiry(userID, email, time.Now().Add(-time.Hour))
}
