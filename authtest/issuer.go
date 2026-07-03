// Package testing provides utilities for testing applications that use authkit.
package authtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

// TestIssuer provides a complete mock authentication setup for testing.
type TestIssuer struct {
	server   *httptest.Server
	signer   jwtkit.Signer
	audience string
}

// NewTestIssuer creates a new test issuer with an RSA key pair.
func NewTestIssuer() *TestIssuer {
	return NewTestIssuerWithAudience("test-app")
}

// NewTestIssuerWithAudience creates a test issuer with a specific audience claim.
func NewTestIssuerWithAudience(audience string) *TestIssuer {
	signer, err := jwtkit.NewRSASigner(2048, "test-key-1")
	if err != nil {
		panic("failed to create RSA signer: " + err.Error())
	}
	return NewTestIssuerWithSigner(signer, audience)
}

// NewTestIssuerWithSigner creates a test issuer using any jwtkit.Signer (RSA, EC, Ed25519).
func NewTestIssuerWithSigner(signer jwtkit.Signer, audience string) *TestIssuer {
	if signer == nil {
		panic("signer is required")
	}
	if audience == "" {
		audience = "test-app"
	}
	ti := &TestIssuer{signer: signer, audience: audience}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", ti.handleJWKS)
	ti.server = httptest.NewServer(mux)
	return ti
}

func (ti *TestIssuer) URL() string { return ti.server.URL }

func (ti *TestIssuer) Audience() string { return ti.audience }

func (ti *TestIssuer) Signer() jwtkit.Signer { return ti.signer }

func (ti *TestIssuer) Close() {
	if ti.server != nil {
		ti.server.Close()
	}
}

func (ti *TestIssuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	ps, ok := ti.signer.(jwtkit.PublicKeySigner)
	if !ok {
		http.Error(w, "signer does not expose public key", http.StatusInternalServerError)
		return
	}
	jwk := jwtkit.PublicToJWK(ps.PublicKey(), ti.signer.KID(), ti.signer.Algorithm())
	ks := jwtkit.JWKS{Keys: []jwtkit.JWK{jwk}}
	jwtkit.ServeJWKS(w, r, ks)
}

func (ti *TestIssuer) CreateToken(userID, email string) string {
	return ti.CreateTokenWithClaims(userID, email, nil)
}

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
	for k, v := range extraClaims {
		claims[k] = v
	}
	token, err := jwtkit.SignWithType(context.Background(), ti.signer, claims, jwtkit.AccessTokenType, true)
	if err != nil {
		panic("failed to sign token: " + err.Error())
	}
	return token
}

func (ti *TestIssuer) CreateTokenWithRoles(userID, email string, roles []string) string {
	return ti.CreateTokenWithClaims(userID, email, map[string]any{"roles": roles})
}

func (ti *TestIssuer) CreateTokenWithExpiry(userID, email string, expiry time.Time) string {
	return ti.CreateTokenWithClaims(userID, email, map[string]any{"exp": expiry.Unix()})
}

func (ti *TestIssuer) CreateExpiredToken(userID, email string) string {
	return ti.CreateTokenWithExpiry(userID, email, time.Now().Add(-time.Hour))
}
