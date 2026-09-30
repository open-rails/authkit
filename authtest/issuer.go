package authtest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
)

// TestIssuer is a stand-in token issuer with a JWKS endpoint, for testing a
// service that only verifies tokens (verify.Verifier) without running AuthKit.
type TestIssuer struct {
	server   *httptest.Server
	signer   keys.Signer
	audience string
}

// NewTestIssuer creates a new test issuer with an RSA key pair.
// Register its verifier entry with IsLocal only when modeling local user IDs.
// Otherwise access tokens expose the qualified external Issuer and Subject.
func NewTestIssuer() *TestIssuer {
	return NewTestIssuerWithAudience("test-app")
}

// NewTestIssuerWithAudience creates a test issuer with a specific audience claim.
func NewTestIssuerWithAudience(audience string) *TestIssuer {
	return NewTestIssuerWithSigner(testkeys.RSA("test-key-1"), audience)
}

// NewTestIssuerWithSigner creates a test issuer using any keys.Signer (RSA, EC, Ed25519).
func NewTestIssuerWithSigner(signer keys.Signer, audience string) *TestIssuer {
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

func (ti *TestIssuer) Signer() keys.Signer { return ti.signer }

func (ti *TestIssuer) Close() {
	if ti.server != nil {
		ti.server.Close()
	}
}

func (ti *TestIssuer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	jose.ServeJWKS(w, r, jose.JWKS(testkeys.Source(ti.signer)))
}

func (ti *TestIssuer) CreateToken(userID, email string) string {
	return ti.CreateTokenWithClaims(userID, email, nil)
}

func (ti *TestIssuer) CreateTokenWithClaims(userID, email string, extraClaims map[string]any) string {
	now := time.Now()
	claims := map[string]any{
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
	token, err := jose.Sign(context.Background(), ti.signer, jose.AccessTokenType, claims)
	if err != nil {
		panic("failed to sign token: " + err.Error())
	}
	return token
}

func (ti *TestIssuer) CreateTokenWithExpiry(userID, email string, expiry time.Time) string {
	return ti.CreateTokenWithClaims(userID, email, map[string]any{"exp": expiry.Unix()})
}

func (ti *TestIssuer) CreateExpiredToken(userID, email string) string {
	return ti.CreateTokenWithExpiry(userID, email, time.Now().Add(-time.Hour))
}
