// Package testissuer is a stand-in token issuer with a JWKS endpoint, for
// tests of token verification without AuthKit (the framework adapters).
package testissuer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
)

// Issuer signs access tokens for the audience "test-app" with an RSA key and
// serves its JWKS at URL plus /.well-known/jwks.json.
type Issuer struct {
	server *httptest.Server
	signer keys.Signer
}

// New starts an Issuer, closed at the test's cleanup.
func New(t testing.TB) *Issuer {
	is := &Issuer{signer: testkeys.RSA("test-key-1")}
	is.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jose.ServeJWKS(w, r, jose.JWKS(testkeys.Source(is.signer)))
	}))
	t.Cleanup(is.server.Close)
	return is
}

func (is *Issuer) URL() string         { return is.server.URL }
func (is *Issuer) Audience() string    { return "test-app" }
func (is *Issuer) Signer() keys.Signer { return is.signer }

// Token is an access token for userID, valid for an hour; claims override.
func (is *Issuer) Token(userID, email string, claims map[string]any) string {
	now := time.Now()
	all := map[string]any{"sub": userID, "email": email, "iss": is.URL(), "aud": is.Audience(), "exp": now.Add(time.Hour).Unix(), "iat": now.Unix()}
	for k, v := range claims {
		all[k] = v
	}
	token, err := jose.Sign(context.Background(), is.signer, jose.AccessTokenType, all)
	if err != nil {
		panic("testissuer: sign: " + err.Error())
	}
	return token
}
