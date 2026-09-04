package oidckit

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/zitadel/oidc/v3/pkg/client/rp"

	"github.com/open-rails/authkit/jwtkit"
)

// recordingTransport records every request the RP's configured client sends.
type recordingTransport struct {
	mu    sync.Mutex
	paths []string
}

func (t *recordingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.paths = append(t.paths, r.URL.Path)
	t.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func (t *recordingTransport) saw(path string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, p := range t.paths {
		if p == path {
			return true
		}
	}
	return false
}

// #323: the code exchange must go through the RP's bounded outbound client
// (rp.WithHTTPClient), not http.DefaultClient with no timeout.
func TestDefaultExchangerUsesRelyingPartyHTTPClient(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	const kid, clientID, nonce = "exchanger-kid", "exchanger-client", "exchanger-nonce"
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srv.URL,
				"authorization_endpoint": srv.URL + "/authorize",
				"token_endpoint":         srv.URL + "/token",
				"jwks_uri":               srv.URL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(&key.PublicKey, kid, "RS256")}})
		case "/token":
			now := time.Now()
			tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
				"iss": srv.URL, "aud": clientID, "sub": "subject-1", "nonce": nonce,
				"iat": now.Add(-time.Second).Unix(), "exp": now.Add(time.Minute).Unix(),
				"email": "exchanger@example.com", "email_verified": true,
			})
			tok.Header["kid"] = kid
			signed, err := tok.SignedString(key)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "id_token": signed})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	rec := &recordingTransport{}
	client := &http.Client{Transport: rec, Timeout: 5 * time.Second}
	rpClient, err := rp.NewRelyingPartyOIDC(context.Background(), srv.URL, clientID, "secret", "https://app.example/callback", []string{"openid"}, rp.WithHTTPClient(client))
	if err != nil {
		t.Fatalf("relying party: %v", err)
	}

	claims, err := DefaultExchanger(context.Background(), rpClient, "example", "code", "", nonce)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if claims.Subject != "subject-1" || claims.Email == nil || *claims.Email != "exchanger@example.com" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if !rec.saw("/token") {
		t.Fatalf("token exchange bypassed the RP's HTTP client; requests seen: %v", rec.paths)
	}
}
