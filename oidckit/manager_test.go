package oidckit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestManager_RPCacheHitsOnSecondGetRP(t *testing.T) {
	var discoveryHits atomic.Int32
	srv := newTestOIDCServer(t, &discoveryHits)
	defer srv.Close()

	issuer := srv.URL
	m := NewManager(map[string]RPClient{
		"example": {
			Issuer:       issuer,
			ClientID:     "client",
			ClientSecret: "secret",
			Scopes:       []string{"openid"},
		},
	})
	m.cacheTTL = time.Hour

	ctx := context.Background()
	redirect := "https://app.example/callback"

	_, err := m.GetRPWithRedirect(ctx, "example", redirect)
	if err != nil {
		t.Fatalf("first GetRPWithRedirect: %v", err)
	}
	if got := discoveryHits.Load(); got != 1 {
		t.Fatalf("discovery hits after first call = %d, want 1", got)
	}

	_, err = m.GetRPWithRedirect(ctx, "example", redirect)
	if err != nil {
		t.Fatalf("second GetRPWithRedirect: %v", err)
	}
	if got := discoveryHits.Load(); got != 1 {
		t.Fatalf("discovery hits after cache hit = %d, want 1", got)
	}
}

func TestManager_DynamicSecretBypassesRPCache(t *testing.T) {
	var discoveryHits atomic.Int32
	srv := newTestOIDCServer(t, &discoveryHits)
	defer srv.Close()

	var secretCalls atomic.Int32
	m := NewManager(map[string]RPClient{
		"apple": {
			Issuer:   srv.URL,
			ClientID: "apple-client",
			ClientSecretProvider: func(context.Context) (string, error) {
				secretCalls.Add(1)
				return "fresh-secret", nil
			},
			Scopes: []string{"openid"},
		},
	})

	ctx := context.Background()
	redirect := "https://app.example/callback"

	for i := 0; i < 2; i++ {
		if _, err := m.GetRPWithRedirect(ctx, "apple", redirect); err != nil {
			t.Fatalf("GetRPWithRedirect #%d: %v", i+1, err)
		}
	}
	if got := discoveryHits.Load(); got != 2 {
		t.Fatalf("discovery hits = %d, want 2 (no cache for dynamic secret)", got)
	}
	if got := secretCalls.Load(); got != 2 {
		t.Fatalf("secret provider calls = %d, want 2", got)
	}
}

func TestManager_BeginWithAuthParamsAddsMaxAge(t *testing.T) {
	var discoveryHits atomic.Int32
	srv := newTestOIDCServer(t, &discoveryHits)
	defer srv.Close()

	m := NewManager(map[string]RPClient{
		"example": {
			Issuer:       srv.URL,
			ClientID:     "client",
			ClientSecret: "secret",
			Scopes:       []string{"openid"},
		},
	})
	authURL, err := m.BeginWithAuthParams(context.Background(), "example", "state", "nonce", "", "https://app.example/callback", map[string]string{"max_age": "0"})
	if err != nil {
		t.Fatalf("BeginWithAuthParams: %v", err)
	}
	if got := mustQuery(t, authURL).Get("max_age"); got != "0" {
		t.Fatalf("max_age = %q, want 0 in %s", got, authURL)
	}
}

func TestOutboundHTTPClientHasTimeout(t *testing.T) {
	c := OutboundHTTPClient()
	if c.Timeout != DefaultOutboundTimeout {
		t.Fatalf("timeout = %v, want %v", c.Timeout, DefaultOutboundTimeout)
	}
}

func newTestOIDCServer(t *testing.T, discoveryHits *atomic.Int32) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			discoveryHits.Add(1)
			doc := map[string]string{
				"issuer":                 r.Host,
				"authorization_endpoint": "https://" + r.Host + "/authorize",
				"token_endpoint":         "https://" + r.Host + "/token",
				"jwks_uri":               "https://" + r.Host + "/jwks",
			}
			// Issuer in doc must match trimmed issuer URL for zitadel discovery check.
			if r.TLS != nil {
				doc["issuer"] = "https://" + r.Host
			} else {
				doc["issuer"] = "http://" + r.Host
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(doc)
		case "/jwks":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func mustQuery(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse URL: %v", err)
	}
	return u.Query()
}
