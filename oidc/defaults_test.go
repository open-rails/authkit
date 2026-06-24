package oidckit

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/open-rails/authkit/authprovider"
)

func TestNewManagerFromMinimalDoesNotForceOpenIDForOAuth2Providers(t *testing.T) {
	for _, provider := range []string{"discord", "github"} {
		t.Run(provider, func(t *testing.T) {
			m := NewManagerFromMinimal(map[string]RPConfig{
				provider: {ClientID: provider + "-client"},
			})
			rp, ok := m.Provider(provider)
			if !ok {
				t.Fatalf("expected %s provider", provider)
			}
			for _, scope := range rp.Scopes {
				if scope == "openid" {
					t.Fatalf("%s is OAuth2, not OIDC; scopes must not force openid: %v", provider, rp.Scopes)
				}
			}
		})
	}
}

func TestNewManagerFromMinimalKeepsOpenIDForOIDCProviders(t *testing.T) {
	m := NewManagerFromMinimal(map[string]RPConfig{
		"google": {ClientID: "google-client", Scopes: []string{"email"}},
	})
	rp, ok := m.Provider("google")
	if !ok {
		t.Fatalf("expected google provider")
	}
	for _, scope := range rp.Scopes {
		if scope == "openid" {
			return
		}
	}
	t.Fatalf("google is OIDC; scopes must include openid: %v", rp.Scopes)
}

func TestNewManagerFromProvidersAcceptsCustomOIDCDescriptor(t *testing.T) {
	m := NewManagerFromProviders(map[string]authprovider.Provider{
		"example": {
			Name:         "example",
			Kind:         authprovider.KindOIDC,
			Issuer:       "https://issuer.example",
			ClientID:     "example-client",
			ClientSecret: authprovider.ClientSecret{Value: "example-secret"},
			Scopes:       []string{"email"},
			PKCE:         true,
		},
	})
	rp, ok := m.Provider("example")
	if !ok {
		t.Fatalf("expected example provider")
	}
	if rp.Issuer != "https://issuer.example" || rp.ClientID != "example-client" || rp.ClientSecret != "example-secret" {
		t.Fatalf("unexpected rp config: %+v", rp)
	}
	if !rp.PKCE {
		t.Fatalf("expected custom OIDC provider to keep PKCE flag")
	}
	for _, scope := range rp.Scopes {
		if scope == "openid" {
			return
		}
	}
	t.Fatalf("custom OIDC provider must include openid: %v", rp.Scopes)
}

func TestNewManagerFromProvidersAcceptsCustomOAuth2Descriptor(t *testing.T) {
	m := NewManagerFromProviders(map[string]authprovider.Provider{
		"example-oauth": {
			Name:         "example-oauth",
			Kind:         authprovider.KindOAuth2,
			Issuer:       "https://oauth.example",
			ClientID:     "oauth-client",
			ClientSecret: authprovider.ClientSecret{Value: "oauth-secret"},
			Scopes:       []string{"profile"},
		},
	})
	rp, ok := m.Provider("example-oauth")
	if !ok {
		t.Fatalf("expected example oauth provider")
	}
	for _, scope := range rp.Scopes {
		if scope == "openid" {
			t.Fatalf("custom OAuth2 provider must not force openid: %v", rp.Scopes)
		}
	}
}

func TestMergeScopesPreservesBaseOrder(t *testing.T) {
	got := mergeScopes([]string{"openid", "email", "profile"}, []string{"email", "offline_access"})
	want := []string{"openid", "email", "profile", "offline_access"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("mergeScopes() = %v, want %v", got, want)
	}
}

func TestRPClientFromProviderSurfacesResolveStaticError(t *testing.T) {
	const key = "AUTHKIT_RP_CLIENT_ENV_EMPTY"
	t.Setenv(key, "")

	_, err := RPClientFromProvider(authprovider.Provider{
		Name:         "google",
		Kind:         authprovider.KindOIDC,
		Issuer:       "https://accounts.google.com",
		ClientID:     "google-client",
		ClientSecret: authprovider.ClientSecret{Env: key},
	})
	if !errors.Is(err, authprovider.ErrClientSecretEnvEmpty) {
		t.Fatalf("expected ErrClientSecretEnvEmpty, got %v", err)
	}
}

func TestAppleJWTClientSecretStrategyBuildsSecretProvider(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	rp, err := RPClientFromProvider(authprovider.Provider{
		Name:     "apple",
		Kind:     authprovider.KindOIDC,
		Issuer:   "https://appleid.apple.com",
		ClientID: "com.example.web",
		ClientSecret: authprovider.ClientSecret{
			Strategy: authprovider.SecretStrategyAppleJWT,
			AppleJWT: &authprovider.AppleJWTSecret{
				TeamID:        "TEAMID1234",
				KeyID:         "KEYID1234",
				PrivateKeyPEM: pemBytes,
				TTL:           time.Minute,
			},
		},
		Scopes: []string{"openid", "email"},
	})
	if err != nil {
		t.Fatalf("RPClientFromProvider returned error: %v", err)
	}
	if rp.ClientSecretProvider == nil {
		t.Fatalf("expected apple_jwt strategy to build a secret provider")
	}
	secret, err := rp.ClientSecretProvider(context.Background())
	if err != nil {
		t.Fatalf("secret provider returned error: %v", err)
	}
	if secret == "" {
		t.Fatalf("expected signed apple client secret")
	}
}
