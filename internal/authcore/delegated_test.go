package authcore

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

// writeServiceKeysJSON renders a {active_key_id, active_private_key_pem,
// public_keys} envelope under dir so the local file resolver can load it.
func writeServiceKeysJSON(t *testing.T, dir, kid string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	env := map[string]any{
		"active_key_id":          kid,
		"active_private_key_pem": string(privPEM),
		"public_keys":            map[string]string{},
	}
	data, _ := json.Marshal(env)
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), data, 0600); err != nil {
		t.Fatalf("write keys.json: %v", err)
	}
}

// TestConfigKeysPathResolvesFile verifies that core.Config.KeysPath overrides
// the local filesystem key directory and the service signs with that key.
func TestConfigKeysPathResolvesFile(t *testing.T) {
	// #231: no env clearing needed — the library reads no environment variables.
	dir := t.TempDir()
	writeServiceKeysJSON(t, dir, "cfg-path-kid")

	cfg := Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Path: dir}, // Source is nil => resolver uses this directory.
	}
	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if len(svc.JWKS().Keys) == 0 {
		t.Fatal("no JWKS key")
	}
	found := false
	for _, k := range svc.JWKS().Keys {
		if k.Kid == "cfg-path-kid" {
			found = true
		}
	}
	if !found {
		t.Fatalf("JWKS did not surface the configured key; got %+v", svc.JWKS().Keys)
	}
}

// TestServiceMintDelegatedRoundTrip mints a delegated access token through the
// Service mint API and verifies its signature against the Service's JWKS public
// key — the host passes params only and never touches the key.
func TestServiceMintDelegatedRoundTrip(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	tok, err := svc.MintDelegatedAccessToken(context.Background(), DelegatedAccessParams{
		Audiences:        []string{"tensorhub"},
		DelegatedSubject: "user-123",
		Permissions:      []string{"repo:create"},
	})
	if err != nil {
		t.Fatalf("MintDelegatedAccessToken: %v", err)
	}

	claims := verifyAgainstServiceJWKS(t, svc, tok)
	if claims["iss"] != "https://issuer.test" {
		t.Fatalf("iss defaulted wrong: %v", claims["iss"])
	}
	if claims["delegated_sub"] != "user-123" {
		t.Fatalf("delegated_sub=%v", claims["delegated_sub"])
	}
	if _, hasSub := claims["sub"]; hasSub {
		t.Fatal("delegated token must not carry sub")
	}
}

// TestServiceMintServiceJWTRoundTrip mints a first-party service JWT through the
// Service and verifies it against the Service JWKS.
func TestServiceMintServiceJWTRoundTrip(t *testing.T) {
	svc := mustServiceWithGeneratedKeys(t)

	tok, _, err := svc.MintServiceJWT(context.Background(), ServiceJWTMintOptions{
		Subject:   "service:cozy-art",
		Audiences: []string{"tensorhub"},
	})
	if err != nil {
		t.Fatalf("MintServiceJWT: %v", err)
	}
	claims := verifyAgainstServiceJWKS(t, svc, tok)
	if claims["token_use"] != ServiceJWTTokenUse {
		t.Fatalf("token_use=%v", claims["token_use"])
	}
	if claims["sub"] != "service:cozy-art" {
		t.Fatalf("sub=%v", claims["sub"])
	}
}

func mustServiceWithGeneratedKeys(t *testing.T) *Service {
	t.Helper()
	ks, err := jwtkit.NewGeneratedKeySource()
	if err != nil {
		t.Fatalf("gen keys: %v", err)
	}
	svc, err := NewFromConfig(Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Source: ks},
	}, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	return svc
}

// verifyAgainstServiceJWKS parses tok using the public key the Service exposes
// on its JWKS (by kid), proving the token verifies with public material only.
func verifyAgainstServiceJWKS(t *testing.T, svc *Service, tok string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	_, err := jwt.NewParser(jwt.WithoutClaimsValidation()).ParseWithClaims(tok, claims, func(token *jwt.Token) (any, error) {
		kid, _ := token.Header["kid"].(string)
		pub, ok := svc.keys.PublicKeys[kid]
		if !ok {
			t.Fatalf("kid %q not on JWKS", kid)
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("verify against JWKS: %v", err)
	}
	return claims
}
