package authcore

// #238 regression coverage: the Service must READ the KeySource per-operation
// (never freeze a Keyset snapshot at construction), so a rotated keys.json is
// observed by mint + JWKS without a restart. See jwtkit/keys_reload_test.go
// for the lower-level FileKeySource poller coverage this builds on.

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
)

// writeRotationKeysJSON writes keys.json with a freshly generated RSA active
// key (activeKID) plus an optional public_keys map of retired verify-only PEM
// keys. It returns the new active key's PKIX public-key PEM so a later
// rotation can chain it into public_keys as a retired key.
func writeRotationKeysJSON(t *testing.T, dir, activeKID string, retired map[string]string) string {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, activeKID)
	if err != nil {
		t.Fatalf("generate signer: %v", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(signer.PrivateKey())})
	pubDER, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}))

	pubs := map[string]string{}
	for k, v := range retired {
		pubs[k] = v
	}
	envelope, err := json.Marshal(map[string]any{
		"active_key_id":          activeKID,
		"active_private_key_pem": string(privPEM),
		"public_keys":            pubs,
	})
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "keys.json"), envelope, 0o600); err != nil {
		t.Fatalf("write keys.json: %v", err)
	}
	return pubPEM
}

// kidOf extracts the `kid` JOSE header from a signed token without verifying it.
func kidOf(t *testing.T, tok string) string {
	t.Helper()
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse header: %v", err)
	}
	kid, _ := parsed.Header["kid"].(string)
	return kid
}

// TestServiceObservesKeyRotation is the core #238 proof: a Service constructed
// via NewFromConfig with a live, short-interval FileKeySource must pick up a
// keys.json rotation without a restart — new mints carry the new kid, JWKS
// serves BOTH the new and the retired key, and a token signed before rotation
// still verifies afterward.
func TestServiceObservesKeyRotation(t *testing.T) {
	dir := t.TempDir()
	oldPubPEM := writeRotationKeysJSON(t, dir, "kid-old", nil)

	const interval = 15 * time.Millisecond
	src, err := jwtkit.NewFileKeySource(dir, interval)
	if err != nil {
		t.Fatalf("NewFileKeySource: %v", err)
	}
	defer src.Close()

	cfg := Config{
		Token: TokenConfig{
			Issuer:            "https://rotation-test.example",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Source: src},
	}
	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}

	ctx := context.Background()

	// --- Pre-rotation: mint + JWKS observe kid-old only. ---
	preTok, _, err := svc.MintServiceJWT(ctx, ServiceJWTMintOptions{
		Subject: "service:pre-rotation", Audiences: []string{"app"},
	})
	if err != nil {
		t.Fatalf("mint pre-rotation: %v", err)
	}
	if kid := kidOf(t, preTok); kid != "kid-old" {
		t.Fatalf("pre-rotation mint kid = %q, want kid-old", kid)
	}
	if _, ok := svc.PublicKeysByKID()["kid-old"]; !ok {
		t.Fatalf("JWKS missing kid-old before rotation")
	}

	// --- Rotate: new active key, old key demoted to a retired public key. ---
	writeRotationKeysJSON(t, dir, "kid-new", map[string]string{"kid-old": oldPubPEM})

	// Wait past the reload interval for the poller to pick up the change —
	// this is the crux of #238: nothing here calls src.Reload() directly, the
	// Service must observe the SAME background swap jwtkit's poller performs.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, ok := svc.PublicKeysByKID()["kid-new"]; ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("rotation not observed by Service within %s; keys=%v", 3*time.Second, kidsOf(svc.PublicKeysByKID()))
		}
		time.Sleep(5 * time.Millisecond)
	}

	// --- Post-rotation: new mints carry the new kid. ---
	postTok, _, err := svc.MintServiceJWT(ctx, ServiceJWTMintOptions{
		Subject: "service:post-rotation", Audiences: []string{"app"},
	})
	if err != nil {
		t.Fatalf("mint post-rotation: %v", err)
	}
	if kid := kidOf(t, postTok); kid != "kid-new" {
		t.Fatalf("post-rotation mint kid = %q, want kid-new (Service is still reading a frozen snapshot)", kid)
	}

	// --- JWKS (both PublicKeysByKID and the served JWKS() shape) has BOTH keys. ---
	byKID := svc.PublicKeysByKID()
	if _, ok := byKID["kid-new"]; !ok {
		t.Fatalf("PublicKeysByKID missing kid-new after rotation")
	}
	if _, ok := byKID["kid-old"]; !ok {
		t.Fatalf("PublicKeysByKID missing retired kid-old after rotation (in-flight pre-rotation tokens would fail verification)")
	}
	seen := map[string]bool{}
	for _, k := range svc.JWKS().Keys {
		seen[k.Kid] = true
	}
	if !seen["kid-new"] || !seen["kid-old"] {
		t.Fatalf("served JWKS() missing rotated keys: have %+v", svc.JWKS().Keys)
	}

	// --- Tokens signed BOTH before and after rotation still verify against
	// the Service's CURRENT Keyfunc (the real verify-time code path). ---
	if _, err := jwt.Parse(preTok, svc.Keyfunc()); err != nil {
		t.Fatalf("pre-rotation token failed to verify after rotation: %v", err)
	}
	if _, err := jwt.Parse(postTok, svc.Keyfunc()); err != nil {
		t.Fatalf("post-rotation token failed to verify: %v", err)
	}
}

// kidsOf lists the kids in a public-key map, for failure messages.
func kidsOf(m map[string]crypto.PublicKey) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
