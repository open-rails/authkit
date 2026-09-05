package authcore

import (
	"crypto"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/open-rails/authkit/jwtkit"
)

func TestJWKSIncludesECAndEd25519Keys(t *testing.T) {
	rsaSigner, _ := jwtkit.NewRSASigner(2048, "rsa")
	edSigner, _ := jwtkit.NewEd25519Signer("ed")

	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}, AccessTokenDuration: time.Hour}}, Keyset{
		Active: rsaSigner,
		PublicKeys: map[string]crypto.PublicKey{
			"rsa": rsaSigner.PublicKey(),
			"ed":  edSigner.PublicKey(),
		},
	})

	ks := svc.JWKS()
	if len(ks.Keys) != 2 {
		t.Fatalf("keys len %d", len(ks.Keys))
	}
	seen := map[string]bool{}
	for _, k := range ks.Keys {
		seen[k.Kty] = true
	}
	if !seen["RSA"] || !seen["OKP"] {
		t.Fatalf("kty set: %+v", ks.Keys)
	}
}

func TestPublicKeysByKIDResolvesEd25519ActiveSigner(t *testing.T) {
	edSigner, _ := jwtkit.NewEd25519Signer("ed-active")
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}}, Keyset{
		Active:     edSigner,
		PublicKeys: map[string]crypto.PublicKey{"ed-active": edSigner.PublicKey()},
	})
	if pub, ok := svc.PublicKeysByKID()["ed-active"].(ed25519.PublicKey); !ok {
		t.Fatalf("got %T", pub)
	}
}
