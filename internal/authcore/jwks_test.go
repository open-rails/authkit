package authcore

import (
	"crypto"
	"crypto/ed25519"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

func TestJWKSIncludesECAndEd25519Keys(t *testing.T) {
	rsaSigner, _ := jwtkit.NewRSASigner(2048, "rsa")
	edSigner, _ := jwtkit.NewEd25519Signer("ed")

	svc := NewService(Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}, ExpectedAudiences: []string{"app"}, AccessTokenDuration: time.Hour}}, Keyset{
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

func TestKeyfuncResolvesEd25519ActiveSigner(t *testing.T) {
	edSigner, _ := jwtkit.NewEd25519Signer("ed-active")
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}}, Keyset{
		Active:     edSigner,
		PublicKeys: map[string]crypto.PublicKey{"ed-active": edSigner.PublicKey()},
	})
	pub, err := svc.Keyfunc()(&jwt.Token{Header: map[string]any{"kid": "ed-active"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pub.(ed25519.PublicKey); !ok {
		t.Fatalf("got %T", pub)
	}
}
