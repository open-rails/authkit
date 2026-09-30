package keys_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

// Every supported key signs JWS that verifies under its public key with the
// alg its curve or type implies, through NewSigner and every PEM encoding.
func TestSignerSignsVerifiableJWS(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	signers := map[string]crypto.Signer{"RS256": rsaKey, "EdDSA": edKey}
	for alg, curve := range map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()} {
		signers[alg], err = ecdsa.GenerateKey(curve, rand.Reader)
		require.NoError(t, err)
	}
	for alg, key := range signers {
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		require.NoError(t, err)
		fromPEM, err := keys.SignerFromPEM("k", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))
		require.NoError(t, err)
		direct, err := keys.SignerFromKey("k", key)
		require.NoError(t, err)
		for name, signer := range map[string]keys.Signer{"NewSigner": direct, "PKCS8 PEM": fromPEM} {
			t.Run(alg+" "+name, func(t *testing.T) {
				require.Equal(t, alg, signer.Algorithm())
				token, err := jose.Sign(context.Background(), signer, jose.AccessTokenType, map[string]any{"sub": "u1"})
				require.NoError(t, err)
				typ, claims, err := jose.Verify(token, func(gotAlg, kid string, _ map[string]any) (crypto.PublicKey, error) {
					require.Equal(t, alg, gotAlg)
					require.Equal(t, "k", kid)
					return signer.Public(), nil
				})
				require.NoError(t, err)
				require.Equal(t, jose.AccessTokenType, typ)
				require.Equal(t, "u1", claims["sub"])
			})
		}
	}

	// The legacy encodings: PKCS #1 RSA and SEC 1 EC.
	signer, err := keys.SignerFromPEM("r", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	require.NoError(t, err)
	require.Equal(t, "RS256", signer.Algorithm())
	sec1, err := x509.MarshalECPrivateKey(signers["ES384"].(*ecdsa.PrivateKey))
	require.NoError(t, err)
	signer, err = keys.SignerFromPEM("e", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1}))
	require.NoError(t, err)
	require.Equal(t, "ES384", signer.Algorithm())
}

func TestSignerRefusesUnusableKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	require.NoError(t, err)
	strong, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	for name, build := range map[string]func() (keys.Signer, error){
		"weak RSA":   func() (keys.Signer, error) { return keys.SignerFromKey("k", weak) },
		"P-224":      func() (keys.Signer, error) { return keys.SignerFromKey("k", p224) },
		"empty kid":  func() (keys.Signer, error) { return keys.SignerFromKey("", strong) },
		"padded kid": func() (keys.Signer, error) { return keys.SignerFromKey(" k", strong) },
		"nil key":    func() (keys.Signer, error) { return keys.SignerFromKey("k", nil) },
		"not PEM":    func() (keys.Signer, error) { return keys.SignerFromPEM("k", []byte("secret")) },
		"public PEM": func() (keys.Signer, error) { return keys.SignerFromPEM("k", publicPEM(t, &strong.PublicKey)) },
		"weak RSA PEM": func() (keys.Signer, error) {
			return keys.SignerFromPEM("k", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}))
		},
	} {
		_, err := build()
		require.Error(t, err, name)
	}
}

func publicPEM(t *testing.T, pub crypto.PublicKey) []byte {
	der, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
