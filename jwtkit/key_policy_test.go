package jwtkit

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPublicKeyPolicySharedAcrossIngress(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	strong, err := NewRSASigner(2048, "good")
	require.NoError(t, err)
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ed, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	for name, key := range map[string]crypto.PublicKey{"RSA": strong.PublicKey(), "EC": &ec.PublicKey, "Ed25519": ed, "weak RSA": &weak.PublicKey} {
		t.Run(name, func(t *testing.T) {
			der, err := x509.MarshalPKIXPublicKey(key)
			require.NoError(t, err)
			_, pemErr := ParsePublicKeyFromPEMBytes(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
			_, jwkErr := JWKToPublicKey(PublicToJWK(key, "test", ""))
			require.Equal(t, name == "weak RSA", ValidatePublicKey(key) != nil)
			require.Equal(t, name == "weak RSA", pemErr != nil)
			require.Equal(t, name == "weak RSA", jwkErr != nil)
		})
	}
	for _, key := range []crypto.PublicKey{nil, (*rsa.PublicKey)(nil), (*ecdsa.PublicKey)(nil), &ecdsa.PublicKey{}, ed25519.PublicKey{1}, []byte("secret")} {
		require.Error(t, ValidatePublicKey(key))
	}
	_, err = NewSignerFromPEM("weak", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}))
	require.Error(t, err, "private PEM cannot bypass the verification strength floor")
	_, err = NewRSASigner(1024, "weak")
	require.Error(t, err)
}
