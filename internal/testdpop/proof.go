// Package testdpop creates genuine signed sender proofs for workflow tests.
package testdpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func Key(t testing.TB) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func Proof(t testing.TB, key *ecdsa.PrivateKey, method, target, accessToken string, change func(*jwt.Token)) string {
	t.Helper()
	hash := sha256.Sum256([]byte(accessToken))
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": method, "htu": target, "iat": time.Now().Unix(), "jti": uuid.NewString(),
		"ath": base64.RawURLEncoding.EncodeToString(hash[:]),
	})
	public, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": base64.RawURLEncoding.EncodeToString(public[1:33]), "y": base64.RawURLEncoding.EncodeToString(public[33:])}
	if change != nil {
		change(token)
	}
	proof, err := token.SignedString(key)
	require.NoError(t, err)
	return proof
}
