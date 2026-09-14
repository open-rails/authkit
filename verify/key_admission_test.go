package verify

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

func TestAuditV1AddIssuerInvalidReplacementReturnsError(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "old-key")
	require.NoError(t, err)
	const issuer = "https://audit-issuer.example"
	v := NewVerifier()
	require.NoError(t, v.AddIssuer(issuer, []string{"audit"}, IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	token := mintStatelessAccess(t, signer, issuer, "audit", "audit-user")
	_, err = v.VerifyClaims(context.Background(), token)
	require.NoError(t, err)
	updateErr := v.AddIssuer(issuer, []string{"audit"}, IssuerOptions{Keys: []IssuerKey{{KID: "new-key", PublicKeyPEM: "malformed replacement PEM"}}})
	_, oldErr := v.VerifyClaims(context.Background(), token)
	t.Logf("AddIssuer error=%v previous-key token error=%v", updateErr, oldErr)
	require.Error(t, updateErr, "invalid key rotation must not report success while retaining old keys")
}

func TestAuditV1AddIssuerPEMEnforcesJWKStrength(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	_, jwkErr := jwtkit.JWKToPublicKey(jwtkit.PublicToJWK(&key.PublicKey, "weak", "RS256"))
	require.Error(t, jwkErr)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	v := NewVerifier()
	err = v.AddIssuer("https://weak.example", []string{"audit"}, IssuerOptions{Keys: []IssuerKey{{KID: "weak", PublicKeyPEM: pemText}}})
	t.Logf("JWK rejected=%v PEM AddIssuer=%v", jwkErr, err)
	require.Error(t, err, "same weak RSA key must not bypass strength policy by entering as PEM")
}

func TestAddIssuerReplacementIsAtomic(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "old-key")
	require.NoError(t, err)
	v := NewVerifier()
	const issuer = "https://replacement.example"
	opts := IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}
	require.NoError(t, v.AddIssuer(issuer, []string{"old-audience"}, opts))
	token := mintStatelessAccess(t, signer, issuer, "old-audience", "local-user")
	for name, bad := range map[string]IssuerOptions{
		"malformed PEM":          {IsLocal: true, Keys: []IssuerKey{{KID: "new", PublicKeyPEM: "not PEM"}}},
		"invalid raw key":        {IsLocal: true, RawKeys: map[string]crypto.PublicKey{"new": []byte("symmetric key")}},
		"empty kid":              {IsLocal: true, RawKeys: map[string]crypto.PublicKey{"": signer.PublicKey()}},
		"live mixed with static": {IsLocal: true, PublicKeys: func() map[string]crypto.PublicKey { return opts.RawKeys }, RawKeys: opts.RawKeys},
	} {
		t.Run(name, func(t *testing.T) {
			require.Error(t, v.AddIssuer(issuer, []string{"different-audience"}, bad))
			cl, err := v.Verify(context.Background(), token)
			require.NoError(t, err)
			require.Equal(t, "local-user", cl.UserID, "rejection preserves full previous registration")
		})
	}
	require.NoError(t, v.AddIssuer(issuer, []string{"old-audience"}, IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{}}))
	_, err = v.Verify(context.Background(), token)
	require.Error(t, err, "successful empty replacement revokes all prior keys")
}
