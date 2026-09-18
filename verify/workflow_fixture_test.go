package verify

// Shared fixtures for the retained public workflows and focused security checks.
import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"

	"math/big"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

const confirmationIssuer = "https://issuer.example"

func confirmationLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "delegate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}

func confirmationVerifier(t *testing.T) (*Verifier, *jwtkit.RSASigner) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "cnf-kid")
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier()
	if err := v.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	}); err != nil {
		t.Fatal(err)
	}
	return v, signer
}

func delegatedClaims(extra map[string]any) jwt.MapClaims {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": confirmationIssuer, "aud": []string{"resource"}, "iat": now.Unix(),
		"exp": now.Add(time.Minute).Unix(), "delegated_sub": "user-1", "jti": "token-1",
	}
	for k, v := range extra {
		claims[k] = v
	}
	return claims
}

func signTyped(t *testing.T, signer *jwtkit.RSASigner, typ string, claims jwt.MapClaims) string {
	t.Helper()
	token, err := signer.SignWithHeaders(context.Background(), claims, map[string]any{"typ": typ})
	if err != nil {
		t.Fatal(err)
	}
	return token
}

const testDocumentType = "example.entitlements/v1"

func testSignedDocument(t *testing.T, signer jwtkit.Signer, issuer string) documents.SignedDocument {
	t.Helper()
	document, err := documents.Sign(context.Background(), signer, documents.Envelope{
		Issuer: issuer, Audiences: []string{"resource-b"}, Type: testDocumentType,
		Payload: json.RawMessage(`{"limit":7}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func verifyOptions(issuer string, document documents.SignedDocument) documents.VerifyOptions {
	return documents.VerifyOptions{
		Issuer: issuer, Audience: "resource-b", Type: document.Reference.Type, Reference: document.Reference,
	}
}

func staticApp(t *testing.T, slug, issuer string) (authkit.RemoteApplication, *jwtkit.RSASigner) {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, slug+"-kid")
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	require.NoError(t, err)
	pemKey := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	return authkit.RemoteApplication{
		Slug: slug, Issuer: issuer, Enabled: true, Mode: authkit.RemoteAppModeStatic,
		PublicKeys: []authkit.RemoteAppKey{{KID: signer.KID(), PublicKeyPEM: pemKey}},
	}, signer
}

func (v *Verifier) forceStaleSnapshot() {
	v.mu.Lock()
	v.fedSnapshotAt = time.Time{}
	v.mu.Unlock()
}

func mintStatelessAccess(t *testing.T, signer jwtkit.Signer, iss, aud, sub string) string {
	t.Helper()
	hs, ok := any(signer).(jwtkit.HeaderSigner)
	if !ok {
		t.Fatal("test signer must support JOSE headers")
	}
	now := time.Now()
	tok, err := hs.SignWithHeaders(context.Background(), map[string]any{
		"iss": iss,
		"aud": aud,
		"sub": sub,
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}, map[string]any{"typ": AccessTokenType})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}
