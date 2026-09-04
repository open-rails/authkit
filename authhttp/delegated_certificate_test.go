package authhttp

// ak#277 delegate-certificate validation matrix (no DB) plus the self-signed
// client-certificate helper shared with the mTLS integration test.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// delegateCertificate is a self-signed client leaf a test presents over mTLS.
type delegateCertificate struct {
	Leaf *x509.Certificate
	TLS  tls.Certificate
}

func (c delegateCertificate) encoded() string {
	return base64.RawURLEncoding.EncodeToString(c.Leaf.Raw)
}

func newDelegateCertificate(t *testing.T, mutate func(*x509.Certificate)) delegateCertificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: "delegate"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	if mutate != nil {
		mutate(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return delegateCertificate{Leaf: leaf, TLS: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}}
}

// oversizedExtension pushes a certificate past maxDelegateCertificateDER
// while keeping it parseable.
func oversizedExtension() pkix.Extension {
	return pkix.Extension{Id: asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}, Value: make([]byte, maxDelegateCertificateDER)}
}

func TestParseDelegateCertificate(t *testing.T) {
	now := time.Now()
	good := newDelegateCertificate(t, nil)
	parsed, err := parseDelegateCertificate(good.encoded(), now)
	require.NoError(t, err)
	require.Equal(t, good.Leaf.Raw, parsed.Raw)

	rejected := map[string]string{
		"empty":         "",
		"not base64url": "%%%",
		"padded":        good.encoded() + "=",
		"not DER":       base64.RawURLEncoding.EncodeToString([]byte("nope")),
		"trailing data": base64.RawURLEncoding.EncodeToString(append(append([]byte{}, good.Leaf.Raw...), 0)),
		"CA":            newDelegateCertificate(t, func(c *x509.Certificate) { c.IsCA = true }).encoded(),
		"expired":       newDelegateCertificate(t, func(c *x509.Certificate) { c.NotAfter = now.Add(-time.Second) }).encoded(),
		"not yet valid": newDelegateCertificate(t, func(c *x509.Certificate) { c.NotBefore = now.Add(time.Hour) }).encoded(),
		"serverAuth only": newDelegateCertificate(t, func(c *x509.Certificate) {
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		}).encoded(),
		"no EKU":        newDelegateCertificate(t, func(c *x509.Certificate) { c.ExtKeyUsage = nil }).encoded(),
		"anyEKU only":   newDelegateCertificate(t, func(c *x509.Certificate) { c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny} }).encoded(),
		"oversized DER": newDelegateCertificate(t, func(c *x509.Certificate) { c.ExtraExtensions = []pkix.Extension{oversizedExtension()} }).encoded(),
	}
	for name, encoded := range rejected {
		_, err := parseDelegateCertificate(encoded, now)
		require.Error(t, err, name)
	}
}

func TestValidRequestedGrant(t *testing.T) {
	require.True(t, validRequestedGrant(json.RawMessage(`{}`)))
	require.True(t, validRequestedGrant(json.RawMessage(" \n{\"type\":\"example.read/v1\"}")))
	rejected := map[string]string{
		"absent":    "",
		"null":      "null",
		"array":     "[]",
		"string":    `"grant"`,
		"number":    "1",
		"invalid":   "{",
		"oversized": `{"pad":"` + strings.Repeat("a", maxRequestedGrantBytes) + `"}`,
	}
	for name, raw := range rejected {
		require.False(t, validRequestedGrant(json.RawMessage(raw)), name)
	}
}
