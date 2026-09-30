package keys

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/open-rails/authkit/internal/keypolicy"
)

// ParsePublicPEM parses a PKIX/SPKI, certificate or PKCS #1 RSA public key
// PEM under AuthKit's key policy: RSA of 2048-8192 bits, P-256/384/521 or
// Ed25519.
func ParsePublicPEM(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("bad_pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, certErr := x509.ParseCertificate(block.Bytes); certErr == nil {
			pub = cert.PublicKey
		} else if rsaPub, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes); rsaErr == nil {
			pub = rsaPub
		} else {
			return nil, err
		}
	}
	if err := keypolicy.Validate(pub); err != nil {
		return nil, err
	}
	return pub, nil
}

func clonePublicKeyMap(in map[string]crypto.PublicKey) map[string]crypto.PublicKey {
	if in == nil {
		return nil
	}
	out := make(map[string]crypto.PublicKey, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
