package keys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/open-rails/authkit/internal/keypolicy"
)

// Signer signs JWS signing input with one private key AuthKit never sees, so
// an HSM, KMS or Vault key implements it directly.
type Signer interface {
	// Algorithm is the JWS alg: RS256, ES256, ES384, ES512 or EdDSA.
	Algorithm() string
	// KID is the key id stamped into the header and published in the JWKS.
	KID() string
	// Public is the verification key.
	Public() crypto.PublicKey
	// Sign returns the JWS signature over signingInput (the encoded header
	// and payload joined by "."): PKCS #1 v1.5 for RS256, the fixed-width
	// R||S pair for ES*, and the raw signature for EdDSA.
	Sign(ctx context.Context, signingInput []byte) ([]byte, error)
}

// SignerFromKey wraps key, an in-process private key or any crypto.Signer (a
// KMS client), as a Signer. The algorithm follows the key: RSA is RS256,
// P-256, P-384 and P-521 are ES256, ES384 and ES512, Ed25519 is EdDSA.
func SignerFromKey(kid string, key crypto.Signer) (Signer, error) {
	if kid == "" || kid != strings.TrimSpace(kid) {
		return nil, errors.New("signer kid required without surrounding whitespace")
	}
	if key == nil {
		return nil, errors.New("nil private key")
	}
	pub := key.Public()
	if err := keypolicy.Validate(pub); err != nil {
		return nil, err
	}
	s := &keySigner{kid: kid, key: key, pub: pub, alg: algorithmForPublicKey(pub)}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		s.hash = crypto.SHA256
	case *ecdsa.PublicKey:
		s.size = (k.Curve.Params().BitSize + 7) / 8
		s.hash = map[string]crypto.Hash{"ES256": crypto.SHA256, "ES384": crypto.SHA384, "ES512": crypto.SHA512}[s.alg]
	}
	return s, nil
}

// SignerFromPEM builds a Signer from a PEM private key: PKCS #1 or PKCS #8
// RSA, SEC 1 or PKCS #8 EC, or PKCS #8 Ed25519.
func SignerFromPEM(kid string, pemBytes []byte) (Signer, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("failed to decode private key pem")
	}
	var key any
	var err error
	switch blk.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(blk.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(blk.Bytes)
	default:
		key, err = x509.ParsePKCS8PrivateKey(blk.Bytes)
	}
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("unsupported private key type %T", key)
	}
	return SignerFromKey(kid, signer)
}

type keySigner struct {
	kid, alg string
	key      crypto.Signer
	pub      crypto.PublicKey
	hash     crypto.Hash // zero for EdDSA, which signs the message itself
	size     int         // ECDSA coordinate width
}

func (s *keySigner) Algorithm() string        { return s.alg }
func (s *keySigner) KID() string              { return s.kid }
func (s *keySigner) Public() crypto.PublicKey { return s.pub }

func (s *keySigner) Sign(_ context.Context, signingInput []byte) ([]byte, error) {
	if s.hash == 0 {
		return s.key.Sign(rand.Reader, signingInput, crypto.Hash(0))
	}
	h := s.hash.New()
	h.Write(signingInput)
	sig, err := s.key.Sign(rand.Reader, h.Sum(nil), s.hash)
	if err != nil || s.size == 0 {
		return sig, err
	}
	// crypto.Signer returns ECDSA as ASN.1; JWS wants R||S, each padded.
	var rs struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(sig, &rs); err != nil || len(rest) != 0 {
		return nil, errors.New("malformed ecdsa signature")
	}
	out := make([]byte, 2*s.size)
	rs.R.FillBytes(out[:s.size])
	rs.S.FillBytes(out[s.size:])
	return out, nil
}

// algorithmForPublicKey is the JWS alg a key signs with.
func algorithmForPublicKey(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RS256"
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P384():
			return "ES384"
		case elliptic.P521():
			return "ES512"
		}
		return "ES256"
	case ed25519.PublicKey:
		return "EdDSA"
	}
	return ""
}
