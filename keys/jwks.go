package keys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/keypolicy"
)

// JWK is a JSON Web Key (RSA, EC or OKP).
type JWK = iam.JWK

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK is pub as a JWK; an empty alg is the one the key signs with.
func PublicJWK(pub crypto.PublicKey, kid, alg string) JWK {
	if strings.TrimSpace(alg) == "" {
		alg = algorithmForPublicKey(pub)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return JWK{
			Kty: "RSA", Use: "sig", Kid: kid, Alg: alg,
			N: base64URLEncode(k.N),
			E: base64URLEncode(big.NewInt(int64(k.E))),
		}
	case *ecdsa.PublicKey:
		crv := k.Curve.Params().Name
		size := (k.Curve.Params().BitSize + 7) / 8
		// Go 1.26 deprecated direct big.Int X/Y access on ecdsa.PublicKey. Derive
		// the fixed-length JWK coordinates from the uncompressed SEC1 point
		// (0x04 || X || Y) via crypto/ecdh — the supported path for the NIST
		// curves (P-256/384/521) we sign with.
		var x, y string
		if ek, err := k.ECDH(); err == nil {
			if raw := ek.Bytes(); len(raw) == 1+2*size {
				x = base64.RawURLEncoding.EncodeToString(raw[1 : 1+size])
				y = base64.RawURLEncoding.EncodeToString(raw[1+size:])
			}
		}
		return JWK{Kty: "EC", Use: "sig", Kid: kid, Alg: alg, Crv: crv, X: x, Y: y}
	case ed25519.PublicKey:
		return JWK{
			Kty: "OKP", Use: "sig", Kid: kid, Alg: alg,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString(k),
		}
	default:
		return JWK{Kid: kid, Alg: alg}
	}
}

// ParsePublicJWK parses a public JWK under AuthKit's key policy, like
// ParsePublicPEM.
func ParsePublicJWK(j JWK) (crypto.PublicKey, error) { return publicKey(j) }

// publicKey parses one JWK under the key policy.
func publicKey(j JWK) (crypto.PublicKey, error) {
	switch strings.ToUpper(strings.TrimSpace(j.Kty)) {
	case "RSA":
		if j.N == "" || j.E == "" {
			return nil, errors.New("rsa_jwk_missing_n_or_e")
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
		if err != nil {
			return nil, err
		}
		eInt := new(big.Int).SetBytes(eBytes)
		if !eInt.IsInt64() {
			return nil, errors.New("bad_rsa_exponent")
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: int(eInt.Int64())}
		if err := keypolicy.Validate(pub); err != nil {
			return nil, err
		}
		return pub, nil
	case "EC":
		curve, err := curveForCRV(j.Crv)
		if err != nil {
			return nil, err
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		yBytes, err := base64.RawURLEncoding.DecodeString(j.Y)
		if err != nil {
			return nil, err
		}
		size := (curve.Params().BitSize + 7) / 8
		if len(xBytes) > size || len(yBytes) > size {
			return nil, errors.New("invalid_ec_point")
		}
		point := make([]byte, 1+2*size)
		point[0] = 0x04
		copy(point[1+size-len(xBytes):1+size], xBytes)
		copy(point[1+2*size-len(yBytes):], yBytes)
		pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
		if err != nil {
			return nil, fmt.Errorf("ec_point_not_on_curve: %w", err)
		}
		return pub, nil
	case "OKP":
		if strings.ToUpper(strings.TrimSpace(j.Crv)) != "ED25519" {
			return nil, fmt.Errorf("%w: %s", errUnsupportedJWK, j.Crv)
		}
		xBytes, err := base64.RawURLEncoding.DecodeString(j.X)
		if err != nil {
			return nil, err
		}
		if len(xBytes) != ed25519.PublicKeySize {
			return nil, errors.New("bad_ed25519_jwk_x")
		}
		return ed25519.PublicKey(xBytes), nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedJWK, j.Kty)
	}
}

var errUnsupportedJWK = errors.New("unsupported_jwk")

// PublicKeys is a JWKS's usable keys by kid ("default" for a key without
// one). Malformed, weak or unsupported keys are skipped; a set without a
// usable key is an error.
func PublicKeys(ks JWKS) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey)
	for _, j := range ks.Keys {
		pub, err := publicKey(j)
		if err != nil {
			continue
		}
		kid := strings.TrimSpace(j.Kid)
		if kid == "" {
			kid = "default"
		}
		out[kid] = pub
	}
	if len(out) == 0 {
		return nil, errors.New("jwks has no usable keys")
	}
	return out, nil
}

func curveForCRV(crv string) (elliptic.Curve, error) {
	switch strings.ToUpper(strings.TrimSpace(crv)) {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("%w: %s", errUnsupportedJWK, crv)
	}
}

func base64URLEncode(i *big.Int) string {
	b := i.Bytes()
	for len(b) > 0 && b[0] == 0x00 {
		b = b[1:]
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
