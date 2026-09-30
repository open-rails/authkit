// Package keypolicy is AuthKit's one public-key policy, applied to every
// signing and verification key: RSA of 2048-8192 bits with a sane exponent,
// P-256/384/521, or Ed25519.
package keypolicy

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
)

const (
	// minRSABits is the NIST / RFC 7518 floor: a 1024-bit modulus is
	// factorable by a well-resourced attacker.
	minRSABits = 2048
	// maxRSABits bounds the modulus so a hostile JWKS cannot make every
	// verification pathologically expensive.
	maxRSABits = 8192
)

// Validate refuses a key outside the policy.
func Validate(pub crypto.PublicKey) error {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if k == nil || k.N == nil || k.N.Sign() <= 0 {
			return errors.New("invalid_rsa_modulus")
		}
		if bits := k.N.BitLen(); bits < minRSABits {
			return fmt.Errorf("rsa_key_too_small: %d bits (min %d)", bits, minRSABits)
		} else if bits > maxRSABits {
			return fmt.Errorf("rsa_key_too_large: %d bits (max %d)", bits, maxRSABits)
		}
		// e = 1 is the identity map and an even exponent is never valid.
		if k.E < 3 || k.E%2 == 0 {
			return fmt.Errorf("invalid_rsa_exponent: %d", k.E)
		}
		return nil
	case *ecdsa.PublicKey:
		if k == nil || (k.Curve != elliptic.P256() && k.Curve != elliptic.P384() && k.Curve != elliptic.P521()) {
			return errors.New("unsupported_ec_curve")
		}
		if _, err := k.ECDH(); err != nil {
			return fmt.Errorf("invalid_ec_point: %w", err)
		}
		return nil
	case ed25519.PublicKey:
		if len(k) != ed25519.PublicKeySize {
			return errors.New("bad_ed25519_key_length")
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type %T", pub)
	}
}
