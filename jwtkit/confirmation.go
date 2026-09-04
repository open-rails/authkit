package jwtkit

import (
	"crypto/sha256"
	"encoding/base64"
)

// RFC 8705 certificate-bound token confirmation: `cnf: {"x5t#S256": ...}`.
const (
	ConfirmationClaim            = "cnf"
	CertificateThumbprintMember  = "x5t#S256"
	CertificateThumbprintEncoded = 43 // unpadded base64url of 32 bytes
)

// CertificateSHA256 hashes a certificate's DER encoding, the RFC 8705 binding input.
func CertificateSHA256(der []byte) [32]byte { return sha256.Sum256(der) }

// CertificateThumbprint encodes a certificate hash as the `x5t#S256` value.
func CertificateThumbprint(sum [32]byte) string { return base64.RawURLEncoding.EncodeToString(sum[:]) }

// CertificateThumbprintSHA256 is RFC 8705's `x5t#S256` over certificate DER.
func CertificateThumbprintSHA256(der []byte) string {
	return CertificateThumbprint(CertificateSHA256(der))
}

// ConfirmationClaimValue is the exact `cnf` object minted for a bound token.
func ConfirmationClaimValue(sum [32]byte) map[string]any {
	return map[string]any{CertificateThumbprintMember: CertificateThumbprint(sum)}
}
