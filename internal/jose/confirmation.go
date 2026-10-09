package jose

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
)

// Sender binding (cnf) of a resource token: RFC 8705 binds it to an X.509
// certificate (x5t#S256), RFC 9449 to a DPoP key (jkt). Both thumbprints are
// the unpadded base64url SHA-256 the claim itself carries.
const (
	ConfirmationClaim           = "cnf"
	CertificateThumbprintMember = "x5t#S256"
	JWKThumbprintMember         = "jkt"
)

// CertificateThumbprint is RFC 8705's x5t#S256 of certificate DER.
func CertificateThumbprint(der []byte) string {
	sum := sha256.Sum256(der)
	return b64.EncodeToString(sum[:])
}

// ValidThumbprint reports whether s is an unpadded base64url SHA-256.
func ValidThumbprint(s string) bool {
	sum, err := b64.Strict().DecodeString(s)
	return err == nil && len(sum) == sha256.Size
}

// ErrInvalidConfirmation is a cnf claim that is not exactly one recognized
// member holding a thumbprint.
var ErrInvalidConfirmation = errors.New("invalid cnf claim")

// Confirmation parses token's cnf claim strictly: absent, or exactly
// {"x5t#S256": t} or {"jkt": t}. member is "" when there is none.
func Confirmation(token string) (member, thumbprint string, err error) {
	raw, present, err := RawClaim(token, ConfirmationClaim)
	if err != nil {
		return "", "", ErrInvalidConfirmation
	}
	if !present {
		return "", "", nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return "", "", ErrInvalidConfirmation
	}
	name, err := dec.Token()
	if err != nil || (name != CertificateThumbprintMember && name != JWKThumbprintMember) {
		return "", "", ErrInvalidConfirmation
	}
	if err := dec.Decode(&thumbprint); err != nil || !ValidThumbprint(thumbprint) {
		return "", "", ErrInvalidConfirmation
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return "", "", ErrInvalidConfirmation
	}
	if _, err := dec.Token(); err != io.EOF {
		return "", "", ErrInvalidConfirmation
	}
	return name.(string), thumbprint, nil
}
