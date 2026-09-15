package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/jwtkit"
)

// RFC 8705 certificate-bound delegated tokens (ak#277). A `cnf.x5t#S256`
// claim is honoured only against the leaf certificate Go's TLS stack
// authenticated on THIS request; no header or context value can stand in.
var (
	// ErrSenderProofRequired rejects a certificate-bound token presented
	// without its certificate: no TLS peer, a different leaf, or a token-only
	// verification detached from its request.
	ErrSenderProofRequired = authkit.E(authkit.CodeSenderProofRequired)
	errDPoPProofRequired   = fmt.Errorf("DPoP: %w", ErrSenderProofRequired)
	// ErrInvalidConfirmation rejects a `cnf` claim that is not exactly
	// {"x5t#S256": <unpadded base64url sha256>} or {"jkt": <same format>}.
	ErrInvalidConfirmation = authkit.E(authkit.CodeInvalidConfirmation)
	// ErrConfirmationWrongTokenType rejects `cnf` on any token type AuthKit does
	// not bind — accepting an unenforced binding would be a silent downgrade.
	ErrConfirmationWrongTokenType = authkit.E(authkit.CodeConfirmationWrongTokenType)
)

// confirmationClaim parses the strict `cnf` claim into the bound thumbprint.
func confirmationClaim(token string) (*[32]byte, string, error) {
	raw, present, err := rawTopLevelClaim(token, jwtkit.ConfirmationClaim)
	if err != nil {
		return nil, "", ErrInvalidConfirmation
	}
	if !present {
		return nil, "", nil
	}
	// Exactly one recognized binding: string value, no extra or duplicate members.
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, "", ErrInvalidConfirmation
	}
	member, err := dec.Token()
	if err != nil || (member != jwtkit.CertificateThumbprintMember && member != jwtkit.JWKThumbprintMember) {
		return nil, "", ErrInvalidConfirmation
	}
	var thumbprint string
	if err := dec.Decode(&thumbprint); err != nil || len(thumbprint) != jwtkit.CertificateThumbprintEncoded {
		return nil, "", ErrInvalidConfirmation
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, "", ErrInvalidConfirmation
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, "", ErrInvalidConfirmation
	}
	sum, err := base64.RawURLEncoding.Strict().DecodeString(thumbprint)
	if err != nil || len(sum) != 32 {
		return nil, "", ErrInvalidConfirmation
	}
	var out [32]byte
	copy(out[:], sum)
	return &out, member.(string), nil
}

// peerCertificateSHA256 hashes the TLS-authenticated peer leaf, nil when the
// request carries no authenticated client certificate.
func peerCertificateSHA256(r *http.Request) *[32]byte {
	if r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || r.TLS.PeerCertificates[0] == nil {
		return nil
	}
	sum := jwtkit.CertificateSHA256(r.TLS.PeerCertificates[0].Raw)
	return &sum
}
