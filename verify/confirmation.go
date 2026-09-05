package verify

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	// ErrInvalidConfirmation rejects a `cnf` claim that is not exactly
	// {"x5t#S256": <unpadded base64url sha256>}.
	ErrInvalidConfirmation = authkit.E(authkit.CodeInvalidConfirmation)
	// ErrConfirmationWrongTokenType rejects `cnf` on any token type AuthKit does
	// not bind — accepting an unenforced binding would be a silent downgrade.
	ErrConfirmationWrongTokenType = authkit.E(authkit.CodeConfirmationWrongTokenType)
)

// confirmationClaim parses the strict `cnf` claim into the bound thumbprint.
func confirmationClaim(token string) (*[32]byte, bool, error) {
	raw, present, err := rawTopLevelClaim(token, jwtkit.ConfirmationClaim)
	if err != nil {
		return nil, present, ErrInvalidConfirmation
	}
	if !present {
		return nil, false, nil
	}
	// Exactly {"x5t#S256": "<43 chars>"}: one member, string value, nothing else.
	dec := json.NewDecoder(bytes.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return nil, true, ErrInvalidConfirmation
	}
	if member, err := dec.Token(); err != nil || member != jwtkit.CertificateThumbprintMember {
		return nil, true, ErrInvalidConfirmation
	}
	var thumbprint string
	if err := dec.Decode(&thumbprint); err != nil || len(thumbprint) != jwtkit.CertificateThumbprintEncoded {
		return nil, true, ErrInvalidConfirmation
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, true, ErrInvalidConfirmation
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, true, ErrInvalidConfirmation
	}
	sum, err := base64.RawURLEncoding.DecodeString(thumbprint)
	if err != nil || len(sum) != 32 {
		return nil, true, ErrInvalidConfirmation
	}
	var out [32]byte
	copy(out[:], sum)
	return &out, true, nil
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
