// Package documents defines AuthKit's generic immutable signed-document wire
// contract. It authenticates transport metadata and opaque JSON payload bytes;
// application schema and authorization remain the receiving application's job.
package documents

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/open-rails/authkit/jwtkit"
)

const (
	JOSEType = "authkit-document+jws"

	MaxTypeBytes           = 256
	MaxIssuerBytes         = 2048
	MaxAudienceBytes       = 512
	MaxAudiences           = 32
	MaxPayloadBytes        = 1 << 20
	MaxSignedPayloadBytes  = MaxPayloadBytes + 16<<10
	MaxCompactJWSBytes     = 2 << 20
	MaxReferences          = 16
	MaxReferencesJSONBytes = 4 << 10
)

var (
	ErrInvalidReference     = errors.New("invalid_document_reference")
	ErrInvalidType          = errors.New("invalid_document_type")
	ErrInvalidDigest        = errors.New("invalid_document_digest")
	ErrDuplicateReference   = errors.New("duplicate_document_reference")
	ErrTooManyReferences    = errors.New("too_many_document_references")
	ErrReferencesTooLarge   = errors.New("document_references_too_large")
	ErrWrongTokenType       = errors.New("documents_wrong_token_type")
	ErrReservedAttribute    = errors.New("reserved_document_attribute")
	ErrInvalidEnvelope      = errors.New("invalid_document_envelope")
	ErrPayloadTooLarge      = errors.New("document_payload_too_large")
	ErrMalformedJWS         = errors.New("malformed_document_jws")
	ErrWrongJOSEType        = errors.New("wrong_document_jose_type")
	ErrUnsupportedAlgorithm = errors.New("unsupported_document_algorithm")
	ErrUnsupportedSigner    = errors.New("unsupported_document_signer")
	ErrUnknownKey           = errors.New("unknown_document_key")
	ErrInvalidSignature     = errors.New("invalid_document_signature")
	ErrDigestMismatch       = errors.New("document_digest_mismatch")
	ErrIssuerMismatch       = errors.New("document_issuer_mismatch")
	ErrAudienceMismatch     = errors.New("document_audience_mismatch")
	ErrTypeMismatch         = errors.New("document_type_mismatch")
	ErrUntrustedIssuer      = errors.New("untrusted_document_issuer")
	ErrUnauthorized         = errors.New("document_unauthorized")
	ErrNotFound             = errors.New("document_not_found")
	ErrFetch                = errors.New("document_fetch_failed")
	ErrRedirect             = errors.New("document_redirect_rejected")
)

// Reference identifies one exact signed envelope. Type carries the application
// schema version (for example, example.catalog/v1); Digest covers the exact JWS
// payload bytes, not a decoded/re-encoded JSON value.
type Reference struct {
	Type   string `json:"type"`
	Digest string `json:"digest"`
}

// Envelope is the signed JWS payload. Payload is intentionally opaque to
// AuthKit and may contain any valid JSON value.
type Envelope struct {
	Issuer    string          `json:"iss"`
	Audiences []string        `json:"aud"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

// SignedDocument retains both the compact JWS and the exact bytes used as its
// payload so callers can publish them without a parse/re-encode step.
type SignedDocument struct {
	CompactJWS    string    `json:"jws"`
	Reference     Reference `json:"reference"`
	SignedPayload []byte    `json:"signed_payload"`
}

// VerifyOptions are the caller's authenticated expectations. None may be
// inferred from unsigned request metadata.
type VerifyOptions struct {
	Issuer    string
	Audience  string
	Type      string
	Reference Reference
}

// Header is the security-relevant subset of an inspected compact JWS header.
// Inspecting a header or payload does not verify its signature.
type Header struct {
	Algorithm string
	KeyID     string
	Type      string
}

func (r Reference) Validate() error {
	if err := ValidateType(r.Type); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReference, err)
	}
	if err := ValidateDigest(r.Digest); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidReference, err)
	}
	return nil
}

func NormalizeReference(r Reference) (Reference, error) {
	t, err := NormalizeType(r.Type)
	if err != nil {
		return Reference{}, fmt.Errorf("%w: %v", ErrInvalidReference, err)
	}
	d, err := NormalizeDigest(r.Digest)
	if err != nil {
		return Reference{}, fmt.Errorf("%w: %v", ErrInvalidReference, err)
	}
	return Reference{Type: t, Digest: d}, nil
}

func NormalizeType(value string) (string, error) {
	value = strings.TrimSpace(value)
	if err := ValidateType(value); err != nil {
		return "", err
	}
	return value, nil
}

// ValidateType requires a bounded opaque identifier ending in /vN. AuthKit does
// not interpret the namespace or version beyond enforcing that the version is
// present in the type itself.
func ValidateType(value string) error {
	if value == "" || value != strings.TrimSpace(value) || len(value) > MaxTypeBytes || !utf8.ValidString(value) {
		return ErrInvalidType
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return ErrInvalidType
		}
	}
	i := strings.LastIndex(value, "/v")
	if i <= 0 || i+2 >= len(value) {
		return ErrInvalidType
	}
	version := value[i+2:]
	if version[0] == '0' {
		return ErrInvalidType
	}
	for _, r := range version {
		if r < '0' || r > '9' {
			return ErrInvalidType
		}
	}
	return nil
}

func NormalizeDigest(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if err := ValidateDigest(value); err != nil {
		return "", err
	}
	return value, nil
}

func ValidateDigest(value string) error {
	if value != strings.ToLower(value) || len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return ErrInvalidDigest
	}
	b, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	if err != nil || len(b) != sha256.Size {
		return ErrInvalidDigest
	}
	return nil
}

func Digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func ReferenceFor(documentType string, signedPayload []byte) (Reference, error) {
	t, err := NormalizeType(documentType)
	if err != nil {
		return Reference{}, err
	}
	return Reference{Type: t, Digest: Digest(signedPayload)}, nil
}

// NormalizeEnvelope returns a detached, normalized copy suitable for one-time
// marshaling and signing.
func NormalizeEnvelope(in Envelope) (Envelope, error) {
	out := Envelope{
		Issuer:  strings.TrimSpace(in.Issuer),
		Payload: append(json.RawMessage(nil), in.Payload...),
	}
	var err error
	out.Type, err = NormalizeType(in.Type)
	if err != nil {
		return Envelope{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	seen := map[string]bool{}
	for _, audience := range in.Audiences {
		audience = strings.TrimSpace(audience)
		if audience != "" && !seen[audience] {
			seen[audience] = true
			out.Audiences = append(out.Audiences, audience)
		}
	}
	if err := out.Validate(); err != nil {
		return Envelope{}, err
	}
	return out, nil
}

func (e Envelope) Validate() error {
	if !validText(e.Issuer, MaxIssuerBytes) || len(e.Audiences) == 0 || len(e.Audiences) > MaxAudiences {
		return ErrInvalidEnvelope
	}
	if err := ValidateType(e.Type); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	seen := map[string]bool{}
	for _, audience := range e.Audiences {
		if !validText(audience, MaxAudienceBytes) || seen[audience] {
			return ErrInvalidEnvelope
		}
		seen[audience] = true
	}
	if len(e.Payload) > MaxPayloadBytes {
		return ErrPayloadTooLarge
	}
	if len(e.Payload) == 0 || !json.Valid(e.Payload) {
		return ErrInvalidEnvelope
	}
	return nil
}

func (e Envelope) HasAudience(audience string) bool {
	audience = strings.TrimSpace(audience)
	for _, candidate := range e.Audiences {
		if candidate == audience {
			return true
		}
	}
	return false
}

func validText(value string, max int) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > max || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// Sign marshals the normalized envelope once, signs those exact bytes, and
// returns the retained bytes and their content-addressed reference.
func Sign(ctx context.Context, signer jwtkit.Signer, envelope Envelope) (SignedDocument, error) {
	if signer == nil {
		return SignedDocument{}, ErrUnsupportedSigner
	}
	if kid := signer.KID(); kid == "" || kid != strings.TrimSpace(kid) {
		return SignedDocument{}, ErrUnknownKey
	}
	if !supportedSigningAlgorithm(signer.Algorithm()) {
		return SignedDocument{}, ErrUnsupportedAlgorithm
	}
	normalized, err := NormalizeEnvelope(envelope)
	if err != nil {
		return SignedDocument{}, err
	}
	payload, err := json.Marshal(normalized)
	if err != nil {
		return SignedDocument{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if len(payload) > MaxSignedPayloadBytes {
		return SignedDocument{}, ErrPayloadTooLarge
	}
	reference, err := ReferenceFor(normalized.Type, payload)
	if err != nil {
		return SignedDocument{}, err
	}
	compact, err := jwtkit.SignPayloadWithType(ctx, signer, payload, JOSEType)
	if err != nil {
		if errors.Is(err, jwtkit.ErrPayloadSignerRequired) {
			return SignedDocument{}, ErrUnsupportedSigner
		}
		return SignedDocument{}, err
	}
	header, signedPayload, err := DecodeCompact(compact)
	if err != nil {
		return SignedDocument{}, err
	}
	if header.Type != JOSEType {
		return SignedDocument{}, ErrWrongJOSEType
	}
	if header.KeyID == "" || header.KeyID != signer.KID() {
		return SignedDocument{}, ErrUnknownKey
	}
	if !supportedSigningAlgorithm(header.Algorithm) || header.Algorithm != signer.Algorithm() {
		return SignedDocument{}, ErrUnsupportedAlgorithm
	}
	if !bytes.Equal(signedPayload, payload) {
		return SignedDocument{}, ErrDigestMismatch
	}
	return SignedDocument{CompactJWS: compact, Reference: reference, SignedPayload: payload}, nil
}

func supportedSigningAlgorithm(algorithm string) bool {
	switch algorithm {
	case "RS256", "ES256", "ES384", "ES512", "EdDSA":
		return true
	default:
		return false
	}
}

// DecodeCompact strictly inspects a compact JWS and returns its exact decoded
// payload. It does not verify the signature.
func DecodeCompact(compact string) (Header, []byte, error) {
	if compact == "" || compact != strings.TrimSpace(compact) || len(compact) > MaxCompactJWSBytes {
		return Header{}, nil, ErrMalformedJWS
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Header{}, nil, ErrMalformedJWS
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || len(headerBytes) > 4096 {
		return Header{}, nil, ErrMalformedJWS
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(payload) > MaxSignedPayloadBytes {
		return Header{}, nil, ErrMalformedJWS
	}
	if _, err := base64.RawURLEncoding.DecodeString(parts[2]); err != nil {
		return Header{}, nil, ErrMalformedJWS
	}
	fields, err := strictObject(headerBytes)
	if err != nil {
		return Header{}, nil, ErrMalformedJWS
	}
	var h Header
	if err := decodeOptionalString(fields["alg"], &h.Algorithm); err != nil || h.Algorithm == "" {
		return Header{}, nil, ErrMalformedJWS
	}
	if err := decodeOptionalString(fields["kid"], &h.KeyID); err != nil {
		return Header{}, nil, ErrMalformedJWS
	}
	if err := decodeOptionalString(fields["typ"], &h.Type); err != nil {
		return Header{}, nil, ErrMalformedJWS
	}
	if raw, ok := fields["crit"]; ok {
		var critical []string
		if json.Unmarshal(raw, &critical) != nil || len(critical) != 0 {
			return Header{}, nil, ErrMalformedJWS
		}
	}
	return h, payload, nil
}

func FromCompact(compact string, reference Reference) (SignedDocument, error) {
	if err := reference.Validate(); err != nil {
		return SignedDocument{}, err
	}
	_, payload, err := DecodeCompact(compact)
	if err != nil {
		return SignedDocument{}, err
	}
	if Digest(payload) != reference.Digest {
		return SignedDocument{}, ErrDigestMismatch
	}
	return SignedDocument{CompactJWS: compact, Reference: reference, SignedPayload: payload}, nil
}

// DecodeEnvelope strictly decodes the signed payload, rejecting duplicate or
// unknown fields before any application payload can be returned.
func DecodeEnvelope(payload []byte) (Envelope, error) {
	if len(payload) > MaxSignedPayloadBytes {
		return Envelope{}, ErrPayloadTooLarge
	}
	fields, err := strictObject(payload)
	if err != nil || len(fields) != 4 {
		return Envelope{}, ErrInvalidEnvelope
	}
	for key := range fields {
		if key != "iss" && key != "aud" && key != "type" && key != "payload" {
			return Envelope{}, ErrInvalidEnvelope
		}
	}
	var out Envelope
	if json.Unmarshal(fields["iss"], &out.Issuer) != nil ||
		json.Unmarshal(fields["aud"], &out.Audiences) != nil ||
		json.Unmarshal(fields["type"], &out.Type) != nil || fields["payload"] == nil {
		return Envelope{}, ErrInvalidEnvelope
	}
	out.Payload = append(json.RawMessage(nil), fields["payload"]...)
	if err := out.Validate(); err != nil {
		return Envelope{}, err
	}
	return out, nil
}

func strictObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, ErrInvalidEnvelope
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, ErrInvalidEnvelope
		}
		if _, duplicate := out[key]; duplicate {
			return nil, ErrDuplicateReference
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out[key] = raw
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, ErrInvalidEnvelope
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrInvalidEnvelope
	}
	return out, nil
}

func decodeOptionalString(raw json.RawMessage, out *string) error {
	if raw == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// NormalizeReferences prepares a mint-time documents claim. It trims types,
// canonicalizes digests, and rejects normalization collisions.
func NormalizeReferences(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	if len(in) > MaxReferences {
		return nil, ErrTooManyReferences
	}
	out := make(map[string]string, len(in))
	for documentType, digest := range in {
		normalized, err := NormalizeReference(Reference{Type: documentType, Digest: digest})
		if err != nil {
			return nil, err
		}
		if _, duplicate := out[normalized.Type]; duplicate {
			return nil, ErrDuplicateReference
		}
		out[normalized.Type] = normalized.Digest
	}
	if err := ValidateReferences(out); err != nil {
		return nil, err
	}
	return out, nil
}

func ValidateReferences(references map[string]string) error {
	if len(references) > MaxReferences {
		return ErrTooManyReferences
	}
	for documentType, digest := range references {
		if err := (Reference{Type: documentType, Digest: digest}).Validate(); err != nil {
			return err
		}
	}
	encoded, err := json.Marshal(references)
	if err != nil {
		return ErrInvalidReference
	}
	if len(encoded) > MaxReferencesJSONBytes {
		return ErrReferencesTooLarge
	}
	return nil
}

// ParseReferencesJSON strictly parses a documents claim. Duplicate keys and
// non-canonical values are rejected instead of being overwritten by map decode.
func ParseReferencesJSON(raw []byte) (map[string]string, error) {
	if len(raw) > MaxReferencesJSONBytes {
		return nil, ErrReferencesTooLarge
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, ErrInvalidReference
	}
	out := map[string]string{}
	for dec.More() {
		keyToken, err := dec.Token()
		if err != nil {
			return nil, ErrInvalidReference
		}
		key, ok := keyToken.(string)
		if !ok {
			return nil, ErrInvalidReference
		}
		if _, duplicate := out[key]; duplicate {
			return nil, ErrDuplicateReference
		}
		var digest string
		if err := dec.Decode(&digest); err != nil {
			return nil, ErrInvalidReference
		}
		out[key] = digest
		if len(out) > MaxReferences {
			return nil, ErrTooManyReferences
		}
	}
	if tok, err = dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, ErrInvalidReference
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, ErrInvalidReference
	}
	if err := ValidateReferences(out); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}
