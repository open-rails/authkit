package verify

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/documents"
)

var _ documents.DocumentVerifier = (*Verifier)(nil)

// ValidateDocumentIssuer performs the resolver's pre-network trust check. A
// registered issuer is accepted; a configured remote-application source gets
// the same bounded lazy-load-on-first-use behavior as token verification.
func (v *Verifier) ValidateDocumentIssuer(ctx context.Context, issuer string) error {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return documents.ErrUntrustedIssuer
	}
	if v.matchIssuer(issuer) == nil && !v.lazyLoadIssuer(ctx, issuer) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return documents.ErrUntrustedIssuer
	}
	if v.matchIssuer(issuer) == nil {
		return documents.ErrUntrustedIssuer
	}
	return nil
}

// VerifyDocument verifies exact-byte digest, strict envelope metadata, trusted
// issuer/key resolution, JOSE profile, and signature. It never decodes the
// application-owned Envelope.Payload.
func (v *Verifier) VerifyDocument(ctx context.Context, document documents.SignedDocument, expected documents.VerifyOptions) (documents.Envelope, error) {
	if expected.Issuer == "" || expected.Issuer != strings.TrimSpace(expected.Issuer) {
		return documents.Envelope{}, documents.ErrIssuerMismatch
	}
	if expected.Audience == "" || expected.Audience != strings.TrimSpace(expected.Audience) {
		return documents.Envelope{}, documents.ErrAudienceMismatch
	}
	if err := documents.ValidateType(expected.Type); err != nil || expected.Reference.Type != expected.Type {
		return documents.Envelope{}, documents.ErrTypeMismatch
	}
	if err := expected.Reference.Validate(); err != nil {
		return documents.Envelope{}, err
	}
	if err := document.Reference.Validate(); err != nil {
		return documents.Envelope{}, err
	}
	if document.Reference.Type != expected.Reference.Type {
		return documents.Envelope{}, documents.ErrTypeMismatch
	}
	if document.Reference.Digest != expected.Reference.Digest {
		return documents.Envelope{}, documents.ErrDigestMismatch
	}

	header, payload, err := documents.DecodeCompact(document.CompactJWS)
	if err != nil {
		return documents.Envelope{}, err
	}
	if header.Type != documents.JOSEType {
		return documents.Envelope{}, documents.ErrWrongJOSEType
	}
	if !v.algAllowed(header.Algorithm) {
		return documents.Envelope{}, documents.ErrUnsupportedAlgorithm
	}
	if header.KeyID == "" {
		return documents.Envelope{}, documents.ErrUnknownKey
	}
	if !bytes.Equal(payload, document.SignedPayload) {
		return documents.Envelope{}, documents.ErrDigestMismatch
	}
	if documents.Digest(payload) != expected.Reference.Digest {
		return documents.Envelope{}, documents.ErrDigestMismatch
	}
	if err := v.ValidateDocumentIssuer(ctx, expected.Issuer); err != nil {
		return documents.Envelope{}, err
	}

	verify := func() error {
		key, err := v.documentKey(ctx, header.Algorithm, header.KeyID, expected.Issuer)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return documents.ErrUnknownKey
		}
		parts := strings.Split(document.CompactJWS, ".")
		if len(parts) != 3 {
			return documents.ErrMalformedJWS
		}
		signature, err := base64.RawURLEncoding.DecodeString(parts[2])
		if err != nil {
			return documents.ErrMalformedJWS
		}
		method := jwt.GetSigningMethod(header.Algorithm)
		if method == nil {
			return documents.ErrUnsupportedAlgorithm
		}
		if err := method.Verify(parts[0]+"."+parts[1], signature, key); err != nil {
			return documents.ErrInvalidSignature
		}
		return nil
	}
	if err := verify(); err != nil {
		if errors.Is(err, documents.ErrInvalidSignature) {
			refreshed := v.forceRefreshIssuer(ctx, expected.Issuer)
			if ctx.Err() != nil {
				return documents.Envelope{}, ctx.Err()
			}
			if refreshed {
				err = verify()
			}
		}
		if err != nil {
			return documents.Envelope{}, err
		}
	}

	// Payload bytes remain opaque until their digest and signature have both
	// been authenticated with the caller's expected issuer.
	envelope, err := documents.DecodeEnvelope(payload)
	if err != nil {
		return documents.Envelope{}, err
	}
	if envelope.Issuer != expected.Issuer {
		return documents.Envelope{}, documents.ErrIssuerMismatch
	}
	if envelope.Type != expected.Type {
		return documents.Envelope{}, documents.ErrTypeMismatch
	}
	if !envelope.HasAudience(expected.Audience) {
		return documents.Envelope{}, documents.ErrAudienceMismatch
	}
	return envelope, nil
}

func (v *Verifier) documentKey(ctx context.Context, algorithm, kid, issuer string) (any, error) {
	if !v.algAllowed(algorithm) {
		return nil, documents.ErrUnsupportedAlgorithm
	}
	entry := v.matchIssuer(issuer)
	if entry == nil {
		return nil, documents.ErrUntrustedIssuer
	}
	return v.publicKeyFor(ctx, *entry, kid)
}
