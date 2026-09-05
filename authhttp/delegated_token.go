package authhttp

// ak#261/#277: the delegated-token mint route. AuthKit owns every mechanic —
// audience-subset clamp, TTL clamp, delegate-certificate validation and RFC
// 8705 `cnf.x5t#S256` binding, document stamping from the wired
// DocumentProviders, and post-mint signing-KID reconciliation. The host owns
// exactly one decision: the DelegationAuthorizer's grant, which is the
// complete authority signed. Client input never becomes authority directly.

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// Route bounds (#277). Named constants, not deployment knobs.
const (
	maxDelegateCertificateDER = 8 << 10
	maxRequestedGrantBytes    = 16 << 10
	maxDelegatedTokenBytes    = 16 << 10
)

type delegatedTokenRequest struct {
	// TTLSeconds is an optional override, clamped into the configured
	// floor/ceiling; absent or <= 0 mints the configured default.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Audiences is an optional narrowing; every requested audience must be in
	// the configured allowlist. Absent mints the full configured list.
	Audiences []string `json:"audiences,omitempty"`
	// DelegateCertificateDERB64URL is the delegate's public X.509 leaf as
	// unpadded base64url DER. The token is bound to exactly this certificate.
	DelegateCertificateDERB64URL string `json:"delegate_certificate_der_b64url"`
	// RequestedGrant is one host-schema JSON object passed to the authorizer
	// verbatim and never copied into the token.
	RequestedGrant json.RawMessage `json:"requested_grant"`
}

type delegatedTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (s *Service) handleDelegatedTokenPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}
	authorize := s.svc.DelegationAuthorizer()
	if authorize == nil {
		sendErr(w, http.StatusServiceUnavailable, ErrDelegationAuthorizerUnavailable)
		return
	}

	var req delegatedTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		badRequest(w, ErrInvalidRequest)
		return
	}

	cfg := s.svc.Config().Delegated
	audiences, err := resolveDelegatedAudiences(cfg.Audiences, req.Audiences)
	if err != nil {
		badRequest(w, ErrInvalidAudiences)
		return
	}
	ttl := clampDelegatedTTL(cfg, req.TTLSeconds)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	certificate, err := parseDelegateCertificate(req.DelegateCertificateDERB64URL, now)
	if err != nil {
		badRequestParam(w, ErrInvalidDelegateCertificate, "delegate_certificate_der_b64url")
		return
	}
	if expiresAt.After(certificate.NotAfter) {
		badRequestParam(w, ErrTTLExceedsDelegateCertificate, "ttl_seconds")
		return
	}
	if !validRequestedGrant(req.RequestedGrant) {
		badRequestParam(w, ErrInvalidRequestedGrant, "requested_grant")
		return
	}
	thumbprint := jwtkit.CertificateSHA256(certificate.Raw)

	grant, err := authorize(r.Context(), authkit.DelegationRequest{
		UserID:                        claims.UserID,
		Audiences:                     audiences,
		TTL:                           ttl,
		ConfirmationCertificateSHA256: thumbprint,
		DelegateCertificate:           certificate,
		RequestedGrant:                req.RequestedGrant,
	})
	switch {
	case errors.Is(err, authkit.ErrDelegationRefused):
		forbidden(w, ErrDelegationRefused)
		return
	case err != nil:
		sendErr(w, http.StatusServiceUnavailable, ErrDelegationAuthorizerUnavailable)
		return
	}

	references := make(map[string]string, len(grant.Documents)+len(s.documentProviders))
	for documentType, digest := range grant.Documents {
		references[documentType] = digest
	}
	// Registered providers are authoritative for their document types; a host
	// document colliding with a provider's type on a different digest is a
	// wiring bug and fails loudly.
	for _, p := range s.documentProviders {
		ref := p.Reference()
		if existing, dup := references[ref.Type]; dup && existing != ref.Digest {
			sendErr(w, http.StatusServiceUnavailable, ErrDelegatedDocumentUnavailable)
			return
		}
		references[ref.Type] = ref.Digest
	}

	token, err := s.svc.MintDelegatedAccessToken(r.Context(), authkit.DelegatedAccessParams{
		Audiences:                     audiences,
		DelegatedSubject:              claims.UserID,
		Permissions:                   grant.Permissions,
		Documents:                     references,
		Attributes:                    grant.Attributes,
		TTL:                           ttl,
		ConfirmationCertificateSHA256: &thumbprint,
	})
	if err != nil {
		serverErr(w, ErrDelegatedMintFailed)
		return
	}
	if len(token) > maxDelegatedTokenBytes {
		serverErr(w, ErrDelegatedTokenTooLarge)
		return
	}

	// #260/#261 pairing: every stamped provider document must be verifiable by
	// a reader that trusts the token's signing key — re-sign the persisted
	// artifact if key rotation left it behind, then prove the digest is still
	// the one this token carries.
	if len(s.documentProviders) > 0 {
		kid, err := delegatedTokenSigningKID(token)
		if err != nil {
			sendErr(w, http.StatusServiceUnavailable, ErrDelegatedDocumentUnavailable)
			return
		}
		for _, p := range s.documentProviders {
			if err := p.EnsureSigningKID(r.Context(), kid); err != nil {
				sendErr(w, http.StatusServiceUnavailable, ErrDelegatedDocumentUnavailable)
				return
			}
			digest, err := p.CurrentDigest(r.Context())
			if err != nil || digest != references[p.Reference().Type] {
				sendErr(w, http.StatusServiceUnavailable, ErrDelegatedDocumentUnavailable)
				return
			}
		}
	}

	writeJSON(w, http.StatusOK, delegatedTokenResponse{Token: token, ExpiresAt: expiresAt})
}

// parseDelegateCertificate accepts exactly one currently valid, non-CA X.509
// certificate with an explicit clientAuth extended key usage, as unpadded
// base64url DER of at most maxDelegateCertificateDER bytes.
func parseDelegateCertificate(encoded string, now time.Time) (*x509.Certificate, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(maxDelegateCertificateDER) {
		return nil, errors.New("invalid delegate certificate")
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(der) == 0 || len(der) > maxDelegateCertificateDER {
		return nil, errors.New("invalid delegate certificate")
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, errors.New("invalid delegate certificate")
	}
	switch {
	case certificate.IsCA,
		now.Before(certificate.NotBefore),
		now.After(certificate.NotAfter),
		!slices.Contains(certificate.ExtKeyUsage, x509.ExtKeyUsageClientAuth):
		return nil, errors.New("invalid delegate certificate")
	}
	return certificate, nil
}

// validRequestedGrant requires one JSON object of at most maxRequestedGrantBytes.
func validRequestedGrant(raw json.RawMessage) bool {
	if len(raw) == 0 || len(raw) > maxRequestedGrantBytes || !json.Valid(raw) {
		return false
	}
	return bytes.HasPrefix(bytes.TrimLeft(raw, " \t\r\n"), []byte("{"))
}

// resolveDelegatedAudiences applies the audience-subset clamp: an empty
// request receives the full configured allowlist; a non-empty request must be
// a subset (after trim/dedup) or the whole request is refused.
func resolveDelegatedAudiences(allowed, requested []string) ([]string, error) {
	if len(requested) == 0 {
		return append([]string(nil), allowed...), nil
	}
	allowedSet := make(map[string]bool, len(allowed))
	for _, audience := range allowed {
		allowedSet[audience] = true
	}
	want := make([]string, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, audience := range requested {
		audience = strings.TrimSpace(audience)
		if audience == "" || seen[audience] {
			continue
		}
		seen[audience] = true
		want = append(want, audience)
	}
	if len(want) == 0 {
		return nil, errors.New("invalid audiences")
	}
	for _, audience := range want {
		if !allowedSet[audience] {
			return nil, errors.New("invalid audiences")
		}
	}
	return want, nil
}

// clampDelegatedTTL resolves a requested TTL against the boot-validated
// bounds: absent/non-positive mints the default; anything else is clamped
// into [floor, ceiling]. The CONFIG is never silently clamped (that refuses
// at construction); the per-request value is.
func clampDelegatedTTL(cfg embedded.DelegatedConfig, requestedSeconds int) time.Duration {
	if requestedSeconds <= 0 {
		return cfg.TTLDefault
	}
	ttl := time.Duration(requestedSeconds) * time.Second
	if ttl < cfg.TTLFloor {
		return cfg.TTLFloor
	}
	if ttl > cfg.TTLCeiling {
		return cfg.TTLCeiling
	}
	return ttl
}

// delegatedTokenSigningKID extracts the `kid` protected header of the minted
// compact JWT without re-verifying it (we just minted it).
func delegatedTokenSigningKID(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errors.New("delegated token is not a compact JWT")
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", errors.New("delegated token has a malformed protected header")
	}
	var header struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(raw, &header); err != nil {
		return "", errors.New("delegated token has a malformed protected header")
	}
	header.KeyID = strings.TrimSpace(header.KeyID)
	if header.KeyID == "" {
		return "", errors.New("delegated token signing key id is unavailable")
	}
	return header.KeyID, nil
}
