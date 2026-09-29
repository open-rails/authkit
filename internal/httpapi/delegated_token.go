package httpapi

// ak#261/#277: the delegated-token mint route. AuthKit owns every mechanic:
// audience-subset clamp, TTL clamp, RFC 8705 certificate or RFC 9449 DPoP
// sender binding here; the grant check against the user's live authority and
// published-document stamping in the engine's mint. The host owns exactly one
// decision: the DelegationAuthorizer's grant, which is the complete authority
// signed. Client input never becomes authority directly.

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
)

// Route bounds (#277). Named constants, not deployment knobs.
const (
	MaxDelegateCertificateDER = 8 << 10
	MaxRequestedGrantBytes    = 16 << 10
	MaxDelegatedTokenBytes    = 16 << 10
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

type DelegatedTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	TokenType string    `json:"token_type,omitempty"`
}

func (s *Service) handleDelegatedTokenPOST(w http.ResponseWriter, r *http.Request) {
	claims, ok := verify.ClaimsFromContext(r.Context())
	actor, isActor := verify.ActorFromClaims(claims)
	if !ok || !isActor || actor.Kind() != iam.ActorUser {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	// A delegated token outlives its parent, so the parent must still be a live
	// account and, when session-bound, a live session (ak#392).
	if live, _, err := s.verifier.IsLive(r.Context(), claims); err != nil || !live {
		fail(w, errmodel.CodeUnauthorized)
		return
	}
	if (claims.SessionID != "" || claims.DeviceKeyID != "") && !s.requireLiveCredential(w, r, claims) {
		return
	}
	authorize := s.svc.DelegationAuthorizer()
	if authorize == nil {
		fail(w, errmodel.CodeDelegationAuthorizerUnavailable)
		return
	}

	var req delegatedTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		fail(w, errmodel.CodeInvalidRequest)
		return
	}

	cfg := s.settings.Delegated
	audiences, err := resolveDelegatedAudiences(cfg.Audiences, req.Audiences)
	if err != nil {
		fail(w, errmodel.CodeInvalidAudiences)
		return
	}
	ttl := clampDelegatedTTL(cfg, req.TTLSeconds)
	now := time.Now().UTC()
	expiresAt := now.Add(ttl)

	var certificate *x509.Certificate
	var thumbprint, certificateThumbprint [32]byte
	var certificateBinding, jwkBinding *[32]byte
	tokenType := ""
	if len(r.Header.Values("DPoP")) > 0 {
		if !cfg.AllowDPoP || req.DelegateCertificateDERB64URL != "" {
			fail(w, errmodel.CodeInvalidRequest)
			return
		}
		parent := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
		if len(parent) != 2 || !strings.EqualFold(parent[0], "Bearer") {
			fail(w, errmodel.CodeUnauthorized)
			return
		}
		target := ""
		if s.dpopRequestURL != nil {
			target = s.dpopRequestURL(r)
		} else if issuer, parseErr := url.Parse(s.settings.Issuer); parseErr == nil && issuer.User == nil {
			target = issuer.Scheme + "://" + issuer.Host + r.URL.EscapedPath()
		}
		thumbprint, err = dpop.VerifyRequest(r, target, parent[1], nil, s.svc.ClaimDPoPProof)
		if err != nil {
			if errors.Is(err, dpop.ErrReplayUnavailable) {
				serverErr(w, "dpop_replay", err)
			} else {
				w.Header().Set("WWW-Authenticate", `DPoP error="invalid_dpop_proof", algs="ES256"`)
				fail(w, errmodel.CodeSenderProofRequired)
			}
			return
		}
		jwkBinding, tokenType = &thumbprint, "DPoP"
	} else {
		certificate, err = parseDelegateCertificate(req.DelegateCertificateDERB64URL, now)
		if err != nil {
			fail(w, errmodel.CodeInvalidDelegateCertificate, errmodel.WithParam("delegate_certificate_der_b64url"))
			return
		}
		if expiresAt.After(certificate.NotAfter) {
			fail(w, errmodel.CodeTTLExceedsDelegateCertificate, errmodel.WithParam("ttl_seconds"))
			return
		}
		certificateThumbprint = jwtkit.CertificateSHA256(certificate.Raw)
		certificateBinding = &certificateThumbprint
	}
	if !validRequestedGrant(req.RequestedGrant) {
		fail(w, errmodel.CodeInvalidRequestedGrant, errmodel.WithParam("requested_grant"))
		return
	}

	grant, err := authorize(r.Context(), iam.DelegationRequest{
		UserID:                          claims.UserID,
		Audiences:                       audiences,
		TTL:                             ttl,
		ConfirmationCertificateSHA256:   certificateThumbprint,
		ConfirmationJWKThumbprintSHA256: jwkBinding,
		DelegateCertificate:             certificate,
		RequestedGrant:                  req.RequestedGrant,
	})
	if err != nil {
		writeError(w, fallback(err, errmodel.CodeDelegationAuthorizerUnavailable))
		return
	}
	// The grant is host policy, but never more AuthKit authority than the
	// user holds (ak#394): the engine's mint checks it.
	token, err := s.svc.MintDelegatedAccessToken(r.Context(), actor, iam.DelegatedAccess{
		Audiences:                       audiences,
		Permissions:                     grant.Permissions,
		Documents:                       grant.Documents,
		Attributes:                      grant.Attributes,
		TTL:                             ttl,
		ConfirmationCertificateSHA256:   certificateBinding,
		ConfirmationJWKThumbprintSHA256: jwkBinding,
	})
	if err != nil {
		if e := errmodel.As(err); e != nil && (e.Status() < 500 || errors.Is(err, errmodel.E(errmodel.CodeDelegatedDocumentUnavailable))) {
			writeError(w, err)
		} else {
			serverErr(w, "delegated_mint_failed", err)
		}
		return
	}
	if len(token.Value) > MaxDelegatedTokenBytes {
		serverErr(w, "delegated_token_too_large", nil)
		return
	}

	writeJSON(w, http.StatusOK, DelegatedTokenResponse{Token: token.Value, ExpiresAt: token.ExpiresAt, TokenType: tokenType})
}

// parseDelegateCertificate accepts exactly one currently valid, non-CA X.509
// certificate with an explicit clientAuth extended key usage, as unpadded
// base64url DER of at most maxDelegateCertificateDER bytes.
func parseDelegateCertificate(encoded string, now time.Time) (*x509.Certificate, error) {
	if encoded == "" || len(encoded) > base64.RawURLEncoding.EncodedLen(MaxDelegateCertificateDER) {
		return nil, errors.New("invalid delegate certificate")
	}
	der, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(der) == 0 || len(der) > MaxDelegateCertificateDER {
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
	if len(raw) == 0 || len(raw) > MaxRequestedGrantBytes || !json.Valid(raw) {
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
func clampDelegatedTTL(cfg authflow.DelegatedSettings, requestedSeconds int) time.Duration {
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
