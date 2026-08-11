package authhttp

// ak#261: the delegated-token mint route. All mechanics are AuthKit-owned and
// config-declared (Config.Delegated): audience-subset clamp, TTL clamp into
// the validated floor/default/ceiling, document-digest stamping from the wired
// DocumentProviders, and post-mint signing-KID reconciliation. The host
// contributes ONLY the injected attribute provider (WithDelegatedAttributes)
// — AuthKit never learns what the attributes mean.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/verify"
)

type delegatedTokenRequest struct {
	// TTLSeconds is an optional override, clamped into the configured
	// floor/ceiling; absent or <= 0 mints the configured default.
	TTLSeconds int `json:"ttl_seconds,omitempty"`
	// Audiences is an optional narrowing; every requested audience must be in
	// the configured allowlist. Absent mints the full configured list.
	Audiences []string `json:"audiences,omitempty"`
}

type delegatedTokenResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	// Attributes echoes what the host's attribute provider stamped, so clients
	// need not decode the token to see their own attributes.
	Attributes map[string]any `json:"attributes,omitempty"`
	// Documents echoes the stamped document references (type -> digest).
	Documents map[string]string `json:"documents,omitempty"`
}

func (s *Service) handleDelegatedTokenPOST(w http.ResponseWriter, r *http.Request) {
	if s.rateLimited(w, r, RLDelegatedTokenMint) {
		return
	}
	claims, ok := verify.ClaimsFromContext(r.Context())
	if !ok || claims.UserID == "" {
		unauthorized(w, ErrUnauthorized)
		return
	}

	var req delegatedTokenRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
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

	var attributes map[string]any
	references := map[string]string{}
	if provider := s.svc.DelegatedAttributesProvider(); provider != nil {
		hostAttributes, hostDocuments, err := provider(r.Context(), claims.UserID)
		if err != nil {
			sendErr(w, http.StatusServiceUnavailable, ErrDelegatedAttributesUnavailable)
			return
		}
		attributes = hostAttributes
		for documentType, digest := range hostDocuments {
			references[documentType] = digest
		}
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

	expiresAt := time.Now().UTC().Add(ttl)
	token, err := s.svc.MintDelegatedAccessToken(r.Context(), authkit.DelegatedAccessParams{
		Audiences:        audiences,
		DelegatedSubject: claims.UserID,
		Documents:        references,
		Attributes:       attributes,
		TTL:              ttl,
	})
	if err != nil {
		serverErr(w, ErrDelegatedMintFailed)
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

	if len(references) == 0 {
		references = nil
	}
	writeJSON(w, http.StatusOK, delegatedTokenResponse{
		Token:      token,
		ExpiresAt:  expiresAt,
		Attributes: attributes,
		Documents:  references,
	})
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
