package core

import (
	"context"
	"errors"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	jwtkit "github.com/open-rails/authkit/jwt"
)

const (
	// MaxCustomJWTLifetime caps the TTL of a custom-claims JWT. Custom tokens are
	// short-lived first-party tokens (capability/worker tokens, etc.); they share
	// the same 1h ceiling regardless of the requested TTL. Mirrors the bounded-TTL
	// guardrails on MintServiceJWT / MintDelegatedAccessToken.
	MaxCustomJWTLifetime = time.Hour
	// maxCustomJWTClaims rejects absurdly large host claim sets. A capability /
	// worker token carries on the order of ten claims; this is a generous bound
	// that still stops a host from minting a multi-megabyte token by accident.
	maxCustomJWTClaims = 64
)

var (
	// ErrEmptyCustomClaims is returned when CustomJWTMintOptions.Claims is empty —
	// MintCustomJWT exists to carry host claims, so an empty set is a caller bug.
	ErrEmptyCustomClaims = errors.New("custom_jwt_empty_claims")
	// ErrTooManyCustomClaims is returned when the host claim set exceeds
	// maxCustomJWTClaims.
	ErrTooManyCustomClaims = errors.New("custom_jwt_too_many_claims")
	// ErrCustomClaimsReserved is returned when the host Claims map tries to set a
	// registered claim that AuthKit owns (`iss`/`iat`/`exp`) — those are set by
	// AuthKit and the raw map may not silently clobber them. Use the explicit
	// Issuer option to override `iss`.
	ErrCustomClaimsReserved = errors.New("custom_jwt_reserved_claim")
)

// reservedCustomClaims are the registered claims AuthKit owns and the host
// Claims map is forbidden from setting. `iss` is settable only through the
// explicit Issuer option (defaults to the Service issuer); `iat`/`exp` are
// derived from TTL and are never host-supplied. The `kid`/`alg` JOSE headers are
// likewise owned by AuthKit (set by the signer, which rejects overrides).
var reservedCustomClaims = map[string]struct{}{
	"iss": {},
	"iat": {},
	"exp": {},
}

// CustomJWTMintOptions controls minting of a JWT with an arbitrary first-party
// claim set. This is AuthKit's documented escape hatch: the HOST owns the claim
// semantics, and the verifier side MUST understand them. Prefer the constrained,
// opinionated paths — MintServiceJWT (machine-to-machine service JWT) and
// MintDelegatedAccessToken (cross-service delegated access) — whenever they fit;
// reach for MintCustomJWT only for token shapes those can't express (e.g.
// tensorhub capability/worker tokens with `cap_kind`/`grants`/`release_id`).
//
// Claim precedence (documented + enforced):
//   - AuthKit ALWAYS sets the registered claims it owns: `iss`, `iat`, `exp`
//     (and the `kid`/`alg` JOSE headers, via the signer). The host Claims map
//     may NOT set `iss`/`iat`/`exp` — doing so returns ErrCustomClaimsReserved
//     rather than silently dropping or clobbering them.
//   - `iss` is overridable ONLY via the explicit Issuer option (defaults to the
//     Service's configured Issuer). `sub`/`aud` are set from the explicit
//     Subject/Audiences options when provided; otherwise the host Claims map may
//     carry its own `sub`/`aud` (the host owns those for custom tokens). When an
//     explicit Subject/Audiences IS provided, it wins over any `sub`/`aud` in the
//     Claims map.
type CustomJWTMintOptions struct {
	// Claims is the host's claim set, e.g. {"cap_kind": "...", "grants": [...],
	// "release_id": "..."}. Required and non-empty. It may carry `sub`/`aud`
	// (unless overridden by the Subject/Audiences options) but may NOT carry the
	// AuthKit-owned registered claims `iss`/`iat`/`exp`.
	Claims map[string]any
	// TTL is the token lifetime. Required (must be > 0); capped at
	// MaxCustomJWTLifetime.
	TTL time.Duration
	// Type is the JOSE `typ` header (e.g. "worker-capability+jwt"). When empty the
	// header is left unset — unlike the opinionated minters, MintCustomJWT does
	// not impose a default `typ`; the host owns the token shape.
	Type string
	// Subject, when set, becomes the `sub` claim and wins over any `sub` in Claims.
	Subject string
	// Audiences, when set, becomes the `aud` claim and wins over any `aud` in Claims.
	Audiences []string
	// Issuer, when set, becomes the `iss` claim; otherwise `iss` defaults to the
	// Service's configured Issuer. This is the ONLY way to override `iss`.
	Issuer string
}

// MintCustomJWT signs a JWT carrying an arbitrary first-party claim set using the
// Service's internal signer — the SAME signing path as MintServiceJWT /
// MintDelegatedAccessToken. The host passes a claim map (+ a few controlled
// headers) and NEVER touches the private key, the PEM, or a raw signer; the
// #70 hard boundary holds.
//
// AuthKit sets the `kid`/`alg` JOSE headers (via the signer) and the registered
// `iss`/`iat`/`exp` claims; everything else comes from the host. See
// CustomJWTMintOptions for the claim-precedence rules. The host Claims map may
// not set `iss`/`iat`/`exp` (ErrCustomClaimsReserved).
// Deprecated: use s.Tokens().MintCustomJWT.
func (s *Service) MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error) {
	signer := s.keys.Active
	if signer == nil {
		return "", ErrMissingSigner
	}

	if len(opts.Claims) == 0 {
		return "", ErrEmptyCustomClaims
	}
	if len(opts.Claims) > maxCustomJWTClaims {
		return "", ErrTooManyCustomClaims
	}
	if opts.TTL <= 0 {
		return "", errors.New("custom_jwt_ttl_required")
	}

	// Copy the host claims so we never mutate the caller's map, and reject any
	// attempt to set the AuthKit-owned registered claims `iss`/`iat`/`exp`.
	claims := make(jwt.MapClaims, len(opts.Claims)+4)
	for k, v := range opts.Claims {
		if _, reserved := reservedCustomClaims[k]; reserved {
			return "", ErrCustomClaimsReserved
		}
		claims[k] = v
	}

	ttl := opts.TTL
	if ttl > MaxCustomJWTLifetime {
		ttl = MaxCustomJWTLifetime
	}

	issuer := strings.TrimSpace(opts.Issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(s.opts.Issuer)
	}

	now := time.Now()
	// AuthKit-owned registered claims always win over the (already-rejected) map.
	claims["iss"] = issuer
	claims["iat"] = now.Unix()
	claims["exp"] = now.Add(ttl).Unix()

	// Explicit Subject/Audiences options win over any `sub`/`aud` in Claims.
	if sub := strings.TrimSpace(opts.Subject); sub != "" {
		claims["sub"] = sub
	}
	if len(opts.Audiences) > 0 {
		claims["aud"] = dedupeStrings(opts.Audiences)
	}

	// Set the `typ` header only when the host asked for one; otherwise leave it
	// unset (the host owns the token shape). The signer owns `kid`/`alg` and
	// rejects attempts to override them.
	if typ := strings.TrimSpace(opts.Type); typ != "" {
		hs, ok := signer.(jwtkit.HeaderSigner)
		if !ok {
			return "", errors.New("header signer required")
		}
		return hs.SignWithHeaders(ctx, claims, map[string]any{"typ": typ})
	}
	return signer.Sign(ctx, claims)
}
