package authcore

import (
	"context"
	"errors"
	authkit "github.com/open-rails/authkit"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/jwtkit"
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
	ErrEmptyCustomClaims = authkit.ErrEmptyCustomClaims
	// ErrTooManyCustomClaims is returned when the host claim set exceeds
	// maxCustomJWTClaims.
	ErrTooManyCustomClaims = authkit.ErrTooManyCustomClaims
	// ErrCustomClaimsReserved is returned when the host Claims map tries to set a
	// registered claim that AuthKit owns (`iss`/`iat`/`exp`) — those are set by
	// AuthKit and the raw map may not silently clobber them. Use the explicit
	// Issuer option to override `iss`.
	ErrCustomClaimsReserved = authkit.ErrCustomClaimsReserved
	// ErrCustomJWTReservedType is returned when CustomJWTMintOptions.Type is one of
	// AuthKit's own first-party token classes (access / delegated-access /
	// remote-application-access / service `+jwt`). MintCustomJWT mints CUSTOM token
	// shapes only; minting an AuthKit class would produce a token the verifier
	// trusts as a first-party principal (AK2-AUTH-02).
	ErrCustomJWTReservedType = authkit.ErrCustomJWTReservedType
)

// reservedCustomJWTTypes are AuthKit's own first-party JOSE `typ` values. The
// verifier classifies a token into a trusted principal class by `typ`
// (verify.Verify, case-insensitively), so MintCustomJWT — the escape hatch for
// CUSTOM token shapes — must refuse to stamp any of them; otherwise a host could
// mint a token indistinguishable from a real access / delegated-access /
// remote-application / service token (AK2-AUTH-02).
var reservedCustomJWTTypes = []string{
	jwtkit.AccessTokenType,
	jwtkit.DelegatedAccessTokenType,
	jwtkit.RemoteApplicationAccessTokenType,
	ServiceJWTType,
}

// isReservedCustomJWTType reports whether typ matches an AuthKit first-party token
// class, compared case-insensitively to mirror the verifier's EqualFold check.
func isReservedCustomJWTType(typ string) bool {
	typ = strings.TrimSpace(typ)
	if typ == "" {
		return false
	}
	for _, r := range reservedCustomJWTTypes {
		if strings.EqualFold(typ, r) {
			return true
		}
	}
	return false
}

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
type CustomJWTMintOptions = authkit.CustomJWTMintOptions

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
func (s *Service) MintCustomJWT(ctx context.Context, opts CustomJWTMintOptions) (string, error) {
	signer := s.keys.ActiveSigner()
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
	// AK2-AUTH-02: refuse to stamp one of AuthKit's own first-party `typ` values.
	// The verifier classifies a token's principal class by `typ`, so a custom JWT
	// stamped access+jwt (etc.) with a host-chosen sub/roles would be trusted as a
	// real first-party token. MintCustomJWT is for CUSTOM shapes only.
	if isReservedCustomJWTType(opts.Type) {
		return "", ErrCustomJWTReservedType
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
		issuer = strings.TrimSpace(s.cfg.Token.Issuer)
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
	return jwtkit.SignWithType(ctx, signer, claims, strings.TrimSpace(opts.Type), true)
}
