// Package verify verifies AuthKit tokens without a database: access tokens
// and delegated access tokens of the issuers a Verifier trusts, checked
// against their keys (a JWKS, static keys or a live key source). It also
// holds the claims, actor and context helpers and the net/http middleware,
// which authenticate through a *Verifier or an *authkit.Client (which adds
// API keys and remote applications from its database).
package verify

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/jwks"
	"github.com/open-rails/authkit/keys"
)

// Verifier verifies tokens from the issuers added with AddIssuer.
type Verifier struct {
	skew       time.Duration
	dpopReplay dpop.ReplayGuard
	publicURL  string
	keys       *jwks.Cache

	mu      sync.RWMutex
	issuers map[string]issuer
}

// issuer is one trusted issuer: its audiences and exactly one key source.
type issuer struct {
	audiences []string
	local     bool
	jwks      *jwks.Issuer
	static    map[string]crypto.PublicKey
	source    keys.Source
}

// VerifierOption configures a Verifier.
type VerifierOption func(*verifierConfig)

type verifierConfig struct {
	skew       time.Duration
	client     *http.Client
	dpopReplay dpop.ReplayGuard
	publicURL  string
}

// WithSkew sets the clock skew allowed on exp, nbf and iat (default 60s).
func WithSkew(d time.Duration) VerifierOption {
	return func(c *verifierConfig) { c.skew = d }
}

// WithHTTPClient sets the client JWKS are fetched with (default: a
// timeout-bounded client).
func WithHTTPClient(client *http.Client) VerifierOption {
	return func(c *verifierConfig) { c.client = client }
}

// WithDPoP accepts RFC 9449 DPoP-bound delegated tokens, with WithPublicURL.
// replay is the proof replay store: it atomically claims key until ttl and
// returns true only for the first claim; every replica must share it, and
// its errors fail closed. Client.NewVerifier wires AuthKit's own.
func WithDPoP(replay func(ctx context.Context, key string, ttl time.Duration) (bool, error)) VerifierOption {
	return func(c *verifierConfig) { c.dpopReplay = replay }
}

// WithPublicURL is where clients reach the paths this verifier sees:
// "https://api.example.com", or "https://example.com/api" when a proxy in
// front strips /api. A DPoP proof must name it plus the request's path, the
// rule HTTPConfig.PublicURL sets for AuthKit's own routes. No Host or
// Forwarded header is consulted.
func WithPublicURL(url string) VerifierOption {
	return func(c *verifierConfig) { c.publicURL = strings.TrimRight(strings.TrimSpace(url), "/") }
}

// NewVerifier returns a Verifier that trusts no issuer until AddIssuer.
func NewVerifier(opts ...VerifierOption) *Verifier {
	cfg := verifierConfig{skew: 60 * time.Second}
	for _, o := range opts {
		o(&cfg)
	}
	return &Verifier{
		skew:       cfg.skew,
		dpopReplay: cfg.dpopReplay,
		publicURL:  cfg.publicURL,
		keys:       jwks.New(cfg.client),
		issuers:    map[string]issuer{},
	}
}

// IssuerOptions is where an issuer's keys come from: exactly one of JWKSURI,
// Keys and KeySource.
type IssuerOptions struct {
	// JWKSURI is fetched on first use and refreshed in the background when
	// its keys expire or an unknown kid arrives. Expired keys keep verifying
	// while refreshes fail, up to MaxStale.
	JWKSURI string
	// Keys are static PEM public keys, each with its kid. Replace them by
	// calling AddIssuer again.
	Keys []iam.RemoteApplicationKey
	// KeySource is read live on every verification: a co-located, rotating
	// key source such as AuthKit's own.
	KeySource keys.Source

	// CacheTTL is how long fetched JWKS keys are fresh (default 10m).
	CacheTTL time.Duration
	// MaxStale bounds how long after the last successful fetch JWKS keys
	// keep verifying while refreshes fail, so a peer's key revocation cannot
	// be suppressed by blocking the fetch. Past it the issuer's tokens fail
	// with 503 issuer_keys_unavailable. Default 4h; never below CacheTTL.
	MaxStale time.Duration

	// IsLocal marks the issuer whose users are this host's own: only its
	// access tokens set Claims.UserID (others set Subject).
	IsLocal bool
}

// AddIssuer trusts issuerID's tokens for any of audiences, replacing an
// earlier registration of it. A failure leaves the earlier one in place.
func (v *Verifier) AddIssuer(issuerID string, audiences []string, opts IssuerOptions) error {
	issuerID = strings.TrimSpace(issuerID)
	if issuerID == "" {
		return errors.New("empty issuer ID")
	}
	var accepted []string
	for _, aud := range audiences {
		if aud = strings.TrimSpace(aud); aud != "" {
			accepted = append(accepted, aud)
		}
	}
	if len(accepted) == 0 {
		// An issuer without audiences would accept its tokens for any.
		return fmt.Errorf("issuer %q needs at least one accepted audience", issuerID)
	}
	is := issuer{audiences: accepted, local: opts.IsLocal}
	sources := 0
	if url := strings.TrimSpace(opts.JWKSURI); url != "" {
		sources++
		is.jwks = &jwks.Issuer{Issuer: issuerID, URL: url, TTL: opts.CacheTTL, MaxStale: opts.MaxStale}
	}
	if len(opts.Keys) > 0 {
		sources++
		static, err := staticKeys(opts.Keys)
		if err != nil {
			return err
		}
		is.static = static
	}
	if opts.KeySource != nil {
		sources++
		is.source = opts.KeySource
	}
	if sources != 1 {
		return fmt.Errorf("issuer %q needs exactly one of JWKSURI, Keys and KeySource", issuerID)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.issuers[issuerID]; ok && existing.local && !is.local {
		// A non-local registration must never swap the local signing keys.
		return errors.New("refusing to overwrite local issuer with non-local registration")
	}
	v.issuers[issuerID] = is
	if is.jwks == nil {
		v.keys.Drop(issuerID)
	}
	return nil
}

// RemoveIssuer stops trusting issuerID's tokens and drops its cached keys.
func (v *Verifier) RemoveIssuer(issuerID string) {
	issuerID = strings.TrimSpace(issuerID)
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.issuers, issuerID)
	v.keys.Drop(issuerID)
}

// staticKeys parses and validates a complete static key set.
func staticKeys(set []iam.RemoteApplicationKey) (map[string]crypto.PublicKey, error) {
	out := make(map[string]crypto.PublicKey, len(set))
	for _, k := range set {
		if k.KID == "" || k.KID != strings.TrimSpace(k.KID) {
			return nil, errors.New("key ID required without surrounding whitespace")
		}
		if _, dup := out[k.KID]; dup {
			return nil, fmt.Errorf("duplicate key ID %q", k.KID)
		}
		pub, err := keys.ParsePublicPEM([]byte(k.PublicKeyPEM))
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k.KID, err)
		}
		out[k.KID] = pub
	}
	return out, nil
}

func (v *Verifier) issuer(iss string) (issuer, bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	is, ok := v.issuers[strings.TrimSpace(iss)]
	return is, ok
}

func (v *Verifier) key(ctx context.Context, is issuer, kid string) (crypto.PublicKey, error) {
	switch {
	case is.source != nil:
		return jwks.Select(is.source.PublicKeys(), kid)
	case is.jwks != nil:
		return v.keys.Key(ctx, *is.jwks, kid)
	}
	return jwks.Select(is.static, kid)
}

// VerifyClaims verifies a token's signature, issuer, audience and times and
// returns its raw claims, for host-defined token profiles: it enforces no
// AuthKit token type, subject, permission or sender binding. Use Verify or
// VerifyRequest for AuthKit tokens.
func (v *Verifier) VerifyClaims(ctx context.Context, token string) (map[string]any, error) {
	_, claims, _, err := v.parse(ctx, token)
	return claims, err
}

// parse verifies token's signature under its issuer's keys, then its audience
// and times, and returns its typ, claims and issuer.
func (v *Verifier) parse(ctx context.Context, token string) (string, map[string]any, issuer, error) {
	token = strings.TrimSpace(token)
	if token == "" {
		return "", nil, issuer{}, errmodel.E(errmodel.CodeUnauthenticated)
	}
	var match issuer
	var found bool
	keyFor := func(_, kid string, claims map[string]any) (crypto.PublicKey, error) {
		if match, found = v.issuer(jose.String(claims, "iss")); !found {
			return nil, errmodel.E(errmodel.CodeBadIssuer)
		}
		return v.key(ctx, match, kid)
	}
	typ, claims, err := jose.Verify(token, keyFor)
	// A signature failing under cached JWKS keys may be a rotated key that
	// kept its kid: refetch once (throttled) and retry.
	if errors.Is(err, jose.ErrSignature) && found && match.jwks != nil && v.keys.Refresh(ctx, *match.jwks) {
		typ, claims, err = jose.Verify(token, keyFor)
	}
	if errmodel.CodeOf(err) == errmodel.CodeIssuerKeysUnavailable {
		// An expired or foreign-audience token is refused as such, not 503.
		if cerr := v.checkClaims(claims, match); found && cerr != nil {
			return "", nil, issuer{}, cerr
		}
		return "", nil, issuer{}, errmodel.As(err)
	}
	if err != nil {
		return "", nil, issuer{}, errmodel.E(errmodel.CodeInvalidToken)
	}
	if err := v.checkClaims(claims, match); err != nil {
		return "", nil, issuer{}, err
	}
	return typ, claims, match, nil
}

// checkClaims enforces the audience and exp/nbf/iat with skew.
func (v *Verifier) checkClaims(claims map[string]any, is issuer) error {
	aud := jose.Audiences(claims)
	ok := false
	for _, want := range is.audiences {
		for _, have := range aud {
			ok = ok || have == want
		}
	}
	if !ok {
		return errmodel.E(errmodel.CodeBadAudience)
	}
	now := time.Now()
	exp, ok := jose.Time(claims, "exp")
	if !ok {
		return errmodel.E(errmodel.CodeMissingExp)
	}
	if exp.Before(now.Add(-v.skew)) {
		return errmodel.E(errmodel.CodeTokenExpired)
	}
	for _, key := range []string{"nbf", "iat"} {
		if t, ok := jose.Time(claims, key); ok && t.After(now.Add(v.skew)) {
			return errmodel.E(errmodel.CodeTokenNotYetValid)
		}
	}
	return nil
}

// IssuerKeyStatus is one JWKS issuer's key-refresh state: key count,
// freshness, the age of the last successful fetch against MaxStale, and the
// last error.
type IssuerKeyStatus = jwks.Status

// IssuerKeyStatuses reports every JWKS issuer's key state, sorted by issuer.
func (v *Verifier) IssuerKeyStatuses() []IssuerKeyStatus { return v.keys.Statuses() }

// CheckIssuerKeys is a no-I/O health probe: it fails naming every JWKS
// issuer whose last key fetch failed, with the age of its keys and whether
// they are past MaxStale (its tokens then fail closed). Other issuers are
// unaffected.
func (v *Verifier) CheckIssuerKeys(context.Context) error { return v.keys.Check() }
