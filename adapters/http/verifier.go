package authhttp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	core "github.com/open-rails/authkit/core"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// Verifier validates JWTs from one or more issuers.
//
// For verify-only mode, create with NewVerifier and add issuers via AddIssuer.
// For issuing mode, authhttp.Service creates a Verifier internally.
type Verifier struct {
	skew       time.Duration
	algorithms []string
	orgMode    string

	httpClient *http.Client

	mu      sync.Mutex
	issuers []issuerEntry
	byIss   map[string]*issuerKeys

	enrich *core.Service
}

// issuerEntry describes a trusted issuer (private — replaces core.IssuerAccept).
type issuerEntry struct {
	issuer    string
	audiences []string
	jwksURL   string
	cacheTTL  time.Duration
	maxStale  time.Duration
}

type issuerKeys struct {
	jwks       jwtkit.JWKS
	pubByKID   map[string]*rsa.PublicKey
	fetchedAt  time.Time
	expiresAt  time.Time
	staleUntil time.Time
}

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithSkew sets the clock skew tolerance for exp/nbf/iat checks.
// Default: 60s.
func WithSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.skew = d }
}

// WithAlgorithms sets the allowed JWS algorithms. Default: ["RS256"].
func WithAlgorithms(algs ...string) VerifierOption {
	return func(v *Verifier) { v.algorithms = algs }
}

// WithHTTPClient sets the HTTP client used for JWKS fetching.
func WithHTTPClient(c *http.Client) VerifierOption {
	return func(v *Verifier) {
		if c != nil {
			v.httpClient = c
		}
	}
}

// WithOrgMode sets the organization mode ("single" or "multi") for claim
// extraction. When "multi" and an org claim is present, roles are treated
// as org-scoped roles.
func WithOrgMode(mode string) VerifierOption {
	return func(v *Verifier) { v.orgMode = mode }
}

// NewVerifier creates a new Verifier. Add trusted issuers via AddIssuer.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		skew:       60 * time.Second,
		algorithms: []string{"RS256"},
		httpClient: http.DefaultClient,
		byIss:      map[string]*issuerKeys{},
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// ---------------------------------------------------------------------------
// Issuer management
// ---------------------------------------------------------------------------

// IssuerKey is a public key for an issuer, identified by key ID.
type IssuerKey struct {
	KID          string
	PublicKeyPEM string
}

// IssuerOptions configures how keys are obtained for an issuer.
// Provide one of JWKSURL, Keys, or RawKeys.
type IssuerOptions struct {
	// JWKSURL is the URL to fetch JWKS from. If set, keys are fetched
	// automatically and refreshed when they expire or an unknown kid appears.
	JWKSURL string

	// Keys are pre-provided public keys as PEM. The caller is responsible for
	// refreshing by calling AddIssuer again with updated keys.
	Keys []IssuerKey

	// RawKeys are pre-provided public keys. Useful when the caller already
	// has parsed *rsa.PublicKey values (e.g., from a co-located core.Service).
	RawKeys map[string]*rsa.PublicKey

	// CacheTTL controls how long fetched JWKS keys are considered fresh.
	// Default: 5 minutes.
	CacheTTL time.Duration

	// MaxStale controls how long stale keys may be used as fallback after
	// a failed JWKS refresh. Default: 1 hour.
	MaxStale time.Duration
}

// AddIssuer registers (or updates) a trusted issuer. This is the single
// method for adding any issuer — whether at startup or at runtime, whether
// keys come from a JWKS URL or are pre-provided.
func (v *Verifier) AddIssuer(issuerID string, audiences []string, opts IssuerOptions) error {
	issuerID = strings.TrimSpace(issuerID)
	if issuerID == "" {
		return errors.New("empty issuer ID")
	}

	ie := issuerEntry{
		issuer:    issuerID,
		audiences: audiences,
		jwksURL:   strings.TrimSpace(opts.JWKSURL),
		cacheTTL:  opts.CacheTTL,
		maxStale:  opts.MaxStale,
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Upsert in the issuers list.
	found := false
	for i := range v.issuers {
		if v.issuers[i].issuer == issuerID {
			v.issuers[i] = ie
			found = true
			break
		}
	}
	if !found {
		v.issuers = append(v.issuers, ie)
	}

	// Seed the key cache from pre-provided keys.
	pubByKID := v.collectKeys(opts)
	if len(pubByKID) > 0 {
		now := time.Now()
		farFuture := 24 * time.Hour
		v.byIss[issuerID] = &issuerKeys{
			pubByKID:   pubByKID,
			fetchedAt:  now,
			expiresAt:  now.Add(farFuture),
			staleUntil: now.Add(farFuture * 2),
		}
	}

	return nil
}

// collectKeys merges PEM Keys and RawKeys into a single map.
func (v *Verifier) collectKeys(opts IssuerOptions) map[string]*rsa.PublicKey {
	out := map[string]*rsa.PublicKey{}
	for _, k := range opts.Keys {
		kid := strings.TrimSpace(k.KID)
		if kid == "" {
			continue
		}
		pub, err := parseRSAPublicKeyFromPEM(k.PublicKeyPEM)
		if err != nil {
			continue
		}
		out[kid] = pub
	}
	for kid, pub := range opts.RawKeys {
		kid = strings.TrimSpace(kid)
		if kid == "" || pub == nil {
			continue
		}
		out[kid] = pub
	}
	return out
}

// RemoveIssuer removes a previously added issuer.
func (v *Verifier) RemoveIssuer(issuerID string) {
	issuerID = strings.TrimSpace(issuerID)
	if issuerID == "" {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()

	for i := range v.issuers {
		if v.issuers[i].issuer == issuerID {
			v.issuers = append(v.issuers[:i], v.issuers[i+1:]...)
			break
		}
	}
	delete(v.byIss, issuerID)
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

// WithService enables best-effort enrichment hooks (roles/provider usernames) from Postgres.
func (v *Verifier) WithService(svc *core.Service) *Verifier { v.enrich = svc; return v }

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// Verify parses + verifies a token and returns typed Claims.
// It enforces issuer/audience/expiry with the configured skew.
func (v *Verifier) Verify(tokenStr string) (Claims, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return Claims{}, errors.New("missing_token")
	}

	mapClaims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, err := parser.ParseWithClaims(tokenStr, mapClaims, func(token *jwt.Token) (any, error) {
		return v.keyForToken(token)
	})
	if err != nil || tok == nil || !tok.Valid {
		return Claims{}, errors.New("invalid_token")
	}

	iss, _ := mapClaims["iss"].(string)
	match := v.matchIssuer(iss)
	if match == nil {
		return Claims{}, errors.New("bad_issuer")
	}

	if len(match.audiences) > 0 && !audContainsAny(mapClaims["aud"], match.audiences) {
		return Claims{}, errors.New("bad_audience")
	}

	skew := v.skew
	now := time.Now()
	expUnix, ok := toUnix(mapClaims["exp"])
	if !ok {
		return Claims{}, errors.New("missing_exp")
	}
	if time.Unix(expUnix, 0).Before(now.Add(-skew)) {
		return Claims{}, errors.New("token_expired")
	}
	if nbfUnix, ok := toUnix(mapClaims["nbf"]); ok {
		if time.Unix(nbfUnix, 0).After(now.Add(skew)) {
			return Claims{}, errors.New("token_not_yet_valid")
		}
	}
	if iatUnix, ok := toUnix(mapClaims["iat"]); ok {
		if time.Unix(iatUnix, 0).After(now.Add(skew)) {
			return Claims{}, errors.New("token_not_yet_valid")
		}
	}

	return v.extractClaims(mapClaims), nil
}

// extractClaims converts jwt.MapClaims into typed Claims.
func (v *Verifier) extractClaims(mc jwt.MapClaims) Claims {
	cl := Claims{
		Issuer: strClaim(mc, "iss"),
	}
	cl.UserID = strClaim(mc, "sub")
	cl.Email = strClaim(mc, "email")
	cl.EmailVerified, _ = mc["email_verified"].(bool)
	cl.Username = strClaim(mc, "username")
	cl.DiscordUsername = strClaim(mc, "discord_username")
	cl.SessionID = strClaim(mc, "sid")
	cl.Org = strClaim(mc, "org")
	if cl.Org == "" {
		cl.Org = strClaim(mc, "owner")
	}
	cl.JTI = strClaim(mc, "jti")

	cl.UserTier = strClaim(mc, "user_tier")
	if cl.UserTier == "" {
		cl.UserTier = strClaim(mc, "plan")
	}

	cl.Roles = strSliceClaim(mc, "roles")
	cl.Entitlements = strSliceClaim(mc, "entitlements")

	// In org_mode=multi, if org is present, roles are org-scoped.
	if strings.EqualFold(strings.TrimSpace(v.orgMode), "multi") &&
		strings.TrimSpace(cl.Org) != "" && len(cl.Roles) > 0 {
		cl.OrgRoles = cl.Roles
		cl.Roles = nil
	}

	return cl
}

func strClaim(mc jwt.MapClaims, key string) string {
	v, _ := mc[key].(string)
	return v
}

func strSliceClaim(mc jwt.MapClaims, key string) []string {
	switch rs := mc[key].(type) {
	case []any:
		out := make([]string, 0, len(rs))
		for _, v := range rs {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return rs
	}
	return nil
}

// ---------------------------------------------------------------------------
// Internal key resolution
// ---------------------------------------------------------------------------

func (v *Verifier) keyForToken(token *jwt.Token) (any, error) {
	if token == nil {
		return nil, errors.New("nil_token")
	}

	alg, _ := token.Header["alg"].(string)
	if !v.algAllowed(alg) {
		return nil, fmt.Errorf("disallowed_alg")
	}

	claims, _ := token.Claims.(jwt.MapClaims)
	iss, _ := claims["iss"].(string)
	match := v.matchIssuer(iss)
	if match == nil {
		return nil, fmt.Errorf("bad_issuer")
	}

	kid, _ := token.Header["kid"].(string)
	return v.publicKeyFor(context.Background(), *match, kid)
}

func (v *Verifier) matchIssuer(issuer string) *issuerEntry {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	for i := range v.issuers {
		if v.issuers[i].issuer == issuer {
			ie := v.issuers[i] // copy
			return &ie
		}
	}
	return nil
}

func (v *Verifier) algAllowed(alg string) bool {
	for _, a := range v.algorithms {
		if strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(alg)) {
			return true
		}
	}
	return false
}

func (v *Verifier) publicKeyFor(ctx context.Context, ie issuerEntry, kid string) (*rsa.PublicKey, error) {
	iss := ie.issuer
	if iss == "" {
		return nil, errors.New("bad_issuer")
	}

	cacheTTL := ie.cacheTTL
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}
	maxStale := ie.maxStale
	if maxStale == 0 {
		maxStale = time.Hour
	}

	v.mu.Lock()
	c := v.byIss[iss]
	if c == nil {
		c = &issuerKeys{}
		v.byIss[iss] = c
	}
	now := time.Now()
	shouldFetch := c.pubByKID == nil || now.After(c.expiresAt)
	hasFresh := c.pubByKID != nil && now.Before(c.expiresAt)
	hasStale := c.pubByKID != nil && now.Before(c.staleUntil)
	v.mu.Unlock()

	if shouldFetch {
		if err := v.refreshIssuerKeys(ctx, iss, ie, cacheTTL, maxStale); err != nil && !hasStale && !hasFresh {
			return nil, err
		}
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if kid != "" {
		if pk := c.pubByKID[kid]; pk != nil {
			return pk, nil
		}
		return nil, errors.New("unknown_kid")
	}
	if len(c.pubByKID) == 1 {
		for _, pk := range c.pubByKID {
			return pk, nil
		}
	}
	return nil, errors.New("missing_kid")
}

func (v *Verifier) refreshIssuerKeys(ctx context.Context, issuer string, ie issuerEntry, cacheTTL, maxStale time.Duration) error {
	jwksURL := strings.TrimSpace(ie.jwksURL)
	if jwksURL == "" {
		jwksURL = strings.TrimRight(strings.TrimSpace(issuer), "/") + "/.well-known/jwks.json"
	}

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks_http_%d", resp.StatusCode)
	}

	// Limit response body to 1MB to prevent OOM from malicious JWKS endpoints.
	limited := io.LimitReader(resp.Body, 1<<20)
	var ks jwtkit.JWKS
	if err := json.NewDecoder(limited).Decode(&ks); err != nil {
		return err
	}
	pubByKID, err := jwksToRSAPublicKeys(ks)
	if err != nil {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	c := v.byIss[issuer]
	if c == nil {
		c = &issuerKeys{}
		v.byIss[issuer] = c
	}
	now := time.Now()
	c.jwks = ks
	c.pubByKID = pubByKID
	c.fetchedAt = now
	c.expiresAt = now.Add(cacheTTL)
	c.staleUntil = now.Add(cacheTTL + maxStale)
	return nil
}

// ---------------------------------------------------------------------------
// Audience helpers
// ---------------------------------------------------------------------------

func audContains(aud any, want string) bool {
	switch v := aud.(type) {
	case string:
		return v == want
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok && s == want {
				return true
			}
		}
	case []string:
		for _, e := range v {
			if e == want {
				return true
			}
		}
	}
	return false
}

func audContainsAny(aud any, want []string) bool {
	for _, w := range want {
		if audContains(aud, w) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Key parsing helpers
// ---------------------------------------------------------------------------

func jwksToRSAPublicKeys(ks jwtkit.JWKS) (map[string]*rsa.PublicKey, error) {
	out := map[string]*rsa.PublicKey{}
	for _, k := range ks.Keys {
		if !strings.EqualFold(k.Kty, "RSA") {
			continue
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, err
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, err
		}
		n := new(big.Int).SetBytes(nBytes)
		e := new(big.Int).SetBytes(eBytes)
		if !e.IsInt64() {
			return nil, errors.New("bad_rsa_exponent")
		}
		pk := &rsa.PublicKey{N: n, E: int(e.Int64())}
		kid := strings.TrimSpace(k.Kid)
		if kid == "" {
			kid = "default"
		}
		out[kid] = pk
	}
	if len(out) == 0 {
		return nil, errors.New("empty_jwks")
	}
	return out, nil
}

func parseRSAPublicKeyFromPEM(pemText string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("bad_pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if cert, err2 := x509.ParseCertificate(block.Bytes); err2 == nil {
			pub = cert.PublicKey
			err = nil
		}
		if err != nil {
			return nil, err
		}
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not_rsa")
	}
	return rsaPub, nil
}
