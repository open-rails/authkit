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

	// Federated-issuer lazy-load coherence state. fedSource is the store the
	// lazy-load-on-miss path consults; it defaults to enrich (*core.Service) but
	// can be overridden (tests). fedAudiences is threaded so a lazily-loaded
	// issuer is registered with the SAME audiences the bulk LoadFederatedIssuers
	// used. fedKnown records which issuers were sourced from the federated store
	// so reconciling reload only evicts those (never statically-configured ones).
	fedSource    FederatedIssuerSource
	fedAudiences []string
	fedKnown     map[string]bool

	// negCache remembers issuers the federated source did not return as active,
	// for negCacheTTL, so garbage/unknown `iss` values don't hit the DB per
	// request. fedFlight single-flights concurrent first-use of the same issuer.
	negCache    map[string]time.Time
	negCacheTTL time.Duration
	fedFlight   map[string]*sync.WaitGroup

	// kidRefetch tracks the last forced JWKS refetch per issuer (driven by an
	// unknown-kid for a KNOWN issuer) so a storm of bad kids can't hammer the
	// JWKS endpoint. Guarded by a min-interval and single-flight.
	kidRefetchAt     map[string]time.Time
	kidRefetchFlight map[string]*sync.WaitGroup
	kidRefetchMin    time.Duration
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
		skew:             60 * time.Second,
		algorithms:       []string{"RS256"},
		httpClient:       http.DefaultClient,
		byIss:            map[string]*issuerKeys{},
		fedKnown:         map[string]bool{},
		negCache:         map[string]time.Time{},
		negCacheTTL:      5 * time.Second,
		fedFlight:        map[string]*sync.WaitGroup{},
		kidRefetchAt:     map[string]time.Time{},
		kidRefetchFlight: map[string]*sync.WaitGroup{},
		kidRefetchMin:    30 * time.Second,
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

// WithService enables best-effort enrichment hooks (roles/provider usernames)
// from Postgres, and wires the same *core.Service as the default
// federated-issuer source for lazy-load-on-miss (see keyForToken).
func (v *Verifier) WithService(svc *core.Service) *Verifier {
	v.enrich = svc
	v.mu.Lock()
	if v.fedSource == nil && svc != nil {
		v.fedSource = svc
	}
	v.mu.Unlock()
	return v
}

// ---------------------------------------------------------------------------
// Federated-org issuers (in-house store, no external push/sync)
// ---------------------------------------------------------------------------

// FederatedIssuerSource is the minimal store contract the Verifier needs to
// load federated-org issuers. *core.Service satisfies it. An embedding app may
// supply its own implementation in tests or to source issuers from elsewhere.
type FederatedIssuerSource interface {
	ListFederatedOrgIssuers(ctx context.Context, activeOnly bool) ([]core.FederatedOrgIssuer, error)
	// GetFederatedOrgIssuer fetches a SINGLE federated-org issuer by its
	// issuer_id, used by the lazy-load-on-miss path in keyForToken. *core.Service
	// already implements this.
	GetFederatedOrgIssuer(ctx context.Context, issuerID string) (*core.FederatedOrgIssuer, error)
}

// LoadFederatedIssuers loads the ACTIVE federated-org issuers from authkit's
// OWN store (the federated_org_issuers table) and registers each as a trusted
// issuer via AddIssuer with its JWKS URL. The Verifier's existing in-house
// JWKS fetch/refresh then handles the federated keys — there is NO external
// push or sync of keys.
//
// audiences, when non-empty, is applied to every loaded issuer (typically this
// resource server's own audience). Call this at startup, and re-call (e.g. on
// a ticker, or after an inbound registration) to pick up store changes. Pass
// the embedding app's core.Service (or any FederatedIssuerSource); if nil, the
// Service provided via WithService is used.
func (v *Verifier) LoadFederatedIssuers(ctx context.Context, src FederatedIssuerSource, audiences []string) error {
	if src == nil {
		if v.enrich == nil {
			return errors.New("no federated-issuer source available")
		}
		src = v.enrich
	}

	// Remember the source + audiences so lazy-load-on-miss (keyForToken) behaves
	// IDENTICALLY to this bulk load.
	v.mu.Lock()
	v.fedSource = src
	v.fedAudiences = audiences
	v.mu.Unlock()

	issuers, err := src.ListFederatedOrgIssuers(ctx, true)
	if err != nil {
		return err
	}

	// Build the active set, then AddIssuer each (AddIssuer locks v.mu internally,
	// so it must be called WITHOUT holding v.mu).
	active := make(map[string]bool, len(issuers))
	for _, fi := range issuers {
		issuerID := strings.TrimSpace(fi.IssuerID)
		if issuerID == "" {
			continue
		}
		active[issuerID] = true
		if err := v.AddIssuer(issuerID, audiences, IssuerOptions{JWKSURL: fi.JWKSURL}); err != nil {
			return err
		}
		v.mu.Lock()
		v.fedKnown[issuerID] = true
		delete(v.negCache, issuerID) // it is active now; clear any negative entry
		v.mu.Unlock()
	}

	// RECONCILE: evict in-memory FEDERATED issuers that are no longer in the
	// active set. Only federated issuers (tracked in fedKnown) are eligible —
	// statically-configured issuers added via AddIssuer are never evicted here.
	// This bounds revocation lag to the reload tick. (A Postgres LISTEN/NOTIFY
	// stream of issuer-row changes could give sub-tick eviction; not built here —
	// reconciling reload + on-unknown-kid refetch give bounded correctness.)
	v.mu.Lock()
	var toEvict []string
	for issuerID := range v.fedKnown {
		if !active[issuerID] {
			toEvict = append(toEvict, issuerID)
		}
	}
	for _, issuerID := range toEvict {
		delete(v.fedKnown, issuerID)
	}
	v.mu.Unlock()

	// RemoveIssuer locks v.mu internally; call outside the critical section.
	for _, issuerID := range toEvict {
		v.RemoveIssuer(issuerID)
	}
	return nil
}

// lazyLoadIssuer is the lazy-load-on-miss path: when matchIssuer misses and a
// federated-issuer source is configured, fetch that ONE issuer from the store
// and, if ACTIVE, register it (AddIssuer fetches+caches its JWKS). All DB/JWKS
// work happens WITHOUT holding v.mu (AddIssuer locks v.mu internally, so calling
// it under the lock would deadlock). A short negative cache + single-flight stop
// garbage `iss` values and concurrent first-use from hammering the DB/JWKS.
//
// Returns true if the issuer is now registered (caller should retry matchIssuer).
func (v *Verifier) lazyLoadIssuer(ctx context.Context, issuer string) bool {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return false
	}

	v.mu.Lock()
	src := v.fedSource
	if src == nil {
		v.mu.Unlock()
		return false
	}
	// Negative cache: skip recently-failed lookups.
	if t, ok := v.negCache[issuer]; ok && time.Since(t) < v.negCacheTTL {
		v.mu.Unlock()
		return false
	}
	// Single-flight: if another goroutine is already loading this issuer, wait
	// for it, then let the caller re-check the in-memory cache.
	if wg, inflight := v.fedFlight[issuer]; inflight {
		v.mu.Unlock()
		wg.Wait()
		return true // caller retries matchIssuer; may still miss (load failed)
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	v.fedFlight[issuer] = wg
	aud := v.fedAudiences
	v.mu.Unlock()

	defer func() {
		v.mu.Lock()
		delete(v.fedFlight, issuer)
		v.mu.Unlock()
		wg.Done()
	}()

	fi, err := src.GetFederatedOrgIssuer(ctx, issuer)
	if err != nil || fi == nil || !strings.EqualFold(strings.TrimSpace(fi.Status), "active") {
		v.mu.Lock()
		v.negCache[issuer] = time.Now()
		v.mu.Unlock()
		return false
	}

	if err := v.AddIssuer(fi.IssuerID, aud, IssuerOptions{JWKSURL: fi.JWKSURL}); err != nil {
		v.mu.Lock()
		v.negCache[issuer] = time.Now()
		v.mu.Unlock()
		return false
	}

	v.mu.Lock()
	v.fedKnown[strings.TrimSpace(fi.IssuerID)] = true
	delete(v.negCache, issuer)
	v.mu.Unlock()
	return true
}

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

	// Invariant: a token is EITHER a native-user token (`sub`) XOR a delegated
	// platform token (`delegated_sub`) — never both. Reject the ambiguous case.
	if strClaim(mapClaims, "sub") != "" && strClaim(mapClaims, "delegated_sub") != "" {
		return Claims{}, errors.New("conflicting_subject")
	}

	return v.extractClaims(mapClaims), nil
}

// extractClaims converts jwt.MapClaims into typed Claims.
func (v *Verifier) extractClaims(mc jwt.MapClaims) Claims {
	cl := Claims{
		Issuer: strClaim(mc, "iss"),
	}
	cl.UserID = strClaim(mc, "sub")
	cl.DelegatedSubject = strClaim(mc, "delegated_sub")
	cl.Tenant = strClaim(mc, "tenant")
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

	// Split global/org role claims (additive). `global_roles` carries the user's
	// platform-wide roles in both single and multi-org mode; `org_roles` carries
	// roles scoped to the org on an org-scoped token.
	cl.GlobalRoles = strSliceClaim(mc, "global_roles")
	if oroles := strSliceClaim(mc, "org_roles"); len(oroles) > 0 {
		cl.OrgRoles = oroles
	}

	// A delegated token's tenant comes from `tenant`, falling back to `org`.
	if strings.TrimSpace(cl.Tenant) == "" {
		cl.Tenant = cl.Org
	}

	// Back-compat: in org_mode=multi, if org is present, the legacy `roles` claim
	// is org-scoped. Delegated tokens keep their roles on Roles (the federated
	// principal carries its own roles), so only shuffle for native-user tokens.
	// Only fall back to deriving OrgRoles from Roles when the explicit `org_roles`
	// claim is absent (older tokens).
	if !cl.IsDelegated() &&
		strings.EqualFold(strings.TrimSpace(v.orgMode), "multi") &&
		strings.TrimSpace(cl.Org) != "" && len(cl.Roles) > 0 {
		if len(cl.OrgRoles) == 0 {
			cl.OrgRoles = cl.Roles
		}
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
		// Lazy-load-on-miss: a brand-new federated issuer may already be in the
		// store but not yet in this replica's in-memory cache. Fetch+register it
		// (outside v.mu — AddIssuer locks v.mu) and retry. Backward compatible:
		// when no federated source is configured this is a no-op (-> bad_issuer).
		if v.lazyLoadIssuer(context.Background(), iss) {
			match = v.matchIssuer(iss)
		}
		if match == nil {
			return nil, fmt.Errorf("bad_issuer")
		}
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
	if kid != "" {
		if pk := c.pubByKID[kid]; pk != nil {
			v.mu.Unlock()
			return pk, nil
		}
		// Unknown kid for a KNOWN issuer: a key may have rotated mid-TTL (the
		// cached JWKS is still "fresh" so the TTL refresh above did not fire).
		// Force ONE bounded JWKS refetch (min-interval + single-flight guarded so
		// a storm of bad kids can't hammer the JWKS endpoint) and retry.
		v.mu.Unlock()
		if v.refetchForUnknownKID(ctx, iss, ie, cacheTTL, maxStale) {
			v.mu.Lock()
			if pk := c.pubByKID[kid]; pk != nil {
				v.mu.Unlock()
				return pk, nil
			}
			v.mu.Unlock()
		}
		return nil, errors.New("unknown_kid")
	}
	defer v.mu.Unlock()
	if len(c.pubByKID) == 1 {
		for _, pk := range c.pubByKID {
			return pk, nil
		}
	}
	return nil, errors.New("missing_kid")
}

// refetchForUnknownKID forces a single bounded JWKS refetch for a known issuer
// when an unknown kid arrives mid-TTL (key rotation). A min-interval guard plus
// single-flight ensure a storm of bad kids cannot hammer the JWKS endpoint:
// concurrent callers coalesce onto one fetch, and a fetch is skipped if one ran
// within kidRefetchMin. Returns true if a refetch ran (or just completed).
func (v *Verifier) refetchForUnknownKID(ctx context.Context, issuer string, ie issuerEntry, cacheTTL, maxStale time.Duration) bool {
	v.mu.Lock()
	// Coalesce concurrent unknown-kid storms onto a single in-flight refetch.
	if wg, inflight := v.kidRefetchFlight[issuer]; inflight {
		v.mu.Unlock()
		wg.Wait()
		return true
	}
	// Min-interval guard: don't refetch more than once per kidRefetchMin.
	if last, ok := v.kidRefetchAt[issuer]; ok && time.Since(last) < v.kidRefetchMin {
		v.mu.Unlock()
		return false
	}
	wg := &sync.WaitGroup{}
	wg.Add(1)
	v.kidRefetchFlight[issuer] = wg
	v.mu.Unlock()

	defer func() {
		v.mu.Lock()
		v.kidRefetchAt[issuer] = time.Now()
		delete(v.kidRefetchFlight, issuer)
		v.mu.Unlock()
		wg.Done()
	}()

	_ = v.refreshIssuerKeys(ctx, issuer, ie, cacheTTL, maxStale)
	return true
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
