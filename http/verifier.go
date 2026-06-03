package authhttp

import (
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// tokenPrefix is the host application's OAT brand prefix (see core.Config
	// TokenPrefix). Used to detect Organization Access Tokens in the middleware
	// before JWT verification. Empty -> bare "oat_".
	tokenPrefix string

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

	// Delegated-access-token validation hooks (optional). permValidator checks
	// `permissions` against the resource server's catalog; attrValidator checks
	// `attributes` against a policy schema. Run only by VerifyDelegatedAccess.
	permValidator PermissionValidator
	attrValidator AttributesValidator
}

// issuerEntry describes a trusted issuer (private — replaces core.IssuerAccept).
type issuerEntry struct {
	issuer                 string
	audiences              []string
	jwksURL                string
	cacheTTL               time.Duration
	maxStale               time.Duration
	trustedResourceAccount string
}

type issuerKeys struct {
	jwks       jwtkit.JWKS
	pubByKID   map[string]crypto.PublicKey
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

// WithTokenPrefix sets the host application's Organization Access Token (OAT)
// brand prefix used to detect OATs in the middleware. Empty -> bare "oat_".
func WithTokenPrefix(prefix string) VerifierOption {
	return func(v *Verifier) { v.tokenPrefix = strings.TrimSpace(prefix) }
}

// PermissionValidator validates a delegated access token's `permissions`
// against the receiving service's own permission catalog. Return an error to
// reject the token. Called only for delegated access tokens.
type PermissionValidator func(permissions []string) error

// AttributesValidator validates a delegated access token's `attributes` against
// the receiving service's policy schema. Return an error to reject the token.
// Called only for delegated access tokens.
type AttributesValidator func(attributes map[string]json.RawMessage) error

// WithPermissionCatalog installs a validator that VerifyDelegatedAccess runs
// against the token's `permissions`. Use it to ensure every permission string
// belongs to this resource server's catalog.
func WithPermissionCatalog(fn PermissionValidator) VerifierOption {
	return func(v *Verifier) { v.permValidator = fn }
}

// WithAttributesPolicy installs a validator that VerifyDelegatedAccess runs
// against the token's `attributes`. Use it to enforce a policy schema (allowed
// keys, value shapes/ranges).
func WithAttributesPolicy(fn AttributesValidator) VerifierOption {
	return func(v *Verifier) { v.attrValidator = fn }
}

// resolveServiceToken handles Organization Access Tokens (OATs). It returns
// matched=true when the bearer token carries the configured OAT marker — in
// which case the caller MUST NOT fall through to JWT verification — along with
// service-principal Claims on success or a sanitized error on failure. When the
// token is not an OAT, matched is false and the caller proceeds to JWT verify.
func (v *Verifier) resolveServiceToken(ctx context.Context, token string) (cl Claims, matched bool, err error) {
	if !core.HasOATPrefix(v.tokenPrefix, token) {
		return Claims{}, false, nil
	}
	// Shaped like an OAT: from here we never fall through to JWT verification.
	if v.enrich == nil {
		return Claims{}, true, errors.New("invalid_token")
	}
	keyID, secret, ok := core.ParseOAT(v.tokenPrefix, token)
	if !ok {
		return Claims{}, true, errors.New("invalid_token")
	}
	org, permissions, rerr := v.enrich.ResolveOrgAccessToken(ctx, keyID, secret)
	if rerr != nil {
		switch {
		case errors.Is(rerr, core.ErrAccessTokenRevoked):
			return Claims{}, true, core.ErrAccessTokenRevoked
		case errors.Is(rerr, core.ErrAccessTokenExpired):
			return Claims{}, true, core.ErrAccessTokenExpired
		case errors.Is(rerr, core.ErrInvalidAccessToken):
			return Claims{}, true, core.ErrInvalidAccessToken
		default:
			// Never leak DB/internal errors through the auth response.
			return Claims{}, true, errors.New("invalid_token")
		}
	}
	return Claims{
		Org:         org,
		Permissions: permissions,
		TokenType:   ServiceTokenType,
	}, true, nil
}

// NewVerifier creates a new Verifier. Add trusted issuers via AddIssuer.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		skew:             60 * time.Second,
		algorithms:       []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"},
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

	// RawKeys are pre-provided public keys (e.g., from a co-located core.Service).
	RawKeys map[string]crypto.PublicKey

	// CacheTTL controls how long fetched JWKS keys are considered fresh.
	// Default: 10 minutes.
	CacheTTL time.Duration

	// MaxStale controls how long stale keys may be used as fallback after
	// a failed JWKS refresh. Default: 1 hour.
	MaxStale time.Duration

	// TrustedResourceAccount optionally binds delegated access tokens from this
	// issuer to one resource-service account slug. Federated issuers loaded from
	// the federated_org_issuers store set this to that row's org_slug, so a
	// trusted issuer cannot mint a delegated token for another resource account.
	TrustedResourceAccount string
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
		issuer:                 issuerID,
		audiences:              audiences,
		jwksURL:                strings.TrimSpace(opts.JWKSURL),
		cacheTTL:               opts.CacheTTL,
		maxStale:               opts.MaxStale,
		trustedResourceAccount: strings.ToLower(strings.TrimSpace(opts.TrustedResourceAccount)),
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
func (v *Verifier) collectKeys(opts IssuerOptions) map[string]crypto.PublicKey {
	out := map[string]crypto.PublicKey{}
	for _, k := range opts.Keys {
		kid := strings.TrimSpace(k.KID)
		if kid == "" {
			continue
		}
		pub, err := jwtkit.ParsePublicKeyFromPEM(k.PublicKeyPEM)
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
		if err := v.AddIssuer(issuerID, audiences, IssuerOptions{JWKSURL: fi.JWKSURL, TrustedResourceAccount: fi.OrgSlug}); err != nil {
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

	if err := v.AddIssuer(fi.IssuerID, aud, IssuerOptions{JWKSURL: fi.JWKSURL, TrustedResourceAccount: fi.OrgSlug}); err != nil {
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

// VerifyClaims parses and cryptographically verifies a token against the
// registered issuers and returns its RAW validated claims. It performs the
// generic, token-type-agnostic checks: JWKS key resolution + signature,
// issuer must be registered, audience match, and exp/nbf/iat with the
// configured skew. It does NOT apply authkit's user-token semantics (the
// sub/delegated_sub invariant) or map into the typed Claims struct.
//
// Use it to verify CUSTOM token types (e.g. a host application's capability
// tokens) that should reuse authkit's single JWKS engine — registry, caching,
// rotation, lazy-load — while carrying their own claim shape. The caller
// registers the token's issuer via AddIssuer and parses the returned MapClaims
// itself. Verify() is built on top of this for authkit's own user tokens.
func (v *Verifier) VerifyClaims(tokenStr string) (jwt.MapClaims, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, errors.New("missing_token")
	}

	mapClaims := jwt.MapClaims{}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	tok, err := parser.ParseWithClaims(tokenStr, mapClaims, func(token *jwt.Token) (any, error) {
		return v.keyForToken(token)
	})
	if err != nil || tok == nil || !tok.Valid {
		return nil, errors.New("invalid_token")
	}

	iss, _ := mapClaims["iss"].(string)
	match := v.matchIssuer(iss)
	if match == nil {
		return nil, errors.New("bad_issuer")
	}

	if len(match.audiences) > 0 && !audContainsAny(mapClaims["aud"], match.audiences) {
		return nil, errors.New("bad_audience")
	}

	skew := v.skew
	now := time.Now()
	expUnix, ok := toUnix(mapClaims["exp"])
	if !ok {
		return nil, errors.New("missing_exp")
	}
	if time.Unix(expUnix, 0).Before(now.Add(-skew)) {
		return nil, errors.New("token_expired")
	}
	if nbfUnix, ok := toUnix(mapClaims["nbf"]); ok {
		if time.Unix(nbfUnix, 0).After(now.Add(skew)) {
			return nil, errors.New("token_not_yet_valid")
		}
	}
	if iatUnix, ok := toUnix(mapClaims["iat"]); ok {
		if time.Unix(iatUnix, 0).After(now.Add(skew)) {
			return nil, errors.New("token_not_yet_valid")
		}
	}

	return mapClaims, nil
}

// Verify parses + verifies a token and returns typed Claims.
// It enforces issuer/audience/expiry with the configured skew, plus authkit's
// user-token invariant, on top of VerifyClaims.
func (v *Verifier) Verify(tokenStr string) (Claims, error) {
	mapClaims, typ, err := v.verifyClaimsWithHeader(tokenStr)
	if err != nil {
		return Claims{}, err
	}

	// Invariant: a token is EITHER a native-user token (`sub`) XOR a delegated
	// access token (`delegated_sub`) — never both. Reject the ambiguous case.
	if strClaim(mapClaims, "sub") != "" && strClaim(mapClaims, "delegated_sub") != "" {
		return Claims{}, errors.New("conflicting_subject")
	}

	tokenTyp := strings.TrimSpace(typ)
	hasSub := strClaim(mapClaims, "sub") != ""
	hasDelegatedSub := strClaim(mapClaims, "delegated_sub") != ""
	isAccessTyp := strings.EqualFold(tokenTyp, AccessTokenType)
	isDelegatedAccessTyp := strings.EqualFold(tokenTyp, DelegatedAccessTokenType)

	// Invariant: a delegated access token MUST NOT carry a normal `sub` — no
	// local account may be implied. Reject it explicitly so a misconfigured
	// issuer can't slip a local subject into an access token.
	if isDelegatedAccessTyp && strClaim(mapClaims, "sub") != "" {
		return Claims{}, errors.New("access_token_has_sub")
	}

	switch {
	case hasDelegatedSub && !isDelegatedAccessTyp:
		return Claims{}, errors.New("delegated_access_wrong_typ")
	case hasSub && !isAccessTyp:
		return Claims{}, errors.New("access_token_wrong_typ")
	case tokenTyp == "":
		return Claims{}, errors.New("missing_token_typ")
	case !isAccessTyp && !isDelegatedAccessTyp:
		return Claims{}, errors.New("unsupported_token_typ")
	case isDelegatedAccessTyp && !hasDelegatedSub:
		return Claims{}, errors.New("missing_delegated_sub")
	case isAccessTyp && !hasSub:
		return Claims{}, errors.New("missing_sub")
	}

	tenant := strings.TrimSpace(strClaim(mapClaims, "tenant"))
	org := strings.TrimSpace(strClaim(mapClaims, "org"))
	if isDelegatedAccessTyp {
		if tenant == "" {
			return Claims{}, errors.New("missing_tenant")
		}
		if org != "" {
			return Claims{}, errors.New("delegated_access_has_org")
		}
		if strClaim(mapClaims, "user_tier") != "" {
			return Claims{}, errors.New("delegated_access_has_user_tier")
		}
		if len(strSliceClaim(mapClaims, "roles")) > 0 {
			return Claims{}, errors.New("delegated_access_has_roles")
		}
	}
	if err := v.validateDelegatedIssuerResourceAccount(mapClaims, tenant); err != nil {
		return Claims{}, err
	}

	cl := v.extractClaims(mapClaims)
	cl.TokenTyp = tokenTyp
	return cl, nil
}

// validateDelegatedIssuerResourceAccount binds federated delegated-access tokens
// to the resource account registered for their issuer. The JWT `tenant` claim is
// signed, but it is still issuer-controlled; this check ties it to the resource
// server's trust registry so one trusted issuer cannot claim another resource
// account.
func (v *Verifier) validateDelegatedIssuerResourceAccount(mapClaims jwt.MapClaims, tenant string) error {
	if strClaim(mapClaims, "delegated_sub") == "" {
		return nil
	}
	issuer := strings.TrimSpace(strClaim(mapClaims, "iss"))
	match := v.matchIssuer(issuer)
	if match == nil || strings.TrimSpace(match.trustedResourceAccount) == "" {
		return nil
	}
	resourceAccount := strings.ToLower(strings.TrimSpace(tenant))
	if resourceAccount == "" || resourceAccount != strings.ToLower(strings.TrimSpace(match.trustedResourceAccount)) {
		return errors.New("resource_account_issuer_mismatch")
	}
	return nil
}

// VerifyDelegatedAccess verifies a token, requires it to be a delegated access
// token, and runs any configured permission/attributes validators. It returns
// the typed Claims and the DelegatedPrincipal. Use it on resource servers that
// only accept delegated access tokens and want catalog/policy enforcement.
func (v *Verifier) VerifyDelegatedAccess(tokenStr string) (Claims, DelegatedPrincipal, error) {
	cl, err := v.Verify(tokenStr)
	if err != nil {
		return Claims{}, DelegatedPrincipal{}, err
	}
	dp, ok := cl.DelegatedAccess()
	if !ok {
		return Claims{}, DelegatedPrincipal{}, errors.New("not_delegated_access_token")
	}
	if v.permValidator != nil {
		if err := v.permValidator(cl.Permissions); err != nil {
			return Claims{}, DelegatedPrincipal{}, err
		}
	}
	if v.attrValidator != nil {
		if err := v.attrValidator(cl.Attributes); err != nil {
			return Claims{}, DelegatedPrincipal{}, err
		}
	}
	return cl, dp, nil
}

// verifyClaimsWithHeader is VerifyClaims plus the JOSE `typ` header value, so
// Verify can enforce delegated-access-token typing. The header is read from the
// already-verified token; callers must not trust typ for security decisions
// beyond what the signature and registered-issuer checks already guarantee.
func (v *Verifier) verifyClaimsWithHeader(tokenStr string) (jwt.MapClaims, string, error) {
	mapClaims, err := v.VerifyClaims(tokenStr)
	if err != nil {
		return nil, "", err
	}
	// Re-parse (unverified) only to read the header; signature/issuer/audience
	// were already validated by VerifyClaims above.
	typ := ""
	parser := jwt.NewParser()
	if tok, _, perr := parser.ParseUnverified(strings.TrimSpace(tokenStr), jwt.MapClaims{}); perr == nil && tok != nil {
		typ, _ = tok.Header["typ"].(string)
	}
	return mapClaims, typ, nil
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

	// Permissions are the resource-defined authority source for delegated access
	// tokens (NOT OAuth space-delimited scope).
	cl.Permissions = strSliceClaim(mc, "permissions")

	// Attributes is issuer policy metadata kept as raw JSON for per-service
	// decoding. `attributes.tier` is the canonical home for the tier label.
	cl.Attributes = rawAttributesClaim(mc, "attributes")

	if cl.IsDelegated() {
		// Canonical delegated access tokens carry tier under attributes.tier.
		if tier := rawStringAttribute(cl.Attributes, "tier"); tier != "" {
			cl.UserTier = tier
		}
	} else {
		cl.UserTier = strClaim(mc, "user_tier")
		if cl.UserTier == "" {
			cl.UserTier = strClaim(mc, "plan")
		}
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

// rawAttributesClaim extracts an object-valued claim (e.g. `attributes`) as
// map[string]json.RawMessage so each value can be re-decoded by the receiving
// service into its own typed schema. Returns nil when the claim is absent or
// not an object.
func rawAttributesClaim(mc jwt.MapClaims, key string) map[string]json.RawMessage {
	obj, ok := mc[key].(map[string]any)
	if !ok || len(obj) == 0 {
		return nil
	}
	out := make(map[string]json.RawMessage, len(obj))
	for k, val := range obj {
		b, err := json.Marshal(val)
		if err != nil {
			continue
		}
		out[k] = json.RawMessage(b)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// rawStringAttribute decodes a single attribute value as a JSON string, or
// returns "" when absent / not a string.
func rawStringAttribute(attrs map[string]json.RawMessage, key string) string {
	raw, ok := attrs[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return strings.TrimSpace(s)
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

func (v *Verifier) publicKeyFor(ctx context.Context, ie issuerEntry, kid string) (crypto.PublicKey, error) {
	iss := ie.issuer
	if iss == "" {
		return nil, errors.New("bad_issuer")
	}

	cacheTTL := ie.cacheTTL
	if cacheTTL == 0 {
		cacheTTL = 10 * time.Minute
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
	pubByKID, err := jwtkit.JWKSToPublicKeys(ks)
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
