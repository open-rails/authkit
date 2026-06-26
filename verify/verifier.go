package verify

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
	"github.com/google/uuid"
	authkit "github.com/open-rails/authkit"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// MaxDelegatedRoles bounds how many role UUIDs we lift from attributes.roles on
// a delegated token, so a hostile issuer can't inflate a principal unboundedly.
const MaxDelegatedRoles = 64

// errPermissionNotGranted rejects a token whose `permissions` claim names a
// permission outside the issuer remote application's stored grant.
var errPermissionNotGranted = errors.New("permission_not_granted")

// Verifier validates JWTs from one or more issuers.
//
// For verify-only mode, create with NewVerifier and add issuers via AddIssuer.
// For issuing mode, authhttp.Service creates a Verifier internally.
type Verifier struct {
	skew       time.Duration
	algorithms []string

	// tokenPrefix is the host application's API-key brand prefix (see embedded.Config
	// APIKeyPrefix). Used to detect API keys in the middleware
	// before JWT verification. Empty -> bare "st_".
	tokenPrefix string

	httpClient *http.Client

	mu      sync.RWMutex
	issuers map[string]issuerEntry // keyed by issuer string for O(1) match
	byIss   map[string]*issuerKeys

	enrich Enricher

	// requireMFAEnrollment, when set, turns on the per-request forced-2FA-enrollment
	// gate in VerifyRequest (#148). Set from TwoFactor.Mode == Required.
	requireMFAEnrollment bool

	// Remote-application lazy-load coherence state. fedSource is the store the
	// lazy-load-on-miss path consults; it defaults to enrich (*authkit.Service) but
	// can be overridden (tests). fedAudiences is threaded so a lazily-loaded
	// issuer is registered with the SAME audiences the bulk LoadRemoteApplications
	// used. fedKnown records which issuers were sourced from the remote-application
	// store so reconciling reload only evicts those (never statically-configured ones).
	fedSource    RemoteApplicationSource
	fedAudiences []string
	fedKnown     map[string]bool

	// negCache remembers issuers the remote-application source did not return as
	// enabled, for negCacheTTL, so garbage/unknown `iss` values don't hit the DB
	// per request. fedFlight single-flights concurrent first-use of the same issuer.
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
	// attrHydrate / attrResolver implement opt-in verify-time REFERENCE-mode
	// attribute hydration (#75). Off unless WithAttributeHydration is set.
	attrHydrate  bool
	attrResolver AttributeDefResolver
}

// issuerEntry describes a trusted issuer (private — replaces authkit.IssuerAccept).
type issuerEntry struct {
	issuer                string
	audiences             []string
	jwksURL               string
	cacheTTL              time.Duration
	maxStale              time.Duration
	remoteApplicationSlug string
	// isLocal marks the first-party (host application's own) token signer, as
	// opposed to a remote_application/federated issuer. It guards the signing-key
	// registry: a non-local registration must never overwrite the local issuer's
	// entry (AK-AUTH-01), which would swap the trusted signing keys.
	isLocal bool
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

// WithSSRFGuard installs an SSRF-guarding HTTP client that resolves DNS and
// rejects any private/reserved IP before connecting. Use this on Verifiers that
// fetch JWKS from user-registered (remote_application) issuers. Production
// Services created via NewService/NewFromConfig already include this guard.
func WithSSRFGuard() VerifierOption {
	return WithHTTPClient(NewSSRFGuardedClient())
}

// WithAPIKeyPrefix sets the host application's API-key brand prefix used to
// detect opaque shared-secret API keys in the middleware. Empty -> bare "st_".
func WithAPIKeyPrefix(prefix string) VerifierOption {
	return func(v *Verifier) { v.tokenPrefix = strings.TrimSpace(prefix) }
}

// WithRequireMFAEnrollment enables the per-request forced-enrollment gate (#148):
// when 2FA policy is Required, a native-user request whose token shows the user
// is not yet enrolled (mfa_enrolled absent) is rejected with 2fa_enrollment_required
// unless it targets a 2FA enroll/challenge route. This makes Required gate the
// SESSION — every existing un-enrolled user is challenged on their next request,
// not just new signups. Set by the AuthKit server from TwoFactor.Mode; verify-only
// resource servers leave it off.
func WithRequireMFAEnrollment(require bool) VerifierOption {
	return func(v *Verifier) { v.requireMFAEnrollment = require }
}

// PermissionValidator validates a delegated access token's `permissions`
// against the receiving service's own permissions. Return an error to
// reject the token. Called only for delegated access tokens.
type PermissionValidator func(permissions []string) error

// AttributesValidator validates a delegated access token's `attributes` against
// the receiving service's policy schema. Return an error to reject the token.
// Called only for delegated access tokens.
type AttributesValidator func(attributes map[string]json.RawMessage) error

// WithPermissions installs a validator that VerifyDelegatedAccess runs
// against the token's `permissions`. Use it to ensure every permission string
// belongs to this resource server's permissions.
func WithPermissions(fn PermissionValidator) VerifierOption {
	return func(v *Verifier) { v.permValidator = fn }
}

// WithAttributesPolicy installs a validator that VerifyDelegatedAccess runs
// against the token's `attributes`. Use it to enforce a policy schema (allowed
// keys, value shapes/ranges).
func WithAttributesPolicy(fn AttributesValidator) VerifierOption {
	return func(v *Verifier) { v.attrValidator = fn }
}

// AttributeDefResolver resolves a REFERENCE-mode attribute (#75) to its opaque
// definition, given the token's validated issuer, the attribute key, and the
// reference value the token carried. It returns the resolved definition (raw
// JSON) to substitute for the reference, or an error. *authkit.Service-backed
// resolvers map issuer -> remote_application -> registered definition.
type AttributeDefResolver func(ctx context.Context, issuer, key, ref string) (json.RawMessage, error)

// WithAttributeHydration enables OPT-IN verify-time hydration (#75): after a
// delegated token verifies, VerifyDelegatedAccess resolves each REFERENCE-mode
// attribute (a JSON-string value) into its full definition via resolver, so the
// consumer sees a uniform INLINE shape whether the token used inline or
// reference. OFF by default. A resolver miss leaves that attribute untouched
// (the consumer can still resolve it itself); only a hard resolver error fails
// the call. Pass nil to use the Service-backed default resolver (requires
// WithService).
func WithAttributeHydration(resolver AttributeDefResolver) VerifierOption {
	return func(v *Verifier) {
		v.attrHydrate = true
		v.attrResolver = resolver
	}
}

// resolveAPIKey handles opaque shared-secret API keys. It returns matched=true
// when the bearer token carries the configured API-key marker, in
// which case the caller MUST NOT fall through to JWT verification — along with
// API-key principal Claims on success or a sanitized error on failure. When the
// token is not an API key, matched is false and the caller proceeds to JWT verify.
func (v *Verifier) resolveAPIKey(ctx context.Context, token string) (cl Claims, matched bool, err error) {
	if !authkit.HasAPIKeyPrefix(v.tokenPrefix, token) {
		return Claims{}, false, nil
	}
	// Shaped like an API key: from here we never fall through to JWT verification.
	if v.enrich == nil {
		return Claims{}, true, errors.New("invalid_token")
	}
	keyID, secret, ok := authkit.ParseAPIKey(v.tokenPrefix, token)
	if !ok {
		return Claims{}, true, errors.New("invalid_token")
	}
	resolved, rerr := v.enrich.ResolveAPIKeyDetailed(ctx, keyID, secret)
	if rerr != nil {
		switch {
		case errors.Is(rerr, authkit.ErrAccessTokenRevoked):
			return Claims{}, true, authkit.ErrAccessTokenRevoked
		case errors.Is(rerr, authkit.ErrAccessTokenExpired):
			return Claims{}, true, authkit.ErrAccessTokenExpired
		case errors.Is(rerr, authkit.ErrInvalidAccessToken):
			return Claims{}, true, authkit.ErrInvalidAccessToken
		default:
			// Never leak DB/internal errors through the auth response.
			return Claims{}, true, errors.New("invalid_token")
		}
	}
	return Claims{
		Permissions: resolved.Permissions,
		TokenType:   APIKeyPrincipalType,
	}, true, nil
}

// remoteApplication maps a validated issuer to its remote_application.
func (v *Verifier) remoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, errors.New("bad_issuer")
	}
	var src RemoteApplicationSource
	if v.fedSource != nil {
		src = v.fedSource
	} else if v.enrich != nil {
		src = v.enrich
	}
	if src == nil {
		return nil, errors.New("invalid_token")
	}

	ra, err := src.GetRemoteApplication(ctx, issuer)
	if err != nil || ra == nil {
		return nil, errors.New("bad_issuer")
	}
	return ra, nil
}

func permissionsWithinAuthority(claimedPerms, authorityPerms []string) ([]string, error) {
	if claimedPerms == nil {
		return authorityPerms, nil
	}
	eff := make([]string, 0, len(claimedPerms))
	seen := map[string]struct{}{}
	for _, p := range claimedPerms {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ok := false
		for _, grant := range authorityPerms {
			if authkit.PermissionTokenCovers(grant, p) {
				ok = true
				break
			}
		}
		if !ok {
			return nil, errPermissionNotGranted
		}
		if _, dup := seen[p]; dup {
			continue
		}
		seen[p] = struct{}{}
		eff = append(eff, p)
	}
	return eff, nil
}

// resolveRemoteApplicationSelf authenticates a remote application access token:
// it maps the VALIDATED issuer to its remote_application and returns Claims
// populated the way an API-key-authenticated principal would be. The token's own
// role claims are never consulted — authority is stored.
//
// claimedPerms is the token's `permissions` down-scoping request (#76 amendment):
// nil => no claim => full stored ceiling; non-nil => effective = the claim, but
// EVERY claimed perm must be within the stored ceiling — an out-of-grant claimed
// perm REJECTS the whole token (errPermissionNotGranted), never a widening and
// never a silent clamp.
func (v *Verifier) resolveRemoteApplicationSelf(ctx context.Context, issuer, tokenTyp string, claimedPerms []string) (Claims, error) {
	ra, err := v.remoteApplication(ctx, issuer)
	if err != nil {
		return Claims{}, err
	}

	// The remote application's STORED permission ceiling (its assigned authority)
	// is resolved by the core layer through the permission-group assignment path.
	if v.enrich == nil {
		return Claims{}, errors.New("invalid_token")
	}
	authorityPerms, err := v.enrich.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		return Claims{}, errors.New("invalid_token")
	}

	// Down-scoping (#76 amendment): a present `permissions` claim narrows the
	// stored ceiling to the claimed subset; absent (nil) keeps the full ceiling.
	// Any claimed perm OUTSIDE the ceiling rejects the whole token — a
	// misconfigured caller must fail loudly, not silently lose perms.
	perms, err := permissionsWithinAuthority(claimedPerms, authorityPerms)
	if err != nil {
		return Claims{}, err
	}

	return Claims{
		Issuer:                issuer,
		TokenType:             RemoteApplicationTokenType,
		TokenTyp:              tokenTyp,
		Permissions:           perms,
		RemoteApplicationID:   ra.ID,
		RemoteApplicationSlug: ra.Slug,
	}, nil
}

// NewVerifier creates a new Verifier. Add trusted issuers via AddIssuer.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		skew:             60 * time.Second,
		algorithms:       []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"},
		httpClient:       defaultOutboundHTTPClient,
		issuers:          map[string]issuerEntry{},
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
// Provide one of JWKSURI, Keys, or RawKeys.
type IssuerOptions struct {
	// JWKSURI is the URL to fetch JWKS from. If set, keys are fetched
	// automatically and refreshed when they expire or an unknown kid appears.
	JWKSURI string

	// Keys are pre-provided public keys as PEM. The caller is responsible for
	// refreshing by calling AddIssuer again with updated keys.
	Keys []IssuerKey

	// RawKeys are pre-provided public keys (e.g., from a co-located authkit.Service).
	RawKeys map[string]crypto.PublicKey

	// CacheTTL controls how long fetched JWKS keys are considered fresh.
	// Default: 10 minutes.
	CacheTTL time.Duration

	// MaxStale controls how long stale keys may be used as fallback after
	// a failed JWKS refresh. Default: 1 hour.
	MaxStale time.Duration

	// RemoteApplicationSlug is the receiver-internal remote-application slug
	// registered for this issuer. Tokens do not self-assert this value; it comes
	// only from the trusted issuer registry.
	RemoteApplicationSlug string

	// IsLocal marks this issuer as the host application's own (first-party) token
	// signer, as opposed to a remote_application/federated issuer. It guards the
	// signing-key registry against a non-local registration overwriting the local
	// issuer entry (AK-AUTH-01); it does not change how claims are parsed.
	IsLocal bool
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
		issuer:                issuerID,
		audiences:             audiences,
		jwksURL:               strings.TrimSpace(opts.JWKSURI),
		cacheTTL:              opts.CacheTTL,
		maxStale:              opts.MaxStale,
		remoteApplicationSlug: strings.TrimSpace(opts.RemoteApplicationSlug),
		isLocal:               opts.IsLocal,
	}

	v.mu.Lock()
	defer v.mu.Unlock()

	// Upsert in the issuers map.
	if existing, ok := v.issuers[issuerID]; ok {
		// AK-AUTH-01: never let a non-local (federated/remote_application)
		// registration overwrite the trusted local issuer entry. Doing so
		// would swap the first-party signing keys and break verification of
		// all first-party tokens. The core layer already rejects this at
		// registration; this is defense-in-depth for any other AddIssuer caller.
		if existing.isLocal && !ie.isLocal {
			return errors.New("refusing to overwrite local issuer with non-local registration")
		}
	}
	v.issuers[issuerID] = ie

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

	delete(v.issuers, issuerID)
	delete(v.byIss, issuerID)
}

// ---------------------------------------------------------------------------
// Enrichment
// ---------------------------------------------------------------------------

// Enricher is the optional, DB-backed hook surface the Verifier and middleware
// use for best-effort enrichment (roles/email/provider username), the live-user
// ban/deleted gate, opaque API-key resolution, and remote_application
// + attribute lookups. *authkit.Service satisfies it. The Verifier holds this as an
// INTERFACE (not *authkit.Service) so the verification layer carries no hard
// dependency on core's storage stack — a verify-only consumer can leave it nil
// or supply a lightweight implementation (#110).
type Enricher interface {
	ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (authkit.ResolvedAPIKey, error)
	GetRemoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error)
	ListRemoteApplications(ctx context.Context, activeOnly bool) ([]authkit.RemoteApplication, error)
	ResolveRemoteApplicationAuthority(ctx context.Context, appID string) ([]string, error)
	ResolveRemoteAppAttributeDef(ctx context.Context, appID, key string, version int32) (*authkit.RemoteAppAttributeDef, error)
	GetProviderUsername(ctx context.Context, userID, provider string) (string, error)
	ListRoleSlugsByUser(ctx context.Context, userID string) []string
	GetEmailByUserID(ctx context.Context, id string) (string, error)
	IsUserAllowed(ctx context.Context, userID string) (bool, error)
}

// WithService enables best-effort enrichment hooks (roles/provider usernames)
// from Postgres, and wires the same enricher as the default remote-application
// source for lazy-load-on-miss (see keyForToken). *authkit.Service satisfies Enricher.
func (v *Verifier) WithService(svc Enricher) *Verifier {
	v.enrich = svc
	v.mu.Lock()
	if v.fedSource == nil && svc != nil {
		v.fedSource = svc
	}
	v.mu.Unlock()
	return v
}

// ---------------------------------------------------------------------------
// Remote-application issuers (in-house store, no external push/sync)
// ---------------------------------------------------------------------------

// remoteAppOptions maps a stored remote_application to verifier options for its
// trust mode (#74): jwks mode fetches+refreshes from the URI; static mode seeds
// the human-managed PEM list (no URL fetching ever for static principals).
func remoteAppOptions(ra authkit.RemoteApplication) IssuerOptions {
	opts := IssuerOptions{RemoteApplicationSlug: ra.Slug}
	if ra.Mode == authkit.RemoteAppModeStatic {
		for _, k := range ra.PublicKeys {
			opts.Keys = append(opts.Keys, IssuerKey{KID: k.KID, PublicKeyPEM: k.PublicKeyPEM})
		}
		return opts
	}
	opts.JWKSURI = ra.JWKSURI
	return opts
}

// RemoteApplicationSource is the minimal store contract the Verifier needs to
// load remote_application principals (#74). *authkit.Service satisfies it. An
// embedding app may supply its own implementation in tests.
type RemoteApplicationSource interface {
	ListRemoteApplications(ctx context.Context, enabledOnly bool) ([]authkit.RemoteApplication, error)
	// GetRemoteApplication fetches a SINGLE remote_application by its issuer,
	// used by the lazy-load-on-miss path in keyForToken. *authkit.Service already
	// implements this.
	GetRemoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error)
}

// LoadRemoteApplications loads the ACTIVE remote_applications from authkit's OWN
// store (the remote_applications table) and registers each as a trusted issuer
// via AddIssuer with its JWKS URL. The Verifier's in-house JWKS fetch/refresh
// then handles the keys — there is NO external push or sync of keys.
//
// audiences, when non-empty, is applied to every loaded issuer (typically this
// resource server's own audience). Call this at startup, and re-call (e.g. on
// a ticker, or after an inbound registration) to pick up store changes. Pass
// the embedding app's authkit.Service (or any RemoteApplicationSource); if nil, the
// Service provided via WithService is used.
func (v *Verifier) LoadRemoteApplications(ctx context.Context, src RemoteApplicationSource, audiences []string) error {
	if src == nil {
		if v.enrich == nil {
			return errors.New("no remote-application source available")
		}
		src = v.enrich
	}

	// Remember the source + audiences so lazy-load-on-miss (keyForToken) behaves
	// IDENTICALLY to this bulk load.
	v.mu.Lock()
	v.fedSource = src
	v.fedAudiences = audiences
	v.mu.Unlock()

	issuers, err := src.ListRemoteApplications(ctx, true)
	if err != nil {
		return err
	}

	// Build the enabled set, then AddIssuer each (AddIssuer locks v.mu internally,
	// so it must be called WITHOUT holding v.mu).
	enabled := make(map[string]bool, len(issuers))
	for _, fi := range issuers {
		issuerID := strings.TrimSpace(fi.Issuer)
		if issuerID == "" {
			continue
		}
		enabled[issuerID] = true
		if err := v.AddIssuer(issuerID, audiences, remoteAppOptions(fi)); err != nil {
			return err
		}
		v.mu.Lock()
		v.fedKnown[issuerID] = true
		delete(v.negCache, issuerID) // it is enabled now; clear any negative entry
		v.mu.Unlock()
	}

	// RECONCILE: evict in-memory FEDERATED issuers that are no longer in the
	// enabled set. Only remote-application issuers (tracked in fedKnown) are eligible —
	// statically-configured issuers added via AddIssuer are never evicted here.
	// This bounds revocation lag to the reload tick. (A Postgres LISTEN/NOTIFY
	// stream of issuer-row changes could give sub-tick eviction; not built here —
	// reconciling reload + on-unknown-kid refetch give bounded correctness.)
	v.mu.Lock()
	var toEvict []string
	for issuerID := range v.fedKnown {
		if !enabled[issuerID] {
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
// remote-application source is configured, fetch that ONE issuer from the store
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

	fi, err := src.GetRemoteApplication(ctx, issuer)
	if err != nil || fi == nil || !fi.Enabled {
		v.mu.Lock()
		v.negCache[issuer] = time.Now()
		v.mu.Unlock()
		return false
	}

	if err := v.AddIssuer(fi.Issuer, aud, remoteAppOptions(*fi)); err != nil {
		v.mu.Lock()
		v.negCache[issuer] = time.Now()
		v.mu.Unlock()
		return false
	}

	v.mu.Lock()
	v.fedKnown[strings.TrimSpace(fi.Issuer)] = true
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

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	keyFn := func(token *jwt.Token) (any, error) { return v.keyForToken(token) }
	mapClaims := jwt.MapClaims{}
	tok, err := parser.ParseWithClaims(tokenStr, mapClaims, keyFn)
	if err != nil || tok == nil || !tok.Valid {
		// Resilience: a verification failure can mean our cached signing key is
		// stale/rotated (same kid, new key material) or the JWKS was never
		// fetched (peer was starting on first use). If the token names a KNOWN
		// issuer, force an inline JWKS refetch and retry the verification before
		// rejecting. The refetch goes through the per-issuer min-interval +
		// single-flight guard, so a storm of bad tokens coalesces to at most one
		// fetch per kidRefetchMin and cannot hammer the JWKS endpoint.
		if v.forceRefreshForToken(tokenStr) {
			mapClaims = jwt.MapClaims{}
			tok, err = parser.ParseWithClaims(tokenStr, mapClaims, keyFn)
		}
		if err != nil || tok == nil || !tok.Valid {
			return nil, errors.New("invalid_token")
		}
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
	// API key (`delegated_sub`) — never both. Reject the ambiguous case.
	if strClaim(mapClaims, "sub") != "" && strClaim(mapClaims, "delegated_sub") != "" {
		return Claims{}, errors.New("conflicting_subject")
	}

	tokenTyp := strings.TrimSpace(typ)
	hasSub := strClaim(mapClaims, "sub") != ""
	hasDelegatedSub := strClaim(mapClaims, "delegated_sub") != ""
	isAccessTyp := strings.EqualFold(tokenTyp, AccessTokenType)
	isDelegatedAccessTyp := strings.EqualFold(tokenTyp, DelegatedAccessTokenType)
	isRemoteAppTyp := strings.EqualFold(tokenTyp, RemoteApplicationAccessTokenType)

	// Remote application access token (#76): a remote_application acting AS
	// ITSELF. Its identity is the VALIDATED `iss` (already mapped to a registered
	// remote_application by the signature/issuer checks); it carries NEITHER
	// `sub` NOR `delegated_sub`, so the user-XOR-delegated invariant below is
	// untouched. Authority is STORED (resolved server-side); any self-claimed
	// roles on the token are IGNORED; a `permissions` claim, if present, may only
	// DOWN-SCOPE the stored authority (#76 amendment), never widen it.
	if isRemoteAppTyp {
		if hasSub || hasDelegatedSub {
			return Claims{}, errors.New("remote_application_access_has_subject")
		}
		var claimedPerms []string
		if _, ok := mapClaims["permissions"]; ok {
			claimedPerms = strSliceClaim(mapClaims, "permissions")
			if claimedPerms == nil {
				claimedPerms = []string{} // present-but-empty => narrow to nothing
			}
		}
		return v.resolveRemoteApplicationSelf(context.Background(), strClaim(mapClaims, "iss"), tokenTyp, claimedPerms)
	}

	// Invariant: a delegated access token MUST NOT carry a normal `sub` — no
	// local account may be implied. Reject it explicitly so a misconfigured
	// issuer can't slip a local subject into a API key.
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

	if isDelegatedAccessTyp {
		// A delegated access token carries tier/roles under `attributes`, never as
		// top-level claims; reject the top-level forms as token hygiene.
		if strClaim(mapClaims, "user_tier") != "" {
			return Claims{}, errors.New("delegated_access_has_user_tier")
		}
		if len(strSliceClaim(mapClaims, "roles")) > 0 {
			return Claims{}, errors.New("delegated_access_has_roles")
		}
	}

	cl := v.extractClaims(mapClaims)
	cl.TokenTyp = tokenTyp

	// Delegated permission ceiling (#76 target model). A delegated access token's
	// concrete `permissions` are a DOWN-SCOPING request bounded by the SIGNING
	// remote application's STORED authority — a remote app must never mint a
	// delegated token carrying permissions beyond its own assigned grants (no
	// privilege escalation). When this verifier can resolve the validated `iss`
	// to a remote_application it stores (i.e. it is the issuing-side AuthKit, the
	// only party that knows the stored grant), it enforces the subset and rejects
	// any out-of-ceiling claim — fail closed. A pure federated resource server
	// that only trusts the issuer's JWKS (no remote-app store) cannot bound the
	// claim here; it relies on its WithPermissions catalog validator instead.
	if isDelegatedAccessTyp && len(cl.Permissions) > 0 && v.enrich != nil {
		ctx := context.Background()
		if ra, rerr := v.remoteApplication(ctx, cl.Issuer); rerr == nil && ra != nil {
			authorityPerms, aerr := v.enrich.ResolveRemoteApplicationAuthority(ctx, ra.ID)
			if aerr != nil {
				// Never swallow an authority-resolution failure into "allow": a
				// backend outage must fail closed, not grant the claimed perms.
				return Claims{}, errors.New("invalid_token")
			}
			perms, perr := permissionsWithinAuthority(cl.Permissions, authorityPerms)
			if perr != nil {
				return Claims{}, perr
			}
			cl.Permissions = perms
		}
	}

	return cl, nil
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
	if v.attrHydrate {
		if err := v.hydrateAttributes(&cl); err != nil {
			return Claims{}, DelegatedPrincipal{}, err
		}
		dp, _ = cl.Delegated() // refresh principal view (UserTier etc. unchanged keys)
	}
	return cl, dp, nil
}

// hydrateAttributes resolves each REFERENCE-mode attribute (#75) in place into
// its full definition, so the consumer sees a uniform INLINE shape. A resolver
// miss (ErrAttributeDefNotFound) leaves the reference untouched; only a hard
// resolver error fails. Uses the configured resolver, or a Service-backed
// default (issuer -> remote_application -> registered definition).
func (v *Verifier) hydrateAttributes(cl *Claims) error {
	if len(cl.Attributes) == 0 {
		return nil
	}
	resolver := v.attrResolver
	if resolver == nil {
		if v.enrich == nil {
			return nil // nothing to resolve against
		}
		resolver = v.defaultAttributeResolver
	}
	for key := range cl.Attributes {
		ref, isRef := cl.AttributeReference(key)
		if !isRef {
			continue
		}
		def, err := resolver(context.Background(), cl.Issuer, key, ref)
		if err != nil {
			if errors.Is(err, authkit.ErrAttributeDefNotFound) {
				continue
			}
			return err
		}
		if len(def) > 0 {
			cl.Attributes[key] = def
		}
	}
	return nil
}

// defaultAttributeResolver maps a validated issuer to its remote_application and
// resolves the registered definition for the REFERENCE value (the token's
// {"<attr>":"<ref>"} carries <ref> as the registry key, e.g. "tier-1"). Latest
// version. Used when WithAttributeHydration was passed a nil resolver.
func (v *Verifier) defaultAttributeResolver(ctx context.Context, issuer, _key, ref string) (json.RawMessage, error) {
	ra, err := v.enrich.GetRemoteApplication(ctx, issuer)
	if err != nil {
		return nil, err
	}
	def, err := v.enrich.ResolveRemoteAppAttributeDef(ctx, ra.ID, ref, 0)
	if err != nil {
		return nil, err
	}
	return def.Definition, nil
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
	cl.Email = strClaim(mc, "email")
	cl.EmailVerified, _ = mc["email_verified"].(bool)
	cl.Username = strClaim(mc, "username")
	cl.DiscordUsername = strClaim(mc, "discord_username")
	cl.SessionID = strClaim(mc, "sid")
	cl.JTI = strClaim(mc, "jti")
	cl.AMR = strSliceClaim(mc, "amr")
	cl.ACR = strClaim(mc, "acr")
	cl.TwoFAEnrollment, _ = mc["2fa_enrollment"].(bool)
	cl.MFAEnrolled, _ = mc["mfa_enrolled"].(bool)
	if authTime, ok := toUnix(mc["auth_time"]); ok {
		cl.AuthTime = time.Unix(authTime, 0)
	}

	// Permissions are the resource-defined authority source for delegated access
	// tokens (NOT OAuth space-delimited scope).
	cl.Permissions = strSliceClaim(mc, "permissions")

	// Attributes is issuer policy metadata kept as raw JSON for per-service
	// decoding. `attributes.tier` is the canonical home for the tier label.
	cl.Attributes = rawAttributesClaim(mc, "attributes")

	if cl.isDelegated() {
		// Canonical delegated access tokens carry tier under attributes.tier.
		if tier := rawStringAttribute(cl.Attributes, "tier"); tier != "" {
			cl.UserTier = tier
		}
		// Role UUIDs ride under attributes.roles (a JSON array of UUID strings).
		// Validate + cap; malformed entries are dropped rather than failing the
		// token. The top-level `roles` claim is forbidden on delegated tokens
		// (rejected earlier), so this is the only role surface they carry.
		cl.DelegatedRoles = rawUUIDStringsAttribute(cl.Attributes, "roles", MaxDelegatedRoles)
	} else {
		cl.UserTier = strClaim(mc, "user_tier")
		if cl.UserTier == "" {
			cl.UserTier = strClaim(mc, "plan")
		}
	}

	cl.Roles = strSliceClaim(mc, "roles")
	cl.Entitlements = strSliceClaim(mc, "entitlements")

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

// rawUUIDStringsAttribute decodes a single attribute value as a JSON array of
// strings and returns those that are well-formed UUIDs, capped at limit.
// Malformed entries (non-UUID, blank) are dropped rather than failing — a
// hostile issuer can't poison the whole token with one bad role. Returns nil
// when the attribute is absent, not an array, or yields no valid UUIDs.
func rawUUIDStringsAttribute(attrs map[string]json.RawMessage, key string, limit int) []string {
	raw, ok := attrs[key]
	if !ok {
		return nil
	}
	// Decode element-wise so a single non-string entry doesn't void the whole
	// array — non-string and malformed elements are skipped individually.
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, el := range arr {
		var s string
		if err := json.Unmarshal(el, &s); err != nil {
			continue
		}
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, err := uuid.Parse(s); err != nil {
			continue
		}
		out = append(out, s)
		if limit > 0 && len(out) >= limit {
			break
		}
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
		// Lazy-load-on-miss: a brand-new remote-application issuer may already be in the
		// store but not yet in this replica's in-memory cache. Fetch+register it
		// (outside v.mu — AddIssuer locks v.mu) and retry. Backward compatible:
		// when no remote-application source is configured this is a no-op (-> bad_issuer).
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
	v.mu.RLock()
	defer v.mu.RUnlock()
	if ie, ok := v.issuers[issuer]; ok {
		ie := ie // copy
		return &ie
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

// JWKS fetch resilience knobs: a momentarily-unreachable JWKS endpoint (a peer
// still starting, a transient network blip / 5xx) should not fail token
// verification on the first try. refreshIssuerKeys retries this many times with
// exponential backoff starting at jwksRefreshBackoff.
const (
	jwksRefreshAttempts = 3
	jwksRefreshBackoff  = 250 * time.Millisecond
)

// forceRefreshForToken parses the token's `iss` WITHOUT verifying it, and if it
// names a KNOWN issuer, force-refreshes that issuer's JWKS inline (bypassing the
// TTL/known-kid guards). Returns true when a refresh ran, so VerifyClaims can
// retry the signature check once. This is the "on a verify reject, refetch keys
// inline and retry" resilience path — it recovers from a stale/rotated signing
// key or a JWKS that wasn't reachable on first use.
func (v *Verifier) forceRefreshForToken(tokenStr string) bool {
	mc := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, mc); err != nil {
		return false
	}
	iss := strClaim(mc, "iss")
	if iss == "" {
		return false
	}
	ie := v.matchIssuer(iss)
	if ie == nil {
		return false
	}
	entry := *ie // copy out from under the verifier lock before fetching
	cacheTTL := entry.cacheTTL
	if cacheTTL == 0 {
		cacheTTL = 10 * time.Minute
	}
	maxStale := entry.maxStale
	if maxStale == 0 {
		maxStale = time.Hour
	}
	// Route through the throttled, single-flighted unknown-kid refetch path rather
	// than calling refreshIssuerKeys directly. Otherwise a storm of bad tokens
	// hammers the JWKS endpoint: each verify failure would force its own fetch with
	// no min-interval or coalescing. refetchForUnknownKID caps this at one fetch
	// per issuer per kidRefetchMin and coalesces concurrent callers onto it.
	return v.refetchForUnknownKID(context.Background(), iss, entry, cacheTTL, maxStale)
}

func (v *Verifier) refreshIssuerKeys(ctx context.Context, issuer string, ie issuerEntry, cacheTTL, maxStale time.Duration) error {
	jwksURL := strings.TrimSpace(ie.jwksURL)
	if jwksURL == "" {
		jwksURL = strings.TrimRight(strings.TrimSpace(issuer), "/") + "/.well-known/jwks.json"
	}

	// One fetch+parse attempt. A nil error means the JWKS was fetched and parsed.
	attempt := func() (jwtkit.JWKS, map[string]crypto.PublicKey, error) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
		resp, err := v.httpClient.Do(req)
		if err != nil {
			return jwtkit.JWKS{}, nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return jwtkit.JWKS{}, nil, fmt.Errorf("jwks_http_%d", resp.StatusCode)
		}
		// Limit response body to 1MB to prevent OOM from malicious JWKS endpoints.
		limited := io.LimitReader(resp.Body, 1<<20)
		var ks jwtkit.JWKS
		if derr := json.NewDecoder(limited).Decode(&ks); derr != nil {
			return jwtkit.JWKS{}, nil, derr
		}
		pub, perr := jwtkit.JWKSToPublicKeys(ks)
		if perr != nil {
			return jwtkit.JWKS{}, nil, perr
		}
		return ks, pub, nil
	}

	// Resilience: a JWKS endpoint can be momentarily unreachable (peer still
	// starting, transient network/5xx). Retry a few times with bounded backoff
	// before giving up, rather than failing the whole token verification on a
	// single blip. Aborts early if the request context is cancelled.
	var (
		ks       jwtkit.JWKS
		pubByKID map[string]crypto.PublicKey
		err      error
	)
	backoff := jwksRefreshBackoff
	for i := 0; i < jwksRefreshAttempts; i++ {
		ks, pubByKID, err = attempt()
		if err == nil {
			break
		}
		if i == jwksRefreshAttempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
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
