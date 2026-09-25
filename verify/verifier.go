package verify

import (
	"cmp"
	"context"
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/dpop"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/jwtkit"
)

// MaxDelegatedRoles bounds how many role UUIDs we lift from attributes.roles on
// a delegated token, so a hostile issuer can't inflate a principal unboundedly.
const MaxDelegatedRoles = 64

// errPermissionNotGranted rejects a token whose `permissions` claim names a
// permission outside the issuer remote application's stored grant.
var errPermissionNotGranted = authkit.E(authkit.CodePermissionNotGranted)

// Verifier validates JWTs from one or more issuers.
//
// For verify-only mode, create with NewVerifier and add issuers via AddIssuer.
// For issuing mode, authhttp.Service creates a Verifier internally.
type Verifier struct {
	dpopReplay     dpop.ReplayGuard
	dpopRequestURL func(*http.Request) string
	skew           time.Duration
	algorithms     []string

	// tokenPrefix is the host application's API-key brand prefix (see embedded.Config
	// APIKeyPrefix). Used to detect API keys in the middleware
	// before JWT verification. Empty -> bare "st_".
	tokenPrefix string

	httpClient *http.Client

	mu      sync.RWMutex
	issuers map[string]issuerEntry // keyed by issuer string for O(1) match
	byIss   map[string]*issuerKeys

	enrich Enricher

	// liveness is the optional account-liveness backend for VerifyRequestLive /
	// RequiredLive (#267). Nil on the stateless default path; guarded by mu.
	liveness            LivenessSource
	permissionChecker   PermissionChecker
	permissionAuthority string

	// requireMFAEnrollment, when set, turns on the per-request forced-2FA-enrollment
	// gate in VerifyRequest (#148). Set from TwoFactor.Mode == Required.
	requireMFAEnrollment bool

	// mfaEnrollmentExemptPaths is the set of route paths (suffix-matched) exempt
	// from requireMFAEnrollment and from the TwoFAEnrollment-only-token gate —
	// see SetMFAEnrollmentExemptPaths (#243). Nil/empty exempts nothing
	// (fail-closed default for a verify-only Verifier that never calls it).
	mfaEnrollmentExemptPaths map[string]bool
	// mfaEnrollmentExemptRoutes are the ANCHORED exempt paths (mount prefix +
	// route path) MountHandler registers; once present they are matched exactly
	// and the suffix set above is not consulted (ak#324).
	mfaEnrollmentExemptRoutes map[string]bool

	// Remote-application lazy-load coherence state. fedSource is the store the
	// lazy-load-on-miss path consults; it defaults to enrich (*authkit.Service) but
	// can be overridden (tests). fedAudiences is threaded so a lazily-loaded
	// issuer is registered with the SAME audiences the bulk LoadRemoteApplications
	// used. fedKnown records which issuers were sourced from the remote-application
	// store so reconciling reload only evicts those (never statically-configured ones).
	fedSource    RemoteApplicationSource
	fedAudiences []string
	fedKnown     map[string]bool

	// fedSnapshot is the enabled remote-application set from the last
	// ListRemoteApplications (bulk load or on-miss refresh), keyed by issuer. The
	// lazy-load-on-miss path answers a token's self-asserted `iss` from it and
	// refreshes it at most once per fedSnapshotTTL, so attacker-chosen issuers
	// never reach the store and no map grows with them (ak#297).
	// fedSnapshotFlight single-flights the refresh.
	fedSnapshot       map[string]authkit.RemoteApplication
	fedSnapshotAt     time.Time
	fedSnapshotTTL    time.Duration
	fedSnapshotFlight chan struct{}

	// negCache remembers snapshot members whose registration (JWKS fetch)
	// failed, for negCacheTTL; fedFlight single-flights concurrent first-use of
	// one issuer. Both are keyed only by snapshot members, so they are bounded
	// by the registered set, and negCache is swept on every snapshot refresh.
	negCache    map[string]time.Time
	negCacheTTL time.Duration
	fedFlight   map[string]chan struct{}

	// kidRefetch tracks the last forced JWKS refetch per issuer (driven by an
	// unknown-kid for a KNOWN issuer) so a storm of bad kids can't hammer the
	// JWKS endpoint. Guarded by a min-interval and single-flight.
	kidRefetchAt     map[string]time.Time
	kidRefetchFlight map[string]chan struct{}
	kidRefetchMin    time.Duration

	// JWKS refresh timing: each fetch attempt is bounded by jwksAttemptTimeout;
	// a failing issuer is retried in the background with full-jitter backoff.
	jwksAttemptTimeout time.Duration
	jwksBackoffBase    time.Duration
	jwksBackoffMax     time.Duration
	// now is the key-cache clock (TTL, MaxStale); tests may replace it.
	now func() time.Time

	// permValidator (optional) checks a delegated access token's `permissions`
	// against the resource server's catalog on every typed verification path.
	permValidator PermissionValidator
}

// issuerEntry describes a trusted issuer (private — replaces authkit.IssuerAccept).
type issuerEntry struct {
	issuer    string
	audiences []string
	jwksURL   string
	cacheTTL  time.Duration
	maxStale  time.Duration
	// isLocal marks the first-party (host application's own) token signer, as
	// opposed to a remote_application/federated issuer. It guards the signing-key
	// registry: a non-local registration must never overwrite the local issuer's
	// entry (AK-AUTH-01), which would swap the trusted signing keys.
	isLocal bool
	// managed entries belong to the application store, never the human namespace.
	managed    bool
	publicKeys func() map[string]crypto.PublicKey
	// application is a per-verification live snapshot, never registry state.
	application *authkit.RemoteApplication
}

// issuerKeys is one issuer's key cache. Everything but pubByKID is meaningful
// only for JWKS issuers: keys past expiresAt keep being served while a single
// background loop (refreshing) refetches them (stale-while-revalidate), until
// maxStale after fetchedAt, the last successful fetch.
type issuerKeys struct {
	jwksURL   string
	pubByKID  map[string]crypto.PublicKey
	expiresAt time.Time
	fetchedAt time.Time
	maxStale  time.Duration

	// fetchSeq numbers fetches as they start; appliedSeq is the newest whose
	// result was recorded, so a slower older fetch never overwrites it.
	fetchSeq, appliedSeq uint64

	refreshing bool
	attempted  chan struct{} // closed after the running loop's first attempt
	checkedAt  time.Time
	lastErr    error
	failures   int
}

// ---------------------------------------------------------------------------
// Functional options
// ---------------------------------------------------------------------------

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithDPoP enables RFC 9449 sender-bound delegated requests. requestURL returns
// the trusted externally visible URL (including any proxy-stripped prefix).
// Both callbacks are required; no Host/Forwarded header fallback is used.
func WithDPoP(replay dpop.ReplayGuard, requestURL func(*http.Request) string) VerifierOption {
	return func(v *Verifier) { v.dpopReplay, v.dpopRequestURL = replay, requestURL }
}

// WithSkew sets the clock skew tolerance for exp/nbf/iat checks.
// Default: 60s.
// WithRemoteApplicationAudiences sets the audiences a lazily-loaded remote
// application issuer is registered with on the resolveIssuer miss path when the
// host never calls LoadRemoteApplications (which overrides it). NewServer passes
// Config.Token.ExpectedAudiences so both load paths enforce the same audience
// (ak#324).
func WithRemoteApplicationAudiences(audiences ...string) VerifierOption {
	return func(v *Verifier) { v.fedAudiences = append([]string(nil), audiences...) }
}

func WithSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.skew = d }
}

// WithAlgorithms REPLACES the allowed JWS algorithm set; it does not add to it.
//
// The default is ["RS256", "ES256", "ES384", "ES512", "EdDSA"], not ["RS256"].
// The breadth is deliberate: federated and remote-application issuers
// legitimately sign with EC or Ed25519 keys and must verify out of the box.
// Narrow it only if you control every issuer this Verifier accepts.
//
// The list is a pure allow-list checked in resolveIssuer, so "none" and the
// symmetric HS* algorithms are absent from the default and rejected there. A
// caller who adds them anyway does not open an algorithm-confusion hole:
// authkit only ever hands the parser an asymmetric public key, which
// golang-jwt's HMAC and none signing methods refuse as the wrong key type.
//
// Passing an empty list rejects every token (fail closed).
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

// WithSSRFGuard installs NewSSRFGuardedClient as the JWKS client: DNS is
// resolved first and any private/reserved answer is refused. Use it on
// Verifiers that fetch JWKS from user-registered (remote_application) issuers.
func WithSSRFGuard() VerifierOption { return WithHTTPClient(NewSSRFGuardedClient()) }

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

// WithPermissions installs a validator that every typed verification path runs
// against the token's `permissions`. Use it to ensure every permission string
// belongs to this resource server's permissions.
func WithPermissions(fn PermissionValidator) VerifierOption {
	return func(v *Verifier) { v.permValidator = fn }
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
		return Claims{}, true, authkit.E(authkit.CodeInvalidToken)
	}
	keyID, secret, ok := authkit.ParseAPIKey(v.tokenPrefix, token)
	if !ok {
		return Claims{}, true, authkit.E(authkit.CodeInvalidToken)
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
			return Claims{}, true, authkit.E(authkit.CodeInvalidToken)
		}
	}
	return Claims{
		APIKeyID:    resolved.APIKeyID,
		Permissions: resolved.Permissions,
		TokenType:   APIKeyPrincipalType,
		// Bind the key's authority to the group instance it was minted on (#248).
		PermissionGroupID:              resolved.PermissionGroupID,
		PermissionGroupAuthorityIssuer: resolved.AuthorityIssuer,
		PermissionGroupPersona:         string(resolved.Persona),
		PermissionGroupInstance:        resolved.InstanceSlug,
	}, true, nil
}

// remoteApplication maps a validated issuer to its remote_application.
func (v *Verifier) remoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return nil, authkit.E(authkit.CodeBadIssuer)
	}
	v.mu.RLock()
	var src RemoteApplicationSource
	if v.fedSource != nil {
		src = v.fedSource
	} else if v.enrich != nil {
		src = v.enrich
	}
	v.mu.RUnlock()
	if src == nil {
		return nil, authkit.E(authkit.CodeInvalidToken)
	}

	ra, err := src.GetRemoteApplication(ctx, issuer)
	if err != nil || ra == nil || !ra.Enabled || ra.Issuer != issuer {
		return nil, authkit.E(authkit.CodeBadIssuer)
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
			if authkit.Perm(p).Matches(authkit.Perm(grant)) {
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

// resolveRemoteApplicationSelf resolves the stored permission ceiling and group
// binding shared by application self tokens and delegated tokens. A nil claim
// uses the full ceiling; a present claim must be a subset or the token fails.
func (v *Verifier) resolveRemoteApplicationSelf(ctx context.Context, ra *authkit.RemoteApplication, tokenTyp string, claimedPerms []string) (Claims, error) {
	if v.enrich == nil || ra.ID == "" {
		return Claims{}, authkit.E(authkit.CodeInvalidToken)
	}
	authority, err := v.enrich.ResolveRemoteApplicationAuthority(ctx, ra.ID)
	if err != nil {
		return Claims{}, authkit.E(authkit.CodeInvalidToken)
	}

	perms, err := permissionsWithinAuthority(claimedPerms, authority.Permissions)
	if err != nil {
		return Claims{}, err
	}

	return Claims{
		Issuer:                     ra.Issuer,
		TokenType:                  RemoteApplicationTokenType,
		TokenTyp:                   tokenTyp,
		Permissions:                perms,
		RemoteApplicationID:        ra.ID,
		RemoteApplicationSlug:      ra.Slug,
		RemoteApplicationDomain:    ra.Domain,
		RemoteApplicationTier:      ra.Tier,
		RemoteApplicationTrustRoot: ra.TrustRoot,
		// Bind the stored authority to its owning group instance (#248),
		// resolved server-side alongside the permission ceiling.
		PermissionGroupID:              authority.PermissionGroupID,
		PermissionGroupAuthorityIssuer: authority.AuthorityIssuer,
		PermissionGroupPersona:         string(authority.Persona),
		PermissionGroupInstance:        authority.InstanceSlug,
	}, nil
}

// NewVerifier creates a new Verifier. Add trusted issuers via AddIssuer.
func NewVerifier(opts ...VerifierOption) *Verifier {
	v := &Verifier{
		skew:             60 * time.Second,
		algorithms:       []string{"RS256", "ES256", "ES384", "ES512", "EdDSA"},
		httpClient:       netguard.Client(netguard.DefaultTimeout, true),
		issuers:          map[string]issuerEntry{},
		byIss:            map[string]*issuerKeys{},
		fedKnown:         map[string]bool{},
		fedSnapshot:      map[string]authkit.RemoteApplication{},
		fedSnapshotTTL:   5 * time.Second,
		negCache:         map[string]time.Time{},
		negCacheTTL:      5 * time.Second,
		fedFlight:        map[string]chan struct{}{},
		kidRefetchAt:     map[string]time.Time{},
		kidRefetchFlight: map[string]chan struct{}{},
		kidRefetchMin:    30 * time.Second,

		jwksAttemptTimeout: 3 * time.Second,
		jwksBackoffBase:    500 * time.Millisecond,
		jwksBackoffMax:     30 * time.Second,
		now:                time.Now,
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
// Use snapshot Keys/RawKeys, a JWKSURI, or the live PublicKeys provider.
// Keys/RawKeys may seed a JWKS cache for its configured CacheTTL.
type IssuerOptions struct {
	// JWKSURI is the URL to fetch JWKS from. If set, keys are fetched
	// automatically and refreshed in the background when they expire or an
	// unknown kid appears. Expired keys keep verifying until a refresh succeeds.
	JWKSURI string

	// Keys are pre-provided public keys as PEM. The caller is responsible for
	// refreshing by calling AddIssuer again with updated keys.
	Keys []IssuerKey

	// RawKeys are a static snapshot. Replace them by calling AddIssuer again.
	RawKeys map[string]crypto.PublicKey

	// PublicKeys reads live in-process keys on every verification, without
	// caching or network requests. Use for a co-located rotating KeySource.
	PublicKeys func() map[string]crypto.PublicKey

	// CacheTTL controls how long fetched JWKS keys are considered fresh.
	// Default: 10 minutes.
	CacheTTL time.Duration

	// MaxStale bounds how long after the last successful JWKS fetch cached keys
	// keep verifying while refreshes fail (anything but a JSON JWKS), so a
	// peer's key revocation cannot be suppressed by blocking our fetch. Past it
	// the issuer's tokens fail with 503 issuer_keys_unavailable. Default: 4
	// hours; never less than CacheTTL.
	MaxStale time.Duration

	// IsLocal marks this issuer as the host application's own (first-party) token
	// signer, as opposed to a remote_application/federated issuer. It guards the
	// signing-key registry against a non-local registration overwriting the local
	// issuer entry. Only this explicit trust may populate Claims.UserID.
	IsLocal bool

	managed bool
}

// AddIssuer registers (or updates) a trusted issuer. This is the single
// method for adding any issuer — whether at startup or at runtime, whether
// keys come from a JWKS URL or are pre-provided.
func (v *Verifier) AddIssuer(issuerID string, audiences []string, opts IssuerOptions) error {
	issuerID = strings.TrimSpace(issuerID)
	if issuerID == "" {
		return errors.New("empty issuer ID")
	}
	if opts.PublicKeys != nil && (opts.JWKSURI != "" || len(opts.Keys) > 0 || len(opts.RawKeys) > 0) {
		return errors.New("live PublicKeys cannot be combined with another key source")
	}
	// An issuer without audiences would accept its tokens for any audience.
	var accepted []string
	for _, aud := range audiences {
		if aud = strings.TrimSpace(aud); aud != "" {
			accepted = append(accepted, aud)
		}
	}
	if len(accepted) == 0 {
		return fmt.Errorf("issuer %q needs at least one accepted audience", issuerID)
	}
	pubByKID, err := collectKeys(opts)
	if err != nil {
		return err
	}
	ie := issuerEntry{
		issuer: issuerID, audiences: accepted,
		jwksURL: strings.TrimSpace(opts.JWKSURI), cacheTTL: opts.CacheTTL, maxStale: opts.MaxStale,
		isLocal: opts.IsLocal, managed: opts.managed, publicKeys: opts.PublicKeys,
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if existing, ok := v.issuers[issuerID]; ok {
		if existing.isLocal && !ie.isLocal {
			return errors.New("refusing to overwrite local issuer with non-local registration")
		}
		if !existing.managed && ie.managed {
			return errors.New("refusing to overwrite explicit issuer trust with application registration")
		}
	}
	// Validate first, then replace metadata and keys together. Failure preserves
	// the complete previous registration; success never retains replaced keys.
	v.issuers[issuerID] = ie
	entry := &issuerKeys{jwksURL: ie.jwksURL, pubByKID: pubByKID, maxStale: issuerMaxStale(ie)}
	if ie.jwksURL != "" && len(pubByKID) > 0 {
		entry.fetchedAt = v.now()
		entry.expiresAt = entry.fetchedAt.Add(issuerCacheTTL(ie))
	}
	v.byIss[issuerID] = entry
	return nil
}

// collectKeys validates the complete key set before any registration changes.
func collectKeys(opts IssuerOptions) (map[string]crypto.PublicKey, error) {
	out := map[string]crypto.PublicKey{}
	add := func(kid string, pub crypto.PublicKey) error {
		if kid == "" || kid != strings.TrimSpace(kid) {
			return errors.New("key ID required without surrounding whitespace")
		}
		if _, exists := out[kid]; exists {
			return fmt.Errorf("duplicate key ID %q", kid)
		}
		if err := jwtkit.ValidatePublicKey(pub); err != nil {
			return fmt.Errorf("key %q: %w", kid, err)
		}
		out[kid] = pub
		return nil
	}
	for _, k := range opts.Keys {
		pub, err := jwtkit.ParsePublicKeyFromPEM(k.PublicKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("key %q: %w", k.KID, err)
		}
		if err := add(k.KID, pub); err != nil {
			return nil, err
		}
	}
	keys := opts.RawKeys
	if opts.PublicKeys != nil {
		keys = opts.PublicKeys()
	}
	for kid, pub := range keys {
		if err := add(kid, pub); err != nil {
			return nil, err
		}
	}
	return out, nil
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

// Enricher resolves API keys and stored application authority. Local access
// tokens remain stateless; account liveness uses the separate LivenessSource.
type Enricher interface {
	ResolveAPIKeyDetailed(ctx context.Context, keyID, secret string) (authkit.ResolvedAPIKey, error)
	GetRemoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error)
	ListEnabledRemoteApplications(ctx context.Context) ([]authkit.RemoteApplication, error)
	ResolveRemoteApplicationAuthority(ctx context.Context, appID string) (authkit.RemoteApplicationAuthority, error)
	// (#215/#220: the former per-request enrichment methods — provider username,
	// role slugs, user refs, live ban gate — are gone from this seam; the request
	// path is stateless and those reads live on authkit.Client.)
}

// WithService installs the API-key/application backend and default lazy source.
// Explicit AddIssuer entries retain their configured trust; stored entries are
// loaded through LoadRemoteApplications or lazy discovery, never AddIssuer.
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
	opts := IssuerOptions{managed: true}
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
	ListEnabledRemoteApplications(ctx context.Context) ([]authkit.RemoteApplication, error)
	// GetRemoteApplication fetches a SINGLE remote_application by its issuer,
	// used after signature verification to resolve a service principal
	// (remoteApplication). The lazy-load-on-miss path never calls it: it answers
	// from the ListEnabledRemoteApplications snapshot (ak#297). *authkit.Service already
	// implements this.
	GetRemoteApplication(ctx context.Context, issuer string) (*authkit.RemoteApplication, error)
}

// LoadRemoteApplications registers enabled store-managed issuers and removes
// entries no longer in the enabled set. Every verification also reads the live
// row for eligibility and key-source changes; callers need not reload for key
// rotation or revocation. Explicit AddIssuer registrations are not reconciled.
// A nil source uses the backend installed by WithService.
func (v *Verifier) LoadRemoteApplications(ctx context.Context, src RemoteApplicationSource, audiences []string) error {
	if src == nil {
		if v.enrich == nil {
			return errors.New("no remote-application source available")
		}
		src = v.enrich
	}

	// Remember the source + audiences so lazy-load-on-miss (resolveIssuer) behaves
	// IDENTICALLY to this bulk load.
	v.mu.Lock()
	v.fedSource = src
	v.fedAudiences = audiences
	v.mu.Unlock()

	issuers, err := src.ListEnabledRemoteApplications(ctx)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.setSnapshotLocked(issuers)
	v.mu.Unlock()

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

// setSnapshotLocked replaces the enabled-issuer snapshot and sweeps negCache
// entries that expired or left the enabled set. Caller holds v.mu.
func (v *Verifier) setSnapshotLocked(apps []authkit.RemoteApplication) {
	snap := make(map[string]authkit.RemoteApplication, len(apps))
	for _, ra := range apps {
		if id := strings.TrimSpace(ra.Issuer); id != "" && ra.Enabled {
			snap[id] = ra
		}
	}
	v.fedSnapshot = snap
	v.fedSnapshotAt = time.Now()
	for id, t := range v.negCache {
		if _, ok := snap[id]; !ok || time.Since(t) >= v.negCacheTTL {
			delete(v.negCache, id)
		}
	}
}

// FederationStats is a point-in-time view of the verifier's remote-application
// lazy-load state, for diagnostics and tests. Every count is bounded by the
// number of enabled remote applications, never by request traffic.
type FederationStats struct {
	Snapshot   int       // enabled issuers in the last snapshot
	SnapshotAt time.Time // when it was taken (zero: never)
	Negative   int       // snapshot members whose registration recently failed
	InFlight   int       // issuers currently being registered
}

func (v *Verifier) FederationStats() FederationStats {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return FederationStats{Snapshot: len(v.fedSnapshot), SnapshotAt: v.fedSnapshotAt, Negative: len(v.negCache), InFlight: len(v.fedFlight)}
}

// snapshotApplication answers whether issuer is an enabled remote application,
// from the in-memory snapshot when it is fresh, otherwise after ONE
// single-flighted ListRemoteApplications refresh. A refresh that fails still
// stamps the snapshot so a failing store is consulted at most once per TTL.
func (v *Verifier) snapshotApplication(ctx context.Context, src RemoteApplicationSource, issuer string) (authkit.RemoteApplication, bool) {
	v.mu.Lock()
	if ra, ok := v.fedSnapshot[issuer]; ok {
		v.mu.Unlock()
		return ra, true
	}
	if time.Since(v.fedSnapshotAt) < v.fedSnapshotTTL {
		v.mu.Unlock()
		return authkit.RemoteApplication{}, false
	}
	ttl := v.fedSnapshotTTL
	if wait := v.fedSnapshotFlight; wait != nil {
		v.mu.Unlock()
		// Waiters are released by the refresh, the caller's context, or the
		// TTL — a stalled store never pins a request past its own deadline.
		select {
		case <-wait:
		case <-ctx.Done():
			return authkit.RemoteApplication{}, false
		case <-time.After(ttl):
			return authkit.RemoteApplication{}, false
		}
		v.mu.RLock()
		ra, ok := v.fedSnapshot[issuer]
		v.mu.RUnlock()
		return ra, ok
	}
	done := make(chan struct{})
	v.fedSnapshotFlight = done
	v.mu.Unlock()

	fetchCtx, cancel := context.WithTimeout(ctx, ttl)
	apps, err := src.ListEnabledRemoteApplications(fetchCtx)
	cancel()
	v.mu.Lock()
	if err == nil {
		v.setSnapshotLocked(apps)
	} else {
		v.fedSnapshotAt = time.Now()
	}
	v.fedSnapshotFlight = nil
	close(done)
	ra, ok := v.fedSnapshot[issuer]
	v.mu.Unlock()
	return ra, ok
}

// lazyLoadIssuer is the lazy-load-on-miss path: when matchIssuer misses and a
// remote-application source is configured, decide from the enabled-issuer
// snapshot whether `iss` is a registered application and, if so, register it
// (AddIssuer fetches+caches its JWKS). It runs inside the JWT key callback,
// before the signature is checked and before any handler rate limit, so nothing
// here may cost per distinct attacker-chosen `iss`: a value that cannot be a
// registered issuer is refused by shape, the store is consulted at most once per
// fedSnapshotTTL, and negCache/fedFlight are keyed only by snapshot members.
// All DB/JWKS work happens WITHOUT holding v.mu (AddIssuer locks v.mu).
//
// Returns true if the issuer is now registered (caller should retry matchIssuer).
func (v *Verifier) lazyLoadIssuer(ctx context.Context, issuer string) bool {
	issuer = strings.TrimSpace(issuer)
	if !authkit.ValidRemoteApplicationIssuer(issuer) {
		return false
	}

	v.mu.Lock()
	src := v.fedSource
	if src == nil {
		v.mu.Unlock()
		return false
	}
	if t, ok := v.negCache[issuer]; ok && time.Since(t) < v.negCacheTTL {
		v.mu.Unlock()
		return false
	}
	v.mu.Unlock()

	ra, ok := v.snapshotApplication(ctx, src, issuer)
	if !ok {
		return false
	}

	v.mu.Lock()
	if done, inflight := v.fedFlight[issuer]; inflight {
		v.mu.Unlock()
		select {
		case <-done:
			return true // caller retries matchIssuer; may still miss (load failed)
		case <-ctx.Done():
			return false
		}
	}
	done := make(chan struct{})
	v.fedFlight[issuer] = done
	aud := v.fedAudiences
	v.mu.Unlock()

	defer func() {
		v.mu.Lock()
		delete(v.fedFlight, issuer)
		close(done)
		v.mu.Unlock()
	}()

	if err := v.AddIssuer(ra.Issuer, aud, remoteAppOptions(ra)); err != nil {
		v.mu.Lock()
		v.negCache[issuer] = time.Now()
		v.mu.Unlock()
		return false
	}

	v.mu.Lock()
	v.fedKnown[strings.TrimSpace(ra.Issuer)] = true
	delete(v.negCache, issuer)
	v.mu.Unlock()
	return true
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

// VerifyClaims verifies signature, issuer eligibility, audience and exp/nbf/iat,
// returning raw claims for host-defined token profiles. It does not enforce
// AuthKit token type, subject, permission or sender-proof semantics. Hosts must
// enforce their custom profile; use Verify or VerifyRequest for AuthKit access
// tokens. A store-managed issuer always requires a live enabled application row.
func (v *Verifier) VerifyClaims(ctx context.Context, tokenStr string) (jwt.MapClaims, error) {
	mapClaims, _, _, err := v.verifyClaimsWithHeader(ctx, tokenStr)
	return mapClaims, err
}

// Verify parses + verifies a token and returns typed Claims.
// It enforces issuer/audience/expiry with the configured skew, plus authkit's
// user-token invariant, on top of VerifyClaims. ctx bounds every key lookup
// the verification needs (JWKS fetch, lazy issuer load, remote-application
// resolution); a cancelled ctx aborts them. It is detached from any request,
// so a certificate-bound delegated token (cnf) fails with
// ErrSenderProofRequired here; verify those through VerifyRequest.
func (v *Verifier) Verify(ctx context.Context, tokenStr string) (Claims, error) {
	return v.verify(ctx, tokenStr, nil)
}

// verify additionally checks sender bindings against the originating request.
func (v *Verifier) verify(ctx context.Context, tokenStr string, r *http.Request) (Claims, error) {
	mapClaims, typ, issuer, err := v.verifyClaimsWithHeader(ctx, tokenStr)
	if err != nil {
		return Claims{}, err
	}

	tokenTyp := strings.TrimSpace(typ)
	hasSub := strClaim(mapClaims, "sub") != ""
	hasDelegatedSub := strClaim(mapClaims, "delegated_sub") != ""
	isAccessTyp := strings.EqualFold(tokenTyp, AccessTokenType)
	isDelegatedAccessTyp := strings.EqualFold(tokenTyp, DelegatedAccessTokenType)
	isRemoteAppTyp := strings.EqualFold(tokenTyp, RemoteApplicationAccessTokenType)
	documentReferences, hasDocumentReferences, err := documentReferencesClaim(tokenStr)
	if err != nil {
		return Claims{}, err
	}
	if hasReservedDocumentsAttribute(mapClaims) {
		return Claims{}, documents.ErrReservedAttribute
	}
	if hasDocumentReferences && !isDelegatedAccessTyp {
		return Claims{}, documents.ErrWrongTokenType
	}
	confirmation, confirmationKind, err := confirmationClaim(tokenStr)
	hasConfirmation := confirmation != nil
	if err != nil {
		return Claims{}, err
	}
	if hasConfirmation && !isDelegatedAccessTyp {
		return Claims{}, ErrConfirmationWrongTokenType
	}
	if confirmationKind == jwtkit.CertificateThumbprintMember {
		peer := peerCertificateSHA256(r)
		if peer == nil || *peer != *confirmation {
			return Claims{}, ErrSenderProofRequired
		}
	}
	if isDPoPRequest(r) && confirmationKind != jwtkit.JWKThumbprintMember {
		return Claims{}, errDPoPProofRequired
	}
	if confirmationKind == jwtkit.JWKThumbprintMember && (!isDPoPRequest(r) || v.dpopRequestURL == nil || v.dpopReplay == nil) {
		return Claims{}, errDPoPProofRequired
	}

	// Invariant: a token is EITHER a native-user token (`sub`) XOR a delegated
	// API key (`delegated_sub`) — never both. Reject the ambiguous case.
	if hasSub && hasDelegatedSub {
		return Claims{}, authkit.E(authkit.CodeConflictingSubject)
	}

	// Remote application access token (#76): a remote_application acting AS
	// ITSELF. Its identity is the VALIDATED `iss` (already mapped to a registered
	// remote_application by the signature/issuer checks); it carries NEITHER
	// `sub` NOR `delegated_sub`, so the user-XOR-delegated invariant below is
	// untouched. Authority is STORED (resolved server-side); any self-claimed
	// roles on the token are IGNORED; a `permissions` claim, if present, may only
	// DOWN-SCOPE the stored authority (#76 amendment), never widen it.
	if isRemoteAppTyp {
		if hasSub || hasDelegatedSub {
			return Claims{}, authkit.E(authkit.CodeRemoteApplicationAccessHasSubject)
		}
		var claimedPerms []string
		if _, ok := mapClaims["permissions"]; ok {
			claimedPerms = strSliceClaim(mapClaims, "permissions")
			if claimedPerms == nil {
				claimedPerms = []string{} // present-but-empty => narrow to nothing
			}
		}
		if issuer.application == nil {
			return Claims{}, authkit.E(authkit.CodeBadIssuer)
		}
		return v.resolveRemoteApplicationSelf(ctx, issuer.application, tokenTyp, claimedPerms)
	}

	// Invariant: a delegated access token MUST NOT carry a normal `sub` — no
	// local account may be implied. Reject it explicitly so a misconfigured
	// issuer can't slip a local subject into a API key.
	if isDelegatedAccessTyp && strClaim(mapClaims, "sub") != "" {
		return Claims{}, authkit.E(authkit.CodeAccessTokenHasSub)
	}

	switch {
	case hasDelegatedSub && !isDelegatedAccessTyp:
		return Claims{}, authkit.E(authkit.CodeDelegatedAccessWrongTyp)
	case hasSub && !isAccessTyp:
		return Claims{}, authkit.E(authkit.CodeAccessTokenWrongTyp)
	case tokenTyp == "":
		return Claims{}, authkit.E(authkit.CodeMissingTokenTyp)
	case !isAccessTyp && !isDelegatedAccessTyp:
		return Claims{}, authkit.E(authkit.CodeUnsupportedTokenTyp)
	case isDelegatedAccessTyp && !hasDelegatedSub:
		return Claims{}, authkit.E(authkit.CodeMissingDelegatedSub)
	case isAccessTyp && !hasSub:
		return Claims{}, authkit.E(authkit.CodeMissingSub)
	}

	if isDelegatedAccessTyp {
		// A delegated access token carries tier/roles under `attributes`, never as
		// top-level claims; reject the top-level forms as token hygiene.
		if strClaim(mapClaims, "user_tier") != "" {
			return Claims{}, authkit.E(authkit.CodeDelegatedAccessHasUserTier)
		}
		if len(strSliceClaim(mapClaims, "roles")) > 0 {
			return Claims{}, authkit.E(authkit.CodeDelegatedAccessHasRoles)
		}
	}
	cl := v.extractClaims(mapClaims)
	if isAccessTyp {
		if issuer.managed {
			return Claims{}, authkit.E(authkit.CodeBadIssuer)
		}
		if issuer.isLocal {
			// Native JWTs establish identity, never group/role/permission
			// authority. Machine and delegated profiles retain their ceilings.
			cl.Roles = nil
			cl.Permissions = nil
		}
		if !issuer.isLocal {
			cl.Subject, cl.UserID = cl.UserID, ""
		}
	}
	cl.TokenTyp = tokenTyp
	cl.Documents = documentReferences
	if confirmationKind == jwtkit.CertificateThumbprintMember {
		cl.ConfirmationCertificateSHA256 = confirmation
	}
	if confirmationKind == jwtkit.JWKThumbprintMember {
		cl.ConfirmationJWKThumbprintSHA256 = confirmation
	}

	if isDelegatedAccessTyp {
		if issuer.application != nil {
			// Delegation inherits the same stored ceiling AND group binding as
			// the application acting as itself. Missing permissions grant nothing.
			perms := cl.Permissions
			if perms == nil {
				perms = []string{}
			}
			authority, err := v.resolveRemoteApplicationSelf(ctx, issuer.application, tokenTyp, perms)
			if err != nil {
				return Claims{}, err
			}
			cl.Permissions = authority.Permissions
			cl.RemoteApplicationID = authority.RemoteApplicationID
			cl.RemoteApplicationSlug = authority.RemoteApplicationSlug
			cl.PermissionGroupID = authority.PermissionGroupID
			cl.PermissionGroupAuthorityIssuer = authority.PermissionGroupAuthorityIssuer
			cl.PermissionGroupPersona = authority.PermissionGroupPersona
			cl.PermissionGroupInstance = authority.PermissionGroupInstance
		}
		if v.permValidator != nil {
			if err := v.permValidator(cl.Permissions); err != nil {
				return Claims{}, err
			}
		}
	}

	if confirmationKind == jwtkit.JWKThumbprintMember {
		if _, err := dpop.VerifyRequest(r, v.dpopRequestURL(r), tokenStr, confirmation, v.dpopReplay); err != nil {
			if errors.Is(err, dpop.ErrReplayUnavailable) {
				return Claims{}, authkit.E(authkit.CodeInternalError, authkit.WithCause(err))
			}
			return Claims{}, errDPoPProofRequired
		}
	}
	return cl, nil
}

// VerifyDelegatedAccess verifies a token, requires it to be a delegated access
// token, and runs any configured permission/attributes validators. It returns
// the typed Claims and the DelegatedPrincipal. Use it on resource servers that
// only accept delegated access tokens and want catalog/policy enforcement.
func (v *Verifier) VerifyDelegatedAccess(ctx context.Context, tokenStr string) (Claims, DelegatedPrincipal, error) {
	return v.verifyDelegatedAccess(ctx, tokenStr, nil)
}

// VerifyDelegatedAccessRequest is VerifyDelegatedAccess bound to the request's
// authorization scheme and sender proof (DPoP or TLS peer certificate).
func (v *Verifier) VerifyDelegatedAccessRequest(r *http.Request) (Claims, DelegatedPrincipal, error) {
	return v.verifyDelegatedAccess(r.Context(), requestToken(r), r)
}

func (v *Verifier) verifyDelegatedAccess(ctx context.Context, tokenStr string, r *http.Request) (Claims, DelegatedPrincipal, error) {
	cl, err := v.verify(ctx, tokenStr, r)
	if err != nil {
		return Claims{}, DelegatedPrincipal{}, err
	}
	dp, ok := cl.DelegatedAccess()
	if !ok {
		return Claims{}, DelegatedPrincipal{}, authkit.E(authkit.CodeNotDelegatedAccessToken)
	}
	return cl, dp, nil
}

// verifyClaimsWithHeader keeps the JOSE type and issuer provenance from the
// same signature verification used by every typed entrypoint.
func (v *Verifier) verifyClaimsWithHeader(ctx context.Context, tokenStr string) (jwt.MapClaims, string, *issuerEntry, error) {
	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		return nil, "", nil, authkit.E(authkit.CodeMissingToken)
	}

	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	var match *issuerEntry
	keyFn := func(token *jwt.Token) (any, error) {
		alg, _ := token.Header["alg"].(string)
		if !v.algAllowed(alg) {
			return nil, errors.New("disallowed_alg")
		}
		var err error
		claims, _ := token.Claims.(jwt.MapClaims)
		match, err = v.resolveIssuer(ctx, strClaim(claims, "iss"))
		if err != nil {
			return nil, err
		}
		kid, _ := token.Header["kid"].(string)
		return v.publicKeyFor(ctx, *match, kid)
	}
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
		if errors.Is(err, jwt.ErrTokenSignatureInvalid) && v.forceRefreshForToken(ctx, tokenStr) {
			mapClaims = jwt.MapClaims{}
			tok, err = parser.ParseWithClaims(tokenStr, mapClaims, keyFn)
		}
		if unavailable := authkit.AsError(err); unavailable != nil && unavailable.Code == authkit.CodeIssuerKeysUnavailable {
			// An expired or foreign-audience token is rejected as such, not 503.
			if cerr := v.checkClaims(mapClaims, match); cerr != nil {
				return nil, "", nil, cerr
			}
			return nil, "", nil, unavailable
		}
		if err != nil || tok == nil || !tok.Valid {
			return nil, "", nil, authkit.E(authkit.CodeInvalidToken)
		}
	}

	if err := v.checkClaims(mapClaims, match); err != nil {
		return nil, "", nil, err
	}

	// typ off the ALREADY-VERIFIED token header — no second ParseUnverified.
	typ, _ := tok.Header["typ"].(string)
	return mapClaims, typ, match, nil
}

// checkClaims enforces issuer match, audience and exp/nbf/iat with skew.
func (v *Verifier) checkClaims(mapClaims jwt.MapClaims, match *issuerEntry) error {
	if match == nil {
		return authkit.E(authkit.CodeBadIssuer)
	}
	if !audContainsAny(mapClaims["aud"], match.audiences) {
		return authkit.E(authkit.CodeBadAudience)
	}
	skew := v.skew
	now := time.Now()
	expUnix, ok := toUnix(mapClaims["exp"])
	if !ok {
		return authkit.E(authkit.CodeMissingExp)
	}
	if time.Unix(expUnix, 0).Before(now.Add(-skew)) {
		return authkit.E(authkit.CodeAccessTokenExpired)
	}
	if nbfUnix, ok := toUnix(mapClaims["nbf"]); ok && time.Unix(nbfUnix, 0).After(now.Add(skew)) {
		return authkit.E(authkit.CodeTokenNotYetValid)
	}
	if iatUnix, ok := toUnix(mapClaims["iat"]); ok && time.Unix(iatUnix, 0).After(now.Add(skew)) {
		return authkit.E(authkit.CodeTokenNotYetValid)
	}
	return nil
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
	cl.DeviceKeyID = strClaim(mc, "device_key_id")
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

func hasReservedDocumentsAttribute(mc jwt.MapClaims) bool {
	attributes, ok := mc["attributes"].(map[string]any)
	if !ok {
		return false
	}
	_, reserved := attributes["documents"]
	return reserved
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

// resolveIssuer binds registry provenance to the live application row before
// any key is used. An unavailable, deleted, or disabled store entry always denies.
func (v *Verifier) resolveIssuer(ctx context.Context, issuer string) (*issuerEntry, error) {
	match := v.matchIssuer(issuer)
	if match == nil && v.lazyLoadIssuer(ctx, issuer) {
		match = v.matchIssuer(issuer)
	}
	if match == nil {
		return nil, authkit.E(authkit.CodeBadIssuer)
	}
	if match.managed {
		ra, err := v.remoteApplication(ctx, issuer)
		if err != nil {
			return nil, err
		}
		match.application = ra
		match.jwksURL = ""
		switch ra.Mode {
		case authkit.RemoteAppModeJWKS:
			match.jwksURL = strings.TrimSpace(ra.JWKSURI)
			if match.jwksURL == "" {
				return nil, authkit.E(authkit.CodeBadIssuer)
			}
		case authkit.RemoteAppModeStatic:
		default:
			return nil, authkit.E(authkit.CodeBadIssuer)
		}
	}
	return match, nil
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
		return nil, authkit.E(authkit.CodeBadIssuer)
	}

	if ie.publicKeys != nil {
		return selectPublicKey(ie.publicKeys(), kid)
	}
	if ie.application != nil && ie.application.Mode == authkit.RemoteAppModeStatic {
		v.mu.Lock()
		delete(v.byIss, iss)
		v.mu.Unlock()
		keys, err := collectKeys(remoteAppOptions(*ie.application))
		if err != nil {
			return nil, err
		}
		return selectPublicKey(keys, kid)
	}

	// Snapshot keys never expire or fetch; only configured JWKS URLs do.
	if ie.jwksURL == "" {
		v.mu.RLock()
		var keys map[string]crypto.PublicKey
		if c := v.byIss[iss]; c != nil {
			keys = c.pubByKID
		}
		v.mu.RUnlock()
		return selectPublicKey(keys, kid)
	}

	// Stale-while-revalidate: cached keys are served past their TTL, up to
	// MaxStale after the last successful fetch, while one background loop per
	// issuer refetches them. A request waits only when the issuer has no usable
	// keys, and then for at most one bounded attempt.
	v.mu.Lock()
	c := v.byIss[iss]
	if c == nil || c.jwksURL != ie.jwksURL {
		c = &issuerKeys{jwksURL: ie.jwksURL, maxStale: issuerMaxStale(ie)}
		v.byIss[iss] = c
	}
	now := v.now()
	keys := c.usableKeysLocked(now)
	if len(keys) == 0 || now.After(c.expiresAt) {
		v.startRefreshLocked(iss, c, ie)
	}
	attempted, lastErr := c.attempted, c.lastErr
	v.mu.Unlock()
	if len(keys) == 0 {
		select {
		case <-attempted:
		case <-ctx.Done():
		}
		v.mu.RLock()
		keys, lastErr = c.usableKeysLocked(v.now()), c.lastErr
		v.mu.RUnlock()
		if len(keys) == 0 {
			if lastErr == nil {
				lastErr = cmp.Or(ctx.Err(), errKeysPastMaxStale)
			}
			return nil, issuerKeysUnavailable(lastErr)
		}
		return selectPublicKey(keys, kid)
	}
	key, err := selectPublicKey(keys, kid)
	if err == nil || kid == "" {
		return key, err
	}
	// A new kid can arrive during the fresh-cache window (key rotation). While
	// the issuer is failing, the background loop owns refetching.
	if lastErr != nil {
		return nil, issuerKeysUnavailable(lastErr)
	}
	if v.refetchForUnknownKID(ctx, iss, c, ie) {
		v.mu.RLock()
		keys = c.usableKeysLocked(v.now())
		v.mu.RUnlock()
		key, err = selectPublicKey(keys, kid)
	}
	return key, err
}

var errKeysPastMaxStale = errors.New("cached keys exceed max stale")

// usableKeysLocked returns the cached keys unless they are older than maxStale.
func (c *issuerKeys) usableKeysLocked(now time.Time) map[string]crypto.PublicKey {
	if c.pastMaxStale(now) {
		return nil
	}
	return c.pubByKID
}

func (c *issuerKeys) pastMaxStale(now time.Time) bool {
	return len(c.pubByKID) > 0 && now.Sub(c.fetchedAt) > c.maxStale
}

func issuerKeysUnavailable(cause error) error {
	return authkit.E(authkit.CodeIssuerKeysUnavailable, authkit.WithCause(cause))
}

// startRefreshLocked starts the issuer's background refresh loop unless one is
// running. Caller holds v.mu.
func (v *Verifier) startRefreshLocked(iss string, c *issuerKeys, ie issuerEntry) {
	if c.refreshing {
		return
	}
	c.refreshing, c.attempted = true, make(chan struct{})
	go v.refreshLoop(iss, c, ie, c.attempted)
}

// refreshLoop refetches until one attempt succeeds or the issuer's cache entry
// is replaced or removed, sleeping with capped full-jitter backoff between
// failures.
func (v *Verifier) refreshLoop(iss string, c *issuerKeys, ie issuerEntry, attempted chan struct{}) {
	for attempt := 0; ; attempt++ {
		err := v.refreshIssuerKeys(context.Background(), iss, c, ie)
		if attempt == 0 {
			close(attempted)
		}
		v.mu.Lock()
		done := err == nil || v.byIss[iss] != c
		if done {
			c.refreshing = false
		}
		v.mu.Unlock()
		if done {
			return
		}
		time.Sleep(netguard.Backoff(attempt, v.jwksBackoffBase, v.jwksBackoffMax))
	}
}

// refetchForUnknownKID runs one synchronous JWKS refetch for a known, healthy
// issuer when an unknown kid arrives (key rotation). A min-interval guard plus
// single-flight ensure a storm of bad kids cannot hammer the JWKS endpoint.
// A failed refetch hands the issuer to the background loop. Returns true if a
// refetch ran (or just completed).
func (v *Verifier) refetchForUnknownKID(ctx context.Context, issuer string, c *issuerKeys, ie issuerEntry) bool {
	v.mu.Lock()
	if done, inflight := v.kidRefetchFlight[issuer]; inflight {
		v.mu.Unlock()
		select {
		case <-done:
			return true
		case <-ctx.Done():
			return false
		}
	}
	if last, ok := v.kidRefetchAt[issuer]; ok && time.Since(last) < v.kidRefetchMin {
		v.mu.Unlock()
		return false
	}
	done := make(chan struct{})
	v.kidRefetchFlight[issuer] = done
	v.mu.Unlock()

	err := v.refreshIssuerKeys(context.WithoutCancel(ctx), issuer, c, ie)

	v.mu.Lock()
	v.kidRefetchAt[issuer] = time.Now()
	delete(v.kidRefetchFlight, issuer)
	close(done)
	if err != nil && v.byIss[issuer] == c {
		v.startRefreshLocked(issuer, c, ie)
	}
	v.mu.Unlock()
	return true
}

// forceRefreshForToken parses the token's `iss` WITHOUT verifying it, and if it
// names a KNOWN issuer, force-refreshes that issuer's JWKS inline (bypassing the
// TTL/known-kid guards). Returns true when a refresh ran, so VerifyClaims can
// retry the signature check once. This recovers from a rotated signing key
// that kept its kid.
func (v *Verifier) forceRefreshForToken(ctx context.Context, tokenStr string) bool {
	mc := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, mc); err != nil {
		return false
	}
	iss := strClaim(mc, "iss")
	if iss == "" {
		return false
	}
	return v.forceRefreshIssuer(ctx, iss)
}

// forceRefreshIssuer goes through the throttled, single-flighted unknown-kid
// path so a storm of bad signatures cannot hammer the JWKS endpoint. Permanent
// issuers (no JWKS URI, #239) and failing issuers are left alone.
func (v *Verifier) forceRefreshIssuer(ctx context.Context, iss string) bool {
	ie, err := v.resolveIssuer(ctx, iss)
	if err != nil || strings.TrimSpace(ie.jwksURL) == "" {
		return false
	}
	entry := *ie
	v.mu.RLock()
	c := v.byIss[iss]
	healthy := c != nil && c.jwksURL == entry.jwksURL && c.lastErr == nil
	v.mu.RUnlock()
	if !healthy {
		return false
	}
	return v.refetchForUnknownKID(ctx, iss, c, entry)
}

// refreshIssuerKeys runs one bounded JWKS fetch and records its outcome on c.
// A transient failure keeps the cached keys (bounded by MaxStale); a JSON JWKS
// replaces them, and one with no usable keys drops them (fail closed).
func (v *Verifier) refreshIssuerKeys(ctx context.Context, issuer string, c *issuerKeys, ie issuerEntry) error {
	v.mu.Lock()
	c.fetchSeq++
	seq := c.fetchSeq
	v.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, v.jwksAttemptTimeout)
	defer cancel()
	keys, authoritative, err := v.fetchJWKS(ctx, ie.jwksURL)

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.byIss[issuer] != c {
		// A concurrent replacement owns the cache now. Never publish an old
		// endpoint's response into that registration.
		return errors.New("issuer keys changed during refresh")
	}
	if seq < c.appliedSeq {
		return c.lastErr // a newer fetch already recorded its result
	}
	c.appliedSeq = seq
	c.checkedAt, c.lastErr = v.now(), err
	switch {
	case err == nil:
		c.pubByKID, c.fetchedAt, c.expiresAt, c.failures = keys, c.checkedAt, c.checkedAt.Add(issuerCacheTTL(ie)), 0
	case authoritative:
		c.pubByKID = nil
		c.failures++
	default:
		c.failures++
	}
	return err
}

// fetchJWKS fetches and parses a JWKS. authoritative reports whether the answer
// states the issuer's current key set: only a 200 that parses as a JSON JWKS
// does. Transport errors, non-200 statuses and non-JSON bodies are transient.
// Individual malformed, weak or unsupported keys are skipped; an authoritative
// answer without usable keys is an error that drops the cache.
func (v *Verifier) fetchJWKS(ctx context.Context, jwksURL string) (map[string]crypto.PublicKey, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, false, err
	}
	resp, err := v.httpClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("jwks_http_%d", resp.StatusCode)
	}
	var ks jwtkit.JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&ks); err != nil {
		return nil, false, fmt.Errorf("jwks: %w", err)
	}
	keys := map[string]crypto.PublicKey{}
	for _, j := range ks.Keys {
		pub, err := jwtkit.JWKToPublicKey(j)
		if err != nil {
			continue
		}
		kid := strings.TrimSpace(j.Kid)
		if kid == "" {
			kid = "default"
		}
		keys[kid] = pub
	}
	if len(keys) == 0 {
		return nil, true, errors.New("jwks has no usable keys")
	}
	return keys, true, nil
}

// IssuerKeyStatus is one JWKS-backed issuer's key-refresh state. Age is the
// time since the last successful fetch (export Age.Seconds() as a gauge);
// past MaxStale the issuer's tokens fail with 503 (Expired).
type IssuerKeyStatus struct {
	Issuer    string
	JWKSURI   string
	Keys      int
	Fresh     bool      // keys are within CacheTTL
	FetchedAt time.Time // last successful fetch; zero before the first
	Age       time.Duration
	MaxStale  time.Duration
	Expired   bool      // Age exceeds MaxStale: verification fails closed
	CheckedAt time.Time // last fetch attempt; zero before the first
	Failures  int       // consecutive failed fetches
	LastError string
}

// IssuerKeyStatuses reports every JWKS-backed issuer, sorted by issuer.
func (v *Verifier) IssuerKeyStatuses() []IssuerKeyStatus {
	v.mu.RLock()
	defer v.mu.RUnlock()
	now := v.now()
	var out []IssuerKeyStatus
	for iss, c := range v.byIss {
		if c.jwksURL == "" {
			continue
		}
		st := IssuerKeyStatus{Issuer: iss, JWKSURI: c.jwksURL, Keys: len(c.pubByKID),
			Fresh: len(c.pubByKID) > 0 && now.Before(c.expiresAt), FetchedAt: c.fetchedAt,
			MaxStale: c.maxStale, Expired: c.pastMaxStale(now), CheckedAt: c.checkedAt, Failures: c.failures}
		if !c.fetchedAt.IsZero() {
			st.Age = now.Sub(c.fetchedAt)
		}
		if c.lastErr != nil {
			st.LastError = c.lastErr.Error()
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Issuer < out[j].Issuer })
	return out
}

// CheckIssuerKeys is a no-I/O health probe for a host dependency supervisor:
// it fails naming every JWKS issuer whose last key fetch failed, with the age
// of its cached keys and whether they exceed MaxStale (tokens then fail
// closed). Other issuers are unaffected.
func (v *Verifier) CheckIssuerKeys(context.Context) error {
	v.mu.RLock()
	defer v.mu.RUnlock()
	now := v.now()
	var errs []error
	for iss, c := range v.byIss {
		switch {
		case c.jwksURL == "" || c.lastErr == nil:
		case c.pastMaxStale(now):
			errs = append(errs, fmt.Errorf("issuer %s keys expired (age %s > max stale %s), verification failing closed: %w",
				iss, now.Sub(c.fetchedAt).Round(time.Second), c.maxStale, c.lastErr))
		case len(c.pubByKID) > 0:
			errs = append(errs, fmt.Errorf("issuer %s keys stale (age %s, max stale %s): %w",
				iss, now.Sub(c.fetchedAt).Round(time.Second), c.maxStale, c.lastErr))
		default:
			errs = append(errs, fmt.Errorf("issuer %s has no keys: %w", iss, c.lastErr))
		}
	}
	return errors.Join(errs...)
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

func issuerMaxStale(ie issuerEntry) time.Duration {
	return max(cmp.Or(ie.maxStale, 4*time.Hour), issuerCacheTTL(ie))
}

func issuerCacheTTL(ie issuerEntry) time.Duration {
	if ie.cacheTTL > 0 {
		return ie.cacheTTL
	}
	return 10 * time.Minute
}

func selectPublicKey(keys map[string]crypto.PublicKey, kid string) (crypto.PublicKey, error) {
	key := keys[kid]
	if kid == "" {
		if len(keys) != 1 {
			return nil, authkit.E(authkit.CodeMissingKID)
		}
		for _, candidate := range keys {
			key = candidate
		}
	}
	if key == nil {
		return nil, authkit.E(authkit.CodeUnknownKID)
	}
	if err := jwtkit.ValidatePublicKey(key); err != nil {
		return nil, err
	}
	return key, nil
}
