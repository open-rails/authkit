package engine

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/apikey"
	"github.com/open-rails/authkit/internal/enrollment"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/verify"
)

// Authenticator authenticates requests against this deployment: its API
// keys, the tokens it issues (verified statelessly against its live key
// source) and the tokens its stored remote applications issue (federation),
// for a set of audiences. The engine's own serves AuthKit's routes and the
// Client; NewAuthenticator builds one for a host resource server.
type Authenticator struct {
	s         *Engine
	v         *verify.Verifier
	audiences []string
	// own marks the deployment's authenticator: it applies the Required 2FA
	// gate and its enrollment-route exemptions.
	own bool

	mu sync.Mutex
	// registered is each application's key source as last registered on v,
	// re-registered when the live row's differs.
	registered map[string]string
}

// newAuthenticator trusts this deployment's issuer for audiences; opts come
// after the defaults (WithRequestOrigin overrides the issuer's origin).
func (s *Engine) newAuthenticator(audiences []string, own bool, opts ...verify.VerifierOption) (*Authenticator, error) {
	cfg := s.cfg
	base := []verify.VerifierOption{
		verify.WithSkew(5 * time.Second),
		// Applications register their own JWKS URIs: SSRF-guarded unless the
		// deployment federates on a private network (#257).
		verify.WithHTTPClient(netguard.Client(netguard.DefaultTimeout, cfg.Applications.AllowPrivateNetworkJWKS)),
		verify.WithDPoP(s.ClaimDPoPProof),
		verify.WithRequestOrigin(issuerOrigin(cfg.Token.Issuer)),
	}
	a := &Authenticator{s: s, v: verify.NewVerifier(append(base, opts...)...), audiences: audiences, own: own}
	if cfg.Token.Issuer != "" {
		if err := a.v.AddIssuer(cfg.Token.Issuer, audiences, verify.IssuerOptions{KeySource: s.keys, IsLocal: true}); err != nil {
			return nil, err
		}
	}
	return a, nil
}

// NewAuthenticator builds an authenticator for a host resource server in this
// process: this deployment's API keys and tokens and its remote
// applications' tokens, for audiences. DPoP proofs are spent in this
// deployment's replay store and checked against the issuer's origin unless
// opts say otherwise (verify.WithRequestOrigin). It applies no 2FA policy.
func (s *Engine) NewAuthenticator(audiences []string, opts ...verify.VerifierOption) (*Authenticator, error) {
	return s.newAuthenticator(audiences, false, opts...)
}

// issuerOrigin is scheme://host of the issuer; "" (no DPoP proof can match)
// when the issuer is not a URL.
func issuerOrigin(issuer string) string {
	u, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil || u.Scheme == "" || u.Host == "" || u.User != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// VerifyRequest authenticates the engine's own requests (verify.Authenticator).
func (s *Engine) VerifyRequest(r *http.Request) (verify.Claims, error) {
	return s.auth.VerifyRequest(r)
}

// Verify is VerifyRequest for a token detached from any request.
func (s *Engine) Verify(ctx context.Context, token string) (verify.Claims, error) {
	return s.auth.Verify(ctx, token)
}

// VerifyServiceJWT verifies a service JWT this deployment or one of its
// remote applications issued.
func (s *Engine) VerifyServiceJWT(ctx context.Context, token string, opts ...verify.ServiceJWTVerifyOption) (iam.ServiceJWTClaims, error) {
	return s.auth.VerifyServiceJWT(ctx, token, opts...)
}

// CheckIssuerKeys is the no-I/O health probe of the remote applications'
// JWKS keys (verify.Verifier.CheckIssuerKeys).
func (s *Engine) CheckIssuerKeys(ctx context.Context) error { return s.auth.CheckIssuerKeys(ctx) }

// IssuerKeyStatuses reports the remote applications' JWKS key state.
func (s *Engine) IssuerKeyStatuses() []verify.IssuerKeyStatus { return s.auth.IssuerKeyStatuses() }

// VerifyRequest authenticates r: an API key is resolved and never tried as
// a JWT; a JWT is this deployment's or a stored application's.
func (a *Authenticator) VerifyRequest(r *http.Request) (verify.Claims, error) {
	token, dpop := jose.RequestToken(r)
	if token == "" {
		return verify.Claims{}, errmodel.E(errmodel.CodeUnauthenticated)
	}
	if a.own && a.s.mfaExempt.has(r) {
		r = r.WithContext(enrollment.Route(r.Context()))
	}
	return a.authenticate(r.Context(), token, r, dpop)
}

// Verify is VerifyRequest for a token detached from any request, so a
// sender-bound delegated token fails with verify.ErrSenderProofRequired.
func (a *Authenticator) Verify(ctx context.Context, token string) (verify.Claims, error) {
	if token = strings.TrimSpace(token); token == "" {
		return verify.Claims{}, errmodel.E(errmodel.CodeUnauthenticated)
	}
	return a.authenticate(ctx, token, nil, false)
}

// VerifyServiceJWT verifies a service JWT (verify.Verifier.VerifyServiceJWT)
// of this deployment or of a stored application.
func (a *Authenticator) VerifyServiceJWT(ctx context.Context, token string, opts ...verify.ServiceJWTVerifyOption) (iam.ServiceJWTClaims, error) {
	if _, claims, ok := jose.Unverified(strings.TrimSpace(token)); ok {
		if _, _, err := a.federated(ctx, jose.String(claims, "iss")); err != nil {
			return iam.ServiceJWTClaims{}, err
		}
	}
	return a.v.VerifyServiceJWT(ctx, token, opts...)
}

// CheckIssuerKeys is the no-I/O health probe of the applications' JWKS keys.
func (a *Authenticator) CheckIssuerKeys(ctx context.Context) error { return a.v.CheckIssuerKeys(ctx) }

// IssuerKeyStatuses reports the applications' JWKS key state and age.
func (a *Authenticator) IssuerKeyStatuses() []verify.IssuerKeyStatus { return a.v.IssuerKeyStatuses() }

func (a *Authenticator) authenticate(ctx context.Context, token string, r *http.Request, dpop bool) (verify.Claims, error) {
	cl, err := a.credential(ctx, token, r, dpop)
	if err != nil {
		return verify.Claims{}, err
	}
	// Under a Required 2FA policy a user not yet enrolled reaches only the
	// enrollment routes (#148).
	if a.own && a.s.requireMFAEnrollment() && cl.IsUser() && !cl.MFAEnrolled && !enrollment.IsRoute(ctx) {
		return verify.Claims{}, errmodel.E(errmodel.CodeTwoFAEnrollmentRequired)
	}
	return cl, nil
}

func (a *Authenticator) credential(ctx context.Context, token string, r *http.Request, dpop bool) (verify.Claims, error) {
	if apikey.HasMarker(a.s.cfg.APIKeys.Prefix, token) {
		if dpop {
			return verify.Claims{}, verify.ErrSenderProofRequired
		}
		return a.s.apiKeyClaims(ctx, token)
	}
	if typ, claims, ok := jose.Unverified(token); ok {
		app, found, err := a.federated(ctx, jose.String(claims, "iss"))
		if err != nil {
			return verify.Claims{}, err
		}
		if found {
			return a.applicationClaims(ctx, app, token, typ, r, dpop)
		}
	}
	if r != nil {
		return a.v.VerifyRequest(r)
	}
	return a.v.Verify(ctx, token)
}

// apiKeyClaims resolves an API key: its live role's permissions, bound to the
// group it was minted in (#248). Store errors never reach the response.
func (s *Engine) apiKeyClaims(ctx context.Context, token string) (verify.Claims, error) {
	p, err := s.ResolveAPIKey(ctx, token)
	switch {
	case errors.Is(err, iam.ErrAPIKeyRevoked):
		return verify.Claims{}, iam.ErrAPIKeyRevoked
	case errors.Is(err, iam.ErrAPIKeyExpired):
		return verify.Claims{}, iam.ErrAPIKeyExpired
	case err != nil:
		return verify.Claims{}, iam.ErrAPIKeyInvalid
	}
	return verify.Claims{
		Kind:        iam.ActorAPIKey,
		APIKeyID:    p.ID,
		Permissions: ident.Strings(p.Permissions),
		Group:       &verify.PermissionScope{GroupID: p.Group.ID, AuthorityIssuer: p.Issuer, Persona: p.Group.Persona},
	}, nil
}

// AddMFAEnrollmentExemptRoutes registers the anchored paths (mount prefix and
// route path) of the 2FA enrollment routes, matched exactly: the only paths
// a 2FA-enrollment-only token, or a user a Required policy has yet to
// enroll, may reach. A host route replacing one (HTTPConfig.Exclude) keeps
// the exemption; one that merely ends in the same path does not (ak#324).
func (s *Engine) AddMFAEnrollmentExemptRoutes(paths []string) {
	s.mfaExempt.mu.Lock()
	defer s.mfaExempt.mu.Unlock()
	if s.mfaExempt.paths == nil {
		s.mfaExempt.paths = map[string]bool{}
	}
	for _, p := range paths {
		if p = strings.TrimRight(strings.TrimSpace(p), "/"); p != "" {
			s.mfaExempt.paths[p] = true
		}
	}
}

type exemptPaths struct {
	mu    sync.RWMutex
	paths map[string]bool
}

func (e *exemptPaths) has(r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.paths[strings.TrimRight(r.URL.Path, "/")]
}
