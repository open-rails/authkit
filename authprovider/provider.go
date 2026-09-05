// Package authprovider defines the external identity providers AuthKit's
// browser login flows delegate to. A Provider owns everything specific to one
// IdP — endpoints, scopes, PKCE, the shape of its authorization response, how
// its client secret is produced, and how its identity is read — so the HTTP
// layer keeps only the browser state machine. Use Google/Apple/Discord/GitHub
// for the built-ins and OIDC/OAuth2 for anything else.
package authprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/open-rails/authkit/internal/netguard"
)

var (
	ErrProviderNonHTTPSURL = errors.New("provider_non_https_url")
	ErrProviderInvalid     = errors.New("provider_invalid")
)

// Identity is what a provider asserts about the signed-in user after a
// successful code exchange. EmailVerified is true only when the provider
// itself vouches for the address.
type Identity struct {
	Subject           string
	Email             string
	EmailVerified     bool
	PreferredUsername string
	DisplayName       string
	// AuthTime is when the user last authenticated interactively at the IdP;
	// zero when the provider does not assert one.
	AuthTime time.Time
}

// AuthRequest carries the per-flow values the browser state machine generated.
// CodeChallenge is set only when the provider reports PKCE.
type AuthRequest struct {
	State         string
	Nonce         string
	CodeChallenge string
	RedirectURI   string
	// Params are extra authorization parameters for this request (for example
	// max_age=0 on a step-up).
	Params map[string]string
}

// ExchangeRequest carries the authorization response plus the flow values it
// must be checked against.
type ExchangeRequest struct {
	Code         string
	CodeVerifier string
	Nonce        string
	RedirectURI  string
}

// Provider is one external identity provider.
type Provider interface {
	// Name is the slug used in routes (/oidc/{name}/…) and stored on links.
	Name() string
	DisplayName() string
	// Issuer identifies the identity source; provider links are keyed by it.
	Issuer() string
	// PKCE reports whether the authorization request carries an S256 challenge.
	PKCE() bool
	// ResponseModeFormPost reports whether the IdP posts the authorization
	// response cross-site (response_mode=form_post) instead of redirecting.
	ResponseModeFormPost() bool
	// SupportsStepUp reports whether a completed login proves a fresh
	// interactive authentication (OIDC max_age=0 checked against auth_time).
	// OAuth2 IdPs silently re-authorize an approved app, so they never do.
	SupportsStepUp() bool
	AuthCodeURL(ctx context.Context, req AuthRequest) (string, error)
	Exchange(ctx context.Context, req ExchangeRequest) (Identity, error)
	// Validate checks the static configuration; it performs no network calls.
	Validate() error
}

// Secret produces the client secret sent on a code exchange.
type Secret interface {
	ClientSecret(ctx context.Context) (string, error)
}

// StaticSecret is a fixed client secret.
type StaticSecret string

func (s StaticSecret) ClientSecret(context.Context) (string, error) { return string(s), nil }

// SecretFunc mints a client secret per exchange.
type SecretFunc func(ctx context.Context) (string, error)

func (f SecretFunc) ClientSecret(ctx context.Context) (string, error) { return f(ctx) }

// Option adjusts a provider at construction.
type Option func(*base)

// WithScopes replaces the requested scopes.
func WithScopes(scopes ...string) Option {
	return func(b *base) { b.scopes = append([]string(nil), scopes...) }
}

// WithDisplayName sets the human-readable name reported by DisplayName.
func WithDisplayName(name string) Option {
	return func(b *base) { b.displayName = strings.TrimSpace(name) }
}

// WithSecret replaces the client secret source (dynamic secrets).
func WithSecret(secret Secret) Option {
	return func(b *base) { b.secret = secret }
}

// WithPKCE turns the S256 code challenge on or off.
func WithPKCE(on bool) Option {
	return func(b *base) { b.pkce = on }
}

// WithHTTPClient sets the outbound client for discovery, token and userinfo
// calls. The default is timeout-bounded and may reach private addresses,
// since IdP endpoints are operator configuration.
func WithHTTPClient(c *http.Client) Option {
	return func(b *base) {
		if c != nil {
			b.httpClient = c
		}
	}
}

// WithAuthParams adds fixed authorization-request parameters (for example
// response_mode=form_post).
func WithAuthParams(params map[string]string) Option {
	return func(b *base) {
		if b.authParams == nil {
			b.authParams = map[string]string{}
		}
		for k, v := range params {
			b.authParams[k] = v
		}
	}
}

type base struct {
	name        string
	displayName string
	issuer      string
	clientID    string
	secret      Secret
	scopes      []string
	pkce        bool
	authParams  map[string]string
	httpClient  *http.Client
}

func newBase(name, issuer, clientID string, secret Secret, scopes []string, pkce bool, opts []Option) base {
	b := base{
		name:       strings.ToLower(strings.TrimSpace(name)),
		issuer:     strings.TrimSpace(issuer),
		clientID:   strings.TrimSpace(clientID),
		secret:     secret,
		scopes:     append([]string(nil), scopes...),
		pkce:       pkce,
		httpClient: netguard.Client(netguard.DefaultTimeout, true),
	}
	for _, o := range opts {
		if o != nil {
			o(&b)
		}
	}
	if b.displayName == "" {
		b.displayName = b.name
	}
	return b
}

func (b *base) Name() string        { return b.name }
func (b *base) DisplayName() string { return b.displayName }
func (b *base) Issuer() string      { return b.issuer }
func (b *base) PKCE() bool          { return b.pkce }
func (b *base) ResponseModeFormPost() bool {
	return strings.EqualFold(b.authParams["response_mode"], "form_post")
}

func (b *base) clientSecret(ctx context.Context) (string, error) {
	if b.secret == nil {
		return "", fmt.Errorf("%w: %s has no client secret", ErrProviderInvalid, b.name)
	}
	return b.secret.ClientSecret(ctx)
}

func (b *base) validate() error {
	if b.name == "" {
		return fmt.Errorf("%w: provider name is required", ErrProviderInvalid)
	}
	if b.issuer == "" {
		return fmt.Errorf("%w: %s has no issuer", ErrProviderInvalid, b.name)
	}
	if b.clientID == "" {
		return fmt.Errorf("%w: %s has no client id", ErrProviderInvalid, b.name)
	}
	if b.secret == nil {
		return fmt.Errorf("%w: %s has no client secret", ErrProviderInvalid, b.name)
	}
	if s, ok := b.secret.(StaticSecret); ok && strings.TrimSpace(string(s)) == "" {
		return fmt.Errorf("%w: %s has an empty client secret", ErrProviderInvalid, b.name)
	}
	if v, ok := b.secret.(interface{ validate() error }); ok {
		return v.validate()
	}
	return nil
}

func requireHTTPS(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return fmt.Errorf("%w: %s", ErrProviderNonHTTPSURL, raw)
	}
	return nil
}
