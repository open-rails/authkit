package provider

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/internal/cachepolicy"
	"github.com/open-rails/helpers/cache"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// OIDC returns an OpenID Connect provider: endpoints and keys come from the
// issuer's discovery document, the ID token is verified (signature, audience,
// nonce) and identity is read from its standard claims. "openid" is always
// requested. Discovery is cached under cachepolicy.OIDCDiscovery: stale
// metadata keeps serving while it is reloaded, up to MaxStale after the last
// success; past that logins fail closed, so blocking discovery cannot keep
// revoked keys valid.
func OIDC(name, issuer, clientID, clientSecret string, opts ...Option) Provider {
	b := newBase(name, issuer, clientID, StaticSecret(clientSecret), []string{"openid", "email", "profile"}, true, opts)
	b.scopes = ensureOpenID(b.scopes)
	p := &oidcProvider{base: b}
	p.useCache(cachepolicy.OIDCDiscovery)
	return p
}

// discovery is the issuer metadata a login needs, with a key set built for it.
type discovery struct {
	endpoint oauth2.Endpoint
	keys     oidc.KeySet
}

type oidcProvider struct {
	base
	opts cache.Options
	disc *cache.Cache[string, *discovery]

	mu        sync.Mutex
	fetchedAt time.Time
	lastErr   error
}

func (p *oidcProvider) useCache(o cache.Options) {
	p.opts, p.disc = o, cachepolicy.New(o, p.load)
}

func (p *oidcProvider) SupportsStepUp() bool { return true }

func (p *oidcProvider) Validate() error { return p.validate() }

// CheckHealth reports the last discovery failure; nil once discovery has
// succeeded (or before it was first needed). It reads discovery through the
// cache, so a failing provider is retried without logins (at most once per
// failure backoff).
func (p *oidcProvider) CheckHealth(ctx context.Context) error {
	p.mu.Lock()
	used := !p.fetchedAt.IsZero() || p.lastErr != nil
	p.mu.Unlock()
	if used {
		_, _ = p.disc.Get(ctx, []string{p.issuer})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.fetchedAt.IsZero() && cachepolicy.Now(p.opts).Sub(p.fetchedAt) > p.opts.MaxStale {
		return fmt.Errorf("%w: %s discovery older than %s, logins failing closed: %w", ErrUnavailable, p.name, p.opts.MaxStale, cmp.Or(p.lastErr, errDiscoveryPastMaxStale))
	}
	if p.lastErr != nil {
		return fmt.Errorf("%w: %s discovery: %w", ErrUnavailable, p.name, p.lastErr)
	}
	return nil
}

func (p *oidcProvider) config(d *discovery, secret, redirectURI string) *oauth2.Config {
	return &oauth2.Config{ClientID: p.clientID, ClientSecret: secret, RedirectURL: redirectURI, Scopes: p.scopes, Endpoint: d.endpoint}
}

func (p *oidcProvider) AuthCodeURL(ctx context.Context, req AuthRequest) (string, error) {
	d, err := p.discovery(ctx)
	if err != nil {
		return "", err
	}
	opts := []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("nonce", req.Nonce)}
	if p.pkce && req.CodeChallenge != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	for k, v := range p.authParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	for k, v := range req.Params {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return p.config(d, "", req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

func (p *oidcProvider) Exchange(ctx context.Context, req ExchangeRequest) (Identity, error) {
	d, err := p.discovery(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx, classify := trackOutage(ctx)
	identity, err := p.exchange(ctx, d, req)
	return identity, classify(err)
}

func (p *oidcProvider) exchange(ctx context.Context, d *discovery, req ExchangeRequest) (Identity, error) {
	secret, err := p.clientSecret(ctx)
	if err != nil {
		return Identity{}, err
	}
	var opts []oauth2.AuthCodeOption
	if req.CodeVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.CodeVerifier))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	token, err := p.config(d, secret, req.RedirectURI).Exchange(ctx, req.Code, opts...)
	if err != nil {
		return Identity{}, fmt.Errorf("%s: token exchange: %w", p.name, err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return Identity{}, fmt.Errorf("%s: no id_token in token response", p.name)
	}
	nonce := req.Nonce
	claims, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, rawIDToken, rp.NewIDTokenVerifier(
		p.issuer, p.clientID, d.keys,
		rp.WithNonce(func(context.Context) string { return nonce }),
	))
	if err != nil {
		return Identity{}, fmt.Errorf("%s: id_token verification: %w", p.name, err)
	}
	if claims == nil || claims.GetSubject() == "" {
		return Identity{}, errors.New(p.name + ": id_token has no subject")
	}
	return Identity{
		Subject:           claims.GetSubject(),
		Email:             strings.TrimSpace(claims.UserInfoEmail.Email),
		EmailVerified:     bool(claims.UserInfoEmail.EmailVerified),
		PreferredUsername: claims.PreferredUsername,
		DisplayName:       claims.UserInfoProfile.Name,
		AuthTime:          claims.GetAuthTime(),
	}, nil
}

// discovery returns the issuer metadata. A request waits only when none is
// usable, and then for at most one bounded load.
func (p *oidcProvider) discovery(ctx context.Context) (*discovery, error) {
	m, err := p.disc.Get(ctx, []string{p.issuer})
	if d := m[p.issuer]; d != nil {
		return d, nil
	}
	return nil, fmt.Errorf("%w: %s discovery: %w", ErrUnavailable, p.name, cmp.Or(err, errDiscoveryPastMaxStale))
}

var errDiscoveryPastMaxStale = errors.New("discovery metadata exceeds max stale")

func (p *oidcProvider) load(ctx context.Context, _ []string) (map[string]*discovery, error) {
	cfg, err := client.Discover(ctx, p.issuer, p.httpClient)
	p.mu.Lock()
	defer p.mu.Unlock()
	failing := p.lastErr != nil
	if p.lastErr = err; err != nil {
		if !failing {
			slog.WarnContext(ctx, "authkit: identity provider discovery failed; its sign-ins answer provider_unavailable while it is retried", "provider", p.name, "error", err)
		}
		return nil, err
	}
	if failing {
		slog.InfoContext(ctx, "authkit: identity provider discovery recovered", "provider", p.name)
	}
	p.fetchedAt = cachepolicy.Now(p.opts)
	// A fresh key set per discovery: the library's set never drops keys, so
	// reusing it would keep keys the IdP has revoked.
	d := &discovery{endpoint: oauth2.Endpoint{AuthURL: cfg.AuthorizationEndpoint, TokenURL: cfg.TokenEndpoint},
		keys: rp.NewRemoteKeySet(p.httpClient, cfg.JwksURI)}
	return map[string]*discovery{p.issuer: d}, nil
}

func ensureOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append([]string{"openid"}, scopes...)
}
