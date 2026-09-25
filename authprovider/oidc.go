package authprovider

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/open-rails/authkit/internal/netguard"
	"github.com/zitadel/oidc/v3/pkg/client"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

const (
	// discoveryTTL bounds how long discovered metadata is fresh. Stale metadata
	// keeps serving while one background loop rediscovers it.
	discoveryTTL            = time.Hour
	discoveryAttemptTimeout = 5 * time.Second
	discoveryBackoffBase    = 500 * time.Millisecond
	discoveryBackoffMax     = time.Minute
)

// OIDC returns an OpenID Connect provider: endpoints and keys come from the
// issuer's discovery document, the ID token is verified (signature, audience,
// nonce) and identity is read from its standard claims. "openid" is always
// requested.
func OIDC(name, issuer, clientID, clientSecret string, opts ...Option) Provider {
	b := newBase(name, issuer, clientID, StaticSecret(clientSecret), []string{"openid", "email", "profile"}, true, opts)
	b.scopes = ensureOpenID(b.scopes)
	return &oidcProvider{base: b, ttl: discoveryTTL, backoffBase: discoveryBackoffBase, backoffMax: discoveryBackoffMax}
}

// discovery is the issuer metadata a login needs. keys is reused across
// rediscoveries of the same jwks_uri so its cached signing keys survive.
type discovery struct {
	endpoint oauth2.Endpoint
	jwksURI  string
	keys     oidc.KeySet
	expiry   time.Time
}

type oidcProvider struct {
	base
	ttl, backoffBase, backoffMax time.Duration

	mu         sync.Mutex
	disc       *discovery
	refreshing bool
	attempted  chan struct{} // closed after the running loop's first attempt
	lastErr    error
}

func (p *oidcProvider) SupportsStepUp() bool { return true }

func (p *oidcProvider) Validate() error { return p.validate() }

// CheckHealth reports the last discovery failure without network I/O; nil
// once discovery has succeeded (or before it was first needed).
func (p *oidcProvider) CheckHealth(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lastErr != nil {
		return fmt.Errorf("%w: %s discovery: %w", ErrProviderUnavailable, p.name, p.lastErr)
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

// discovery returns the issuer metadata, stale-while-revalidate: cached
// metadata is served past its TTL while one background loop rediscovers it. A
// request waits only before the first success, and then for at most one
// bounded attempt; afterwards it fails fast with ErrProviderUnavailable until
// the loop succeeds.
func (p *oidcProvider) discovery(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	d := p.disc
	if d == nil || time.Now().After(d.expiry) {
		p.startRefreshLocked()
	}
	attempted := p.attempted
	p.mu.Unlock()
	if d != nil {
		return d, nil
	}
	select {
	case <-attempted:
	case <-ctx.Done():
	}
	p.mu.Lock()
	d, err := p.disc, cmp.Or(p.lastErr, ctx.Err())
	p.mu.Unlock()
	if d == nil {
		return nil, fmt.Errorf("%w: %s discovery: %w", ErrProviderUnavailable, p.name, err)
	}
	return d, nil
}

func (p *oidcProvider) startRefreshLocked() {
	if p.refreshing {
		return
	}
	p.refreshing, p.attempted = true, make(chan struct{})
	go p.refreshLoop(p.attempted)
}

func (p *oidcProvider) refreshLoop(attempted chan struct{}) {
	for attempt := 0; ; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), discoveryAttemptTimeout)
		cfg, err := client.Discover(ctx, p.issuer, p.httpClient)
		cancel()
		p.mu.Lock()
		p.lastErr = err
		if err == nil {
			d := &discovery{
				endpoint: oauth2.Endpoint{AuthURL: cfg.AuthorizationEndpoint, TokenURL: cfg.TokenEndpoint},
				jwksURI:  cfg.JwksURI,
				expiry:   time.Now().Add(p.ttl),
			}
			if p.disc != nil && p.disc.jwksURI == d.jwksURI {
				d.keys = p.disc.keys
			} else {
				d.keys = rp.NewRemoteKeySet(p.httpClient, d.jwksURI)
			}
			p.disc, p.refreshing = d, false
		}
		p.mu.Unlock()
		if attempt == 0 {
			close(attempted)
		}
		if err == nil {
			return
		}
		time.Sleep(netguard.Backoff(attempt, p.backoffBase, p.backoffMax))
	}
}

func ensureOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append([]string{"openid"}, scopes...)
}
