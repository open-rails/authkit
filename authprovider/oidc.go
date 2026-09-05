package authprovider

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
	"golang.org/x/oauth2"
)

// discoveryTTL bounds how long a relying party built from OIDC discovery is
// reused before the issuer's metadata and key set are fetched again.
const discoveryTTL = time.Hour

// OIDC returns an OpenID Connect provider: endpoints and keys come from the
// issuer's discovery document, the ID token is verified (signature, audience,
// nonce) and identity is read from its standard claims. "openid" is always
// requested.
func OIDC(name, issuer, clientID, clientSecret string, opts ...Option) Provider {
	b := newBase(name, issuer, clientID, StaticSecret(clientSecret), []string{"openid", "email", "profile"}, true, opts)
	b.scopes = ensureOpenID(b.scopes)
	return &oidcProvider{base: b, rps: map[string]rpEntry{}}
}

type rpEntry struct {
	rp     rp.RelyingParty
	expiry time.Time
}

type oidcProvider struct {
	base
	mu  sync.Mutex
	rps map[string]rpEntry // by redirect URI
}

func (p *oidcProvider) SupportsStepUp() bool { return true }

func (p *oidcProvider) Validate() error { return p.validate() }

func (p *oidcProvider) AuthCodeURL(ctx context.Context, req AuthRequest) (string, error) {
	rpc, err := p.relyingParty(ctx, req.RedirectURI)
	if err != nil {
		return "", err
	}
	opts := []rp.AuthURLOpt{rp.AuthURLOpt(rp.WithURLParam("nonce", req.Nonce))}
	if p.pkce && req.CodeChallenge != "" {
		opts = append(opts, rp.WithCodeChallenge(req.CodeChallenge), rp.AuthURLOpt(rp.WithURLParam("code_challenge_method", "S256")))
	}
	for k, v := range p.authParams {
		opts = append(opts, rp.AuthURLOpt(rp.WithURLParam(k, v)))
	}
	for k, v := range req.Params {
		opts = append(opts, rp.AuthURLOpt(rp.WithURLParam(k, v)))
	}
	return rp.AuthURL(req.State, rpc, opts...), nil
}

func (p *oidcProvider) Exchange(ctx context.Context, req ExchangeRequest) (Identity, error) {
	rpc, err := p.relyingParty(ctx, req.RedirectURI)
	if err != nil {
		return Identity{}, err
	}
	secret, err := p.clientSecret(ctx)
	if err != nil {
		return Identity{}, err
	}
	cfg := *rpc.OAuthConfig()
	cfg.ClientSecret = secret
	var opts []oauth2.AuthCodeOption
	if req.CodeVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.CodeVerifier))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	token, err := cfg.Exchange(ctx, req.Code, opts...)
	if err != nil {
		return Identity{}, fmt.Errorf("%s: token exchange: %w", p.name, err)
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	if rawIDToken == "" {
		return Identity{}, fmt.Errorf("%s: no id_token in token response", p.name)
	}
	verifier := rpc.IDTokenVerifier()
	nonce := req.Nonce
	claims, err := rp.VerifyIDToken[*oidc.IDTokenClaims](ctx, rawIDToken, rp.NewIDTokenVerifier(
		verifier.Issuer, verifier.ClientID, verifier.KeySet,
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

// relyingParty returns the discovery-backed relying party for a redirect URI,
// refreshed every discoveryTTL. The client secret is never part of it: the
// exchange sets the (possibly per-request) secret on a copy of its config.
func (p *oidcProvider) relyingParty(ctx context.Context, redirectURI string) (rp.RelyingParty, error) {
	now := time.Now()
	p.mu.Lock()
	if e, ok := p.rps[redirectURI]; ok && now.Before(e.expiry) {
		p.mu.Unlock()
		return e.rp, nil
	}
	p.mu.Unlock()

	built, err := rp.NewRelyingPartyOIDC(ctx, p.issuer, p.clientID, "", redirectURI, p.scopes, rp.WithHTTPClient(p.httpClient))
	if err != nil {
		return nil, fmt.Errorf("%s: discovery: %w", p.name, err)
	}
	p.mu.Lock()
	p.rps[redirectURI] = rpEntry{rp: built, expiry: now.Add(discoveryTTL)}
	p.mu.Unlock()
	return built, nil
}

func ensureOpenID(scopes []string) []string {
	for _, s := range scopes {
		if s == "openid" {
			return scopes
		}
	}
	return append([]string{"openid"}, scopes...)
}
