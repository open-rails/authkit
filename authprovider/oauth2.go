package authprovider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
)

// Endpoint is a plain OAuth2 authorization server. Client credentials are sent
// in the token request body.
type Endpoint struct {
	AuthorizeURL string
	TokenURL     string
}

// UserInfoFunc reads the signed-in user's identity. client already sends the
// access token as a bearer credential.
type UserInfoFunc func(ctx context.Context, client *http.Client) (Identity, error)

// OAuth2 returns a provider for an authorization server without OpenID
// Connect: the code is exchanged for an access token and userInfo reads the
// identity with it. issuer keys the stored provider links.
func OAuth2(name, issuer string, ep Endpoint, clientID, clientSecret string, userInfo UserInfoFunc, opts ...Option) Provider {
	return &oauth2Provider{base: newBase(name, issuer, clientID, StaticSecret(clientSecret), nil, false, opts), ep: ep, userInfo: userInfo}
}

type oauth2Provider struct {
	base
	ep       Endpoint
	userInfo UserInfoFunc
}

func (p *oauth2Provider) SupportsStepUp() bool { return false }

func (p *oauth2Provider) Validate() error {
	if err := p.validate(); err != nil {
		return err
	}
	for _, u := range []string{p.ep.AuthorizeURL, p.ep.TokenURL} {
		if err := requireHTTPS(u); err != nil {
			return err
		}
	}
	if p.userInfo == nil {
		return fmt.Errorf("%w: %s has no userinfo reader", ErrProviderInvalid, p.name)
	}
	return nil
}

func (p *oauth2Provider) config(secret, redirectURI string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     p.clientID,
		ClientSecret: secret,
		RedirectURL:  redirectURI,
		Scopes:       p.scopes,
		Endpoint:     oauth2.Endpoint{AuthURL: p.ep.AuthorizeURL, TokenURL: p.ep.TokenURL, AuthStyle: oauth2.AuthStyleInParams},
	}
}

func (p *oauth2Provider) AuthCodeURL(_ context.Context, req AuthRequest) (string, error) {
	var opts []oauth2.AuthCodeOption
	if p.pkce && req.CodeChallenge != "" {
		opts = append(opts, oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	}
	for k, v := range p.authParams {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	for k, v := range req.Params {
		opts = append(opts, oauth2.SetAuthURLParam(k, v))
	}
	return p.config("", req.RedirectURI).AuthCodeURL(req.State, opts...), nil
}

func (p *oauth2Provider) Exchange(ctx context.Context, req ExchangeRequest) (Identity, error) {
	secret, err := p.clientSecret(ctx)
	if err != nil {
		return Identity{}, err
	}
	var opts []oauth2.AuthCodeOption
	if req.CodeVerifier != "" {
		opts = append(opts, oauth2.VerifierOption(req.CodeVerifier))
	}
	ctx = context.WithValue(ctx, oauth2.HTTPClient, p.httpClient)
	cfg := p.config(secret, req.RedirectURI)
	token, err := cfg.Exchange(ctx, req.Code, opts...)
	if err != nil {
		return Identity{}, fmt.Errorf("%s: token exchange: %w", p.name, err)
	}
	if strings.TrimSpace(token.AccessToken) == "" {
		return Identity{}, errors.New(p.name + ": token response has no access_token")
	}
	identity, err := p.userInfo(ctx, oauth2.NewClient(ctx, oauth2.StaticTokenSource(token)))
	if err != nil {
		return Identity{}, fmt.Errorf("%s: userinfo: %w", p.name, err)
	}
	if strings.TrimSpace(identity.Subject) == "" {
		return Identity{}, errors.New(p.name + ": userinfo has no subject")
	}
	identity.EmailVerified = identity.EmailVerified && strings.TrimSpace(identity.Email) != ""
	return identity, nil
}

// GetJSON fetches url with client (Accept: accept when non-empty) and decodes
// the JSON body into out. A non-200 status is an error. UserInfoFunc
// implementations use it to read userinfo endpoints.
func GetJSON(ctx context.Context, client *http.Client, url, accept string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", url, resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}
