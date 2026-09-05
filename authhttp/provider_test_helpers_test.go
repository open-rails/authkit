package authhttp

import (
	"context"
	"net/http"

	"github.com/open-rails/authkit/authprovider"
)

// testOAuth2Provider is an OAuth2 provider against a fake IdP rooted at base:
// /authorize, /token, and /me returning {id|sub, email, email_verified, login, name}.
func testOAuth2Provider(name, base, clientID, secret string, opts ...authprovider.Option) authprovider.Provider {
	return authprovider.OAuth2(name, base, authprovider.Endpoint{AuthorizeURL: base + "/authorize", TokenURL: base + "/token"},
		clientID, secret, testUserInfo(base+"/me"), opts...)
}

func testUserInfo(url string) authprovider.UserInfoFunc {
	return func(ctx context.Context, client *http.Client) (authprovider.Identity, error) {
		var me struct {
			ID       any    `json:"id"`
			Sub      string `json:"sub"`
			Email    string `json:"email"`
			Verified bool   `json:"email_verified"`
			Login    string `json:"login"`
			Name     string `json:"name"`
		}
		if err := authprovider.GetJSON(ctx, client, url, "", &me); err != nil {
			return authprovider.Identity{}, err
		}
		subject := authprovider.IdentityID(me.ID)
		if subject == "" {
			subject = me.Sub
		}
		return authprovider.Identity{Subject: subject, Email: me.Email, EmailVerified: me.Verified, PreferredUsername: me.Login, DisplayName: me.Name}, nil
	}
}

// setTestProviders installs providers on a Service without validation (tests
// that point at http fake IdPs).
func setTestProviders(s *Service, providers ...authprovider.Provider) {
	s.providers = make(map[string]authprovider.Provider, len(providers))
	for _, p := range providers {
		s.providers[p.Name()] = p
	}
}
