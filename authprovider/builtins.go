package authprovider

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Google is Google Sign-In over OIDC with PKCE.
func Google(clientID, clientSecret string, opts ...Option) Provider {
	return OIDC("google", "https://accounts.google.com", clientID, clientSecret,
		append([]Option{WithDisplayName("Google")}, opts...)...)
}

// AppleSecret is how Sign in with Apple authenticates the client: either a
// pre-minted client secret JWT (Static) or the developer key that mints a
// fresh ES256 JWT per exchange (TeamID, KeyID, PrivateKeyPEM; TTL defaults to
// five minutes).
type AppleSecret struct {
	Static        string
	TeamID        string
	KeyID         string
	PrivateKeyPEM []byte
	TTL           time.Duration
}

// Apple is Sign in with Apple over OIDC. Apple returns the authorization
// response as a cross-site POST (response_mode=form_post) whenever name or
// email is requested, does not support PKCE for web flows, and asserts
// email_verified on its ID token.
func Apple(clientID string, secret AppleSecret, opts ...Option) Provider {
	base := []Option{
		WithDisplayName("Apple"),
		WithScopes("openid", "email", "name"),
		WithPKCE(false),
		WithAuthParams(map[string]string{"response_mode": "form_post"}),
	}
	if secret.Static == "" {
		base = append(base, WithSecret(appleSecret{clientID: strings.TrimSpace(clientID), spec: secret}))
	}
	return OIDC("apple", "https://appleid.apple.com", clientID, secret.Static, append(base, opts...)...)
}

// appleSecret mints the client secret JWT lazily so an unusable key is a
// Validate error at boot and never a panic.
type appleSecret struct {
	clientID string
	spec     AppleSecret
}

func (s appleSecret) ClientSecret(ctx context.Context) (string, error) {
	mint, err := s.minter()
	if err != nil {
		return "", err
	}
	return mint(ctx)
}

func (s appleSecret) minter() (func(context.Context) (string, error), error) {
	return newAppleClientSecretMinter(s.spec.TeamID, s.spec.KeyID, s.clientID, s.spec.PrivateKeyPEM, s.spec.TTL)
}

func (s appleSecret) validate() error {
	_, err := s.minter()
	return err
}

// Discord is Discord OAuth2. /users/@me reports whether Discord itself has
// verified the address (`verified`), which is what EmailVerified carries.
func Discord(clientID, clientSecret string, opts ...Option) Provider {
	return OAuth2("discord", "https://discord.com",
		Endpoint{AuthorizeURL: "https://discord.com/api/oauth2/authorize", TokenURL: "https://discord.com/api/oauth2/token"},
		clientID, clientSecret, discordUserInfo("https://discord.com/api/users/@me"),
		append([]Option{WithDisplayName("Discord"), WithScopes("identify", "email")}, opts...)...)
}

func discordUserInfo(url string) UserInfoFunc {
	return func(ctx context.Context, client *http.Client) (Identity, error) {
		var me struct {
			ID         string `json:"id"`
			Username   string `json:"username"`
			GlobalName string `json:"global_name"`
			Email      string `json:"email"`
			Verified   bool   `json:"verified"`
		}
		if err := GetJSON(ctx, client, url, "", &me); err != nil {
			return Identity{}, err
		}
		return Identity{Subject: me.ID, Email: me.Email, EmailVerified: me.Verified, PreferredUsername: me.Username, DisplayName: me.GlobalName}, nil
	}
}

// GitHub is GitHub OAuth2 with PKCE. /user.email is the public profile
// address and carries no verification guarantee, so the verified address is
// taken from /user/emails (the primary+verified entry); the public address is
// only a fallback and is never reported verified.
func GitHub(clientID, clientSecret string, opts ...Option) Provider {
	return OAuth2("github", "https://github.com/login/oauth",
		Endpoint{AuthorizeURL: "https://github.com/login/oauth/authorize", TokenURL: "https://github.com/login/oauth/access_token"},
		clientID, clientSecret, gitHubUserInfo("https://api.github.com"),
		append([]Option{WithDisplayName("GitHub"), WithScopes("read:user", "user:email"), WithPKCE(true)}, opts...)...)
}

const gitHubAccept = "application/vnd.github+json"

func gitHubUserInfo(apiBase string) UserInfoFunc {
	return func(ctx context.Context, client *http.Client) (Identity, error) {
		var user struct {
			ID    any    `json:"id"`
			Login string `json:"login"`
			Name  string `json:"name"`
			Email string `json:"email"`
		}
		if err := GetJSON(ctx, client, apiBase+"/user", gitHubAccept, &user); err != nil {
			return Identity{}, err
		}
		id := IdentityID(user.ID)
		if id == "" {
			return Identity{}, errors.New("github: /user has no id")
		}
		identity := Identity{Subject: id, Email: strings.TrimSpace(user.Email), PreferredUsername: user.Login, DisplayName: user.Name}
		var emails []struct {
			Email    string `json:"email"`
			Primary  bool   `json:"primary"`
			Verified bool   `json:"verified"`
		}
		if err := GetJSON(ctx, client, apiBase+"/user/emails", gitHubAccept, &emails); err == nil {
			for _, e := range emails {
				if e.Primary && e.Verified && strings.TrimSpace(e.Email) != "" {
					identity.Email = strings.TrimSpace(e.Email)
					identity.EmailVerified = true
					break
				}
			}
		}
		return identity, nil
	}
}

// IdentityID renders a JSON id (string or number) as the subject string;
// numbers render without a fractional part.
func IdentityID(v any) string {
	switch id := v.(type) {
	case nil:
		return ""
	case string:
		return strings.TrimSpace(id)
	case float64:
		return fmt.Sprintf("%.0f", id)
	default:
		return strings.TrimSpace(fmt.Sprint(id))
	}
}
