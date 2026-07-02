package authprovider

import (
	"errors"
	"fmt"
	"strings"
)

var builtIns = map[string]Provider{
	// Google and Apple are OIDC: identity comes from standard ID-token claims read
	// on the oidc path (see http/oidc_browser.go), so they carry no IdentityMapper.
	"google": {
		Name:   "google",
		Kind:   KindOIDC,
		Issuer: "https://accounts.google.com",
		Scopes: []string{"openid", "email", "profile"},
		PKCE:   true,
	},
	"apple": {
		Name:            "apple",
		Kind:            KindOIDC,
		Issuer:          "https://appleid.apple.com",
		Scopes:          []string{"openid", "email", "name"},
		PKCE:            false,
		ExtraAuthParams: map[string]string{"response_mode": "form_post"},
	},
	"discord": {
		Name:           "discord",
		Kind:           KindOAuth2,
		Issuer:         "https://discord.com",
		AuthorizeURL:   "https://discord.com/api/oauth2/authorize",
		TokenURL:       "https://discord.com/api/oauth2/token",
		UserInfoURL:    "https://discord.com/api/users/@me",
		Scopes:         []string{"identify", "email"},
		IdentityMapper: mapDiscordIdentity,
	},
	"github": {
		Name:           "github",
		Kind:           KindOAuth2,
		Issuer:         "https://github.com/login/oauth",
		AuthorizeURL:   "https://github.com/login/oauth/authorize",
		TokenURL:       "https://github.com/login/oauth/access_token",
		UserInfoURL:    "https://api.github.com/user",
		UserInfoAccept: "application/vnd.github+json",
		Scopes:         []string{"read:user", "user:email"},
		PKCE:           true,
		IdentityMapper: mapGitHubIdentity,
		// GitHub's /user.email is the public profile address and carries NO
		// verification guarantee, so mapGitHubIdentity must NOT assert
		// email_verified. A verified address is sourced only from the
		// /user/emails fallback below, which selects the primary+verified entry
		// (AK security audit F4).
		EmailFallbackURL:    "https://api.github.com/user/emails",
		EmailFallbackAccept: "application/vnd.github+json",
	},
}

// mapDiscordIdentity reads the Discord /users/@me userinfo JSON into an Identity.
func mapDiscordIdentity(root any) (Identity, error) {
	subject := stringField(root, "id")
	if subject == "" {
		return Identity{}, errors.New("provider_mapping_missing_subject")
	}
	return Identity{
		Subject:           subject,
		Email:             stringField(root, "email"),
		EmailVerified:     boolField(root, "verified"),
		PreferredUsername: stringField(root, "username"),
		DisplayName:       stringField(root, "global_name"),
	}, nil
}

// mapGitHubIdentity reads the GitHub /user userinfo JSON into an Identity. It
// deliberately leaves EmailVerified false: /user.email is unverified, and a
// verified address is sourced only from the /user/emails fallback (AK F4).
func mapGitHubIdentity(root any) (Identity, error) {
	subject := stringField(root, "id")
	if subject == "" {
		return Identity{}, errors.New("provider_mapping_missing_subject")
	}
	return Identity{
		Subject:           subject,
		Email:             stringField(root, "email"),
		PreferredUsername: stringField(root, "login"),
		DisplayName:       stringField(root, "name"),
	}, nil
}

// stringField reads root[key] as a trimmed string. Numeric ids (JSON numbers
// decode to float64) render without a fractional part via fmt.Sprint.
func stringField(root any, key string) string {
	m, ok := root.(map[string]any)
	if !ok {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

// boolField reads root[key] as a bool (false when absent or not a JSON bool).
func boolField(root any, key string) bool {
	m, ok := root.(map[string]any)
	if !ok {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

// Google returns the built-in Google OIDC provider configured with the given
// OAuth client credentials — the convenience form of an authprovider.Provider
// for IdentityConfig.Providers (#143). Override fields on the result for custom
// scopes/mapping.
func Google(clientID, clientSecret string) Provider {
	return builtInWithCredentials("google", clientID, clientSecret)
}

// Apple returns the built-in Apple OIDC provider configured with the given OAuth
// client credentials. For the Apple "client secret JWT" strategy, set
// ClientSecret.Strategy / ClientSecret.AppleJWT on the returned provider.
func Apple(clientID, clientSecret string) Provider {
	return builtInWithCredentials("apple", clientID, clientSecret)
}

// Discord returns the built-in Discord OAuth2 provider configured with the given
// OAuth client credentials.
func Discord(clientID, clientSecret string) Provider {
	return builtInWithCredentials("discord", clientID, clientSecret)
}

// GitHub returns the built-in GitHub OAuth2 provider configured with the given
// OAuth client credentials.
func GitHub(clientID, clientSecret string) Provider {
	return builtInWithCredentials("github", clientID, clientSecret)
}

// builtInWithCredentials clones a built-in template and sets static client
// credentials. The named built-in always exists (compile-time-known keys).
func builtInWithCredentials(name, clientID, clientSecret string) Provider {
	p, _ := BuiltIn(name)
	p.ClientID = clientID
	p.ClientSecret = ClientSecret{Value: clientSecret}
	return p
}
