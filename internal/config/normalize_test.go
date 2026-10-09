package config

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
)

// Normalizing a normalized Config changes nothing: the engine hands its
// Config to code that may normalize it again.
func TestNormalizeIsIdempotent(t *testing.T) {
	deps := Deps{
		Postgres: &pgxpool.Pool{},
		Email:    nopEmail{},
		DelegatedAuthorization: func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{}, nil
		},
	}
	for name, c := range map[string]Config{
		"minimal": {Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}},
		"rich": {
			Token:     TokenConfig{Issuer: "https://example.com/auth", IssuedAudiences: []string{"app"}, AccountIssuers: []string{"https://peer.example"}},
			Password:  PasswordPolicy{MinLength: 12},
			Username:  UsernameConfig{Renames: true, FormerNames: FormerNamesConfig{Mode: FormerNamesForever}},
			Languages: LanguageConfig{Supported: []string{"EN", "es-MX"}, Default: "es"},
			Delegated: DelegatedConfig{Audiences: []string{"platform"}, TTLCeiling: 2 * time.Hour},
			HTTP:      &HTTPConfig{DirectPeerIP: true, APIPath: "/"},
		},
	} {
		once, err := Normalize(c, deps)
		require.NoError(t, err, name)
		twice, err := Normalize(once, deps)
		require.NoError(t, err, name)
		require.Equal(t, once, twice, name)
	}
}

// A delegated-token setting without the route's audiences is dead
// configuration and refuses.
func TestNormalizeRefusesDeadDelegatedConfig(t *testing.T) {
	c := Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}}
	c.Delegated.TTLDefault = time.Minute
	_, err := Normalize(c, Deps{})
	require.ErrorContains(t, err, "Delegated.Audiences is empty")
}

type nopEmail struct{}

func (nopEmail) Send(context.Context, iam.EmailMessage) error { return nil }
func (nopEmail) CheckHealth(context.Context) error            { return nil }

// The authorization server's clients refuse grant combinations that could
// not work or would be unsafe, and a client ID that could pass for a user.
func TestNormalizeAuthorizationServerClients(t *testing.T) {
	secret := strings.Repeat("a", 64)
	base := func(cl OAuthClientConfig) Config {
		return Config{
			Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}},
			HTTP:  &HTTPConfig{DirectPeerIP: true},
			AuthorizationServer: AuthorizationServerConfig{
				Resources: []ResourceServerConfig{{ID: "https://api.example.com", Scopes: []string{"api"}, Permissions: []string{"merchant:*"}}},
				Clients:   []OAuthClientConfig{cl},
			},
		}
	}
	ok := []OAuthClientConfig{
		{ID: "console", RedirectURIs: []string{"https://c.example/cb"}, GrantTypes: []OAuthGrantType{GrantAuthorizationCode, GrantRefreshToken}},
		{ID: "admin-ui", Resources: []string{"https://api.example.com"}, Origins: []string{"https://admin.example.com"}, GrantTypes: []OAuthGrantType{GrantTokenExchange}},
		{ID: "worker", SecretSHA256: secret, Resources: []string{"https://api.example.com"}, Permissions: []string{"merchant:payouts:read"}, GrantTypes: []OAuthGrantType{GrantClientCredentials}},
	}
	for _, cl := range ok {
		once, err := Normalize(base(cl), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
		require.NoError(t, err, cl.ID)
		require.Equal(t, DefaultOAuthRefreshTokenTTL, once.AuthorizationServer.RefreshTokenTTL)
	}
	for name, tc := range map[string]struct {
		client OAuthClientConfig
		want   string
	}{
		"refresh without code":         {OAuthClientConfig{ID: "c", GrantTypes: []OAuthGrantType{GrantRefreshToken}}, "refresh tokens come only with"},
		"public client credentials":    {OAuthClientConfig{ID: "c", Resources: []string{"https://api.example.com"}, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "confidential client"},
		"client credentials no target": {OAuthClientConfig{ID: "c", SecretSHA256: secret, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "need Resources"},
		"exchange no target":           {OAuthClientConfig{ID: "c", GrantTypes: []OAuthGrantType{GrantTokenExchange}}, "needs Resources"},
		"permissions without grant":    {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, Permissions: []string{"merchant:*"}}, "client-credentials client's own grants"},
		"root permissions":             {OAuthClientConfig{ID: "c", SecretSHA256: secret, Resources: []string{"https://api.example.com"}, Permissions: []string{"root:*"}, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "root namespace"},
		"UUID client ID":               {OAuthClientConfig{ID: "0199b1a2-7c3d-7e4f-8a9b-0c1d2e3f4a5b", RedirectURIs: []string{"https://c.example/cb"}}, "looks like a user ID"},
		"origin with a path":           {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, Origins: []string{"https://admin.example.com/app"}}, "is not an origin"},
		"plain-http origin":            {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, Origins: []string{"http://admin.example.com"}}, "must use https"},
		"unknown grant":                {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, GrantTypes: []OAuthGrantType{"password"}}, "unsupported grant type"},
	} {
		_, err := Normalize(base(tc.client), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
		require.ErrorContains(t, err, tc.want, name)
	}
	c := base(ok[0])
	c.AuthorizationServer.RefreshTokenTTL = 31 * 24 * time.Hour
	_, err := Normalize(c, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
	require.ErrorContains(t, err, "RefreshTokenTTL")

	// Grant extensions: authorization_details need a grant authorizer, and
	// the per-client knobs are bounded.
	grants := func(context.Context, iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{}, nil
	}
	machine := OAuthClientConfig{ID: "cli", RedirectURIs: []string{"https://c.example/cb"}, GrantTypes: []OAuthGrantType{GrantAuthorizationCode, GrantRefreshToken},
		AuthorizationDetailsTypes: []string{"machine", "machine"}, Offline: true, KeyBound: true, AccessTokenTTL: time.Minute, RefreshTokenTTL: 7 * 24 * time.Hour}
	_, err = Normalize(base(machine), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
	require.ErrorContains(t, err, "Deps.OAuthGrants")
	once, err := Normalize(base(machine), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}, OAuthGrants: grants})
	require.NoError(t, err)
	require.Equal(t, []string{"machine"}, once.AuthorizationServer.Clients[0].AuthorizationDetailsTypes)
	require.Equal(t, time.Minute, OAuthClientAccessTTL(once.AuthorizationServer, once.AuthorizationServer.Clients[0]))
	require.Equal(t, 7*24*time.Hour, OAuthClientRefreshTTL(once.AuthorizationServer, once.AuthorizationServer.Clients[0]))
	for want, mutate := range map[string]func(*OAuthClientConfig){
		"AccessTokenTTL must be":  func(c *OAuthClientConfig) { c.AccessTokenTTL = 16 * time.Minute },
		"RefreshTokenTTL must be": func(c *OAuthClientConfig) { c.RefreshTokenTTL = 31 * 24 * time.Hour },
		"Offline needs the refresh_token": func(c *OAuthClientConfig) {
			c.GrantTypes = []OAuthGrantType{GrantAuthorizationCode}
			c.RefreshTokenTTL = 0
		},
		"RefreshTokenTTL needs":              func(c *OAuthClientConfig) { c.GrantTypes = []OAuthGrantType{GrantAuthorizationCode}; c.Offline = false },
		"invalid authorization_details type": func(c *OAuthClientConfig) { c.AuthorizationDetailsTypes = []string{"has space"} },
	} {
		cl := machine
		mutate(&cl)
		_, err := Normalize(base(cl), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}, OAuthGrants: grants})
		require.ErrorContains(t, err, want)
	}
}
