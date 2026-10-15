package config

import (
	"context"
	"errors"
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
		OAuthGrants: func(context.Context, iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
			return iam.OAuthGrantDecision{}, nil
		},
	}
	for name, c := range map[string]Config{
		"minimal": {Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}},
		"rich": {
			Token:     TokenConfig{Issuer: "https://example.com/auth", IssuedAudiences: []string{"app"}, AccountIssuers: []string{"https://peer.example"}},
			Password:  PasswordPolicy{MinLength: 12},
			Username:  UsernameConfig{Renames: true, FormerNames: FormerNamesConfig{Mode: FormerNamesForever}},
			Languages: LanguageConfig{Supported: []string{"EN", "es-MX"}, Default: "es"},
			AuthorizationServer: AuthorizationServerConfig{
				Resources: []ResourceServerConfig{{ID: "https://api.example.com", Scopes: []string{"api"}, Permissions: []string{"merchant:*"}}},
				Clients: []OAuthClientConfig{{ID: "cli", RedirectURIs: []string{"http://127.0.0.1/cb"}, Resources: []string{"https://api.example.com"},
					GrantTypes: []OAuthGrantType{GrantAuthorizationCode, GrantRefreshToken}}, {ID: "tensord", Resources: []string{"https://api.example.com"},
					GrantTypes: []OAuthGrantType{GrantJWTBearer}, AuthorizationDetailsTypes: []string{"op"}}},
			},
			DeviceKeys: DeviceKeysConfig{Enabled: true},
			HTTP:       &HTTPConfig{DirectPeerIP: true, APIPath: "/"},
		},
	} {
		once, _, err := Normalize(c, deps)
		require.NoError(t, err, name)
		twice, _, err := Normalize(once, deps)
		require.NoError(t, err, name)
		require.Equal(t, once, twice, name)
	}
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
		once, _, err := Normalize(base(cl), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
		require.NoError(t, err, cl.ID)
		require.Equal(t, DefaultOAuthRefreshTokenTTL, once.AuthorizationServer.RefreshTokenTTL)
	}
	for name, tc := range map[string]struct {
		client OAuthClientConfig
		want   string
	}{
		"refresh without code":          {OAuthClientConfig{ID: "c", GrantTypes: []OAuthGrantType{GrantRefreshToken}}, "refresh tokens come only with"},
		"public client credentials":     {OAuthClientConfig{ID: "c", Resources: []string{"https://api.example.com"}, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "confidential client"},
		"client credentials no target":  {OAuthClientConfig{ID: "c", SecretSHA256: secret, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "need Resources"},
		"exchange no target":            {OAuthClientConfig{ID: "c", GrantTypes: []OAuthGrantType{GrantTokenExchange}}, "needs Resources"},
		"permissions without grant":     {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, Permissions: []string{"merchant:*"}}, "client-credentials client's own grants"},
		"root permissions":              {OAuthClientConfig{ID: "c", SecretSHA256: secret, Resources: []string{"https://api.example.com"}, Permissions: []string{"root:*"}, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "root namespace"},
		"an app's root permission":      {OAuthClientConfig{ID: "c", SecretSHA256: secret, Resources: []string{"https://api.example.com"}, Permissions: []string{"root:billing:read"}, GrantTypes: []OAuthGrantType{GrantClientCredentials}}, "root namespace"},
		"UUID client ID":                {OAuthClientConfig{ID: "0199b1a2-7c3d-7e4f-8a9b-0c1d2e3f4a5b", RedirectURIs: []string{"https://c.example/cb"}}, "looks like a user ID"},
		"origin with a path":            {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, Origins: []string{"https://admin.example.com/app"}}, "is not an origin"},
		"plain-http origin":             {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, Origins: []string{"http://admin.example.com"}}, "must use https"},
		"unknown grant":                 {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, GrantTypes: []OAuthGrantType{"password"}}, "unsupported grant type"},
		"jwt-bearer no target":          {OAuthClientConfig{ID: "c", GrantTypes: []OAuthGrantType{GrantJWTBearer}, AuthorizationDetailsTypes: []string{"op"}}, "jwt-bearer grant needs Resources"},
		"jwt-bearer no operations":      {OAuthClientConfig{ID: "c", Resources: []string{"https://api.example.com"}, GrantTypes: []OAuthGrantType{GrantJWTBearer}}, "needs AuthorizationDetailsTypes"},
		"operations without jwt-bearer": {OAuthClientConfig{ID: "c", RedirectURIs: []string{"https://c.example/cb"}, AuthorizationDetailsTypes: []string{"op"}}, "jwt-bearer client's capability operations"},
	} {
		_, _, err := Normalize(base(tc.client), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
		require.ErrorContains(t, err, tc.want, name)
	}
	c := base(ok[0])
	c.AuthorizationServer.RefreshTokenTTL = 31 * 24 * time.Hour
	_, _, err := Normalize(c, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
	require.ErrorContains(t, err, "RefreshTokenTTL")

	// A resource's ceiling on users' authority may hold the app's own root
	// permissions, never AuthKit's built-in ones; at most 15-minute tokens.
	for perm, allowed := range map[string]bool{"root:billing:read": true, "root:billing:*": true, "root:*": false, "root:users:read": false, "root:members:*": false} {
		c := base(ok[0])
		c.AuthorizationServer.Resources[0].Permissions = []string{"merchant:*", perm}
		_, _, err := Normalize(c, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
		if allowed {
			require.NoError(t, err, perm)
		} else {
			require.ErrorContains(t, err, "root namespace", perm)
		}
	}
	c = base(ok[0])
	c.AuthorizationServer.AccessTokenTTL = 15 * time.Minute
	_, _, err = Normalize(c, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
	require.NoError(t, err)
	c.AuthorizationServer.AccessTokenTTL = 16 * time.Minute
	_, _, err = Normalize(c, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
	require.ErrorContains(t, err, "AccessTokenTTL")

	grants := func(context.Context, iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{}, nil
	}
	// A jwt-bearer client, public or not, needs device keys to sign its
	// capabilities and the authorizer to judge them.
	workload := OAuthClientConfig{ID: "tensord", Resources: []string{"https://api.example.com"}, GrantTypes: []OAuthGrantType{GrantJWTBearer}, AuthorizationDetailsTypes: []string{"op"}}
	withKeys := base(workload)
	withKeys.DeviceKeys.Enabled = true
	_, _, err = Normalize(base(workload), Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}, OAuthGrants: grants})
	require.ErrorContains(t, err, "needs DeviceKeys.Enabled")
	_, _, err = Normalize(withKeys, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}})
	require.ErrorContains(t, err, "Deps.OAuthGrants")
	_, _, err = Normalize(withKeys, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}, OAuthGrants: grants})
	require.NoError(t, err)
	withKeys.AuthorizationServer.Clients[0].AuthorizationDetailsTypes = []string{"op", "op"}
	once, _, err := Normalize(withKeys, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}, OAuthGrants: grants})
	require.NoError(t, err)
	require.Equal(t, []string{"op"}, once.AuthorizationServer.Clients[0].AuthorizationDetailsTypes)
	withKeys.AuthorizationServer.Clients[0].AuthorizationDetailsTypes = []string{"has space"}
	_, _, err = Normalize(withKeys, Deps{Postgres: &pgxpool.Pool{}, Email: nopEmail{}, OAuthGrants: grants})
	require.ErrorContains(t, err, "invalid authorization_details type")
}

// A survivable problem defaults or switches off only what it concerns and is
// reported, never fatal; normalizing the result again changes nothing and
// reports only what the dependencies still lack.
func TestNormalizeDegradesSurvivableProblems(t *testing.T) {
	deps := Deps{Postgres: &pgxpool.Pool{}}
	base := func(edit func(*Config)) Config {
		c := Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}, HTTP: &HTTPConfig{DirectPeerIP: true}}
		edit(&c)
		return c
	}
	for name, tc := range map[string]struct {
		edit    func(*Config)
		problem string
		check   func(*testing.T, Config)
	}{
		"an invalid language": {
			edit:    func(c *Config) { c.Languages = LanguageConfig{Supported: []string{"es", "??"}, Default: "fr"} },
			problem: `Languages.Supported "??"`,
			check: func(t *testing.T, c Config) {
				require.Equal(t, LanguageConfig{Supported: []string{"es"}, Default: "es"}, c.Languages)
			},
		},
		"an absolute frontend path": {
			edit:    func(c *Config) { c.Frontend.PasswordResetPath = "https://evil.example/reset" },
			problem: "FrontendPasswordResetPath must be a relative absolute-path",
			check:   func(t *testing.T, c Config) { require.Equal(t, "/reset", c.Frontend.PasswordResetPath) },
		},
		"an unknown Solana network": {
			edit:    func(c *Config) { c.SolanaNetwork = "moonnet" },
			problem: `invalid SolanaNetwork "moonnet"`,
			check:   func(t *testing.T, c Config) { require.Empty(t, c.SolanaNetwork) },
		},
		"a sub-second cleanup": {
			edit:    func(c *Config) { c.CleanupInterval = time.Millisecond },
			problem: "CleanupInterval",
			check:   func(t *testing.T, c Config) { require.Equal(t, time.Hour, c.CleanupInterval) },
		},
		"an invalid Redis key prefix": {
			edit:    func(c *Config) { c.HTTP.RedisKeyPrefix = "Not Valid" },
			problem: "RedisKeyPrefix",
			check:   func(t *testing.T, c Config) { require.Equal(t, "authkit:profiles:", c.HTTP.RedisKeyPrefix) },
		},
		"required verification without senders": {
			edit:    func(c *Config) { c.Registration.Verification = iam.RegistrationVerificationRequired },
			problem: "no email or SMS sender is configured",
			check: func(t *testing.T, c Config) {
				require.Equal(t, iam.RegistrationVerificationRequired, c.Registration.Verification, "never relaxed")
			},
		},
		"remote applications without an issuer or twice": {
			edit: func(c *Config) {
				c.RemoteApplications = []RemoteApplicationConfig{{Issuer: " "}, {Issuer: "https://a.example"}, {Issuer: "https://B.example/"}, {Issuer: "https://b.example"}}
			},
			problem: `declares "https://B.example/" 2 times`,
			check: func(t *testing.T, c Config) {
				require.Equal(t, []RemoteApplicationConfig{{Issuer: "https://a.example"}}, c.RemoteApplications, "only the sound one is declared")
			},
		},
		"misconfigured provisioning targets": {
			edit: func(c *Config) {
				c.DefaultTenantID = iam.NewTenantID()
				c.Provisioning = ProvisioningConfig{Targets: []ProvisioningTarget{
					{Name: "Bad Name", URL: "https://x.example"},
					{Name: "nourl"},
					{Name: "twice", URL: "https://1.example"},
					{Name: "twice", URL: "https://2.example"},
					{Name: "fine", URL: "https://ok.example/"},
				}}
			},
			problem: `invalid name "Bad Name"`,
			check: func(t *testing.T, c Config) {
				var names []string
				for _, target := range c.Provisioning.Targets {
					names = append(names, target.Name)
					require.Equal(t, target.Name != "fine", TargetInvalid(target) != nil, target.Name)
				}
				require.Equal(t, []string{"nourl", "twice", "fine"}, names, "disabled targets stay registered")
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			once, degraded, err := Normalize(base(tc.edit), deps)
			require.NoError(t, err)
			require.ErrorContains(t, errors.Join(degraded...), tc.problem)
			tc.check(t, once)
			twice, again, err := Normalize(once, deps)
			require.NoError(t, err)
			require.Equal(t, once, twice)
			for _, problem := range again {
				require.ErrorContains(t, problem, "no email or SMS sender")
			}
		})
	}
}
