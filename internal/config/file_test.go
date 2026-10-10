package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/open-rails/authkit/internal/config"
)

// A host passes its auth: section through: AuthKit's Config decodes from
// YAML with snake_case keys, durations and role texts included, and Go-only
// fields take no key.
func TestConfigFromYAML(t *testing.T) {
	var c config.Config
	require.NoError(t, yaml.Unmarshal([]byte(`
token:
  issuer: https://auth.example.com
  issued_audiences: [app]
  access_token_duration: 10m
sign_in:
  dpop: required
resource:
  id: https://api.example.com
  scopes:
    "api:merchant": ["merchant:*"]
remote_applications:
  - issuer: https://shop.example
    role: merchant:owner
    role_map: {admin: merchant:owner}
http:
  api_path: /auth
  rate_limits:
    login: {limit: 5, window: 1m, cooldown: 2s}
provisioning:
  targets:
    - {name: billing, url: https://billing.example.com/scim/v2, bearer_token: secret}
`), &c))
	require.Equal(t, "https://auth.example.com", c.Token.Issuer)
	require.Equal(t, []string{"app"}, c.Token.IssuedAudiences)
	require.Equal(t, 10*time.Minute, c.Token.AccessTokenDuration)
	require.Equal(t, config.DPoPRequired, c.SignIn.DPoP)
	require.Equal(t, "https://api.example.com", c.Resource.ID)
	require.Equal(t, []string{"merchant:*"}, c.Resource.Scopes["api:merchant"])
	require.Len(t, c.RemoteApplications, 1)
	require.Equal(t, "merchant:owner", c.RemoteApplications[0].Role.String())
	require.Equal(t, "merchant:owner", c.RemoteApplications[0].RoleMap["admin"].String())
	require.Equal(t, "/auth", c.HTTP.APIPath)
	require.Equal(t, config.RateLimit{Limit: 5, Window: time.Minute, Cooldown: 2 * time.Second}, c.HTTP.RateLimits["login"])
	require.Equal(t, "secret", c.Provisioning.Targets[0].BearerToken)
	require.Nil(t, c.Roles)
}
