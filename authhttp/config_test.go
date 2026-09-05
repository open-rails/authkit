package authhttp

import (
	"testing"

	"github.com/open-rails/authkit/ratelimit"
	"github.com/stretchr/testify/require"
)

// ak#314: Config.Validate is the HTTP layer's one validator — a client-IP
// posture is required, proxy CIDRs must parse, and the rate-limit choice is
// exclusive. Nothing here depends on an environment.
func TestConfigValidate(t *testing.T) {
	err := Config{}.Validate()
	require.Error(t, err)
	require.Contains(t, err.Error(), "client-IP posture")

	for name, cfg := range map[string]Config{
		"direct peer":     {DirectPeerIP: true},
		"trusted proxies": {TrustedProxies: []string{"10.0.0.0/8"}},
		"cloudflare":      {CloudflareProxies: []string{"103.21.244.0/22"}},
		"client ip":       {ClientIP: DefaultClientIP()},
		"overrides":       {DirectPeerIP: true, RateLimits: map[string]ratelimit.Limit{RLPasswordLogin: {Limit: 1, Window: 1}}},
	} {
		require.NoError(t, cfg.Validate(), name)
	}

	require.ErrorContains(t, Config{TrustedProxies: []string{"not-a-cidr"}}.Validate(), "trusted proxy CIDR")
	require.ErrorContains(t, Config{CloudflareProxies: []string{"not-a-cidr"}}.Validate(), "Cloudflare proxy CIDR")
	require.ErrorContains(t, Config{DirectPeerIP: true, DisableRateLimiting: true, Limiter: erroringLimiter{}}.Validate(), "mutually exclusive")
	require.ErrorContains(t, Config{DirectPeerIP: true, Documents: []DocumentProvider{nil}}.Validate(), "nil provider")
}
