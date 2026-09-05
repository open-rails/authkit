package authhttp

import (
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/redis/go-redis/v9"
)

// Test-only Config builders: New takes one Config; tests compose it from these
// so a call site names only what it sets. newServer supplies the direct-peer
// posture unless the options declare one.
type Option func(*Config)

func WithRedis(rd *redis.Client) Option     { return func(c *Config) { c.Redis = rd } }
func WithRateLimiter(rl RateLimiter) Option { return func(c *Config) { c.Limiter = rl } }
func WithoutRateLimiter() Option            { return func(c *Config) { c.DisableRateLimiting = true } }
func WithTrustedProxies(cidrs ...string) Option {
	return func(c *Config) { c.TrustedProxies = append(c.TrustedProxies, cidrs...) }
}
func WithCloudflareProxies(cidrs ...string) Option {
	return func(c *Config) { c.CloudflareProxies = append(c.CloudflareProxies, cidrs...) }
}
func WithDirectPeerIP() Option                    { return func(c *Config) { c.DirectPeerIP = true } }
func WithClientIPFunc(fn ClientIPFunc) Option     { return func(c *Config) { c.ClientIP = fn } }
func WithLanguageConfig(lc LanguageConfig) Option { return func(c *Config) { c.Languages = lc } }
func WithDocuments(providers ...DocumentProvider) Option {
	return func(c *Config) { c.Documents = append(c.Documents, providers...) }
}
func WithRateLimitOverrides(overrides map[string]ratelimit.Limit) Option {
	return func(c *Config) {
		if c.RateLimits == nil {
			c.RateLimits = map[string]ratelimit.Limit{}
		}
		for bucket, lim := range overrides {
			c.RateLimits[bucket] = lim
		}
	}
}
func withMemoryLimiterSweep(d time.Duration) Option {
	return func(c *Config) { c.memoryLimiterSweep = d }
}

func configOf(opts ...Option) Config {
	var c Config
	for _, o := range opts {
		if o != nil {
			o(&c)
		}
	}
	if c.ClientIP == nil && !c.DirectPeerIP && len(c.TrustedProxies) == 0 && len(c.CloudflareProxies) == 0 {
		c.DirectPeerIP = true
	}
	return c
}

func newServer(client *embedded.Client, opts ...Option) (*Service, error) {
	return New(client, configOf(opts...))
}
