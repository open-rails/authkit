package authhttp

import (
	"strings"

	"github.com/open-rails/authkit/authprovider"
	oidckit "github.com/open-rails/authkit/oidc"
)

func (s *Service) authProviders() map[string]authprovider.Provider {
	out := map[string]authprovider.Provider{}
	for name, cfg := range s.oidcProviders {
		if provider, ok := authprovider.BuiltIn(name); ok {
			applyRPConfigToProvider(&provider, cfg)
			out[provider.NormalizedName()] = provider
		}
	}
	for name, provider := range s.providers {
		if strings.TrimSpace(provider.Name) == "" {
			provider.Name = name
		}
		out[provider.NormalizedName()] = authprovider.Clone(provider)
	}
	return out
}

func (s *Service) authProvider(name string) (authprovider.Provider, bool) {
	provider, ok := s.authProviders()[strings.ToLower(strings.TrimSpace(name))]
	return provider, ok
}

func applyRPConfigToProvider(provider *authprovider.Provider, cfg oidckit.RPConfig) {
	provider.ClientID = cfg.ClientID
	provider.ClientSecret.Value = cfg.ClientSecret
	provider.SecretProvider = cfg.SecretProvider
	if len(cfg.Scopes) > 0 {
		provider.Scopes = mergeStringSets(provider.Scopes, cfg.Scopes)
	}
}

func mergeStringSets(base, extra []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(base)+len(extra))
	for _, item := range append(base, extra...) {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}
