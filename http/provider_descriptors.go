package authhttp

import (
	"errors"
	"sort"
	"strings"

	"github.com/open-rails/authkit/authprovider"
	oidckit "github.com/open-rails/authkit/oidc"
)

func buildAuthProvidersMap(oidcProviders map[string]oidckit.RPConfig, providers map[string]authprovider.Provider) (map[string]authprovider.Provider, error) {
	out := make(map[string]authprovider.Provider)
	for name, cfg := range oidcProviders {
		if provider, ok := authprovider.BuiltIn(name); ok {
			applyRPConfigToProvider(&provider, cfg)
			if authProviderConfigured(provider) {
				out[provider.NormalizedName()] = provider
			}
		}
	}
	for name, provider := range providers {
		if strings.TrimSpace(provider.Name) == "" {
			provider.Name = name
		}
		provider = authprovider.Clone(provider)
		if err := provider.Validate(); err != nil {
			return nil, err
		}
		if authProviderConfigured(provider) {
			out[provider.NormalizedName()] = provider
		}
	}
	return out, nil
}

func (s *Service) authProviders() map[string]authprovider.Provider {
	if len(s.authProvidersByName) == 0 {
		return map[string]authprovider.Provider{}
	}
	out := make(map[string]authprovider.Provider, len(s.authProvidersByName))
	for name, provider := range s.authProvidersByName {
		out[name] = authprovider.Clone(provider)
	}
	return out
}

func (s *Service) authProvider(name string) (authprovider.Provider, bool) {
	key := strings.ToLower(strings.TrimSpace(name))
	provider, ok := s.authProvidersByName[key]
	if !ok {
		return authprovider.Provider{}, false
	}
	return authprovider.Clone(provider), true
}

func (s *Service) providerSummaries() []providerSummary {
	providers := s.authProviders()
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]providerSummary, 0, len(names))
	for _, name := range names {
		provider := providers[name]
		out = append(out, providerSummary{
			ID:                   provider.NormalizedName(),
			Name:                 providerDisplayName(provider),
			Kind:                 string(provider.Kind),
			SupportsLogin:        true,
			SupportsRegistration: true,
			SupportsLink:         true,
		})
	}
	return out
}

func authProviderConfigured(provider authprovider.Provider) bool {
	if strings.TrimSpace(provider.NormalizedName()) == "" {
		return false
	}
	if strings.TrimSpace(provider.Issuer) == "" {
		return false
	}
	if strings.TrimSpace(provider.ClientID) == "" {
		return false
	}
	if provider.Kind == authprovider.KindOAuth2 {
		if strings.TrimSpace(provider.AuthorizeURL) == "" ||
			strings.TrimSpace(provider.TokenURL) == "" ||
			strings.TrimSpace(provider.UserInfoURL) == "" {
			return false
		}
	}

	if provider.SecretProvider != nil {
		return true
	}
	if strings.TrimSpace(provider.ClientSecret.Strategy) != "" {
		return true
	}
	secret, err := provider.ClientSecret.ResolveStatic()
	if err != nil {
		if errors.Is(err, authprovider.ErrClientSecretEnvEmpty) {
			return false
		}
		return false
	}
	return strings.TrimSpace(secret) != ""
}

func providerDisplayName(provider authprovider.Provider) string {
	name := strings.TrimSpace(provider.Name)
	if name == "" {
		return ""
	}
	switch strings.ToLower(name) {
	case "google":
		return "Google"
	case "apple":
		return "Apple"
	case "discord":
		return "Discord"
	case "github":
		return "GitHub"
	default:
		return name
	}
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
