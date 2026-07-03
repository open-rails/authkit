package authhttp

import (
	"sort"
	"strings"

	"github.com/open-rails/authkit/authprovider"
)

// buildAuthProvidersMap validates the configured identity providers and indexes
// them by normalized name. A provider is a provider (#143): built-ins come from
// authprovider.Google/Apple/… constructors and custom providers from a full
// authprovider.Provider descriptor — both validated identically here.
func buildAuthProvidersMap(providers []authprovider.Provider) (map[string]authprovider.Provider, error) {
	out := make(map[string]authprovider.Provider, len(providers))
	for _, provider := range providers {
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

func (s *Service) providerSummaries() []AuthProviderSummary {
	providers := s.authProviders()
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]AuthProviderSummary, 0, len(names))
	for _, name := range names {
		provider := providers[name]
		out = append(out, AuthProviderSummary{
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
	return provider.ClientSecret.ResolveStatic() != ""
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
