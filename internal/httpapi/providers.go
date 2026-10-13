package httpapi

import (
	"sort"
	"strings"

	"github.com/open-rails/authkit/provider"
)

// providerRegistry indexes the usable identity providers by name: the engine
// already disabled any misconfigured one (Engine.Providers).
func providerRegistry(providers []provider.Provider) map[string]provider.Provider {
	out := make(map[string]provider.Provider, len(providers))
	for _, p := range providers {
		out[p.Name()] = p
	}
	return out
}

func (s *Service) provider(name string) (provider.Provider, bool) {
	p, ok := s.providers[strings.ToLower(strings.TrimSpace(name))]
	return p, ok
}

func (s *Service) providerNames() []string {
	names := make([]string, 0, len(s.providers))
	for name := range s.providers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (s *Service) providerSummaries() []ExternalLoginProvider {
	names := s.providerNames()
	out := make([]ExternalLoginProvider, 0, len(names))
	for _, name := range names {
		out = append(out, ExternalLoginProvider{
			ID:                   name,
			Name:                 s.providers[name].DisplayName(),
			SupportsLogin:        true,
			SupportsRegistration: true,
			SupportsLink:         true,
		})
	}
	return out
}
