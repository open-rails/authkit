package authhttp

import (
	"fmt"
	"sort"
	"strings"

	"github.com/open-rails/authkit/authprovider"
)

// providerRegistry validates the configured identity providers and indexes
// them by name. Every listed provider must validate; a duplicate name is a
// configuration error, never a silent override. Provider links are keyed by
// issuer, so two providers may not share one, and none may claim a reserved
// issuer (this deployment's own account issuers).
func providerRegistry(providers []authprovider.Provider, reservedIssuers []string) (map[string]authprovider.Provider, error) {
	out := make(map[string]authprovider.Provider, len(providers))
	issuers := map[string]string{}
	for _, iss := range reservedIssuers {
		issuers[issuerKey(iss)] = ""
	}
	for _, p := range providers {
		if p == nil {
			return nil, fmt.Errorf("%w: nil provider", authprovider.ErrProviderInvalid)
		}
		if err := p.Validate(); err != nil {
			return nil, err
		}
		name := p.Name()
		if _, dup := out[name]; dup {
			return nil, fmt.Errorf("%w: provider %q listed twice", authprovider.ErrProviderInvalid, name)
		}
		if other, taken := issuers[issuerKey(p.Issuer())]; taken {
			if other == "" {
				return nil, fmt.Errorf("%w: provider %q uses reserved issuer %q", authprovider.ErrProviderInvalid, name, p.Issuer())
			}
			return nil, fmt.Errorf("%w: providers %q and %q share issuer %q", authprovider.ErrProviderInvalid, other, name, p.Issuer())
		}
		issuers[issuerKey(p.Issuer())] = name
		out[name] = p
	}
	return out, nil
}

// issuerKey compares issuers the way a mix-up would: case-insensitively and
// ignoring a trailing slash.
func issuerKey(issuer string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(issuer), "/"))
}

// requireHTTPSForFormPost refuses a response_mode=form_post provider unless the
// deployment is HTTPS: its state cookie must be SameSite=None; Secure (#295),
// which browsers only ever send over HTTPS, so the flow could never complete.
func requireHTTPSForFormPost(providers map[string]authprovider.Provider, baseURL string) error {
	origin, ok := originFromBaseURL(baseURL)
	if ok && strings.HasPrefix(strings.ToLower(origin), "https://") {
		return nil
	}
	for name, p := range providers {
		if p.ResponseModeFormPost() {
			return fmt.Errorf("authkit: provider %q uses response_mode=form_post, which needs an HTTPS deployment (SameSite=None; Secure state cookie); set Frontend.BaseURL to an https URL", name)
		}
	}
	return nil
}

func (s *Service) provider(name string) (authprovider.Provider, bool) {
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

func (s *Service) providerSummaries() []AuthProviderSummary {
	names := s.providerNames()
	out := make([]AuthProviderSummary, 0, len(names))
	for _, name := range names {
		out = append(out, AuthProviderSummary{
			ID:                   name,
			Name:                 s.providers[name].DisplayName(),
			SupportsLogin:        true,
			SupportsRegistration: true,
			SupportsLink:         true,
		})
	}
	return out
}
