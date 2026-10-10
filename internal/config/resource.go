package config

import (
	"fmt"
	"net/url"
	"strings"
)

// ResourceConfig makes this deployment a resource server (RFC 9068): its
// Authenticator admits the access tokens (at+jwt) minted for ID by this
// deployment's authorization server and by its trusted issuers, the remote
// applications. The zero value admits none.
type ResourceConfig struct {
	// ID is the resource identifier (RFC 8707): an accepted access token's
	// aud must contain it. An absolute URI without a fragment, usually the
	// API's base URL.
	ID string
	// PublicURL is where clients reach the API, the origin a DPoP proof's
	// htu names (RFC 9449 §4.3): "https://api.example.com", or with the path
	// a proxy strips. Empty is ID's origin. Deps.ResourceHosts admits more
	// hosts.
	PublicURL string
	// Scopes are the resource's scopes and the permission ceiling each one
	// grants (RFC 6749 §3.3), as grant patterns: an access token's
	// permissions count only within the ceilings of the scopes it was
	// granted. A scope with no permissions grants none. Empty applies no
	// scope ceiling.
	Scopes map[string][]string
}

// Enabled reports whether this deployment accepts access tokens as a
// resource server.
func (r ResourceConfig) Enabled() bool { return r.ID != "" }

func normalizeResource(r *ResourceConfig) error {
	r.ID = strings.TrimSpace(r.ID)
	r.PublicURL = strings.TrimRight(strings.TrimSpace(r.PublicURL), "/")
	if r.ID == "" {
		if r.PublicURL != "" || len(r.Scopes) > 0 {
			return fmt.Errorf("authkit: Resource has a PublicURL or Scopes but no ID")
		}
		return nil
	}
	if err := validResourceID(r.ID); err != nil {
		return fmt.Errorf("authkit: Resource.ID: %w", err)
	}
	if r.PublicURL == "" {
		u, _ := url.Parse(r.ID)
		if u.Scheme != "https" && u.Scheme != "http" || u.Host == "" {
			return fmt.Errorf("authkit: Resource.PublicURL is required when Resource.ID %q is not an http(s) URL", r.ID)
		}
		r.PublicURL = u.Scheme + "://" + u.Host
	}
	if u, err := url.Parse(r.PublicURL); err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
		return fmt.Errorf("authkit: Resource.PublicURL %q must be an https URL (http only on a loopback host) without query or fragment", r.PublicURL)
	}
	scopes := make(map[string][]string, len(r.Scopes))
	for name, perms := range r.Scopes {
		name = strings.TrimSpace(name)
		if !scopePattern.MatchString(name) || OIDCScope(name) {
			return fmt.Errorf("authkit: Resource.Scopes: invalid scope %q", name)
		}
		normalized, err := normalizeResourcePermissions(perms)
		if err != nil {
			return fmt.Errorf("authkit: Resource.Scopes[%q]: %w", name, err)
		}
		scopes[name] = normalized
	}
	r.Scopes = scopes
	return nil
}
