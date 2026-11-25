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
	// aud must contain it. The API's base URL, https (http only on a
	// loopback host): its origin is the one a DPoP proof's htu names (RFC
	// 9449 §4.3). Deps.ResourceHosts admits more hosts.
	ID string `yaml:"id"`
	// Scopes are the resource's scopes and the permission ceiling each one
	// grants (RFC 6749 §3.3), as grant patterns: an access token's
	// permissions count only within the ceilings of the scopes it was
	// granted. A scope with no permissions grants none. Empty applies no
	// scope ceiling.
	Scopes map[string][]string `yaml:"scopes"`
}

// Enabled reports whether this deployment accepts access tokens as a
// resource server.
func (r ResourceConfig) Enabled() bool { return r.ID != "" }

// ResourceOrigin is where clients reach the resource: its ID's origin.
func ResourceOrigin(r ResourceConfig) string {
	u, _ := url.Parse(r.ID)
	return u.Scheme + "://" + u.Host
}

func normalizeResource(r *ResourceConfig) error {
	r.ID = strings.TrimSpace(r.ID)
	if r.ID == "" {
		if len(r.Scopes) > 0 {
			return fmt.Errorf("authkit: Resource has Scopes but no ID")
		}
		return nil
	}
	if err := validResourceID(r.ID); err != nil {
		return fmt.Errorf("authkit: Resource.ID: %w", err)
	}
	if u, _ := url.Parse(r.ID); u.Host == "" || u.User != nil || u.RawQuery != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
		return fmt.Errorf("authkit: Resource.ID %q must be an https URL (http only on a loopback host) without user info or query", r.ID)
	}
	scopes := make(map[string][]string, len(r.Scopes))
	for name, perms := range r.Scopes {
		name = strings.TrimSpace(name)
		if !scopePattern.MatchString(name) || OIDCScope(name) {
			return fmt.Errorf("authkit: Resource.Scopes: invalid scope %q", name)
		}
		normalized, err := normalizeResourcePermissions(perms, true)
		if err != nil {
			return fmt.Errorf("authkit: Resource.Scopes[%q]: %w", name, err)
		}
		scopes[name] = normalized
	}
	r.Scopes = scopes
	return nil
}
