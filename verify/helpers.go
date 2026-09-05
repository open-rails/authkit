package verify

import (
	"net/http"
	"strings"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/netguard"
	"github.com/open-rails/authkit/jwtkit"
)

// DefaultOutboundTimeout bounds the verify layer's outbound HTTP calls (JWKS
// fetches).
const DefaultOutboundTimeout = netguard.DefaultTimeout

// NewSSRFGuardedClient returns a timeout-bounded *http.Client whose dialer
// resolves the target itself and refuses any private/reserved address, so a
// crafted jwks_uri (including DNS rebinding) can never reach internal
// services. WithSSRFGuard installs it on a Verifier.
func NewSSRFGuardedClient() *http.Client { return netguard.Client(netguard.DefaultTimeout, false) }

// Token-type tags used by the verification layer. Sourced from jwtkit so they
// stay in lockstep with the signer; authhttp exposes the same values via its own
// delegation.go constants.
const (
	AccessTokenType                  = jwtkit.AccessTokenType
	DelegatedAccessTokenType         = jwtkit.DelegatedAccessTokenType
	RemoteApplicationAccessTokenType = jwtkit.RemoteApplicationAccessTokenType
)

// forbidden writes a 403 with the given code through the one authkit writer,
// so responses are byte-identical whether a route is mounted through authhttp
// or the verify package directly.
func forbidden(w http.ResponseWriter, code authkit.Code) {
	authkit.WriteError(w, authkit.E(code, authkit.WithStatus(http.StatusForbidden)))
}

// bearerToken extracts the token from an "Authorization: Bearer <token>" header.
func bearerToken(authorization string) string {
	if authorization == "" {
		return ""
	}
	parts := strings.SplitN(authorization, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// HTTPClient returns the outbound HTTP client the Verifier uses for JWKS
// fetches (the WithHTTPClient override, or the default timeout-bounded client).
func (v *Verifier) HTTPClient() *http.Client { return v.httpClient }

// SetRemoteApplicationSource overrides the federation source consulted by the
// lazy-load-on-miss path (keyForToken). LoadRemoteApplications is the normal
// way to set it; this is the explicit seam for tests and advanced wiring.
func (v *Verifier) SetRemoteApplicationSource(src RemoteApplicationSource) {
	v.mu.Lock()
	v.fedSource = src
	v.mu.Unlock()
}
