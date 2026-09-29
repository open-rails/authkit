package verify

import (
	"net/http"
	"strings"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/netguard"
)

// DefaultOutboundTimeout bounds the verify layer's outbound HTTP calls (JWKS
// fetches).
const DefaultOutboundTimeout = netguard.DefaultTimeout

// NewSSRFGuardedClient returns a timeout-bounded *http.Client whose dialer
// resolves the target itself and refuses any private/reserved address, so a
// crafted jwks_uri (including DNS rebinding) can never reach internal
// services. WithSSRFGuard installs it on a Verifier.
func NewSSRFGuardedClient() *http.Client { return netguard.Client(netguard.DefaultTimeout, false) }

// fail writes code through the one AuthKit writer, so responses are
// byte-identical whether a route is mounted through AuthKit's handler or the
// verify package directly.
func fail(w http.ResponseWriter, code errmodel.Code) { iam.WriteError(w, errmodel.E(code)) }

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

func isDPoPRequest(r *http.Request) bool {
	return r != nil && strings.EqualFold(strings.SplitN(r.Header.Get("Authorization"), " ", 2)[0], "DPoP")
}

func requestToken(r *http.Request) string {
	if r == nil || len(r.Header.Values("Authorization")) != 1 {
		return ""
	}
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) != 2 || (!strings.EqualFold(parts[0], "Bearer") && !strings.EqualFold(parts[0], "DPoP")) || strings.ContainsAny(parts[1], " \t\r\n") {
		return ""
	}
	return parts[1]
}
