package verify

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/open-rails/authkit/authbase"
	jwtkit "github.com/open-rails/authkit/jwt"
)

// RemoteAppOptions builds the verifier IssuerOptions for a remote_application
// (issuer/JWKS or static keys + allowed origins). Exported so authhttp handlers
// that register issuers from stored remote_applications can reuse it.
func RemoteAppOptions(ra authbase.RemoteApplication) IssuerOptions {
	return remoteAppOptions(ra)
}

// DefaultOutboundTimeout bounds the verify layer's outbound HTTP calls (JWKS
// fetches). Mirrors authhttp's constant of the same name.
const DefaultOutboundTimeout = 30 * time.Second

// defaultOutboundHTTPClient is the timeout-bounded client used when a caller
// does not supply one via WithHTTPClient.
var defaultOutboundHTTPClient = &http.Client{Timeout: DefaultOutboundTimeout}

// Token-type tags used by the verification layer. Sourced from jwtkit so they
// stay in lockstep with the signer; authhttp exposes the same values via its own
// delegation.go constants.
const (
	AccessTokenType                  = jwtkit.AccessTokenType
	DelegatedAccessTokenType         = jwtkit.DelegatedAccessTokenType
	RemoteApplicationAccessTokenType = jwtkit.RemoteApplicationAccessTokenType
)

// writeErr writes the canonical Stripe-style error envelope
// ({"error":{type,code,message}}) via the shared authbase builder, so responses
// are byte-identical whether a route is mounted through authhttp or the verify
// package directly.
func writeErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(authbase.NewErrorEnvelope(status, code, nil, nil))
}

func writeErrData(w http.ResponseWriter, status int, code string, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(authbase.NewErrorEnvelope(status, code, nil, data))
}

func unauthorized(w http.ResponseWriter, code string) { writeErr(w, http.StatusUnauthorized, code) }
func forbidden(w http.ResponseWriter, code string)    { writeErr(w, http.StatusForbidden, code) }

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

// requestContextHook lets the embedding layer (authhttp) install request-scoped
// context state — specifically core's permission-resolution memo — without the
// verify package importing core. It is applied to the request context right
// after claims are attached in Required. A verify-only consumer leaves it nil
// (no-op): correctness is unaffected, only core's RBAC-resolution caching.
var requestContextHook func(context.Context) context.Context

// SetRequestContextHook installs the per-request context hook. authhttp wires it
// to core.WithPermissionMemo at init so RBAC resolution caching works per
// request; the verify package itself never imports core.
func SetRequestContextHook(fn func(context.Context) context.Context) { requestContextHook = fn }

func applyRequestContext(ctx context.Context) context.Context {
	if requestContextHook != nil {
		return requestContextHook(ctx)
	}
	return ctx
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
