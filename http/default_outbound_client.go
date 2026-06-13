package authhttp

import (
	"net/http"
	"time"
)

// DefaultOutboundTimeout bounds AuthKit's first-party outbound HTTP calls that
// reach networked dependencies under partial attacker control — most notably
// the Verifier's JWKS fetches (the issuer/JWKS URL can come from tenant-issuer
// federation data) and the tenant-issuer registration POST. Without a timeout a
// slow or hostile endpoint can wedge a request goroutine indefinitely; when the
// caller also single-flights (as the Verifier does on first use of an issuer or
// after an unknown-kid refetch), one hung fetch stalls every concurrent waiter
// — a cheap denial-of-service amplifier.
const DefaultOutboundTimeout = 30 * time.Second

// defaultOutboundHTTPClient is the timeout-bounded client used when a caller
// does not inject its own via WithHTTPClient / WithTenantIssuersHTTPClient.
// It mirrors the oidc package's DefaultOutboundTimeout convention. Callers that
// need custom transport behaviour (proxy, mTLS, an SSRF-guarding dialer) should
// still inject their own client.
var defaultOutboundHTTPClient = &http.Client{Timeout: DefaultOutboundTimeout}
