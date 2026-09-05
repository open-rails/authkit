package oidckit

import (
	"net/http"
	"time"
)

// DefaultOutboundTimeout bounds OIDC discovery, JWKS fetch, and token exchange.
const DefaultOutboundTimeout = 30 * time.Second

var outboundHTTPClient = &http.Client{Timeout: DefaultOutboundTimeout}

// OutboundHTTPClient returns the HTTP client used for zitadel RP discovery and token calls.
func OutboundHTTPClient() *http.Client { return outboundHTTPClient }
