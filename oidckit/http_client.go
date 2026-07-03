package oidckit

import (
	"net/http"
	"sync"
	"time"
)

// DefaultOutboundTimeout bounds OIDC discovery, JWKS fetch, and token exchange.
const DefaultOutboundTimeout = 30 * time.Second

var (
	outboundHTTPClient   = &http.Client{Timeout: DefaultOutboundTimeout}
	outboundHTTPClientMu sync.RWMutex
)

// OutboundHTTPClient returns the HTTP client used for zitadel RP discovery and token calls.
func OutboundHTTPClient() *http.Client {
	outboundHTTPClientMu.RLock()
	defer outboundHTTPClientMu.RUnlock()
	return outboundHTTPClient
}

// SetOutboundHTTPClientForTest overrides the outbound client (tests only).
func SetOutboundHTTPClientForTest(c *http.Client) {
	outboundHTTPClientMu.Lock()
	defer outboundHTTPClientMu.Unlock()
	if c == nil {
		outboundHTTPClient = &http.Client{Timeout: DefaultOutboundTimeout}
		return
	}
	outboundHTTPClient = c
}
