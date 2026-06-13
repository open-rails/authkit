package authhttp

import (
	"net/http"
	"testing"
)

// The default outbound client must carry a bounded timeout: NewVerifier and
// NewTenantIssuersClient previously defaulted to http.DefaultClient, which has
// none, so a slow/hostile JWKS or registration endpoint could hang a request
// goroutine forever.
func TestDefaultOutboundClientHasTimeout(t *testing.T) {
	if defaultOutboundHTTPClient == http.DefaultClient {
		t.Fatal("default outbound client must not be http.DefaultClient (no timeout)")
	}
	if defaultOutboundHTTPClient.Timeout <= 0 {
		t.Fatalf("default outbound client timeout = %v, want > 0", defaultOutboundHTTPClient.Timeout)
	}
	if defaultOutboundHTTPClient.Timeout != DefaultOutboundTimeout {
		t.Fatalf("default outbound client timeout = %v, want %v", defaultOutboundHTTPClient.Timeout, DefaultOutboundTimeout)
	}
}

func TestNewVerifierUsesBoundedClient(t *testing.T) {
	v := NewVerifier()
	if v.httpClient == nil || v.httpClient == http.DefaultClient {
		t.Fatal("NewVerifier must default to a bounded outbound client")
	}
	if v.httpClient.Timeout <= 0 {
		t.Fatalf("verifier client timeout = %v, want > 0", v.httpClient.Timeout)
	}
}

func TestNewTenantIssuersClientUsesBoundedClient(t *testing.T) {
	fc := NewTenantIssuersClient()
	if fc.httpClient == nil || fc.httpClient == http.DefaultClient {
		t.Fatal("NewTenantIssuersClient must default to a bounded outbound client")
	}
	if fc.httpClient.Timeout <= 0 {
		t.Fatalf("federation client timeout = %v, want > 0", fc.httpClient.Timeout)
	}
}
