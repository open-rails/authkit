package authhttp

import (
	"github.com/open-rails/authkit/verify"
	"net/http"
	"testing"
)

// The default outbound client must carry a bounded timeout: NewVerifier and
// NewRemoteApplicationIssuersClient must not default to http.DefaultClient,
// which has no timeout, because a slow/hostile JWKS or registration endpoint
// could hang a request goroutine forever.
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
	v := verify.NewVerifier()
	if v.HTTPClient() == nil || v.HTTPClient() == http.DefaultClient {
		t.Fatal("NewVerifier must default to a bounded outbound client")
	}
	if v.HTTPClient().Timeout <= 0 {
		t.Fatalf("verifier client timeout = %v, want > 0", v.HTTPClient().Timeout)
	}
}

func TestNewRemoteApplicationIssuersClientUsesBoundedClient(t *testing.T) {
	fc := NewRemoteApplicationIssuersClient()
	if fc.httpClient == nil || fc.httpClient == http.DefaultClient {
		t.Fatal("NewRemoteApplicationIssuersClient must default to a bounded outbound client")
	}
	if fc.httpClient.Timeout <= 0 {
		t.Fatalf("federation client timeout = %v, want > 0", fc.httpClient.Timeout)
	}
}
