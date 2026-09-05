package authhttp

import (
	"github.com/open-rails/authkit/verify"
	"net/http"
	"testing"
)

// Every outbound client must carry a bounded timeout: NewVerifier,
// NewRemoteApplicationIssuersClient and the Service's OAuth2 client must not
// default to http.DefaultClient, which has none, because a slow/hostile JWKS,
// IdP or registration endpoint could hang a request goroutine forever.
func TestServiceOutboundClientHasTimeout(t *testing.T) {
	s := newTestService(t)
	if s.outboundHTTP == nil || s.outboundHTTP == http.DefaultClient || s.outboundHTTP.Timeout <= 0 {
		t.Fatalf("service outbound client = %+v, want a bounded non-default client", s.outboundHTTP)
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
