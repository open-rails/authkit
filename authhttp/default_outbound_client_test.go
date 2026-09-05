package authhttp

import (
	"net/http"
	"testing"

	"github.com/open-rails/authkit/verify"
)

func TestNewVerifierUsesBoundedClient(t *testing.T) {
	v := verify.NewVerifier()
	if v.HTTPClient() == nil || v.HTTPClient() == http.DefaultClient {
		t.Fatal("NewVerifier must default to a bounded outbound client")
	}
	if v.HTTPClient().Timeout <= 0 {
		t.Fatalf("verifier client timeout = %v, want > 0", v.HTTPClient().Timeout)
	}
}
