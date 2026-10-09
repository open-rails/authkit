package authtest

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/verify"
	hauth "github.com/open-rails/helpers/auth"
)

// Identity is the identity a request bearing credential (an access token or
// API key) acts as, verified as auth's gates verify it (verify.Required):
// AuthKit's operations accept it, as they accept the identity behind a gate.
// The test fails when auth refuses the credential.
func Identity(t testing.TB, auth *authkit.Client, credential string) hauth.Identity {
	t.Helper()
	var id hauth.Identity
	var ok bool
	gate := verify.Required(auth)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		id, ok = auth.Identity(r.Context())
	}))
	r := httptest.NewRequest(http.MethodGet, "https://authtest/identity", nil)
	r.Header.Set("Authorization", "Bearer "+credential)
	w := httptest.NewRecorder()
	gate.ServeHTTP(w, r)
	if !ok {
		t.Fatalf("authtest: identity: the credential was refused (%d %s)", w.Code, w.Body.String())
	}
	return id
}
