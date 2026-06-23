package verify

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
)

func TestExtractClaimsAssurance(t *testing.T) {
	now := time.Now().Add(-time.Minute).Unix()
	cl := NewVerifier().extractClaims(jwt.MapClaims{
		"sub":       "user-1",
		"sid":       "session-1",
		"auth_time": float64(now),
		"amr":       []any{"pwd", "mfa"},
		"acr":       "urn:authkit:loa:2",
	})

	if cl.UserID != "user-1" || cl.SessionID != "session-1" {
		t.Fatalf("identity claims not parsed: %+v", cl)
	}
	if cl.AuthTime.Unix() != now {
		t.Fatalf("auth_time = %d, want %d", cl.AuthTime.Unix(), now)
	}
	if !cl.HasAMR("pwd") || !cl.HasAMR("MFA") {
		t.Fatalf("amr not parsed case-insensitively: %+v", cl.AMR)
	}
	if cl.ACR != "urn:authkit:loa:2" {
		t.Fatalf("acr = %q", cl.ACR)
	}
}

func TestRequireFreshAuth(t *testing.T) {
	h := assuranceProtected(RequireFreshAuth(15 * time.Minute))

	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Minute)}); w.Code != http.StatusOK {
		t.Fatalf("fresh user status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Hour)}); w.Code != http.StatusForbidden {
		t.Fatalf("stale user status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(time.Minute)}); w.Code != http.StatusForbidden {
		t.Fatalf("future auth_time status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{TokenType: ServicePrincipalType, AuthTime: time.Now()}); w.Code != http.StatusForbidden {
		t.Fatalf("service principal status = %d", w.Code)
	}
}

func TestRequireMFA(t *testing.T) {
	h := assuranceProtected(RequireMFA())

	if w := serveVerifyClaims(h, Claims{UserID: "u1", AMR: []string{"pwd", "otp"}}); w.Code != http.StatusOK {
		t.Fatalf("otp status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AMR: []string{"pwd"}}); w.Code != http.StatusForbidden {
		t.Fatalf("pwd-only status = %d", w.Code)
	}
}

func assuranceProtected(mw func(http.Handler) http.Handler) http.Handler {
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func serveVerifyClaims(h http.Handler, cl Claims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r = r.WithContext(SetClaims(r.Context(), cl))
	h.ServeHTTP(w, r)
	return w
}
