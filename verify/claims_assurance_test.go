package verify

import (
	"encoding/json"
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

func TestSensitiveDefaults(t *testing.T) {
	h := assuranceProtected(Sensitive())

	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Minute), AMR: []string{"pwd"}}); w.Code != http.StatusOK {
		t.Fatalf("recent password status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Hour), AMR: []string{"pwd", "mfa"}}); w.Code != http.StatusOK {
		t.Fatalf("old mfa status = %d", w.Code)
	}
	w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Hour), AMR: []string{"pwd"}})
	if w.Code != http.StatusForbidden {
		t.Fatalf("old password status = %d", w.Code)
	}
	var body struct {
		Error struct {
			Code     string         `json:"code"`
			Metadata map[string]any `json:"metadata"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode reauth_required body: %v", err)
	}
	if body.Error.Code != "reauth_required" || body.Error.Metadata["max_age_seconds"] == nil {
		t.Fatalf("reauth envelope = %+v", body)
	}
}

func TestSensitiveRequireMFA(t *testing.T) {
	h := assuranceProtected(Sensitive(SensitiveOptions{RequireMFA: true}))

	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now(), AMR: []string{"pwd", "otp"}}); w.Code != http.StatusOK {
		t.Fatalf("mfa status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now(), AMR: []string{"pwd"}}); w.Code != http.StatusForbidden {
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
