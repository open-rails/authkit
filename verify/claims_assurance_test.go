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

func TestSensitiveDefaults(t *testing.T) {
	h := assuranceProtected(Sensitive())

	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Minute), AMR: []string{"pwd"}}); w.Code != http.StatusOK {
		t.Fatalf("recent password status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Hour), AMR: []string{"pwd", "mfa"}}); w.Code != http.StatusForbidden {
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
		t.Fatalf("decode step_up_required body: %v", err)
	}
	if body.Error.Code != "step_up_required" || body.Error.Metadata["max_age_seconds"] == nil {
		t.Fatalf("step-up envelope = %+v", body)
	}
}

// MFA-if-enrolled is the default behavior of Sensitive(): a user who has 2FA
// enrolled (cl.MFAEnrolled) must step up with 2FA; a user without 2FA may use any
// method. There is no RequireMFA flag — the gate never locks out a non-2FA user.
func TestSensitiveMFAIfEnrolled(t *testing.T) {
	h := assuranceProtected(Sensitive())

	// Enrolled user: 2FA satisfies, password alone does not.
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now(), MFAEnrolled: true, AMR: []string{"pwd", "otp"}}); w.Code != http.StatusOK {
		t.Fatalf("enrolled+mfa status = %d", w.Code)
	}
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now(), MFAEnrolled: true, AMR: []string{"pwd"}}); w.Code != http.StatusForbidden {
		t.Fatalf("enrolled+pwd-only status = %d, want forbidden", w.Code)
	}
	// Not enrolled: password is sufficient (never locked out).
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now(), MFAEnrolled: false, AMR: []string{"pwd"}}); w.Code != http.StatusOK {
		t.Fatalf("not-enrolled+pwd status = %d, want ok", w.Code)
	}
	// Recency still applies regardless of enrollment.
	if w := serveVerifyClaims(h, Claims{UserID: "u1", AuthTime: time.Now().Add(-time.Hour), MFAEnrolled: true, AMR: []string{"pwd", "otp"}}); w.Code != http.StatusForbidden {
		t.Fatalf("enrolled+stale status = %d, want forbidden", w.Code)
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
