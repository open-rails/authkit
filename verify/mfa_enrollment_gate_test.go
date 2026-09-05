package verify

import (
	"net/http"
	"testing"
)

// enrollmentExemptPaths mirrors the 2FA enroll/challenge/verify routes tagged
// MFAEnrollmentExempt in authhttp/routes.go (#243) — the exempt set NewServer
// derives from the route registry at construction.
var enrollmentExemptPaths = []string{"/user/2fa", "/user/2fa/backup-codes", "/2fa/challenge", "/2fa/verify"}

// #148 note c: the forced-enrollment allowlist must let a gated user reach every
// 2FA enroll/challenge/verify route, and nothing else.
func TestMFAEnrollmentExemptPath(t *testing.T) {
	v := NewVerifier()
	v.SetMFAEnrollmentExemptPaths(enrollmentExemptPaths)

	allowed := []struct{ method, path string }{
		{http.MethodGet, "/user/2fa"},
		{http.MethodPost, "/user/2fa"},
		{http.MethodPost, "/api/v1/user/2fa"},
		{http.MethodPost, "/api/v1/user/2fa/"},
		{http.MethodDelete, "/user/2fa"},
		{http.MethodPost, "/user/2fa/backup-codes"},
		{http.MethodPost, "/2fa/challenge"},
		{http.MethodPost, "/2fa/verify"},
	}
	for _, c := range allowed {
		if !v.mfaEnrollmentExemptPath(c.method, c.path) {
			t.Errorf("expected %s %s to be on the enrollment allowlist", c.method, c.path)
		}
	}
	blocked := []struct{ method, path string }{
		{http.MethodPost, "/orders"},
		{http.MethodGet, "/me"},
		{http.MethodPost, "/user/profile"},
		{http.MethodPut, "/user/2fa"}, // PUT is not an enrollment verb
	}
	for _, c := range blocked {
		if v.mfaEnrollmentExemptPath(c.method, c.path) {
			t.Errorf("expected %s %s to be blocked by the gate", c.method, c.path)
		}
	}
}

// A Verifier that never calls SetMFAEnrollmentExemptPaths (verify-only, no
// authhttp server wiring it from the route registry) exempts nothing —
// fail-closed default, not fail-open.
func TestMFAEnrollmentExemptPath_UnsetIsFailClosed(t *testing.T) {
	v := NewVerifier()
	if v.mfaEnrollmentExemptPath(http.MethodGet, "/user/2fa") {
		t.Fatal("a Verifier with no exempt paths set must not exempt any route")
	}
}
