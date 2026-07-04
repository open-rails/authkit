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

// The per-request gate fires only for an un-enrolled native user when policy is
// Required; enrolled users and machine principals pass.
func TestRequireMFAEnrollmentGateClaims(t *testing.T) {
	v := NewVerifier()
	v.SetMFAEnrollmentExemptPaths(enrollmentExemptPaths)

	cases := []struct {
		name    string
		require bool
		cl      Claims
		path    string
		blocked bool
	}{
		{"policy off", false, Claims{UserID: "u1"}, "/orders", false},
		{"required + unenrolled user", true, Claims{UserID: "u1"}, "/orders", true},
		{"required + unenrolled on enroll route", true, Claims{UserID: "u1"}, "/user/2fa", false},
		{"required + enrolled user", true, Claims{UserID: "u1", MFAEnrolled: true}, "/orders", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gate := c.require && c.cl.IsUser() && !c.cl.MFAEnrolled && !v.mfaEnrollmentExemptPath(http.MethodPost, c.path)
			if gate != c.blocked {
				t.Fatalf("gate=%v, want %v", gate, c.blocked)
			}
		})
	}
}
