package verify

import (
	"net/http"
	"testing"
)

// #148 note c: the forced-enrollment allowlist must let a gated user reach every
// 2FA enroll/challenge/verify route, and nothing else.
func TestAllowed2FAEnrollmentPath(t *testing.T) {
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
		if !allowed2FAEnrollmentPath(c.method, c.path) {
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
		if allowed2FAEnrollmentPath(c.method, c.path) {
			t.Errorf("expected %s %s to be blocked by the gate", c.method, c.path)
		}
	}
}

// The per-request gate fires only for an un-enrolled native user when policy is
// Required; enrolled users and machine principals pass.
func TestRequireMFAEnrollmentGateClaims(t *testing.T) {
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
			gate := c.require && c.cl.IsUser() && !c.cl.MFAEnrolled && !allowed2FAEnrollmentPath(http.MethodPost, c.path)
			if gate != c.blocked {
				t.Fatalf("gate=%v, want %v", gate, c.blocked)
			}
		})
	}
}
