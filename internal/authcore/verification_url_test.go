package authcore

import "testing"

// #131: AuthKit builds verification/reset links at the host-configured FRONTEND
// landing path + ?token=…&channel=email|phone (SPA-link model). Verify and reset
// are symmetric — same mechanism, different configured path. No DB needed.
func TestVerificationLinkURLs_UseConfiguredFrontendPaths(t *testing.T) {
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://issuer.example"}, Frontend: FrontendConfig{BaseURL: "https://app.example", VerifyPath: "/verify-registration", PasswordResetPath: "/reset-password"}}, Keyset{})

	cases := []struct{ name, got, want string }{
		{"email verify", svc.emailVerificationURL("T"), "https://app.example/verify-registration?channel=email&token=T"},
		{"phone verify", svc.phoneVerificationURL("T"), "https://app.example/verify-registration?channel=phone&token=T"},
		{"email reset", svc.emailPasswordResetURL("T"), "https://app.example/reset-password?channel=email&token=T"},
		{"phone reset", svc.phonePasswordResetURL("T"), "https://app.example/reset-password?channel=phone&token=T"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s: got %q want %q", c.name, c.got, c.want)
		}
	}
}

// Defaults: empty paths fall back to /verify and /reset.
func TestVerificationLinkURLs_Defaults(t *testing.T) {
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://issuer.example"}, Frontend: FrontendConfig{BaseURL: "https://app.example"}}, Keyset{})
	if got, want := svc.emailVerificationURL("T"), "https://app.example/verify?channel=email&token=T"; got != want {
		t.Errorf("default verify path: got %q want %q", got, want)
	}
	if got, want := svc.emailPasswordResetURL("T"), "https://app.example/reset?channel=email&token=T"; got != want {
		t.Errorf("default reset path: got %q want %q", got, want)
	}
}
