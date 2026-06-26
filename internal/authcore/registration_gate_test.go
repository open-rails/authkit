package authcore

import (
	"context"
	"testing"
)

func TestRegistrationAllowedForEmail(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		mode RegistrationMode
		want bool
	}{
		{RegistrationModeOpen, true},
		{RegistrationModeClosed, false},
		// InviteOnly is fail-closed until the account-registration-invite subsystem
		// lands (hasValidAccountRegistrationInvite returns false).
		{RegistrationModeInviteOnly, false},
	}
	for _, c := range cases {
		t.Run(string(c.mode), func(t *testing.T) {
			s := NewService(Options{Issuer: "x", NativeUserRegistrationMode: c.mode}, Keyset{})
			got, err := s.registrationAllowedForEmail(ctx, "a@b.com")
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if got != c.want {
				t.Fatalf("mode %q: allowed=%v, want %v", c.mode, got, c.want)
			}
		})
	}
}
