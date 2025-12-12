package authgin

import "testing"

func TestUserContextHelpers(t *testing.T) {
	uc := UserContext{
		UserID:       "u_123",
		Roles:        []string{"Admin", "mod"},
		Entitlements: []string{"Premium", "founder"},
	}

	if !uc.IsLoggedIn() {
		t.Fatalf("expected IsLoggedIn true")
	}
	if !uc.IsAdmin() {
		t.Fatalf("expected IsAdmin true")
	}
	if !uc.HasRole("admin") {
		t.Fatalf("expected HasRole(admin) true")
	}
	if !uc.HasRole("MOD") {
		t.Fatalf("expected HasRole(MOD) true")
	}
	if uc.HasRole("missing") {
		t.Fatalf("expected HasRole(missing) false")
	}
	if !uc.HasEntitlement("premium") {
		t.Fatalf("expected HasEntitlement(premium) true")
	}
	if !uc.HasEntitlement("FOUNDER") {
		t.Fatalf("expected HasEntitlement(FOUNDER) true")
	}
	if uc.HasEntitlement("gold") {
		t.Fatalf("expected HasEntitlement(gold) false")
	}
}
