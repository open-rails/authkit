package core

import "testing"

func TestPolicySwitches_DefaultPreservesCurrentBehavior(t *testing.T) {
	cfg := baseTestConfig(t)
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.PublicRegistrationDisabled {
		t.Fatalf("PublicRegistrationDisabled should default to false")
	}
	if opts.PublicOrgManagementDisabled {
		t.Fatalf("PublicOrgManagementDisabled should default to false")
	}
	if !opts.PublicRegistrationEnabled() {
		t.Fatalf("PublicRegistrationEnabled should default to true")
	}
	if !opts.PublicOrgManagementEnabled() {
		t.Fatalf("PublicOrgManagementEnabled should default to true")
	}
}

func TestPolicySwitches_Plumbed(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.PublicRegistrationDisabled = true
	cfg.PublicOrgManagementDisabled = true
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if !opts.PublicRegistrationDisabled {
		t.Fatalf("PublicRegistrationDisabled not plumbed through NewFromConfig")
	}
	if !opts.PublicOrgManagementDisabled {
		t.Fatalf("PublicOrgManagementDisabled not plumbed through NewFromConfig")
	}
	if opts.PublicRegistrationEnabled() {
		t.Fatalf("PublicRegistrationEnabled should be false when disabled")
	}
	if opts.PublicOrgManagementEnabled() {
		t.Fatalf("PublicOrgManagementEnabled should be false when disabled")
	}
}

// CreatePendingRegistration is the core front-door chokepoint for public
// password registration. It must hard-fail with ErrRegistrationDisabled when
// the switch is on, before touching storage.
func TestPolicySwitches_CoreRegistrationGate(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.PublicRegistrationDisabled = true
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if _, err := svc.CreatePendingRegistration(t.Context(), "a@b.com", "alice", "hash", 0); err != ErrRegistrationDisabled {
		t.Fatalf("want ErrRegistrationDisabled, got %v", err)
	}
	if _, err := svc.CreatePendingPhoneRegistration(t.Context(), "+12025550123", "alice", "hash"); err != ErrRegistrationDisabled {
		t.Fatalf("want ErrRegistrationDisabled, got %v", err)
	}
}
