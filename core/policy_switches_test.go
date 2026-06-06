package core

import "testing"

func TestPolicySwitches_DefaultPreservesCurrentBehavior(t *testing.T) {
	cfg := baseTestConfig(t)
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeOpen {
		t.Fatalf("NativeUserRegistrationMode should default to open")
	}
	if opts.TenantRegistrationMode != RegistrationModeOpen {
		t.Fatalf("TenantRegistrationMode should default to open")
	}
	if !opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should default to true")
	}
	if !opts.PublicTenantRegistrationEnabled() {
		t.Fatalf("PublicTenantRegistrationEnabled should default to true")
	}
}

func TestPolicySwitches_Plumbed(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.NativeUserRegistrationMode = RegistrationModeBootstrapOnly
	cfg.TenantRegistrationMode = RegistrationModeBootstrapOnly
	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeBootstrapOnly {
		t.Fatalf("NativeUserRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.TenantRegistrationMode != RegistrationModeBootstrapOnly {
		t.Fatalf("TenantRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should be false when disabled")
	}
	if opts.PublicTenantRegistrationEnabled() {
		t.Fatalf("PublicTenantRegistrationEnabled should be false when disabled")
	}
}

// CreatePendingRegistration is the core front-door chokepoint for public
// password registration. It must hard-fail with ErrRegistrationDisabled when
// the switch is on, before touching storage.
func TestPolicySwitches_CoreRegistrationGate(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.NativeUserRegistrationMode = RegistrationModeBootstrapOnly
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
