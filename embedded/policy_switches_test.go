package embedded

import (
	"testing"

	"github.com/open-rails/authkit/jwtkit"
)

func mustGeneratedKeys(t *testing.T) jwtkit.KeySource {
	t.Helper()
	ks := testKeySource(t)
	return ks
}

func baseTestConfig(t *testing.T) Config {
	t.Helper()
	return Config{
		Token: TokenConfig{
			Issuer:            "https://issuer.test",
			IssuedAudiences:   []string{"app"},
			ExpectedAudiences: []string{"app"},
		},
		Keys: KeysConfig{Source: mustGeneratedKeys(t)},
	}
}

func TestPolicySwitches_DefaultPreservesCurrentBehavior(t *testing.T) {
	cfg := baseTestConfig(t)
	svc, err := newFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if svc.Config().Registration.NativeUserMode != RegistrationModeOpen {
		t.Fatalf("NativeUserRegistrationMode should default to open")
	}
	if !svc.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should default to true")
	}
}

// CreatePendingRegistration is the core front-door chokepoint for public
// password registration. It must hard-fail with ErrRegistrationDisabled when
// the switch is on, before touching storage.
func TestPolicySwitches_CoreRegistrationGate(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationModeClosed
	svc, err := newFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if _, err := svc.CreatePendingRegistrationWithLanguage(t.Context(), "a@b.com", "alice", "hash", 0, ""); err != ErrRegistrationDisabled {
		t.Fatalf("want ErrRegistrationDisabled, got %v", err)
	}
	if _, err := svc.CreatePendingPhoneRegistrationWithLanguage(t.Context(), "+12025550123", "alice", "hash", ""); err != ErrRegistrationDisabled {
		t.Fatalf("want ErrRegistrationDisabled, got %v", err)
	}
}

func TestPolicySwitches_RegistrationModes(t *testing.T) {
	for _, mode := range []RegistrationMode{
		RegistrationModeInviteOnly,
		RegistrationModeClosed,
	} {
		t.Run(string(mode), func(t *testing.T) {
			svc := mustNewWithKeys(t, Config{Registration: RegistrationConfig{NativeUserMode: mode}}, Keyset{})
			if svc.PublicNativeUserRegistrationEnabled() {
				t.Fatalf("native public registration should be disabled for %q", mode)
			}
		})
	}
}

func TestPolicySwitches_RejectsLegacyBootstrapOnlyMode(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationMode("bootstrap_only")
	if _, err := newFromConfig(cfg, nil); err == nil {
		t.Fatalf("legacy bootstrap_only mode should be rejected")
	}
}
