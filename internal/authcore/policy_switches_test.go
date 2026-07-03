package authcore

import (
	"testing"

	jwtkit "github.com/open-rails/authkit/jwt"
)

func mustGeneratedKeys(t *testing.T) jwtkit.KeySource {
	t.Helper()
	ks, err := jwtkit.NewGeneratedKeySource()
	if err != nil {
		t.Fatalf("generate keys: %v", err)
	}
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
	svc, err := NewFromConfig(cfg, nil)
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

func TestPolicySwitches_Plumbed(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationModeClosed
	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	if svc.Config().Registration.NativeUserMode != RegistrationModeClosed {
		t.Fatalf("NativeUserRegistrationMode not plumbed through NewFromConfig")
	}
	if svc.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should be false when disabled")
	}
}

// CreatePendingRegistration is the core front-door chokepoint for public
// password registration. It must hard-fail with ErrRegistrationDisabled when
// the switch is on, before touching storage.
func TestPolicySwitches_CoreRegistrationGate(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationModeClosed
	svc, err := NewFromConfig(cfg, nil)
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
			svc := NewService(Config{Registration: RegistrationConfig{NativeUserMode: mode}}, Keyset{})
			if svc.PublicNativeUserRegistrationEnabled() {
				t.Fatalf("native public registration should be disabled for %q", mode)
			}
		})
	}
}

func TestPolicySwitches_DeploymentModeMatrix(t *testing.T) {
	tests := []struct {
		name                  string
		nativeMode            RegistrationMode
		wantPublicNativeUsers bool
	}{
		{
			name:                  "doujins-hentai0-native-app",
			nativeMode:            RegistrationModeOpen,
			wantPublicNativeUsers: true,
		},
		{
			name:       "tensorhub-b2b-admin-created",
			nativeMode: RegistrationModeClosed,
		},
		{
			name:       "openrails-relying-party-closed",
			nativeMode: RegistrationModeClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}, Registration: RegistrationConfig{NativeUserMode: tt.nativeMode}}, Keyset{})
			if svc.PublicNativeUserRegistrationEnabled() != tt.wantPublicNativeUsers {
				t.Fatalf("PublicNativeUserRegistrationEnabled=%v, want %v", svc.PublicNativeUserRegistrationEnabled(), tt.wantPublicNativeUsers)
			}
		})
	}
}

func TestPolicySwitches_RejectsLegacyBootstrapOnlyMode(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationMode("bootstrap_only")
	if _, err := NewFromConfig(cfg, nil); err == nil {
		t.Fatalf("legacy bootstrap_only mode should be rejected")
	}
}
