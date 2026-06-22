package core

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
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeOpen {
		t.Fatalf("NativeUserRegistrationMode should default to open")
	}
	if !opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should default to true")
	}
}

func TestPolicySwitches_Plumbed(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationModeAdminBootstrapOnly
	svc, err := NewFromConfig(cfg, nil)
	if err != nil {
		t.Fatalf("NewFromConfig: %v", err)
	}
	opts := svc.Options()
	if opts.NativeUserRegistrationMode != RegistrationModeAdminBootstrapOnly {
		t.Fatalf("NativeUserRegistrationMode not plumbed through NewFromConfig")
	}
	if opts.PublicNativeUserRegistrationEnabled() {
		t.Fatalf("PublicNativeUserRegistrationEnabled should be false when disabled")
	}
}

// CreatePendingRegistration is the core front-door chokepoint for public
// password registration. It must hard-fail with ErrRegistrationDisabled when
// the switch is on, before touching storage.
func TestPolicySwitches_CoreRegistrationGate(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Registration.NativeUserMode = RegistrationModeAdminBootstrapOnly
	svc, err := NewFromConfig(cfg, nil)
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

func TestPolicySwitches_RegistrationModes(t *testing.T) {
	for _, mode := range []RegistrationMode{
		RegistrationModeInviteOnly,
		RegistrationModeAdminOnly,
		RegistrationModeAdminBootstrapOnly,
		RegistrationModeManifestOnly,
		RegistrationModeClosed,
	} {
		t.Run(string(mode), func(t *testing.T) {
			svc := NewService(Options{NativeUserRegistrationMode: mode}, Keyset{})
			got := svc.Options()
			if got.PublicNativeUserRegistrationEnabled() {
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
			nativeMode: RegistrationModeAdminOnly,
		},
		{
			name:       "openrails-relying-party-closed",
			nativeMode: RegistrationModeClosed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := NewService(Options{
				Issuer:                     "https://test",
				NativeUserRegistrationMode: tt.nativeMode,
			}, Keyset{})
			opts := svc.Options()
			if opts.PublicNativeUserRegistrationEnabled() != tt.wantPublicNativeUsers {
				t.Fatalf("PublicNativeUserRegistrationEnabled=%v, want %v", opts.PublicNativeUserRegistrationEnabled(), tt.wantPublicNativeUsers)
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
