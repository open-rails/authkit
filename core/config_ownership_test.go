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
		Issuer:            "https://issuer.test",
		IssuedAudiences:   []string{"app"},
		ExpectedAudiences: []string{"app"},
		Keys:              mustGeneratedKeys(t),
	}
}

func TestRequireVerifiedRegistrationsResolution(t *testing.T) {
	tests := []struct {
		name string
		ptr  *bool
		want bool
	}{
		{name: "default_true", ptr: nil, want: true},
		{name: "canonical_false", ptr: Bool(false), want: false},
		{name: "canonical_true", ptr: Bool(true), want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			cfg.RequireVerifiedRegistrations = tt.ptr

			svc, err := NewFromConfig(cfg)
			if err != nil {
				t.Fatalf("NewFromConfig failed: %v", err)
			}

			opts := svc.Options()
			if opts.RequireVerifiedRegistrations != tt.want {
				t.Fatalf("RequireVerifiedRegistrations=%v, want %v", opts.RequireVerifiedRegistrations, tt.want)
			}
		})
	}
}

func TestRuntimeBehaviorIsDerivedFromConfigOnly(t *testing.T) {
	t.Setenv("ENV", "production")
	t.Setenv("APP_ENV", "production")
	t.Setenv("ENVIRONMENT", "production")
	t.Setenv("SOLANA_NETWORK", "mainnet")

	cfg := baseTestConfig(t)
	cfg.Environment = "dev"
	cfg.SolanaNetwork = "testnet"

	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig failed: %v", err)
	}
	if !svc.isDevEnvironment() {
		t.Fatalf("expected dev environment from config")
	}
	if got := svc.solanaChainID(); got != "testnet" {
		t.Fatalf("solanaChainID=%q, want %q", got, "testnet")
	}

	cfgProd := baseTestConfig(t)
	cfgProd.Environment = "production"
	svcProd, err := NewFromConfig(cfgProd)
	if err != nil {
		t.Fatalf("NewFromConfig(prod) failed: %v", err)
	}
	if svcProd.isDevEnvironment() {
		t.Fatalf("expected production environment from config")
	}
	if got := svcProd.solanaChainID(); got != "mainnet" {
		t.Fatalf("solanaChainID=%q, want %q", got, "mainnet")
	}
}
