package core

import (
	"bytes"
	stdlog "log"
	"strings"
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

func TestRegistrationVerificationResolution(t *testing.T) {
	tests := []struct {
		name string
		val  RegistrationVerificationPolicy
		want RegistrationVerificationPolicy
	}{
		{name: "default_none", val: "", want: RegistrationVerificationNone},
		{name: "optional", val: RegistrationVerificationOptional, want: RegistrationVerificationOptional},
		{name: "required", val: RegistrationVerificationRequired, want: RegistrationVerificationRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseTestConfig(t)
			cfg.RegistrationVerification = tt.val

			svc, err := NewFromConfig(cfg)
			if err != nil {
				t.Fatalf("NewFromConfig failed: %v", err)
			}

			opts := svc.Options()
			if opts.RegistrationVerificationPolicy() != tt.want {
				t.Fatalf("RegistrationVerification=%v, want %v", opts.RegistrationVerificationPolicy(), tt.want)
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

func TestBaseURLDefaultsToIssuerWhenIssuerIsURL(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Issuer = "https://issuer.example"
	cfg.BaseURL = ""

	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig failed: %v", err)
	}
	if got := svc.Options().BaseURL; got != "https://issuer.example" {
		t.Fatalf("BaseURL=%q, want %q", got, "https://issuer.example")
	}
}

func TestIssuerNonURLWithoutBaseURLReturnsError(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Issuer = "issuer-local"
	cfg.BaseURL = ""

	svc, err := NewFromConfig(cfg)
	if err == nil {
		_ = svc
		t.Fatalf("expected error when issuer is not a URL and base_url is empty")
	}
	if !strings.Contains(err.Error(), "BaseURL is required when Issuer is not a well-formatted URL") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIssuerNonURLWithBaseURLLogsWarningAndSucceeds(t *testing.T) {
	cfg := baseTestConfig(t)
	cfg.Issuer = "issuer-local"
	cfg.BaseURL = "https://app.example"

	var buf bytes.Buffer
	oldWriter := stdlog.Writer()
	oldFlags := stdlog.Flags()
	stdlog.SetOutput(&buf)
	stdlog.SetFlags(0)
	t.Cleanup(func() {
		stdlog.SetOutput(oldWriter)
		stdlog.SetFlags(oldFlags)
	})

	svc, err := NewFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewFromConfig failed: %v", err)
	}
	if svc.Options().BaseURL != "https://app.example" {
		t.Fatalf("BaseURL=%q, want %q", svc.Options().BaseURL, "https://app.example")
	}
	logged := buf.String()
	if !strings.Contains(logged, "Issuer is not a well-formatted URL") {
		t.Fatalf("expected warning log, got: %q", logged)
	}
}
