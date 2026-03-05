package main

import "testing"

func resetDevserverEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"DB_URL", "DATABASE_URL",
		"DEVSERVER_LISTEN_ADDR", "AUTHKIT_LISTEN_ADDR",
		"DEVSERVER_ISSUER", "AUTHKIT_ISSUER",
		"DEVSERVER_DEV_MODE", "AUTHKIT_DEV_MODE",
		"DEVSERVER_DEV_MINT_SECRET", "AUTHKIT_DEV_MINT_SECRET",
		"DEVSERVER_REQUIRE_VERIFIED_REGISTRATIONS",
		"DEVSERVER_VERIFICATION_REQUIRED",
		"AUTHKIT_VERIFICATION_REQUIRED",
		"DEVSERVER_MIGRATE_ON_START", "AUTHKIT_MIGRATE_ON_START",
		"DEVSERVER_ISSUED_AUDIENCES", "AUTHKIT_ISSUED_AUDIENCES",
		"DEVSERVER_EXPECTED_AUDIENCES", "AUTHKIT_EXPECTED_AUDIENCES",
		"DEVSERVER_ENVIRONMENT", "AUTHKIT_ENVIRONMENT",
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}
}

func TestLoadConfigVerificationEnvAliases(t *testing.T) {
	t.Run("default_true", func(t *testing.T) {
		resetDevserverEnv(t)
		t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
		t.Setenv("DEVSERVER_ISSUER", "http://issuer:8080")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig failed: %v", err)
		}
		if !cfg.RequireVerifiedRegistrations {
			t.Fatalf("expected RequireVerifiedRegistrations=true by default")
		}
	})

	t.Run("legacy_authkit_alias", func(t *testing.T) {
		resetDevserverEnv(t)
		t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
		t.Setenv("AUTHKIT_ISSUER", "http://legacy-issuer:8080")
		t.Setenv("AUTHKIT_VERIFICATION_REQUIRED", "false")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig failed: %v", err)
		}
		if cfg.Issuer != "http://legacy-issuer:8080" {
			t.Fatalf("issuer=%q, want %q", cfg.Issuer, "http://legacy-issuer:8080")
		}
		if cfg.RequireVerifiedRegistrations {
			t.Fatalf("expected RequireVerifiedRegistrations=false from AUTHKIT_VERIFICATION_REQUIRED")
		}
	})

	t.Run("legacy_devserver_alias", func(t *testing.T) {
		resetDevserverEnv(t)
		t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
		t.Setenv("DEVSERVER_ISSUER", "http://issuer:8080")
		t.Setenv("DEVSERVER_VERIFICATION_REQUIRED", "false")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig failed: %v", err)
		}
		if cfg.RequireVerifiedRegistrations {
			t.Fatalf("expected RequireVerifiedRegistrations=false from DEVSERVER_VERIFICATION_REQUIRED")
		}
	})
}

func TestLoadConfigCanonicalPrecedence(t *testing.T) {
	resetDevserverEnv(t)
	t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
	t.Setenv("DEVSERVER_ISSUER", "http://canonical-issuer:8080")
	t.Setenv("AUTHKIT_ISSUER", "http://legacy-issuer:8080")
	t.Setenv("DEVSERVER_REQUIRE_VERIFIED_REGISTRATIONS", "true")
	t.Setenv("AUTHKIT_VERIFICATION_REQUIRED", "false")
	t.Setenv("DEVSERVER_ISSUED_AUDIENCES", "a,b")
	t.Setenv("AUTHKIT_ISSUED_AUDIENCES", "legacy")
	t.Setenv("DEVSERVER_EXPECTED_AUDIENCES", "a")
	t.Setenv("AUTHKIT_EXPECTED_AUDIENCES", "legacy")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if cfg.Issuer != "http://canonical-issuer:8080" {
		t.Fatalf("issuer=%q, want canonical value", cfg.Issuer)
	}
	if !cfg.RequireVerifiedRegistrations {
		t.Fatalf("expected canonical DEVSERVER_REQUIRE_VERIFIED_REGISTRATIONS to win")
	}
	if len(cfg.IssuedAudiences) != 2 || cfg.IssuedAudiences[0] != "a" || cfg.IssuedAudiences[1] != "b" {
		t.Fatalf("issued audiences=%v, want [a b]", cfg.IssuedAudiences)
	}
	if len(cfg.ExpectedAudiences) != 1 || cfg.ExpectedAudiences[0] != "a" {
		t.Fatalf("expected audiences=%v, want [a]", cfg.ExpectedAudiences)
	}
}
