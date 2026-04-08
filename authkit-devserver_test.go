package main

import "testing"

func resetDevserverEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"DB_URL", "DATABASE_URL",
		"DEVSERVER_LISTEN_ADDR",
		"DEVSERVER_ISSUER",
		"DEVSERVER_DEV_MODE",
		"DEVSERVER_DEV_MINT_SECRET",
		"DEVSERVER_REGISTRATION_VERIFICATION",
		"DEVSERVER_MIGRATE_ON_START",
		"DEVSERVER_ISSUED_AUDIENCES",
		"DEVSERVER_EXPECTED_AUDIENCES",
		"DEVSERVER_ENVIRONMENT",
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}
}

func TestLoadConfigRegistrationVerification(t *testing.T) {
	t.Run("default_none", func(t *testing.T) {
		resetDevserverEnv(t)
		t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
		t.Setenv("DEVSERVER_ISSUER", "http://issuer:8080")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig failed: %v", err)
		}
		if cfg.RegistrationVerification != "none" {
			t.Fatalf("expected RegistrationVerification=none, got %q", cfg.RegistrationVerification)
		}
	})

	t.Run("required", func(t *testing.T) {
		resetDevserverEnv(t)
		t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
		t.Setenv("DEVSERVER_ISSUER", "http://issuer:8080")
		t.Setenv("DEVSERVER_REGISTRATION_VERIFICATION", "required")

		cfg, err := loadConfig()
		if err != nil {
			t.Fatalf("loadConfig failed: %v", err)
		}
		if cfg.RegistrationVerification != "required" {
			t.Fatalf("expected RegistrationVerification=required, got %q", cfg.RegistrationVerification)
		}
	})

	t.Run("invalid", func(t *testing.T) {
		resetDevserverEnv(t)
		t.Setenv("DB_URL", "postgres://u:p@localhost:5432/db?sslmode=disable")
		t.Setenv("DEVSERVER_ISSUER", "http://issuer:8080")
		t.Setenv("DEVSERVER_REGISTRATION_VERIFICATION", "true")

		if _, err := loadConfig(); err == nil {
			t.Fatal("expected error for invalid DEVSERVER_REGISTRATION_VERIFICATION")
		}
	})
}
