package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-rails/authkit/embedded"
)

// setBaseEnv sets the minimum valid environment for loadConfig and clears the
// vars the #266 tests assert on, so ambient env can't leak in.
func setBaseEnv(t *testing.T) {
	t.Helper()
	t.Setenv("AUTHKIT_ISSUER", "https://auth.test")
	t.Setenv("DB_URL", "postgres://localhost/authkit_test")
	for _, k := range []string{
		"DATABASE_URL",
		"AUTHKIT_LANGUAGES", "AUTHKIT_DEFAULT_LANGUAGE",
		"AUTHKIT_ACTIVE_KEY_ID", "AUTHKIT_ACTIVE_PRIVATE_KEY_PEM", "AUTHKIT_PUBLIC_KEYS",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadConfigRefusesBothDatabaseURLNames(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("DATABASE_URL", "postgres://localhost/other")

	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "not both") {
		t.Fatalf("want both-set refusal, got %v", err)
	}
}

func TestLoadConfigAcceptsEitherDatabaseURLName(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("DB_URL", "")
	t.Setenv("DATABASE_URL", "postgres://localhost/via_database_url")

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.dbURL != "postgres://localhost/via_database_url" {
		t.Fatalf("dbURL = %q", cfg.dbURL)
	}
}

func TestLoadConfigDefaultLanguageMustBeSupported(t *testing.T) {
	cases := []struct {
		name, languages, def string
		wantErr              bool
	}{
		{"default outside supported", "en,fr", "de", true},
		{"default inside supported", "en,fr", "fr", false},
		{"implicit en default outside supported", "fr,de", "", true},
		{"default without languages must be en", "", "fr", true},
		{"unset pair is fine", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			t.Setenv("AUTHKIT_LANGUAGES", tc.languages)
			t.Setenv("AUTHKIT_DEFAULT_LANGUAGE", tc.def)

			_, err := loadConfig()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "AUTHKIT_DEFAULT_LANGUAGE") {
					t.Fatalf("want AUTHKIT_DEFAULT_LANGUAGE boot refusal, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("loadConfig: %v", err)
			}
		})
	}
}

func TestLoadConfigPrefixedKeyMaterialEnv(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("AUTHKIT_ACTIVE_KEY_ID", "kid-1")
	t.Setenv("AUTHKIT_ACTIVE_PRIVATE_KEY_PEM", "-----BEGIN PRIVATE KEY-----")
	t.Setenv("AUTHKIT_PUBLIC_KEYS", `{"kid-0": "-----BEGIN PUBLIC KEY-----"}`)

	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	if cfg.activeKeyID != "kid-1" || cfg.activePrivateKeyPEM != "-----BEGIN PRIVATE KEY-----" {
		t.Fatalf("key material not read from AUTHKIT_* names: %+v", cfg)
	}
	if cfg.publicKeysPEM["kid-0"] != "-----BEGIN PUBLIC KEY-----" {
		t.Fatalf("publicKeysPEM = %v", cfg.publicKeysPEM)
	}
}

func TestLoadConfigRejectsMalformedPublicKeysJSON(t *testing.T) {
	setBaseEnv(t)
	t.Setenv("AUTHKIT_PUBLIC_KEYS", "not-json")

	_, err := loadConfig()
	if err == nil || !strings.Contains(err.Error(), "AUTHKIT_PUBLIC_KEYS") {
		t.Fatalf("want AUTHKIT_PUBLIC_KEYS parse error, got %v", err)
	}
}

// #266: static dev entitlements moved from the AUTHKIT_STATIC_ENTITLEMENTS env
// CSV into the bootstrap manifest's dev fixture section.
func TestBootstrapManifestDevStaticEntitlements(t *testing.T) {
	dir := t.TempDir()

	fixturesOnly := filepath.Join(dir, "dev-only.yaml")
	if err := os.WriteFile(fixturesOnly, []byte("dev:\n  static_entitlements: [pro, beta]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := embedded.LoadBootstrapManifestFile(fixturesOnly)
	if err != nil {
		t.Fatalf("fixtures-only manifest: %v", err)
	}
	if len(m.Dev.StaticEntitlements) != 2 || m.Dev.StaticEntitlements[0] != "pro" {
		t.Fatalf("Dev.StaticEntitlements = %v", m.Dev.StaticEntitlements)
	}
	if len(m.Users) != 0 || len(m.RemoteApplications) != 0 {
		t.Fatalf("fixtures-only manifest must seed nothing: %+v", m)
	}

	combined := filepath.Join(dir, "combined.yaml")
	combinedYAML := "users:\n  - email: op@example.com\n    username: op\ndev:\n  static_entitlements: [pro]\n"
	if err := os.WriteFile(combined, []byte(combinedYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err = embedded.LoadBootstrapManifestFile(combined)
	if err != nil {
		t.Fatalf("combined manifest: %v", err)
	}
	if len(m.Users) != 1 || len(m.Dev.StaticEntitlements) != 1 {
		t.Fatalf("combined manifest parse: %+v", m)
	}
}
