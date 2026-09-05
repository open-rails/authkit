package main

import (
	"os"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
)

func clearNamingEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{"AUTHKIT_NAMING_ENABLED", "AUTHKIT_NAMING_RENAME_INTERVAL", "AUTHKIT_NAMING_FORMER_NAMES_MODE", "AUTHKIT_NAMING_FORMER_NAMES_DURATION"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNamingEnvironmentAndEmbeddedPolicyAgree(t *testing.T) {
	cases := []struct {
		name      string
		env       map[string]string
		enabled   bool
		interval  time.Duration
		mode      authkit.FormerNameRetentionMode
		retention time.Duration
	}{
		{"default", nil, true, 72 * time.Hour, authkit.FormerNamesFinite, 2160 * time.Hour},
		{"disabled", map[string]string{"AUTHKIT_NAMING_ENABLED": "false"}, false, 72 * time.Hour, authkit.FormerNamesFinite, 2160 * time.Hour},
		{"unrestricted", map[string]string{"AUTHKIT_NAMING_RENAME_INTERVAL": "0s"}, true, 0, authkit.FormerNamesFinite, 2160 * time.Hour},
		{"forever", map[string]string{"AUTHKIT_NAMING_FORMER_NAMES_MODE": "forever"}, true, 72 * time.Hour, authkit.FormerNamesForever, 0},
		{"immediate", map[string]string{"AUTHKIT_NAMING_RENAME_INTERVAL": "0s", "AUTHKIT_NAMING_FORMER_NAMES_MODE": "immediate"}, true, 0, authkit.FormerNamesImmediate, 0},
		{"finite zero", map[string]string{"AUTHKIT_NAMING_FORMER_NAMES_DURATION": "0s"}, true, 72 * time.Hour, authkit.FormerNamesImmediate, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setBaseEnv(t)
			clearNamingEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			c, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			client, err := embedded.New(embedded.Config{Naming: c.naming, Keys: embedded.KeysConfig{VerifyOnly: true}, Token: embedded.TokenConfig{Issuer: "https://auth.test", IssuedAudiences: []string{"test"}}}, embedded.Deps{})
			if err != nil {
				t.Fatal(err)
			}
			want := authkit.NamingPolicy{Enabled: tc.enabled, RenameInterval: tc.interval, FormerNameRetentionMode: tc.mode, FormerNameRetention: tc.retention}
			if got := client.NamingPolicy(); got != want {
				t.Fatalf("embedded policy %+v != %+v", got, want)
			}
		})
	}
}

func TestNamingEnvironmentRejectsMalformedValues(t *testing.T) {
	for _, entry := range []struct{ key, value string }{
		{"AUTHKIT_NAMING_ENABLED", ""}, {"AUTHKIT_NAMING_ENABLED", "perhaps"},
		{"AUTHKIT_NAMING_RENAME_INTERVAL", ""}, {"AUTHKIT_NAMING_RENAME_INTERVAL", "-1s"},
		{"AUTHKIT_NAMING_RENAME_INTERVAL", "999999999999999999999h"},
		{"AUTHKIT_NAMING_FORMER_NAMES_DURATION", "-1ns"},
		{"AUTHKIT_NAMING_FORMER_NAMES_MODE", "invalid"},
	} {
		t.Run(entry.key+entry.value, func(t *testing.T) {
			clearNamingEnv(t)
			t.Setenv(entry.key, entry.value)
			if _, err := namingConfigFromEnv(); err == nil {
				t.Fatal("expected invalid config")
			}
		})
	}
	clearNamingEnv(t)
	t.Setenv("AUTHKIT_NAMING_FORMER_NAMES_MODE", "forever")
	t.Setenv("AUTHKIT_NAMING_FORMER_NAMES_DURATION", "0s")
	if _, err := namingConfigFromEnv(); err == nil {
		t.Fatal("contradictory mode/duration accepted")
	}
}
