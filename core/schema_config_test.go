package core

import (
	"strings"
	"testing"
	"time"

	jwtkit "github.com/open-rails/authkit/jwt"
)

func schemaTestConfig(schema string) Config {
	ks, err := jwtkit.NewGeneratedKeySource()
	if err != nil {
		panic(err)
	}
	return Config{
		Issuer:               "https://example.test",
		IssuedAudiences:      []string{"app"},
		ExpectedAudiences:    []string{"app"},
		AccessTokenDuration:  time.Hour,
		RefreshTokenDuration: time.Hour,
		Keys:                 ks,
		Schema:               schema,
	}
}

func TestNewFromConfigSchemaDefaultsToProfiles(t *testing.T) {
	svc, err := NewFromConfig(schemaTestConfig(""))
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Schema(); got != "profiles" {
		t.Fatalf("Schema() = %q, want profiles", got)
	}
}

func TestNewFromConfigSchemaConfigurable(t *testing.T) {
	svc, err := NewFromConfig(schemaTestConfig("openrails_auth"))
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Schema(); got != "openrails_auth" {
		t.Fatalf("Schema() = %q, want openrails_auth", got)
	}
}

func TestNewFromConfigSchemaRejected(t *testing.T) {
	for _, schema := range []string{"Profiles", "1abc", "a-b", "a b", `a"b`, "a;drop", "pro.files", strings.Repeat("a", 64)} {
		if _, err := NewFromConfig(schemaTestConfig(schema)); err == nil {
			t.Errorf("NewFromConfig with Schema=%q should error", schema)
		}
	}
}

func TestNewServicePanicsOnInvalidSchema(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("NewService with invalid Schema should panic")
		}
	}()
	NewService(Options{Schema: "not;valid"}, Keyset{})
}
