package authcore

import (
	"crypto"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/jwtkit"
)

func schemaTestConfig(schema string) Config {
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	if err != nil {
		panic(err)
	}
	ks := jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{"test-kid": signer.PublicKey()}}
	return Config{
		Token: TokenConfig{
			Issuer:               "https://example.test",
			IssuedAudiences:      []string{"app"},
			ExpectedAudiences:    []string{"app"},
			AccessTokenDuration:  time.Hour,
			RefreshTokenDuration: time.Hour,
		},
		Keys:   KeysConfig{Source: ks},
		Schema: schema,
	}
}

func TestNewFromConfigSchemaDefaultsToProfiles(t *testing.T) {
	svc, err := NewFromConfig(schemaTestConfig(""), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Schema(); got != "profiles" {
		t.Fatalf("Schema() = %q, want profiles", got)
	}
}

func TestNewFromConfigSchemaConfigurable(t *testing.T) {
	svc, err := NewFromConfig(schemaTestConfig("openrails_auth"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := svc.Schema(); got != "openrails_auth" {
		t.Fatalf("Schema() = %q, want openrails_auth", got)
	}
}

func TestNewFromConfigSchemaRejected(t *testing.T) {
	for _, schema := range []string{"Profiles", "1abc", "a-b", "a b", `a"b`, "a;drop", "pro.files", strings.Repeat("a", 64)} {
		if _, err := NewFromConfig(schemaTestConfig(schema), nil); err == nil {
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
	NewService(Config{Schema: "not;valid"}, Keyset{})
}
