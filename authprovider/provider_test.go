package authprovider

import (
	"errors"
	"testing"
)

func TestResolveStatic(t *testing.T) {
	t.Run("static value", func(t *testing.T) {
		got, err := (ClientSecret{Value: " secret "}).ResolveStatic()
		if err != nil || got != "secret" {
			t.Fatalf("got %q err %v", got, err)
		}
	})

	t.Run("env set and populated", func(t *testing.T) {
		const key = "AUTHKIT_TEST_CLIENT_SECRET"
		t.Setenv(key, "from-env")
		got, err := (ClientSecret{Env: key}).ResolveStatic()
		if err != nil || got != "from-env" {
			t.Fatalf("got %q err %v", got, err)
		}
	})

	t.Run("env set but empty", func(t *testing.T) {
		const key = "AUTHKIT_TEST_CLIENT_SECRET_EMPTY"
		t.Setenv(key, "")
		_, err := (ClientSecret{Env: key}).ResolveStatic()
		if !errors.Is(err, ErrClientSecretEnvEmpty) {
			t.Fatalf("expected ErrClientSecretEnvEmpty, got %v", err)
		}
	})

	t.Run("dynamic strategy", func(t *testing.T) {
		got, err := (ClientSecret{Strategy: SecretStrategyAppleJWT}).ResolveStatic()
		if err != nil || got != "" {
			t.Fatalf("got %q err %v", got, err)
		}
	})

	t.Run("no source", func(t *testing.T) {
		got, err := (ClientSecret{}).ResolveStatic()
		if err != nil || got != "" {
			t.Fatalf("got %q err %v", got, err)
		}
	})
}

func TestProviderValidateRejectsNonHTTPSOAuthURLs(t *testing.T) {
	err := (Provider{
		Name:        "custom",
		Kind:        KindOAuth2,
		TokenURL:    "http://token.example/oauth/token",
		UserInfoURL: "https://userinfo.example/me",
	}).Validate()
	if !errors.Is(err, ErrProviderNonHTTPSURL) {
		t.Fatalf("expected ErrProviderNonHTTPSURL, got %v", err)
	}
}

func TestProviderValidateRejectsNonHTTPSEmailFallbackURL(t *testing.T) {
	err := (Provider{
		Name:             "custom",
		Kind:             KindOAuth2,
		AuthorizeURL:     "https://oauth.example/authorize",
		TokenURL:         "https://token.example/oauth/token",
		UserInfoURL:      "https://userinfo.example/me",
		EmailFallbackURL: "http://userinfo.example/emails",
	}).Validate()
	if !errors.Is(err, ErrProviderNonHTTPSURL) {
		t.Fatalf("expected ErrProviderNonHTTPSURL, got %v", err)
	}
}

func TestProviderValidateAcceptsHTTPSOAuthURLs(t *testing.T) {
	if err := (Provider{
		Name:         "custom",
		Kind:         KindOAuth2,
		AuthorizeURL: "https://oauth.example/authorize",
		TokenURL:     "https://token.example/oauth/token",
		UserInfoURL:  "https://userinfo.example/me",
	}).Validate(); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
}

func TestBuiltInOAuth2ProvidersHaveIdentityMapper(t *testing.T) {
	for _, name := range []string{"discord", "github"} {
		p, ok := BuiltIn(name)
		if !ok {
			t.Fatalf("missing built-in provider %s", name)
		}
		if p.IdentityMapper == nil {
			t.Fatalf("%s: expected an IdentityMapper", name)
		}
	}
}

func TestBuiltInOIDCProvidersHaveNoIdentityMapper(t *testing.T) {
	for _, name := range []string{"google", "apple"} {
		p, ok := BuiltIn(name)
		if !ok {
			t.Fatalf("missing built-in provider %s", name)
		}
		if p.IdentityMapper != nil {
			t.Fatalf("%s: OIDC providers read standard ID-token claims, want no IdentityMapper", name)
		}
	}
}

func TestDiscordIdentityMapperExtractsFields(t *testing.T) {
	p, _ := BuiltIn("discord")
	id, err := p.IdentityMapper(map[string]any{
		"id":          "123456789",
		"email":       " user@example.com ",
		"verified":    true,
		"username":    " octo ",
		"global_name": " Octo Cat ",
	})
	if err != nil {
		t.Fatalf("discord mapper error: %v", err)
	}
	if id.Subject != "123456789" || id.Email != "user@example.com" || !id.EmailVerified ||
		id.PreferredUsername != "octo" || id.DisplayName != "Octo Cat" {
		t.Fatalf("unexpected discord identity: %+v", id)
	}
}

// AK security audit F4: GitHub's /user.email is a public profile field with no
// verification guarantee, so the identity mapper must NOT assume it is verified.
func TestGitHubIdentityMapperUsesNumericIDAndNeverAssumesVerified(t *testing.T) {
	p, _ := BuiltIn("github")
	id, err := p.IdentityMapper(map[string]any{
		"id":    float64(12345),
		"email": "user@example.com",
		"login": "octocat",
		"name":  "Mona Lisa",
	})
	if err != nil {
		t.Fatalf("github mapper error: %v", err)
	}
	if id.Subject != "12345" || id.Email != "user@example.com" ||
		id.PreferredUsername != "octocat" || id.DisplayName != "Mona Lisa" {
		t.Fatalf("unexpected github identity: %+v", id)
	}
	if id.EmailVerified {
		t.Fatalf("GitHub /user.email must NOT be assumed verified (AK F4)")
	}
}

func TestIdentityMapperRejectsMissingSubject(t *testing.T) {
	p, _ := BuiltIn("github")
	if _, err := p.IdentityMapper(map[string]any{"email": "user@example.com"}); err == nil {
		t.Fatalf("expected error when subject is missing")
	}
}

func TestBuiltInProviderDescriptors(t *testing.T) {
	tests := []struct {
		name string
		kind Kind
	}{
		{name: "google", kind: KindOIDC},
		{name: "apple", kind: KindOIDC},
		{name: "discord", kind: KindOAuth2},
		{name: "github", kind: KindOAuth2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, ok := BuiltIn(tt.name)
			if !ok {
				t.Fatalf("missing built-in provider %s", tt.name)
			}
			if provider.Kind != tt.kind {
				t.Fatalf("unexpected kind for %s: %s", tt.name, provider.Kind)
			}
			if provider.Name == "" || provider.Issuer == "" || len(provider.Scopes) == 0 {
				t.Fatalf("incomplete provider descriptor: %+v", provider)
			}
		})
	}
}
