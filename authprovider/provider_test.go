package authprovider

import (
	"errors"
	"testing"
)

func TestMapIdentityConvertsAndTransformsFields(t *testing.T) {
	root := map[string]any{
		"id":       float64(12345),
		"email":    " Person@Example.COM ",
		"verified": true,
		"profile": map[string]any{
			"login": " OctoCat ",
			"name":  " Mona Lisa ",
		},
	}
	got, err := MapIdentity(root, UserMapping{
		Subject:           FieldMapping{Path: "id", Transforms: []string{"string", "trim"}},
		Email:             FieldMapping{Path: "email", Transforms: []string{"trim", "lowercase"}},
		EmailVerified:     FieldMapping{Path: "verified"},
		PreferredUsername: FieldMapping{Path: "profile.login", Transforms: []string{"trim"}},
		DisplayName:       FieldMapping{Path: "profile.name", Transforms: []string{"trim"}},
	})
	if err != nil {
		t.Fatalf("MapIdentity returned error: %v", err)
	}
	if got.Subject != "12345" || got.Email != "person@example.com" || !got.EmailVerified || got.PreferredUsername != "OctoCat" || got.DisplayName != "Mona Lisa" {
		t.Fatalf("unexpected identity: %+v", got)
	}
}

func TestMapFallbackEmailSelectsVerifiedPrimary(t *testing.T) {
	root := []any{
		map[string]any{"email": "secondary@example.com", "primary": false, "verified": true},
		map[string]any{"email": "primary@example.com", "primary": true, "verified": true},
	}
	email, verified := MapFallbackEmail(root, FallbackLookup{
		Array:         true,
		Select:        map[string]any{"primary": true, "verified": true},
		Email:         FieldMapping{Path: "email"},
		EmailVerified: FieldMapping{Value: true},
	})
	if email != "primary@example.com" || !verified {
		t.Fatalf("unexpected fallback email: %q %v", email, verified)
	}
}

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

func TestMapBoolNumericValues(t *testing.T) {
	cases := []struct {
		value any
		want  bool
	}{
		{value: 1, want: true},
		{value: int64(0), want: false},
		{value: float64(2), want: true},
		{value: uint(0), want: false},
	}
	for _, tc := range cases {
		got, err := mapBool(map[string]any{"v": tc.value}, FieldMapping{Path: "v"})
		if err != nil {
			t.Fatalf("mapBool returned error: %v", err)
		}
		if got != tc.want {
			t.Fatalf("value %v: got %v want %v", tc.value, got, tc.want)
		}
	}
}

func TestProviderValidateRejectsUnknownTransform(t *testing.T) {
	err := (Provider{
		Name: "custom",
		Kind: KindOAuth2,
		UserMapping: UserMapping{
			Subject: FieldMapping{Path: "id", Transforms: []string{"rot13"}},
		},
	}).Validate()
	if !errors.Is(err, ErrProviderInvalidTransform) {
		t.Fatalf("expected ErrProviderInvalidTransform, got %v", err)
	}
}

func TestProviderValidateRejectsNonHTTPSOAuthURLs(t *testing.T) {
	err := (Provider{
		Name:        "custom",
		Kind:        KindOAuth2,
		TokenURL:    "http://token.example/oauth/token",
		UserInfoURL: "https://userinfo.example/me",
		UserMapping: UserMapping{
			Subject: FieldMapping{Path: "id"},
		},
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
		UserMapping: UserMapping{
			Subject: FieldMapping{Path: "id"},
		},
	}).Validate(); err != nil {
		t.Fatalf("unexpected validate error: %v", err)
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
