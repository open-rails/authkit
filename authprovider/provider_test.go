package authprovider

import "testing"

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
