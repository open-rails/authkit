package authhttp

import (
	"testing"

	"github.com/open-rails/authkit/authprovider"
	core "github.com/open-rails/authkit/core"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthProvidersMapRejectsNonHTTPSCustomProvider(t *testing.T) {
	_, err := buildAuthProvidersMap(nil, map[string]authprovider.Provider{
		"evil": {
			Name:        "evil",
			Kind:        authprovider.KindOAuth2,
			TokenURL:    "http://evil.example/token",
			UserInfoURL: "https://evil.example/user",
			UserMapping: authprovider.UserMapping{
				Subject: authprovider.FieldMapping{Path: "id"},
			},
		},
	})
	require.ErrorIs(t, err, authprovider.ErrProviderNonHTTPSURL)
}

func TestAuthProviderCacheIsolation(t *testing.T) {
	s := &Service{
		authProvidersByName: map[string]authprovider.Provider{
			"github": {
				Name:     "github",
				Kind:     authprovider.KindOAuth2,
				ClientID: "original-id",
			},
		},
	}

	first, ok := s.authProvider("github")
	require.True(t, ok)
	first.ClientID = "mutated-id"

	second, ok := s.authProvider("github")
	require.True(t, ok)
	require.Equal(t, "original-id", second.ClientID)
}

func TestNewServicePrebuildsAuthProviders(t *testing.T) {
	cfg := core.Config{
		Issuer:            "https://example.com",
		IssuedAudiences:   []string{"test"},
		ExpectedAudiences: []string{"test"},
		Providers: map[string]oidckit.RPConfig{
			"github": {ClientID: "github-client", ClientSecret: "github-secret"},
		},
		ProviderDescriptors: map[string]authprovider.Provider{
			"custom": {
				Name:        "custom",
				Kind:        authprovider.KindOAuth2,
				Issuer:      "https://custom.example",
				TokenURL:    "https://custom.example/token",
				UserInfoURL: "https://custom.example/user",
				UserMapping: authprovider.UserMapping{
					Subject: authprovider.FieldMapping{Path: "id", Transforms: []string{"string"}},
				},
			},
		},
	}
	s, err := NewService(cfg)
	require.NoError(t, err)

	github, ok := s.authProvider("github")
	require.True(t, ok)
	require.Equal(t, "github-client", github.ClientID)

	custom, ok := s.authProvider("custom")
	require.True(t, ok)
	require.Equal(t, "https://custom.example/token", custom.TokenURL)
}
