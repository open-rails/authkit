package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func TestBuildAuthProvidersMapRejectsNonHTTPSCustomProvider(t *testing.T) {
	_, err := buildAuthProvidersMap([]authprovider.Provider{
		{
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
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test"},
			ExpectedAudiences: []string{"test"},
		},
		Identity: embedded.IdentityConfig{
			Providers: []authprovider.Provider{
				testBuiltInProvider(t, "github", "github-client", "github-secret"),
				{
					Name:     "custom",
					Kind:     authprovider.KindOAuth2,
					Issuer:   "https://custom.example",
					ClientID: "custom-client",
					ClientSecret: authprovider.ClientSecret{
						Value: "custom-secret",
					},
					AuthorizeURL: "https://custom.example/auth",
					TokenURL:     "https://custom.example/token",
					UserInfoURL:  "https://custom.example/user",
					UserMapping: authprovider.UserMapping{
						Subject: authprovider.FieldMapping{Path: "id", Transforms: []string{"string"}},
					},
				},
			},
		},
	}
	s, err := NewServer(newServerClient(t, cfg, newNoDBPool(t)))
	require.NoError(t, err)

	github, ok := s.authProvider("github")
	require.True(t, ok)
	require.Equal(t, "github-client", github.ClientID)

	custom, ok := s.authProvider("custom")
	require.True(t, ok)
	require.Equal(t, "https://custom.example/token", custom.TokenURL)
}

func TestBuildAuthProvidersMapSkipsUnconfiguredProviders(t *testing.T) {
	providers, err := buildAuthProvidersMap([]authprovider.Provider{
		testBuiltInProvider(t, "google", "", "google-secret"),
		testBuiltInProvider(t, "discord", "discord-client", "discord-secret"),
		{
			Name:         "custom",
			Kind:         authprovider.KindOAuth2,
			Issuer:       "https://custom.example",
			ClientID:     "custom-client",
			AuthorizeURL: "https://custom.example/auth",
			TokenURL:     "https://custom.example/token",
			UserInfoURL:  "https://custom.example/user",
		},
	})
	require.NoError(t, err)

	require.NotContains(t, providers, "google")
	require.Contains(t, providers, "discord")
	require.NotContains(t, providers, "custom")
}

func TestBuildAuthProvidersMapTreatsEmptySecretEnvAsUnavailable(t *testing.T) {
	t.Setenv("AUTHKIT_EMPTY_PROVIDER_SECRET", "")

	providers, err := buildAuthProvidersMap([]authprovider.Provider{
		{
			Name:         "custom",
			Kind:         authprovider.KindOAuth2,
			Issuer:       "https://custom.example",
			ClientID:     "custom-client",
			ClientSecret: authprovider.ClientSecret{Env: "AUTHKIT_EMPTY_PROVIDER_SECRET"},
			AuthorizeURL: "https://custom.example/auth",
			TokenURL:     "https://custom.example/token",
			UserInfoURL:  "https://custom.example/user",
		},
	})
	require.NoError(t, err)
	require.Empty(t, providers)
}

func testBuiltInProvider(t *testing.T, name, clientID, secret string) authprovider.Provider {
	t.Helper()
	p, ok := authprovider.BuiltIn(name)
	require.True(t, ok)
	p.ClientID = clientID
	p.ClientSecret = authprovider.ClientSecret{Value: secret}
	return p
}

func TestProvidersGETReturnsConfiguredProvidersOnly(t *testing.T) {
	s := &Service{
		authProvidersByName: map[string]authprovider.Provider{
			"google": {
				Name:     "google",
				Kind:     authprovider.KindOIDC,
				Issuer:   "https://accounts.google.com",
				ClientID: "google-client",
				ClientSecret: authprovider.ClientSecret{
					Value: "google-secret",
				},
			},
		},
	}

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/identity-providers", nil)
	s.handleProvidersGET(w, r)
	require.Equal(t, http.StatusOK, w.Code)

	var body struct {
		Providers []authkit.AuthProviderSummary `json:"providers"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Len(t, body.Providers, 1)
	require.Equal(t, "google", body.Providers[0].ID)
	require.Equal(t, "Google", body.Providers[0].Name)
	require.True(t, body.Providers[0].SupportsLogin)
	require.True(t, body.Providers[0].SupportsRegistration)
	require.True(t, body.Providers[0].SupportsLink)
}
