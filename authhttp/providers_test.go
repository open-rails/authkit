package authhttp

import (
	"testing"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestProviderRegistryRejectsInvalidProviders(t *testing.T) {
	custom := func(auth, token string) authprovider.Provider {
		return authprovider.OAuth2("custom", "https://custom.example", authprovider.Endpoint{AuthorizeURL: auth, TokenURL: token},
			"custom-client", "custom-secret", testUserInfo("https://custom.example/me"))
	}
	_, err := providerRegistry([]authprovider.Provider{custom("https://custom.example/auth", "http://custom.example/token")})
	require.ErrorIs(t, err, authprovider.ErrProviderNonHTTPSURL)

	_, err = providerRegistry([]authprovider.Provider{authprovider.Google("", "google-secret")})
	require.ErrorIs(t, err, authprovider.ErrProviderInvalid)

	// #231: no env-var indirection — an empty explicit secret is a config error.
	_, err = providerRegistry([]authprovider.Provider{authprovider.Discord("discord-client", "  ")})
	require.ErrorIs(t, err, authprovider.ErrProviderInvalid)

	_, err = providerRegistry([]authprovider.Provider{
		authprovider.GitHub("a", "b"),
		authprovider.GitHub("c", "d"),
	})
	require.ErrorIs(t, err, authprovider.ErrProviderInvalid)
	require.Contains(t, err.Error(), "listed twice")

	providers, err := providerRegistry([]authprovider.Provider{
		authprovider.Discord("discord-client", "discord-secret"),
		custom("https://custom.example/auth", "https://custom.example/token"),
	})
	require.NoError(t, err)
	require.Len(t, providers, 2)
	require.Contains(t, providers, "discord")
	require.Contains(t, providers, "custom")
}

func TestNewServerPrebuildsProviders(t *testing.T) {
	cfg := embedded.Config{
		Keys: testKeys(),
		Token: embedded.TokenConfig{
			Issuer:            "https://example.com",
			IssuedAudiences:   []string{"test"},
			ExpectedAudiences: []string{"test"},
		},
		// Provider prebuild only; opt out of the "required" verification default
		// so NewServer doesn't require a sender (#212).
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
		Identity: embedded.IdentityConfig{
			Providers: []authprovider.Provider{
				authprovider.GitHub("github-client", "github-secret"),
				authprovider.OAuth2("custom", "https://custom.example",
					authprovider.Endpoint{AuthorizeURL: "https://custom.example/auth", TokenURL: "https://custom.example/token"},
					"custom-client", "custom-secret", testUserInfo("https://custom.example/user"), authprovider.WithDisplayName("Custom IdP")),
			},
		},
	}
	s, err := NewServer(newServerClient(t, cfg, testdb.UnlockedPool(t)))
	require.NoError(t, err)

	github, ok := s.provider("GitHub")
	require.True(t, ok)
	require.Equal(t, "github", github.Name())
	require.Equal(t, "https://github.com/login/oauth", github.Issuer())
	_, ok = s.provider("custom")
	require.True(t, ok)

	summaries := s.providerSummaries()
	require.Len(t, summaries, 2)
	require.Equal(t, "custom", summaries[0].ID)
	require.Equal(t, "Custom IdP", summaries[0].Name)
	require.Equal(t, "github", summaries[1].ID)
	require.Equal(t, "GitHub", summaries[1].Name)
	require.Equal(t, []string{"custom", "github"}, s.providerNames())
}
