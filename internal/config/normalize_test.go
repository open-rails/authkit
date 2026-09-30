package config

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
)

// Normalizing a normalized Config changes nothing: the engine hands its
// Config to code that may normalize it again.
func TestNormalizeIsIdempotent(t *testing.T) {
	deps := Deps{
		Postgres: &pgxpool.Pool{},
		Email:    nopEmail{},
		DelegatedAuthorization: func(context.Context, iam.DelegationRequest) (iam.DelegationGrant, error) {
			return iam.DelegationGrant{}, nil
		},
	}
	for name, c := range map[string]Config{
		"minimal": {Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}},
		"rich": {
			Token:              TokenConfig{Issuer: "https://example.com/auth", IssuedAudiences: []string{"app"}, AccountIssuers: []string{"https://peer.example"}},
			Password:           &PasswordPolicy{MinLength: 12},
			Username:           UsernameConfig{Renames: true, FormerNames: FormerNamesConfig{Mode: FormerNamesForever}},
			Languages:          LanguageConfig{Supported: []string{"EN", "es-MX"}, Default: "es"},
			Delegated:          DelegatedConfig{Audiences: []string{"platform"}, TTLCeiling: 2 * time.Hour},
			PublicUserMetadata: []string{"bio"},
			HTTP:               &HTTPConfig{DirectPeerIP: true, APIPath: "/"},
		},
	} {
		once, err := Normalize(c, deps)
		require.NoError(t, err, name)
		twice, err := Normalize(once, deps)
		require.NoError(t, err, name)
		require.Equal(t, once, twice, name)
	}
}

// A delegated-token setting without the route's audiences is dead
// configuration and refuses.
func TestNormalizeRefusesDeadDelegatedConfig(t *testing.T) {
	c := Config{Token: TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"app"}}}
	c.Delegated.TTLDefault = time.Minute
	_, err := Normalize(c, Deps{})
	require.ErrorContains(t, err, "Delegated.Audiences is empty")
}

type nopEmail struct{}

func (nopEmail) Send(context.Context, iam.EmailMessage) error { return nil }
func (nopEmail) CheckHealth(context.Context) error            { return nil }
