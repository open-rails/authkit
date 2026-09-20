package authkitgin

import (
	"context"
	"crypto"

	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/jwtkit"

	"github.com/stretchr/testify/require"
)

func newTestService(t *testing.T) *authhttp.Service {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "test-kid")
	require.NoError(t, err)
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:              "https://example.com",
			IssuedAudiences:     []string{"test-app"},
			ExpectedAudiences:   []string{"test-app"},
			AccessTokenDuration: time.Hour,
		},
		Registration: embedded.RegistrationConfig{Verification: embedded.RegistrationVerificationNone},
		Ephemeral:    embedded.EphemeralConfig{AllowMemory: true},
		Identity: embedded.IdentityConfig{
			Providers: []authprovider.Provider{
				authprovider.Google("google-client", "google-secret"),
			},
		},
		Keys: embedded.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{"test-kid": signer.PublicKey()},
		}},
	}
	// NewServer requires a non-nil pool (#108): the shared integration database,
	// never a phantom DSN. Mirrors internal/testdb's fence, which this nested
	// module cannot import.
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("AUTHKIT_TEST_REQUIRE_DB") == "1" {
			t.Fatal("AUTHKIT_TEST_DATABASE_URL not set but AUTHKIT_TEST_REQUIRE_DB=1")
		}
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	client, err := embedded.New(cfg, embedded.Deps{Postgres: pool})
	require.NoError(t, err)
	t.Cleanup(client.Close)
	// Rate limiting off: the parity test probes the whole route table twice
	// (old stack + new mount) and must not trip order-dependent 429s.
	svc, err := authhttp.New(client, authhttp.Config{DisableRateLimiting: true, DirectPeerIP: true})
	require.NoError(t, err)
	t.Cleanup(svc.Close)
	return svc
}
