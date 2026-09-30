// Package harness builds the AuthKit runtime shared by the e2e server and the
// contract generator, so the generated contract is exactly what the server mounts.
package harness

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
)

const (
	Schema   = "profiles"
	Audience = "auth-ui-e2e"
)

// Runtime is a started-or-not AuthKit instance plus its captured deliveries.
type Runtime struct {
	*authkit.Client
	Outbox *authtest.Outbox
}

// Open connects to dsn and applies AuthKit's migrations.
func Open(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	if dsn == "" {
		return nil, errors.New("harness: Postgres DSN is required")
	}
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return nil, err
	}
	if err := authkit.Migrate(ctx, pool, authkit.MigrateOptions{Schema: Schema}); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// New builds the runtime for baseURL (the single same-origin SPA+API origin).
func New(baseURL string, pool *pgxpool.Pool) (*Runtime, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	signer, err := keys.SignerFromKey("e2e-1", key)
	if err != nil {
		return nil, err
	}
	limits := authkit.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = authkit.RateLimit{Limit: 10000, Window: time.Minute}
	}
	outbox := &authtest.Outbox{}
	cfg := authkit.Config{
		HTTP: authkit.HTTPConfig{
			DirectPeerIP:  true,
			RateLimits:    limits,
			RefreshCookie: true,
		},
		Schema: Schema,
		Keys: authkit.KeysConfig{Source: keys.Static{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{signer.KID(): signer.Public()},
		}},
		Token: authkit.TokenConfig{
			Issuer:          baseURL,
			IssuedAudiences: []string{Audience},
		},
		Frontend: authkit.FrontendConfig{BaseURL: baseURL},
		Registration: authkit.RegistrationConfig{
			Verification:      iam.RegistrationVerificationRequired,
			PasswordlessLogin: true,
		},
		TwoFactor: authkit.TwoFactorConfig{
			Mode:          iam.TwoFactorOptional,
			TOTPSecretKey: []byte("auth-ui-e2e-totp-key-32-bytes!!!"),
		},
		Passkeys: authkit.PasskeyConfig{
			RPID:          "localhost",
			RPDisplayName: "auth-ui e2e",
			Origins:       []string{baseURL},
		},
		// Dummy credentials: mounts the provider link/login routes for the
		// contract; the upstream exchange is not exercised.
		Identity:      authkit.IdentityConfig{Providers: []provider.Provider{provider.GitHub("e2e", "e2e")}},
		SolanaNetwork: "devnet",
	}
	rt, err := authkit.New(context.Background(), cfg, authkit.Deps{
		Postgres: pool,
		Email:    outbox.Email(),
		SMS:      outbox.SMS(),
	})
	if err != nil {
		return nil, err
	}
	return &Runtime{Client: rt, Outbox: outbox}, nil
}
