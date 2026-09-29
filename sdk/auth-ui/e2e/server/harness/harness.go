// Package harness builds the AuthKit runtime shared by the e2e server and the
// contract generator, so the generated contract is exactly what the server mounts.
package harness

import (
	"context"
	"crypto"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/open-rails/authkit/verify"
)

const (
	Schema   = "profiles"
	Audience = "auth-ui-e2e"
)

// Runtime is a started-or-not AuthKit runtime plus its captured mount.
type Runtime struct {
	*authkit.Runtime
	Mount  *authhttp.Mount
	Outbox *Outbox
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
	if err := authkit.ApplyMigrations(ctx, pool, Schema); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// New builds the runtime for baseURL (the single same-origin SPA+API origin).
func New(baseURL string, pool *pgxpool.Pool) (*Runtime, error) {
	signer, err := jwtkit.NewRSASigner(2048, "e2e-1")
	if err != nil {
		return nil, err
	}
	limits := authhttp.DefaultRateLimits()
	for bucket := range limits {
		limits[bucket] = ratelimit.Limit{Limit: 10000, Window: time.Minute}
	}
	capture := &mountCapture{cfg: authhttp.Config{
		DirectPeerIP: true,
		RateLimits:   limits,
		Mount:        authhttp.MountOptions{RefreshCookie: true},
	}}
	outbox := &Outbox{}
	cfg := authkit.Config{
		HTTP:   capture,
		Schema: Schema,
		Keys: authkit.KeysConfig{Source: jwtkit.StaticKeySource{
			Active: signer,
			Pubs:   map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
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
		Identity:      authkit.IdentityConfig{Providers: []authprovider.Provider{authprovider.GitHub("e2e", "e2e")}},
		SolanaNetwork: "devnet",
	}
	rt, err := authkit.New(cfg, authkit.Deps{
		Postgres: pool,
		Email:    emailSender{outbox},
		SMS:      smsSender{outbox},
	})
	if err != nil {
		return nil, err
	}
	if capture.mount == nil {
		rt.Close()
		return nil, errors.New("harness: HTTP surface was not built")
	}
	return &Runtime{Runtime: rt, Mount: capture.mount, Outbox: outbox}, nil
}

// mountCapture is authhttp.Config.BuildHTTP that also keeps the Mount, whose
// Routes() carry the group and auth tier the runtime's route list drops.
type mountCapture struct {
	cfg   authhttp.Config
	mount *authhttp.Mount
}

type surface struct {
	*authhttp.Service
	routes []authkit.HTTPRoute
}

func (s surface) Routes() []authkit.HTTPRoute { return s.routes }
func (s surface) Verifier() *verify.Verifier  { return s.Service.Verifier() }

func (m *mountCapture) BuildHTTP(backend any) (authkit.HTTPSurface, error) {
	svc, err := authhttp.New(backend.(authhttp.Backend), m.cfg)
	if err != nil {
		return nil, err
	}
	mount, err := authhttp.NewMount(svc, m.cfg.Mount)
	if err != nil {
		svc.Close()
		return nil, err
	}
	m.mount = mount
	s := surface{Service: svc}
	for _, r := range mount.Routes() {
		s.routes = append(s.routes, authkit.HTTPRoute{Method: r.Method, Path: r.Path, Handler: mount})
	}
	return s, nil
}
