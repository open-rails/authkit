package authkitgin_test

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/authkitmigrate"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/verify"
)

// The root README's snippets, compiled (not run) so the README cannot drift
// from the API. Keep them byte-for-byte in sync.

func readmeMigrate(ctx context.Context, pool *pgxpool.Pool) error {
	res, err := authkitmigrate.New(pool, nil).Migrate(ctx) // &authkitmigrate.Config{Schema: "…"} for a non-default schema
	_ = res
	return err
}

func setupAuth(pg *pgxpool.Pool, rdb *redis.Client, mailer embedded.EmailSender) (*gin.Engine, error) {
	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:              "https://app.example.com",
			IssuedAudiences:     []string{"myapp"},
			ExpectedAudiences:   []string{"myapp"},
			AccessTokenDuration: 15 * time.Minute,
		},
		Frontend:     embedded.FrontendConfig{BaseURL: "https://app.example.com"},
		Registration: embedded.RegistrationConfig{Verification: authkit.RegistrationVerificationRequired},
		Keys:         embedded.KeysConfig{Path: "/vault/auth"}, // keys.json + totp.key; AllowEphemeralDevKeys only in dev
		TwoFactor:    embedded.TwoFactorConfig{Mode: authkit.TwoFactorOptional},
		Passkeys:     embedded.PasskeyConfig{RPID: "app.example.com", Origins: []string{"https://app.example.com"}},
		RBAC: []embedded.PersonaDef{{
			Name:   "org",
			Parent: authkit.RootPersona,
			Roles:  []embedded.RoleDef{{Name: "admin", Permissions: []string{"org:members:read", "org:members:manage"}}},
		}},
	}
	client, err := embedded.New(cfg, embedded.Deps{Postgres: pg, Redis: rdb, Email: mailer})
	if err != nil {
		return nil, err
	}
	srv, err := authhttp.New(client, authhttp.Config{
		TrustedProxies: []string{"10.0.0.0/8"}, // or DirectPeerIP: true when nothing sits in front
	})
	if err != nil {
		return nil, err
	}
	mount, err := authhttp.MountHandler(srv, authhttp.MountOptions{RefreshCookie: true})
	if err != nil {
		return nil, err
	}
	router := gin.New()
	router.NoRoute(authkitgin.Fallback(mount)) // host routes win; AuthKit answers the rest

	requireAuth := authkitgin.Required(srv.Verifier())
	orgScope := func(c *gin.Context) verify.PermissionScope {
		g, err := client.GroupInstanceForSlug(c.Request.Context(), authkit.GroupRef{Persona: "org", Instance: c.Param("org")})
		if err != nil {
			return verify.PermissionScope{} // an empty scope denies
		}
		return verify.PermissionScope{GroupID: g.ID, AuthorityIssuer: cfg.Token.Issuer, Persona: g.Persona, Instance: g.InstanceSlug}
	}
	router.GET("/api/v1/orgs/:org/members", requireAuth,
		authkitgin.RequirePermission(client, authkit.Perm("org:members:read"), orgScope),
		func(c *gin.Context) {
			claims, _ := authkitgin.UserClaims(c)
			c.JSON(http.StatusOK, gin.H{"user_id": claims.UserID, "org": c.Param("org")})
		})
	return router, nil
}

func readmeDelegation(deps *embedded.Deps, mayDelegate func(context.Context, string, []byte) bool) {
	deps.DelegatedAuthorization = func(ctx context.Context, req authkit.DelegationRequest) (authkit.DelegationGrant, error) {
		if !mayDelegate(ctx, req.UserID, req.RequestedGrant) {
			return authkit.DelegationGrant{}, authkit.ErrDelegationRefused // 403 delegation_refused; any other error is 503
		}
		return authkit.DelegationGrant{Permissions: []string{"resource:read"}}, nil
	}
}

func readmeLiveness(srv *authhttp.Service, client authkit.Client) (gin.HandlerFunc, error) {
	srv.Verifier().WithLiveness(client)
	requiredLive, err := authkitgin.RequiredLive(srv.Verifier()) // verify.RequiredLive for net/http
	return requiredLive, err
}

var _ = []any{readmeMigrate, setupAuth, readmeDelegation, readmeLiveness}
