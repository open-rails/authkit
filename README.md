# AuthKit

Embedded auth library for Go applications. (Standalone server coming later.)

## Construction

(Example of entire surface area)

```go
package main

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	emailtwilio "github.com/open-rails/authkit/adapters/twilio/email"
	smstwilio "github.com/open-rails/authkit/adapters/twilio/sms"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	authhttp "github.com/open-rails/authkit/http"
	oidckit "github.com/open-rails/authkit/oidc"
	"github.com/open-rails/authkit/verify"
)

func setupAuth() (*gin.Engine, *authhttp.Server, authkit.Client, error) {
	ctx := context.Background()

	pg, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, nil, nil, err
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     os.Getenv("REDIS_ADDR"),
		Password: os.Getenv("REDIS_PASSWORD"),
		DB:       0,
	})

	emailSender, err := emailtwilio.New(emailtwilio.Config{
		APIKey:    os.Getenv("TWILIO_SENDGRID_API_KEY"),
		FromEmail: "auth@app.example.com",
		FromName:  "My App",
		AppName:   "My App",
	})
	if err != nil {
		return nil, nil, nil, err
	}

	smsSender, err := smstwilio.New(smstwilio.Config{
		AccountSID:          os.Getenv("TWILIO_ACCOUNT_SID"),
		AuthToken:           os.Getenv("TWILIO_AUTH_TOKEN"),
		MessagingServiceSID: os.Getenv("TWILIO_MESSAGING_SERVICE_SID"),
		AppName:             "My App",
	})
	if err != nil {
		return nil, nil, nil, err
	}

	ch, err := clickhouse.Open(&clickhouse.Options{
		Addr: []string{os.Getenv("CLICKHOUSE_ADDR")},
		Auth: clickhouse.Auth{
			Database: os.Getenv("CLICKHOUSE_DATABASE"),
			Username: os.Getenv("CLICKHOUSE_USERNAME"),
			Password: os.Getenv("CLICKHOUSE_PASSWORD"),
		},
	})
	if err != nil {
		return nil, nil, nil, err
	}

	entitlements := NewEntitlementsProvider(pg) // host-owned billing/product provider
	// Trust only infrastructure that overwrites/appends forwarded headers.
	trustedProxies := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}

	cfg := embedded.Config{
		Token: embedded.TokenConfig{
			Issuer:               "https://app.example.com",
			IssuedAudiences:      []string{"myapp"},
			ExpectedAudiences:    []string{"myapp"},
			AccessTokenDuration:  15 * time.Minute,
			RefreshTokenDuration: 30 * 24 * time.Hour,
			SessionMaxPerUser:    3,
		},
		Frontend: embedded.FrontendConfig{
			BaseURL:           "https://app.example.com",
			CallbackPath:      "/login/callback",
			VerifyPath:        "/verify",
			PasswordResetPath: "/reset",
			PasswordlessPath:  "/passwordless",
			InvitePath:        "/accept-invite",
		},
		Registration: embedded.RegistrationConfig{
			Verification:                 embedded.RegistrationVerificationRequired,
			NativeUserMode:               embedded.RegistrationModeOpen,
			PasswordlessLogin:            true,
			PasswordlessAutoRegistration: false,
		},
		Keys: embedded.KeysConfig{
			Path: "/vault/auth",
		},
		Identity: embedded.IdentityConfig{
			Providers: map[string]oidckit.RPConfig{
				"google": {
					ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
					ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
					Scopes:       []string{"openid", "email", "profile"},
				},
			},
			ProviderDescriptors: map[string]authprovider.Provider{
				"custom": {
					Name:         "custom",
					Kind:         authprovider.KindOIDC,
					Issuer:       "https://identity.example.com",
					ClientID:     os.Getenv("CUSTOM_OIDC_CLIENT_ID"),
					ClientSecret: authprovider.ClientSecret{Env: "CUSTOM_OIDC_CLIENT_SECRET"},
					Scopes:       []string{"openid", "email", "profile"},
					UserMapping: authprovider.UserMapping{
						Subject:           authprovider.FieldMapping{Path: "sub"},
						Email:             authprovider.FieldMapping{Path: "email", Transforms: []string{"trim", "lowercase"}},
						EmailVerified:     authprovider.FieldMapping{Path: "email_verified"},
						PreferredUsername: authprovider.FieldMapping{Path: "email", Transforms: []string{"trim", "lowercase"}},
						DisplayName:       authprovider.FieldMapping{Path: "name"},
					},
				},
			},
		},
		APIKeys: embedded.APIKeysConfig{
			Prefix: "myapp",
			MaxTTL: 90 * 24 * time.Hour,
		},
		TwoFactor: embedded.TwoFactorConfig{
			RequireEnrollment: false,
		},
		Passkeys: embedded.PasskeyConfig{
			RPID:             "app.example.com",
			RPDisplayName:    "My App",
			Origins:          []string{"https://app.example.com"},
			UserVerification: "preferred",
		},
		RBAC: embedded.RBACConfig{
			Permissions: []authkit.PermissionDef{
				{Name: "org:members:read", Description: "Read organization members"},
				{Name: "org:members:invite", Description: "Invite organization members"},
				{Name: "repo:models:read", Description: "Read repo models"},
				{Name: "repo:models:deploy", Description: "Deploy repo models"},
			},
			Groups: []authkit.PersonaDef{
				{
					Name:   "org",
					Parent: authkit.RootPersona,
					Roles: []authkit.RoleDef{
						{
							Name: "admin",
							Permissions: []string{
								"org:members:read",
								"org:members:invite",
							},
						},
					},
				},
				{
					Name:   "repo",
					Parent: "org",
					Roles: []authkit.RoleDef{
						{
							Name: "developer",
							Permissions: []string{
								"repo:models:read",
								"repo:models:deploy",
							},
						},
					},
				},
			},
		},
		Environment:   "production",
		Schema:        "profiles",
		SolanaNetwork: "mainnet",
	}

	client, err := embedded.NewClient(cfg, pg,
		embedded.WithRedis(rdb),
		embedded.WithEmailSender(emailSender),
		embedded.WithSMSSender(smsSender),
		embedded.WithEntitlements(entitlements),
		embedded.WithClickHouse(ch),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	srv := authhttp.NewServer(client,
		authhttp.WithTrustedProxies(trustedProxies),
		authhttp.WithLanguageConfig(authhttp.LanguageConfig{
			Supported: []string{"en", "es"},
			Default:   "en",
		}),
	)

	router := gin.New()
	v1 := router.Group("/api/v1")
	authkitgin.RegisterAPI(v1, srv,
		authkitgin.WithGroups(
			authhttp.RouteAuth,
			authhttp.RouteRegistration,
			authhttp.RouteAccount,
			authhttp.RouteAdmin,
			authhttp.RoutePermissionGroups,
		),
	)
	authkitgin.RegisterJWKS(router, srv)
	authkitgin.RegisterOIDC(router, srv, "/oidc")

	// Host route middleware definitions, in the same order as the examples below.
	optionalAuth := authkitgin.Use(verify.Optional(srv.Verifier()))
	requireAuth := authkitgin.Use(verify.Required(srv.Verifier()))
	optionalUser := authkitgin.Use(verify.OptionalUser(srv.Verifier()))
	requireUser := authkitgin.Use(verify.RequiredUser(srv.Verifier()))
	requirePremium := authkitgin.Use(verify.RequireEntitlement("premium"))
	requirePaidPlan := authkitgin.Use(verify.RequireAnyEntitlement("premium", "pro"))
	rootScope := func(*http.Request) verify.PermissionScope {
		return verify.PermissionScope{Persona: authkit.RootPersona}
	}
	requireBanUsersPermission := authkitgin.Use(verify.RequirePermission(client, "root:users:ban", rootScope))
	repoScope := func(c *gin.Context) verify.PermissionScope {
		return verify.PermissionScope{Persona: "repo", Instance: c.Param("repo")}
	}
	requireDeployPermission := authkitgin.RequirePermission(client, "repo:models:deploy", repoScope)
	sensitive := authkitgin.Use(verify.Sensitive())
	requireDeletePermission := authkitgin.RequirePermission(client, "repo:models:delete", repoScope)

	// ====== Public routes ======
	// Public host route: no AuthKit authentication required.
	router.GET("/api/v1/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]any{
			"ok":      true,
			"service": "doujins",
		})
	})

	// ====== Optional and required user routes ======
	// Optional-user host route: public when anonymous, enriched when a user token is present.
	router.GET("/api/v1/session/optional", optionalUser, func(c *gin.Context) {
		userClaims, ok := authkitgin.UserClaims(c)
		resp := map[string]any{"authenticated": ok}
		if ok {
			resp["user_id"] = userClaims.UserID
		}
		c.JSON(http.StatusOK, resp)
	})

	// Authenticated user host route: reads token claims and loads profile data only when needed.
	router.GET("/api/v1/account/debug", requireUser, func(c *gin.Context) {
		userClaims, _ := authkitgin.UserClaims(c)
		email, err := client.GetEmailByUserID(c.Request.Context(), userClaims.UserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, map[string]any{"error": "user_lookup_failed"})
			return
		}

		c.JSON(http.StatusOK, map[string]any{
			"user_id":        userClaims.UserID,
			"email":          email,
			"token_email":    userClaims.Email,
			"email_verified": userClaims.EmailVerified,
			"session_id":     userClaims.SessionID,
		})
	})

	// ====== User account routes ======
	// Sensitive account route: requires recent step-up before changing email.
	router.POST("/api/v1/account/email", requireUser, sensitive, func(c *gin.Context) {
		userClaims, _ := authkitgin.UserClaims(c)
		c.JSON(http.StatusOK, map[string]any{
			"user_id":    userClaims.UserID,
			"session_id": userClaims.SessionID,
			"accepted":   true,
		})
	})

	// ====== Optional and required auth routes ======
	// Optional-auth host route: public when anonymous, enriched by any valid principal.
	router.GET("/api/v1/principal/optional", optionalAuth, func(c *gin.Context) {
		principal, ok := authkitgin.Principal(c)
		resp := map[string]any{"authenticated": ok}
		if ok {
			resp["principal_kind"] = principal.Kind
			resp["issuer"] = principal.Issuer
			resp["subject"] = principal.Subject
		}
		c.JSON(http.StatusOK, resp)
	})

	// Required-auth host route: accepts users, API keys, remote apps, or delegated tokens.
	router.GET("/api/v1/principal/current", requireAuth, func(c *gin.Context) {
		principal, _ := authkitgin.Principal(c)
		c.JSON(http.StatusOK, map[string]any{
			"principal_kind": principal.Kind,
			"issuer":         principal.Issuer,
			"subject":        principal.Subject,
		})
	})

	// Permission-gated host route: accepts any principal with repo:models:deploy.
	router.POST("/api/v1/repos/:repo/models/deploy", requireAuth, requireDeployPermission, func(c *gin.Context) {
		principal, _ := authkitgin.Principal(c)
		c.JSON(http.StatusOK, map[string]any{
			"principal_kind": principal.Kind,
			"issuer":         principal.Issuer,
			"subject":        principal.Subject,
			"repo":           c.Param("repo"),
			"permission":     "repo:models:deploy",
		})
	})

	// ====== Entitlement routes ======
	// Entitlement-gated host route: requires the premium entitlement on the user.
	router.GET("/api/v1/premium/download", requireUser, requirePremium, func(c *gin.Context) {
		userClaims, _ := authkitgin.UserClaims(c)
		c.JSON(http.StatusOK, map[string]any{
			"user_id":      userClaims.UserID,
			"entitlements": userClaims.Entitlements,
			"download_url": "/downloads/premium.zip",
		})
	})

	// Any-entitlement host route: requires at least one accepted entitlement.
	router.GET("/api/v1/account/export", requireUser, requirePaidPlan, func(c *gin.Context) {
		userClaims, _ := authkitgin.UserClaims(c)
		c.JSON(http.StatusOK, map[string]any{
			"user_id":      userClaims.UserID,
			"entitlements": userClaims.Entitlements,
			"export_id":    "exp_123",
		})
	})

	// ====== Permission routes ======
	// Root-admin host route: requires root:users:ban on the singleton root persona.
	router.POST("/api/v1/admin/users/:id/ban", requireUser, requireBanUsersPermission, func(c *gin.Context) {
		userClaims, _ := authkitgin.UserClaims(c)
		c.JSON(http.StatusOK, map[string]any{
			"admin_user_id":  userClaims.UserID,
			"banned_user_id": c.Param("id"),
		})
	})

	// Sensitive permission-gated host route: requires permission plus recent step-up.
	router.DELETE("/api/v1/repos/:repo/models/:id", requireUser, sensitive, requireDeletePermission, func(c *gin.Context) {
		userClaims, _ := authkitgin.UserClaims(c)
		c.JSON(http.StatusOK, map[string]any{
			"user_id":  userClaims.UserID,
			"repo":     c.Param("repo"),
			"model_id": c.Param("id"),
			"deleted":  true,
		})
	})

	return router, srv, client, nil
}
```

This exposes AuthKit routes such as `/api/v1/token`, `/api/v1/me`, and
`/.well-known/jwks.json`.

`RegisterAPI(v1, srv)` registers every enabled JSON API route. Use
`WithGroups(...)` only when the host wants to mount selected surfaces:
`auth`, `registration`, `account`, `admin`, and `permission_groups`. Browser
OIDC redirects are mounted separately with `RegisterOIDC`; JWKS is mounted with
`RegisterJWKS`.

---

## Advanced Host Flows

```go
func mountAdvancedAuthExamples(
	router *gin.Engine,
	client authkit.Client,
	requireAuth gin.HandlerFunc,
	requireUser gin.HandlerFunc,
) {
	type Caller struct {
		Invoker string
		Payer   string
	}
	resolveCaller := func(_ context.Context, principal authkit.Principal) (Caller, error) {
		return Caller{
			Invoker: principal.Subject,
			Payer:   principal.Subject,
		}, nil
	}

	rootScope := func(*http.Request) verify.PermissionScope {
		return verify.PermissionScope{Persona: authkit.RootPersona}
	}
	requireRootRead := authkitgin.Use(verify.RequirePermission(client, "root:resources:read", rootScope))
	requireRootCredentialsManage := authkitgin.Use(verify.RequirePermission(client, "root:credentials:manage", rootScope))
	requireRootUsersInvite := authkitgin.Use(verify.RequirePermission(client, "root:users:invite", rootScope))

	// Operator route: list users for an admin screen.
	router.GET("/api/v1/operator/users", requireUser, requireRootRead, func(c *gin.Context) {
		users, err := client.AdminListUsers(c.Request.Context(), authkit.AdminUserListOptions{
			Page:     1,
			PageSize: 50,
			Status:   authkit.AdminUserStatusActive,
			Sort:     authkit.AdminUserSortCreatedAt,
			Desc:     true,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, map[string]any{"error": "user_list_failed"})
			return
		}
		c.JSON(http.StatusOK, users)
	})

	// Operator route: create a user directly.
	router.POST("/api/v1/operator/users", requireUser, requireRootUsersInvite, func(c *gin.Context) {
		var req struct {
			Email    string `json:"email"`
			Username string `json:"username"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		user, err := client.CreateUser(c.Request.Context(), req.Email, req.Username)
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": "user_create_failed"})
			return
		}
		c.JSON(http.StatusOK, user)
	})

	// Operator route: register a trusted remote application issuer.
	router.POST("/api/v1/operator/remote-applications", requireUser, requireRootCredentialsManage, func(c *gin.Context) {
		var req struct {
			Slug              string `json:"slug"`
			PermissionGroupID string `json:"permission_group_id"`
			Issuer            string `json:"issuer"`
			JWKSURI           string `json:"jwks_uri"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		app, err := client.UpsertRemoteApplication(c.Request.Context(), authkit.RemoteApplication{
			Slug:              req.Slug,
			PermissionGroupID: req.PermissionGroupID,
			Issuer:            req.Issuer,
			JWKSURI:           req.JWKSURI,
			Mode:              authkit.RemoteAppModeJWKS,
			Enabled:           true,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": "remote_application_register_failed"})
			return
		}
		c.JSON(http.StatusOK, app)
	})

	// Platform route: mint a delegated token for another AuthKit-protected API.
	router.POST("/api/v1/platform/delegated-token", requireAuth, func(c *gin.Context) {
		var req struct {
			Subject string `json:"subject"`
			Tier    string `json:"tier"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": "invalid_request"})
			return
		}
		token, err := client.MintDelegatedAccessToken(c.Request.Context(), authkit.DelegatedAccessParams{
			Audiences:        []string{"tensorhub"},
			DelegatedSubject: req.Subject,
			Permissions:      []string{"repo:models:deploy"},
			Attributes:       map[string]any{"tier": req.Tier},
			TTL:              15 * time.Minute,
		})
		if err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": "delegated_token_failed"})
			return
		}
		c.JSON(http.StatusOK, map[string]any{"access_token": token})
	})

	// Resource route: resolve AuthKit's raw principal into the app's caller model.
	router.POST("/api/v1/resources/invoke", requireAuth, func(c *gin.Context) {
		principal, _ := authkitgin.Principal(c)
		caller, err := resolveCaller(c.Request.Context(), principal)
		if err != nil {
			c.JSON(http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		c.JSON(http.StatusOK, map[string]any{
			"invoker": caller.Invoker,
			"payer":   caller.Payer,
		})
	})
}
```

Frontend code calls the AuthKit routes mounted by `RegisterAPI`:

```text
POST /api/v1/password/login
POST /api/v1/token
GET  /api/v1/me
POST /api/v1/passwordless/start
POST /api/v1/passwordless/confirm
POST /api/v1/register
GET  /api/v1/auth/capabilities
POST /api/v1/oidc/{provider}/link/start
```
