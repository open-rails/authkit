# AuthKit

Embedded auth library for Go applications. (Standalone server coming later.)

## Construction

(Basic embedded setup)

```go
package main

import (
	"context"
	"net/http"
	"net/netip"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/embedded"
	authhttp "github.com/open-rails/authkit/http"
	"github.com/open-rails/authkit/verify"
)

func setupAuth() (*gin.Engine, *authhttp.Server, authkit.Client, error) {
	ctx := context.Background()

	pg, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, nil, nil, err
	}

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
			OIDCReturnPath:    "/login/callback",
			VerifyPath:        "/verify",
			PasswordResetPath: "/reset",
			PasswordlessPath:  "/passwordless",
			InvitePath:        "/accept-invite",
		},
		Registration: embedded.RegistrationConfig{
			Verification:                 authkit.RegistrationVerificationRequired,
			NativeUserMode:               authkit.RegistrationModeOpen,
			PasswordlessLogin:            true,
			PasswordlessAutoRegistration: false,
		},
		Keys: embedded.KeysConfig{
			// Vault-mounted key directory. AuthKit reads the JWT signing keys from
			// <Path>/keys.json and the TOTP secret-encryption key (#148) from
			// <Path>/totp.key — a base64/hex-encoded 16/24/32-byte AES key, perms
			// 0600/0400. Hosts never load these secrets manually.
			Path: "/vault/auth",
		},
		Identity: embedded.IdentityConfig{},
		APIKeys: embedded.APIKeysConfig{
			Prefix: "myapp",
			MaxTTL: 90 * 24 * time.Hour,
		},
		TwoFactor: embedded.TwoFactorConfig{
			// Mode: Disabled | Optional | Required. Required gates the SESSION —
			// existing un-enrolled users are challenged on their next request.
			Mode:    authkit.TwoFactorOptional,
			Methods: []authkit.TwoFactorMethod{authkit.TwoFactorEmail, authkit.TwoFactorTOTP},
			// TOTPSecretKey is an override for tests; the normal path loads
			// <Keys.Path>/totp.key (see Keys above).
		},
		Passkeys: embedded.PasskeyConfig{
			RPID:             "app.example.com",
			RPDisplayName:    "My App",
			Origins:          []string{"https://app.example.com"},
			UserVerification: "preferred",
		},
		RBAC: []authkit.PersonaDef{
			{
				Name: authkit.RootPersona,
				Roles: []authkit.RoleDef{
					{
						Name: "support",
						Permissions: []string{
							"root:users:ban",
							"root:users:recover",
						},
					},
				},
				// Optional. Root capabilities are off unless the host enables them.
				Capabilities: authkit.PersonaCapabilities{CustomRoles: true},
				Catalog: []string{
					"root:users:ban",
					"root:users:recover",
				},
			},
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
				Capabilities: authkit.PersonaCapabilities{
					APIKeys:            true,
					RemoteApplications: true,
				},
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
		Environment:   "production",
		Schema:        "profiles",
		SolanaNetwork: "mainnet",
	}

	client, err := embedded.New(cfg, pg)
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
		users, err := client.UsersByIDs(c.Request.Context(), []string{userClaims.UserID})
		if err != nil || len(users) == 0 {
			c.JSON(http.StatusInternalServerError, map[string]any{"error": "user_lookup_failed"})
			return
		}

		c.JSON(http.StatusOK, map[string]any{
			"user_id":        userClaims.UserID,
			"email":          users[0].Email,
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

Use `embedded.New` for in-process AuthKit operations and `authhttp.NewServer`
for mounted HTTP routes. The future standalone server will use `remote.New` for
the same `authkit.Client` contract.

`RegisterAPI(v1, srv)` registers every enabled JSON API route. Use
`WithGroups(...)` only when the host wants to mount selected surfaces:
`auth`, `registration`, `account`, `admin`, and `permission_groups`. Browser
OIDC redirects are mounted separately with `RegisterOIDC`; JWKS is mounted with
`RegisterJWKS`.

### RBAC config and durability

`Config.RBAC` is a single `[]authkit.PersonaDef` slice. Each persona is a
permission namespace and declares roles with `persona:resource:action` grants.
`root` is configured with the same shape as any other persona: `Parent` is empty,
capabilities default off, and any host root entry is merged with AuthKit's
intrinsic root owner and built-in `root:` permissions.

Role definitions and per-persona `Catalog` entries are in-memory config. Editing
a role's grants changes what every holder of that role can do after the new
schema is loaded. The containment shape and runtime rows are durable:
`group_persona_parents` is reconciled from config, while `group_user_roles`,
`group_custom_roles`, and `api_keys` keep name references to personas and roles.

Treat persona names and role names as durable identifiers. Do not rename in
place; create a new name, migrate assignments, then retire the old one. Removing
a role, catalog grant, or persona fails closed: unresolved names grant nothing,
but AuthKit does not auto-delete those rows because a typo in config must not
erase operator intent. Review and clean up drifted rows deliberately, and do not
reuse a retired name for a different meaning until old assignments are cleared.

---

## Advanced Host Flows

For session history, run `migrations/clickhouse` and pass a
`clickhouse.Conn` to `embedded.New` with `embedded.WithClickHouse(ch)`.
`authhttp.NewServer(client)` uses that same client as the admin sign-in reader.

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
