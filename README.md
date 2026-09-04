# AuthKit

Embedded auth library for Go applications. (Standalone server coming later.)

## Migrations

Apply AuthKit's Postgres schema before constructing the client, from your app's
migrate command (same shape as rivermigrate):

```go
import "github.com/open-rails/authkit/authkitmigrate"

migrator := authkitmigrate.New(pool, nil) // &authkitmigrate.Config{Schema: "..."} for a non-default schema
res, err := migrator.Migrate(ctx)         // idempotent; res.Applied lists what ran
```

`migrator.Validate(ctx)` reports pending migrations without applying.

## Construction

(Basic embedded setup)

```go
package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/open-rails/authkit"
	authkitgin "github.com/open-rails/authkit/adapters/gin"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/verify"
)

func setupAuth() (*gin.Engine, *authhttp.Service, authkit.Client, error) {
	ctx := context.Background()

	pg, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return nil, nil, nil, err
	}
	rdb := redis.NewClient(&redis.Options{Addr: os.Getenv("REDIS_ADDR")})
	var mailer embedded.EmailSender // host-provided implementation

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

	// One call builds the embedded engine AND the HTTP transport over it.
	// Engine dependencies (Redis, senders, entitlements, …) ride in via WithEngine.
	srv, client, err := authhttp.New(cfg, pg,
		authhttp.WithEngine(embedded.WithRedis(rdb), embedded.WithEmailSender(mailer)),
		// Trust only infrastructure that overwrites/appends forwarded headers.
		authhttp.WithTrustedProxies("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"),
		authhttp.WithLanguageConfig(authhttp.LanguageConfig{
			Supported: []string{"en", "es"},
			Default:   "en",
		}),
	)
	if err != nil {
		return nil, nil, nil, err
	}

	router := gin.New()
	// The whole AuthKit surface — JWKS at /.well-known/jwks.json, browser OIDC
	// under /oidc, JSON API under /api/v1 — is ONE framework-neutral handler,
	// mounted once as the router's fallback. Host routes always win; excluded
	// routes are the host-shadowing seam.
	mount, err := authhttp.MountHandler(srv, authhttp.MountOptions{})
	if err != nil {
		return nil, nil, nil, err
	}
	router.NoRoute(authkitgin.Fallback(mount))

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

Redis is passed once, on the engine (`embedded.WithRedis`); the HTTP layer
adopts it automatically (#210) — `authhttp.WithRedis` is only an override.

Two-step construction: hosts that need to hold or decorate the engine
separately build it first, then wrap it:

```go
client, err := embedded.New(cfg, pg, embedded.WithRedis(rdb), embedded.WithEmailSender(mailer))
srv, err := authhttp.NewServer(client, authhttp.WithTrustedProxies("10.0.0.0/8"))
```

The returned `client` is the host's `authkit.Client` for in-process operations.
The future standalone server will use `remote.New` for the same contract.

`authhttp.MountHandler` returns the whole surface as one `http.Handler`: every
enabled JSON API route under `APIPrefix` (default `/api/v1`), browser OIDC
redirects under `OIDCPath` (default `/oidc`), and JWKS at
`/.well-known/jwks.json`. Options: `Groups` selects surfaces (`auth`,
`registration`, `account`, `admin`, `permission_groups`, `browser_oidc`);
`ExcludeRoutes` drops routes the host shadows with its own handlers;
`MountPrefix` shifts everything under a host path (boundary-checked, for
non-stripping proxies); `Wrap` decorates every mounted route. gin hosts mount
it once via `router.NoRoute(authkitgin.Fallback(mount))` (or `gin.WrapH` on an
explicit wildcard); any other router mounts it like any `http.Handler`.

### Browser OIDC result contract

The three routes under `OIDCPath` (`{provider}/login`, `{provider}/callback`,
`{provider}/step-up/callback`) are browser navigations, so both outcomes are
delivered to the SPA, never left as a raw response body on the backend URL:

- Success: `302` to `Frontend.BaseURL + OIDCReturnPath` with
  `#access_token=…&refresh_token=…&expires_in=…&provider=…[&return_to=…]`
  (no `refresh_token` under `MountOptions.RefreshCookie` — see below).
- Error: `302` to the same route with
  `#error=<code>&flow=login|link&provider=…[&return_to=…]`. Codes are the
  stable wire codes (`access_denied`, `invalid_state`,
  `account_exists_link_required`, …); an unparseable IdP `?error=` collapses
  to `provider_error`. When the outcome is `2fa_enrollment_required` the
  fragment also carries `enrollment_token`, `enrollment_expires_in` and
  `allowed_methods` (deliberately NOT `access_token`: an enrollment-scoped
  token must not be storable as a session by a fragment parser that only
  looks for `access_token`).
- Popup flows (`?ui=popup&popup_nonce=…` on login): the popup document
  posts `{type: "AUTHKIT_OIDC_RESULT", access_token, …, nonce}` to the opener
  on success and `{type: "AUTHKIT_OIDC_ERROR", error, flow, provider, nonce}`
  on failure — distinct types, so an opener that only understands the success
  shape can never misread an error as a login.
- Step-up flows: failures redirect to the flow's `return_to` with
  `?step_up=failed` (matching the existing success/failure redirects).
- `format=json` or `Accept: application/json` keeps the legacy JSON error
  envelope on every stage. Rate-limit rejections (429) always stay JSON.
- Browser results (fragment redirects and popup documents) are emitted with
  `Cache-Control: no-store` (RFC 6749 §5.1) — they carry tokens.
- The raw IdP `?error=`/`error_description` values are logged server-side
  (`[authkit/oidc]`, quoted and truncated) for diagnostics; only the sanitized
  code is ever reflected to the client.

### Refresh token in an HttpOnly cookie (ak#271)

`MountOptions{RefreshCookie: true}` moves the rotating refresh token out of
every response body into an `HttpOnly` + `Secure` + `SameSite=Lax` cookie named
`authkit_rt`. **Off by default** — a host that does not set it sees byte-identical
behaviour.

```go
h, err := authhttp.MountHandler(srv, authhttp.MountOptions{RefreshCookie: true})
```

| Aspect | Behaviour |
| --- | --- |
| Issue | All ten session-establishing responses (password / passwordless / passkeys / SIWS / 2FA verify / email+phone verify / registration auto-login / refresh rotation / OIDC popup / OIDC fragment) set the cookie and omit `refresh_token` from the body, the fragment and the postMessage payload. |
| Consume | `POST /token` and `POST /sessions/current` take the body's `refresh_token` when present, the cookie otherwise. A cookie-only client sends an empty `refresh_token` and gets a rotation, not a `400`. |
| Clear | `DELETE /logout`, and a refresh that fails with `user_banned`. **Never** on the unknown-token `401` — staleness and death are indistinguishable there, and clearing would destroy a still-live jar value over a transient failure. |
| `Path` | The mount's API anchor (`MountPrefix + APIPrefix`, e.g. `/api/v1`) — the narrowest prefix covering both consuming routes. Keeps the cookie off the SPA document and its assets. |
| `SameSite` | `Lax`, never `Strict`. The OIDC tail is a cross-site top-level GET from the IdP, and emailed verification links land the same way; `Strict` withholds the cookie there and the first refresh fails. Lax still blocks the cross-site POST a CSRF would need. |
| `Secure` | Derived like the OAuth state cookie: HTTPS `Frontend.BaseURL`, or the request's own TLS. Plain-http local dev gets a non-Secure cookie so the flow still works. |

Two gates apply to a **cookie-sourced** credential only (a body token is not
CSRF-relevant): a present-but-mismatched `Origin` is refused, and duplicate
`authkit_rt` cookies fail closed — a sibling host that can set `Domain=<parent>`
would otherwise plant a value that sorts ahead of the host-only one and silently
swap the session. Both refusals leave the session alive and the cookie untouched.

**Requirement:** the SPA and this mount must share an origin, or the cookie never
reaches the refresh call. **Not fixed:** script running in a live tab can still
call the refresh route. This removes theft-and-replay from elsewhere, not abuse
from inside the victim's own tab.

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

Instance creation (`CreatePermissionGroup`, including its unchecked
`OwnerSubjectID` owner-seeding) has no actor-aware `*As` variant: authorizing
*who may create a group instance* is deliberately the HOST's job in the
embedded trust model — the host already decided to call it, which is the
authority. Runtime mutations to an EXISTING instance (assign/unassign a role,
define/delete a custom role, mint an invite or API key) all go through
actor-aware `*As` paths that re-derive authority from the caller's own grants
(#136/#247 no-escalation). `*As` variants for group creation itself are
deferred to the Phase-2 remote transport (#138), where host-trust no longer
holds and every actor must be independently authorized.

---

## Advanced Host Flows

Session history (sign-ins, revocations, password changes) is built in: events
are recorded best-effort in Postgres (`session_events`) and served by
`GET /admin/users/{id}/signins` in every deployment. Retention defaults to 365
days (IP + user-agent are personal data — the ceiling is deliberate); tune it
with `Config.SessionEventRetention` (negative = keep forever). Pruning runs
inside `Client.CleanupExpiredAuthState` — schedule it daily-ish (the standalone
server ticks it itself).

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

### Signed documents and delegated references

AuthKit's `documents` package signs and verifies immutable, content-addressed
JSON envelopes. The signed `iss`, `aud`, versioned `type` (for example
`example.entitlements/v1`), and opaque `payload` are transport/trust metadata;
only the receiving application owns payload schema, normalization,
authorization semantics, and side effects.

`(*embedded.Client).SignDocument` signs with the service's live AuthKit key.
`documents.NewPublisher` serves the retained compact JWS at
`/.well-known/authkit/documents/{digest}`, and `documents.NewResolver` performs
an authenticated issuer-relative fetch before `verify.Verifier` checks the
exact digest, issuer, audience, type, key, and signature. Publisher and resolver
authorization callbacks should use the host's existing AuthKit machine
credentials; nil authorization denies access. The digest identifies immutable
signed payload bytes, while the compact JWS can change when those bytes are
re-signed during key rotation, so publisher responses use a representation ETag
and require cache revalidation.

Delegated tokens pin documents with the top-level `documents` claim:

```json
{"documents":{"example.entitlements/v1":"sha256:<64 lowercase hex>"}}
```

Pre-launch consumers hard-cut from any application-specific
`attributes.policy_digest` convention to `documents[type]`. AuthKit intentionally
provides no compatibility alias and never interprets an application payload.

### Owned document publishing and the delegated mint route (#260/#261)

`documents.NewService` runs the whole publish lifecycle over an AuthKit-owned
Postgres table (migration `0005_signed_documents`): sign → verify → persist →
re-read → re-verify at boot, digest-stable re-signature on key rotation, and
`ErrDigestCollision` on any payload/type change under an existing digest. The
host supplies only its compiled payload:

```go
docSvc, err := documents.NewService(ctx, documents.ServiceConfig{
    Type: "example.entitlements/v1", Payload: payload,
    Issuer: cfg.Token.Issuer, Audiences: cfg.Delegated.Audiences,
    Signer: client, Store: client.DocumentStore(),
})
srv, err := authhttp.NewServer(client, authhttp.WithDocuments(docSvc))
```

`MountHandler` then serves `GET|HEAD /.well-known/authkit/documents/{digest}`
(root-anchored, `RouteDocuments`). Reader authorization is config —
`Config.Documents.Readers` pins the remote applications allowed to fetch by an
identity nobody else can claim (application id, proven domain, or the issuer of
a root-registered application — never the slug), at the approved tier unless
`AllowRegisteredTier` is set; publication is never public and a
providers/readers mismatch refuses at boot.

`POST /delegated/token` (`RouteDelegated`, mounted when
`Config.Delegated.Audiences` is set) mints delegated tokens for the
authenticated user: audience-subset clamp, request TTL clamped into the
boot-validated `TTLFloor <= TTLDefault <= TTLCeiling` triple (an inconsistent
triple never boots), document digests stamped from every `WithDocuments`
provider, and post-mint signing-KID reconciliation so a stamped document always
verifies against the token's key. Every delegated token carries a fresh uuidv7
`jti` (ak#270), so a receiving service can revoke one token by id rather than
the whole session; `DelegatedAccessParams.JTI` still lets a caller pin its own.
Host semantics enter through ONE seam:

```go
embedded.WithDelegatedAttributes(func(ctx context.Context, userID string) (map[string]any, map[string]string, error) {
    tier := billing.ResolveEffectiveTier(ctx, userID) // host-owned meaning
    return map[string]any{"entitlement": tier}, nil, nil
})
```

### Application self-registration (#264)

Enable with `Config.Applications = ApplicationsConfig{SelfRegistration: true,
OrgPersona: "org"}` (OrgPersona: a declared non-root persona parented by root).
Routes mount only when enabled (`RouteApplications` group):

```text
POST /api/v1/applications/register          {"domain": "cozy.art"}
POST /api/v1/applications/{slug}/rotate     {"jws": "<compact JWS>"}
POST /api/v1/applications/{slug}/repoint    {"jws": "<compact JWS>"}
POST /api/v1/admin/applications/{slug}/tier {"tier": "approved"}   (root:credentials:manage)
```

**Registration.** The server fetches
`https://<domain>/.well-known/authkit/application.json` — that fetch IS the
domain-control proof (https-only, redirect-refusing, SSRF-guarded outside
dev-like environments; dev accepts an `http://127.0.0.1:<port>` base URL, and
the manual/bootstrap path remains the loopback escape hatch). SLUGS AND
DOMAINS ARE SEPARATE: the domain is the trust root and the re-registration
key; the document's `slug` field is a REQUESTED handle (defaulting to the
hostname) claimed through the same availability + anti-squat gates as any org
slug — `cozy.art` can claim `cozy-creator`. The document also declares
`issuer` (host must equal the proven domain outside dev), exactly one of
`jwks_uri`/`public_keys`, and optional `display_name` / `document_endpoint`.
Result: a `remote_applications` row (uuidv7 identity, tier `registered`,
trust root `domain`) plus a SERVICE-OWNED org — an `OrgPersona` group whose
instance slug is the claimed slug, owned by the application principal itself.
Re-registering the same domain is idempotent: it re-proves the root and
refreshes issuer/keys/config from the re-fetched document (the boot-time
self-heal); the slug is never changed by a refresh. Per-IP and per-domain
rate limits apply (`application_register` bucket);
`embedded.WithApplicationAdmission` injects a host admission predicate — cost
gates (allowances, card-on-file) are the host's, anti-spam velocity caps are
authkit's.

**Rotation doctrine.** The trust root — domain control, or the owning user
account — rotates keys; the keypair alone NEVER does. If every old key is
gone, re-registration adopts whatever the document declares now. The signed
paths are conveniences: `rotate` (replace the trust source) and `repoint`
(move the trust root to a new domain, proven by fetching the new domain's
document; uuid, slug, and org are all stable)
accept an ACME-style compact JWS signed by a currently-trusted key — JOSE `typ`
`authkit-application-request+jws`, payload `{"op","slug","aud","iat",...}` with
`aud` = this platform's issuer and `iat` within ±5 minutes (anti-replay; both
operations are idempotent within the window). A disabled application's keys are
not trusted — recovery is always the trust root.

**Tiers.** `registered` buys existence only: authenticate + serve/fetch
documents. `approved` is an admin act (`SetApplicationTier`). Re-verification
cadence and dormancy are HOST policy: sweepers read `RootVerifiedAt` and call
`SetApplicationEnabled`; authkit ships no clocks or background jobs.

**Naming doctrine.** uuidv7 is the only join key; slugs are meaningful unique
handles claimed like usernames (GitHub model); `display_name` is free-form non-unique metadata on
both applications and permission groups. `PATCH /api/v1/<persona>/{slug}`
(gated `<persona>:settings:manage`; owners hold it via the wildcard) renames a
group slug or updates its display name. A renamed-away slug is TOMBSTONED:
permanently reserved to the same group and forwarding through slug resolution,
so published references keep working and nobody can ever re-claim it (the group
may reclaim its own tombstone by renaming back). `DeletePermissionGroup`
tombstones the slug by default; `DeletePermissionGroupOptions{ReleaseSlug:
true}` frees it — safe only for names nothing ever referenced, and that
judgment is the host's. Slug renames are velocity-capped per user + per IP
(`group_settings` bucket) — a rename is a claim.

### Liveness-aware verification (#267)

`VerifyRequest` / `Required` are STATELESS by design (#215): a banned or deleted
user keeps a valid access token until it expires (≤1 access TTL). For a
privileged surface that cannot accept that window, wire a liveness source once
and mount the live gate instead:

```go
verifier.WithLiveness(client) // any authkit.Client — embedded or remote

admin := router.Group("/api/v1/admin", authkitgin.RequiredLive(verifier))
```

* `verify.RequiredLive` / `RequiredLiveUser` (and the `authkitgin` twins) — 401
  on a banned, deleted, reserved or unknown account, on the user's NEXT request.
* Claims handed downstream carry `Username`, `Email` and `EmailVerified` FRESH
  as of that lookup. Do not call the admin directory per request to refresh
  display fields; roles and entitlements have their own live reads
  (`RoleSlugsByUsers`, `Allow`, `ListEntitlements`).
* `verifier.AllowLive(ctx, client, claims, perm, scope)` is `verify.Allow` with
  the liveness precondition — "live AND permitted" in one call, so a banned user
  who still holds a permission assignment is denied. `verifier.IsLive` is the
  bare predicate.
* **Fail-closed, no cache.** A lookup error denies. Exactly one
  `UserLivenessByIDs` call per gated request, no memoization — any cache
  reintroduces the staleness window the gate exists to close. Mounting
  `RequiredLive` without `WithLiveness` PANICS at mount rather than silently
  degrading to the weaker gate.

### Public-safe user projections (#268)

Two batch projections, one query each, differing only in who may see the result:

| method | type | use |
|---|---|---|
| `UsersByIDs` | `UserRef{ID, Username, Email}` | PRIVILEGED — admin surfaces, the account's own views |
| `PublicUsersByIDs` | `PublicUserRef{ID, Username, AvatarURL, CreatedAt, Deleted}` | rendering users to other users |

`PublicUserRef` has no email field at all, so a resolved author nests straight
into a response body. Soft-deleted users come back as TOMBSTONES (`Deleted` set,
display fields blank); banned users come back normally (a ban is an access
decision, not a visibility one); unknown ids are absent.
`ref.DisplayName()` / `authkit.PublicDisplayName(refs, id)` render
`user-<id8>` for tombstoned and unresolved ids, so the call site needs no
fallback branch. Derived assets (thumbnail sizes, CDN rewrites) stay host-owned
— authkit stores one avatar string.

Frontend code calls the AuthKit routes mounted by `MountHandler`:

```text
POST /api/v1/password/login
POST /api/v1/token
GET  /api/v1/me
POST /api/v1/passwordless/start
POST /api/v1/passwordless/confirm
POST /api/v1/register
GET  /api/v1/capabilities
POST /api/v1/oidc/{provider}/link/start
```
