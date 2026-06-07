### AuthKit

Lightweight auth library for Go services.

AuthKit is based on a browser-managed bearer-token model: login/OIDC/Solana
flows issue an `access_token` and `refresh_token`, frontend JavaScript stores
them, protected API calls use `Authorization: Bearer <access_token>`, and
refresh uses `POST /token` with the refresh token. It is not a cookie-session
library: it does not currently provide opaque `session_id` browser cookies,
HttpOnly token-cookie callbacks, or CSRF/session middleware for that model.

Note: This repo ships the HTTP transport as the top-level `http` package (`github.com/open-rails/authkit/http`). First-party router adapters live in `github.com/open-rails/authkit/adapters/gin` and `github.com/open-rails/authkit/adapters/chi`.

Scope (minimal)
- Asymmetric JWT issuing (RS256) + JWKS endpoint (no persistence yet).
- Password login and email-based password reset tokens.
- OIDC RP (OAuth2/OIDC) with PKCE (Redis/Garnet or in-memory for ephemeral state; no DB table).
- Solana wallet authentication (SIWS - Sign In With Solana).
- Storage with Postgres + Redis/Garnet for ephemeral auth state.

Packages
- jwt: minimal key management, signer, JWKS helper.
- oidc: client (RP) types; implementation to follow.
- siws: Sign In With Solana - Ed25519 signature verification for Solana wallets.
- storage: minimal interfaces for users, passwords, providers, resets, roles, revocations.
- migrations: embedded SQL defining the `profiles` schema and minimal tables.
- adapters/gin and adapters/chi: optional router adapters that register AuthKit's canonical route specs on host-owned route groups.

Migrations
- Postgres SQL migrations live in `migrations/postgres/` and are embedded via `go:embed`.
- Import `github.com/open-rails/authkit/migrations/postgres` and register `Migrations` with your runner, or use `FS`.
- PostgreSQL-backed storage requires PostgreSQL 18 or newer. Older PostgreSQL versions are not supported. AuthKit migrations use native `uuidv7()` defaults for AuthKit-owned UUID identifiers; PostgreSQL 17 can store UUIDv7 values but does not provide the required `uuidv7()` function.

---

Quick Start (Gin)

```go
package main

import (
  "github.com/gin-gonic/gin"
  authkitgin "github.com/open-rails/authkit/adapters/gin"
  core "github.com/open-rails/authkit/core"
  authhttp "github.com/open-rails/authkit/http"
)

func main() {
  // Build core.Config from your app config.
  cfg := core.Config{
    Issuer:            "https://myapp.com",
    IssuedAudiences:   []string{"myapp"},
    ExpectedAudiences: []string{"myapp"},
    BaseURL:           "https://myapp.com",
    FrontendCallbackPath: "/login/callback",
    // RegistrationVerification: core.RegistrationVerificationRequired, // none|optional|required
    // NativeUserRegistrationMode / TenantRegistrationMode: open|invite_only|admin_only|admin_bootstrap_only|... (host policy)
    // AutoCreatePersonalTenants: true  // opt in to a personal tenant per native user
    // Keys: nil => auto-discovery in AuthKit (env/fs/dev fallback)
  }

  svc, _ := authhttp.NewService(cfg)
  // svc = svc.WithPostgres(pg).WithRedis(redis).WithEmailSender(email).WithSMSSender(sms)...

  router := gin.New()
  v1 := router.Group("/api/v1")

  authkitgin.RegisterJWKS(router, svc)
  authkitgin.RegisterAPI(v1, svc)
  authkitgin.RegisterOIDC(router, svc, "/oidc")

  router.Run(":8080")
}
```

AuthKit route specs are prefix-neutral. The host app chooses the mount point:
registering `RegisterAPI(router.Group("/api/v1"), svc)` exposes `/api/v1/token`,
`/api/v1/user/me`, and `/api/v1/admin/users`, while AuthKit's internal route
paths remain `/token`, `/user/me`, and `/admin/users`.

Hosts can mount only selected route groups or wrap individual handlers:

```go
authkitgin.RegisterAPI(v1, svc, authkitgin.WithRoutes(svc.Routes().Groups(
  authhttp.RouteCore,
  authhttp.RoutePassword,
  authhttp.RouteRegister,
  authhttp.RouteEmailVerification,
  authhttp.RouteUser,
  authhttp.RouteAccountOIDCLinking,
)))
```

For custom routers, iterate `svc.Routes().DefaultAPI()` or
`svc.Routes().Groups(...)` and register each `RouteSpec.Method`,
`RouteSpec.Path`, and `RouteSpec.Handler` yourself. Host apps should not keep
duplicated AuthKit route allowlists.

Registration modes and route selection

Route-group selection is the primary host control: a locked-down host should
mount only the `svc.Routes().Groups(...)` subset it intentionally exposes
instead of `DefaultAPI()`. As a defense-in-depth backstop, AuthKit also exposes
separate registration modes on `core.Config`:

- `NativeUserRegistrationMode`: `open`, `invite_only`, `admin_only`,
  `admin_bootstrap_only`, or `closed`.
- `TenantRegistrationMode`: `open`, `invite_only`, `admin_only`,
  `admin_bootstrap_only`, `manifest_only`, or `closed`.

Both default to `open`. Any non-open native-user mode turns off public user
self-registration and auto-registration paths: `POST /register`,
`/register/availability`, `/register/resend-email`, `/register/resend-phone`,
OIDC/social/Solana auto-create, and pending-registration confirmation all return
a stable `registration_disabled` error (`/register/availability` reports every
field as unavailable, never usable). Existing-user authentication is unaffected:
login, refresh, logout, password reset/recovery, token verification, and
sessions all keep working. Embedded bootstrap/admin creation through exported
core APIs (`CreateUser`, `ImportUser`) still works.

Any non-open tenant *registration* mode denies the public tenant-facing mutation routes
(tenant creation/rename, invites, member changes, role changes, service token
management routes) with a stable `tenant_management_disabled` error. Read-only
tenant routes and the tenant-scoped token exchange (`POST /token/tenant`) stay
available for existing members. Embedded core/bootstrap code can still ensure
initial tenants, roles, admins, trusted issuers, and generated opaque service
tokens through the privileged provisioning API (`ProvisionTenant`) or the tenant
manifest reconciler. Public tenant creation uses `CreateTenantForUser`; lower
level `CreateTenant` is for bootstrap/admin callers that intentionally create an
ownerless tenant.

Locked-down (e.g. self-hosted OpenRails) pattern: mount only the chosen route
groups, set both modes to `admin_bootstrap_only` or `manifest_only`, and
bootstrap through embedded core APIs or a deployment-owned tenant manifest.
Bootstrap authority is an operator/deploy action, not a fake AuthKit tenant.

```go
cfg := core.Config{
  // ...issuer/audiences/keys...
  NativeUserRegistrationMode: core.RegistrationModeAdminBootstrapOnly,
  TenantRegistrationMode:     core.RegistrationModeManifestOnly,
}
svc, _ := authhttp.NewService(cfg)

// Mount only the route groups this deployment intentionally exposes:
authkitgin.RegisterAPI(v1, svc, authkitgin.WithRoutes(svc.Routes().Groups(
  authhttp.RouteCore,     // /token, /sessions/current, /logout
  authhttp.RoutePassword, // login + password reset for existing users
  authhttp.RouteUser,     // self-service for existing accounts
)))

// Bootstrap declared tenants, roles, admins, and service tokens internally via
// AuthKit core APIs (unaffected by the public registration modes):
core := svc.Core()
admin, _ := core.CreateUser(ctx, "ops@example.com", "operator")
bootstrap, _ := core.ProvisionTenant(ctx, core.TenantProvisionRequest{
  Slug: "operator",
  Memberships: []core.TenantProvisionMembership{{UserID: admin.ID, Role: "owner"}},
  ServiceTokens: []core.TenantProvisionServiceToken{{
    Name: "ci",
    Permissions: []string{"tenant:read"},
  }},
}, nil)
_ = bootstrap.MintedTokens[0].Plaintext // write once to a secret store
```

For a closed-registration deployment, the manifest reconciler is the standard
machine/bootstrap path. It declares tenants, trusted delegated-token issuers,
roles, optional memberships, trusted issuers, and optional generated opaque
service tokens, then applies them idempotently under a Postgres advisory lock:

```yaml
tenants:
  - slug: cozy-art
    issuers:
      - issuer: https://cozy.example
        jwks_uri: https://cozy.example/.well-known/jwks.json
        audiences: ["openrails"]
        enabled: true
    roles:
      - name: operator
        permissions: ["tenant:read", "openrails:billing:read"]
    memberships:
      - user_id: 018f0000-0000-7000-8000-000000000001
        role: operator
    service_tokens:
      - name: openrails-runtime
        permissions: ["openrails:entitlements:read"]
        resources:
          - kind: openrails.tenant
            id: cozy-art
        output:
          file: /run/secrets/openrails-runtime-token
```

The standalone AuthKit devserver exposes this as both an opt-in startup hook and
a one-shot deploy-job command:

```bash
DEVSERVER_ISSUER=https://auth.example \
DB_URL=postgres://... \
DEVSERVER_PERMISSION_CATALOG=openrails:billing:read,openrails:entitlements:read \
DEVSERVER_TOKEN_PREFIX=cozy \
DEVSERVER_TENANT_MANIFEST_PATH=/manifests/tenants.yaml \
/authkit-devserver tenant-manifest apply
```

Use `DEVSERVER_RECONCILE_TENANT_MANIFEST_ON_START=true` only for local/dev or
simple self-hosted deployments. Production systems should usually run the
one-shot command as a release job, or call `core.ReconcileTenantManifest` from
their own job with a Vault/Kubernetes-backed `TenantManifestTokenStore`, so API
pods do not need long-lived secret-write credentials.

Hosted SaaS deployments can later set both registration modes to `open` and
mount the `RouteRegister` / `RouteTenants` groups to enable public signup and
tenant onboarding without code changes.

OpenRails' bootstrap flow should call these AuthKit primitives for AuthKit-owned
objects: user-owned tenant registration for public SaaS signup, and
`ProvisionTenant`/`ReconcileTenantManifest` for closed-registration or embedded
bootstrap. OpenRails still owns OpenRails-specific catalog, prices,
entitlements, grants, billing, and provider state.

Quick Start (net/http)

```go
package main

import (
  "net/http"

  authhttp "github.com/open-rails/authkit/http"
  core "github.com/open-rails/authkit/core"
)

func main() {
  cfg := core.Config{
    Issuer:            "https://myapp.com",
    IssuedAudiences:   []string{"myapp"},
    ExpectedAudiences: []string{"myapp"},
    BaseURL:           "https://myapp.com",
    FrontendCallbackPath: "/login/callback",
  }

  svc, _ := authhttp.NewService(cfg)
  mux := http.NewServeMux()
  mux.Handle("/.well-known/jwks.json", svc.JWKSHandler())
  mux.Handle("/api/v1/", http.StripPrefix("/api/v1", svc.APIHandler()))
  mux.Handle("/oidc/", svc.OIDCHandler())
  http.ListenAndServe(":8080", mux)
}
```

Optional Twilio providers
- Core is provider-agnostic and only depends on `core.EmailSender` / `core.SMSSender`.
- Optional convenience providers are available:
  - `github.com/open-rails/authkit/providers/email/twilio` for Twilio Email API (SendGrid endpoint).
  - `github.com/open-rails/authkit/providers/sms/twilio` for Twilio Messaging API.
- AuthKit never reads provider environment variables directly. Host apps load their own config, build the sender, then pass it with `WithEmailSender` / `WithSMSSender`.
- The SMS provider requires `AccountSID`, `AuthToken`, and `MessagingServiceSID`. It uses Twilio Messaging (`Messages.json`) only; there is no Verify service path and no `From` number fallback path.
- The email provider requires a SendGrid/Twilio Email API key and a verified from address. Hosts can provide link builders or full message builders for branded/localized copy.
- A 2xx response from AuthKit means the message was accepted by the configured sender/provider submission call. It does not prove the recipient mailbox or carrier ultimately delivered, accepted, opened, or displayed the message.

```go
emailSender, err := emailtwilio.New(emailtwilio.Config{
    APIKey:    cfg.TwilioEmailAPIKey,
    FromEmail: cfg.TwilioEmailFromAddress,
    FromName:  cfg.TwilioEmailFromName,
    AppName:   "Example",
    VerificationLinkURL: func(token string) string {
        return cfg.SiteBaseURL + "/verify-registration?token=" + url.QueryEscape(token)
    },
    ResetLinkURL: func(token string) string {
        return cfg.SiteBaseURL + "/reset-password?token=" + url.QueryEscape(token)
    },
})
if err != nil {
    return err
}
svc = svc.WithEmailSender(emailSender)

smsSender, err := smstwilio.New(smstwilio.Config{
    AccountSID:          cfg.TwilioAccountSID,
    AuthToken:           cfg.TwilioAuthToken,
    MessagingServiceSID: cfg.TwilioMessagingServiceSID,
    AppName:             "Example",
})
if err != nil {
    return err
}
svc = svc.WithSMSSender(smsSender)
```

External identity providers
- Built-in providers (`google`, `apple`, `discord`, `github`) can still be enabled with `core.Config.Providers` by passing client IDs/secrets.
- For custom providers, prefer `core.Config.ProviderDescriptors`. OIDC providers are usually pure configuration because identity claims are standardized. OAuth2 providers are pure configuration when their userinfo JSON can be mapped with dot paths.
- Apple uses the same descriptor model, but its client secret is a signed JWT. Use `ClientSecret.Strategy: "apple_jwt"` with Apple team/key/private-key fields.

```go
cfg.ProviderDescriptors = map[string]authprovider.Provider{
    "example-oidc": {
        Name:     "example-oidc",
        Kind:     authprovider.KindOIDC,
        Issuer:   "https://issuer.example",
        ClientID: cfg.ExampleClientID,
        ClientSecret: authprovider.ClientSecret{Env: "EXAMPLE_CLIENT_SECRET"},
        Scopes:   []string{"openid", "email", "profile"},
        PKCE:     true,
    },
    "example-oauth": {
        Name:         "example-oauth",
        Kind:         authprovider.KindOAuth2,
        Issuer:       "https://oauth.example",
        ClientID:     cfg.OAuthClientID,
        ClientSecret: authprovider.ClientSecret{Value: cfg.OAuthClientSecret},
        AuthorizeURL: "https://oauth.example/authorize",
        TokenURL:     "https://oauth.example/token",
        UserInfoURL:  "https://oauth.example/me",
        Scopes:       []string{"profile", "email"},
        PKCE:         true,
        UserMapping: authprovider.UserMapping{
            Subject:           authprovider.FieldMapping{Path: "id", Transforms: []string{"string", "trim"}},
            Email:             authprovider.FieldMapping{Path: "email", Transforms: []string{"trim"}},
            EmailVerified:     authprovider.FieldMapping{Path: "email_verified"},
            PreferredUsername: authprovider.FieldMapping{Path: "username"},
            DisplayName:       authprovider.FieldMapping{Path: "name"},
        },
    },
    "apple": {
        Name:     "apple",
        Kind:     authprovider.KindOIDC,
        Issuer:   "https://appleid.apple.com",
        ClientID: "com.example.web",
        Scopes:   []string{"openid", "email", "name"},
        ExtraAuthParams: map[string]string{"response_mode": "form_post"},
        ClientSecret: authprovider.ClientSecret{
            Strategy: "apple_jwt",
            AppleJWT: &authprovider.AppleJWTSecret{
                TeamID:        cfg.AppleTeamID,
                KeyID:         cfg.AppleKeyID,
                PrivateKeyEnv: "APPLE_PRIVATE_KEY_PEM",
            },
        },
    },
}
```

---

Entitlements Provider (Optional)

AuthKit can include entitlements (e.g., "premium", "pro") in JWT service tokens if you provide an `EntitlementsProvider`. This is useful for billing/subscription systems where entitlements are stored outside the `profiles` schema.

**Interface:**
```go
type EntitlementsProvider interface {
    ListEntitlements(ctx context.Context, userID string) ([]entitlements.Entitlement, error)
}
```

**Example implementation** (querying a `billing.entitlements` table):

```go
package main

import (
    "context"
    "time"

    entpg "github.com/open-rails/authkit/entitlements"
    "github.com/jackc/pgx/v5/pgxpool"
)

type BillingEntitlementsProvider struct {
    pg *pgxpool.Pool
}

func (p *BillingEntitlementsProvider) ListEntitlements(ctx context.Context, userID string) ([]entpg.Entitlement, error) {
    rows, err := p.pg.Query(ctx, `
        SELECT entitlement, start_at, end_at, revoked_at
        FROM billing.entitlements
        WHERE user_id = $1
          AND revoked_at IS NULL
          AND start_at <= $2
          AND (end_at IS NULL OR end_at > $2)
          AND deleted_at IS NULL
    `, userID, time.Now())
    if err != nil {
        return nil, err
    }
    defer rows.Close()

    var out []entpg.Entitlement
    for rows.Next() {
        var name string
        var startAt time.Time
        var endAt, revokedAt *time.Time
        if err := rows.Scan(&name, &startAt, &endAt, &revokedAt); err != nil {
            return nil, err
        }
        out = append(out, entpg.Entitlement{
            Name:      name,
            ExpiresAt: endAt,
            RevokedAt: revokedAt,
            Source:    "billing",
        })
    }
    return out, rows.Err()
}

// Wire it up:
svc, _ := authhttp.NewService(cfg)
svc = svc.
    WithPostgres(pg).
    WithEntitlements(&BillingEntitlementsProvider{pg: pg})
```

Entitlements are snapshotted into the JWT at token issuance time. For fresh entitlements, re-issue the token.

---

Concepts (concise)

- Service (issuer + storage): used by `authhttp.NewService(cfg)`; backs the built-in handlers (sessions, login, OIDC, etc).
- Middleware: `github.com/open-rails/authkit/http` provides `Required`/`Optional` (JWT verification) plus helpers like `RequireAdmin(pg)`.
- Verify-only: use `authhttp.NewVerifier()` + `verifier.AddIssuer(...)` to accept tokens from other issuers without issuing tokens yourself.

---

Configuration ownership

AuthKit library behavior is host-owned: the embedding app should pass runtime behavior via `core.Config`, not rely on library env/file reads.

| Area | Ownership | Notes |
| --- | --- | --- |
| `Issuer`, `IssuedAudiences`, `ExpectedAudiences` | Host config | Required token contract inputs. |
| `RequireVerifiedRegistrations`, `Environment`, `SolanaNetwork`, `AutoCreatePersonalTenants`, `NativeUserRegistrationMode`, `TenantRegistrationMode`, `BaseURL` | Host config | Runtime behavior should be deterministic from config. |
| `Keys` provided (`cfg.Keys != nil`) | Host config | Fully disables library key env/filesystem discovery. |
| `Keys` omitted (`cfg.Keys == nil`) | Library exception | Only allowed env/filesystem auto-discovery path (`ACTIVE_KEY_ID`, `ACTIVE_PRIVATE_KEY_PEM`, `PUBLIC_KEYS`, `/vault/auth/keys.json`, `.runtime/authkit/*`). |

---

Notes
- No extra app code needed for OIDC state or user linking — handled internally with Redis (if provided) or a built-in in-memory cache, plus the default resolver.
- Apple: prefer a provider descriptor with `ClientSecret.Strategy: "apple_jwt"` for config-first setup. `oidckit.AppleWithKey(...)` remains available for code-owned wiring.

Token/session model
- AuthKit assumes a browser-managed bearer-token model, not cookie sessions.
- Login, OIDC, Solana, registration confirmation, and refresh flows issue an
  `access_token` plus a `refresh_token`.
- Browser JavaScript stores those tokens and sends protected API requests with
  `Authorization: Bearer <access_token>`.
- Refresh is also JavaScript-managed: the browser calls `POST /token` with the
  refresh token and stores the returned token pair.
- Full-page OIDC callbacks redirect to `{BaseURL}{FrontendCallbackPath}` with
  tokens in the URL fragment (`#access_token=...&refresh_token=...`) so the host
  backend serves the frontend route but does not receive the tokens. The default
  frontend callback path is `/login/callback`; configured paths must be
  app-relative, may include a query string, and must not include a fragment.
- AuthKit stores refresh-session records server-side for refresh-token lifecycle
  and revocation, but it does not provide an opaque `session_id` browser-cookie
  mode or HttpOnly cookie token mode.
- Apps that want cookie/session authentication need a separate integration mode:
  cookie parsing in middleware, CSRF protection, cookie-setting callback
  behavior, and different frontend refresh/logout assumptions.

Admin Gate (DB-backed)

- Use `authhttp.RequireAdmin(pg)` to strictly enforce admin access using the database.
- Example:

```go
ver := authhttp.NewVerifier()
ver.AddIssuer("https://my-issuer.com", []string{"my-app"}, authhttp.IssuerOptions{
  JWKSURI: "https://my-issuer.com/.well-known/jwks.json",
})
ver.WithService(coreSvc)

adminHandler := authhttp.Required(ver)(
  authhttp.RequireAdmin(pg)(
    http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      w.WriteHeader(200)
    }),
  ),
)
```

Roles (global storage)
- AuthKit stores roles in Postgres `profiles.roles` and memberships in `profiles.user_roles`.
- AuthKit does not define app role taxonomy (what roles exist). The embedding application/platform should seed its role catalog.
- Role IDs are deterministic UUIDv5 derived from slug (`uuidv5(namespace, "role:"+slug)`), so role rows are stable across environments.

Tenants
- AuthKit **always** supports tenants + tenant-scoped RBAC — there is no global `TenantMode` switch (issue #60). Tenants are a first-class primitive at the core layer; what a host *exposes* is decided by which route groups it mounts and by the two registration modes (`NativeUserRegistrationMode`, `TenantRegistrationMode`), not by a mode flag. Native users may exist with zero tenants; tenants may exist (via manifest/admin/bootstrap) with zero native users.
  - Shared owner namespace: user slugs and tenant slugs should be treated as one namespace (no collisions).
  - Native users do not create tenant rows by default. Hosts that want personal
    workspaces must opt in with `AutoCreatePersonalTenants: true`; those
    personal tenants are non-transferable and keyed by `owner_user_id`.
  - Users can belong to 0, 1, or many tenants simultaneously.
  - Tenant slug renames create aliases; handlers accept either current slug or alias on `:tenant`.
  - Username renames preserve old owner paths via user slug aliases; personal tenant slug aliases are also retained.
  - Default service tokens do **not** embed tenant membership or tenant roles; apps check membership/roles server-side.
  - `GET /user/me` returns `tenants` (membership list) plus tenant-scoped roles for the user.
  - `GET /user/bootstrap` returns canonical personal tenant + tenant memberships in one call.
  - Tenant-scoped service tokens include `tenant` + `roles` (single tenant only), minted whenever the user is a member (rejected otherwise) — no mode gate.
    - Mint explicitly: `POST /token/tenant`
    - Or mint at login/refresh by providing `tenant` in the request body (accepted on every deployment; the legacy `tenant_not_supported` rejection is gone).
  - Invitation workflow:
    - Tenant owners create/list/revoke invites with `/tenants/:tenant/invites`.
    - Users list their invites via `GET /me/invites` (cross-tenant).
    - Users accept/decline via `/me/invites/:invite_id/accept|decline`.
  - Tenant management is **permission-based RBAC** (a role = a set of permissions). authkit is the generic engine: it ships **base permissions** in the reserved `tenant:` namespace (`tenant:roles:manage`, `tenant:members:manage`, `tenant:service_tokens:manage`, `tenant:read`) that gate all tenant-management endpoints, stores per-tenant role→permission assignments, computes `EffectivePermissions`, and enforces no-escalation + catalog validation. The embedding app declares its own permission catalog (`Config.PermissionCatalog`) + optional default roles (`Config.DefaultRoles`, e.g. an `admin` = `*` minus `{tenant:roles:manage, tenant:members:manage}`); effective catalog = base ∪ app. The `owner` role is hardcoded and seeded with `*` (all), protected, and cannot be removed as the last owner. Permissions are opaque to authkit — the app owns their meaning and enforces them at its own endpoints via `core.EffectivePermissions`. Introspection endpoints complement the management API: `GET /tenants/:tenant/me` (self-read of `{roles, permissions}`, membership only — no `tenant:read`) and `POST /tenants/:tenant/permissions/check` (a `testIamPermissions`-style "does this principal hold X?" → `{granted[]}`). Roles are RESTful resources: `GET /tenants/:tenant/roles/:role` (detail), `PUT /tenants/:tenant/roles/:role` (idempotent create-or-replace, body `{permissions[]}`), `DELETE /tenants/:tenant/roles/:role`; members likewise (`DELETE /tenants/:tenant/members/:user_id`). Invitee self-routes live at top-level `/me/invites` (cross-tenant — the invitee isn't a member yet).
- Token claim shape (uniform; no mode):
  - A user access token always includes `global_roles` (platform-wide) and a legacy `roles` claim that mirrors `global_roles` (fixed token-shape compatibility). Tenant-scoped tokens additionally carry `tenant` + tenant `roles`/`tenant_roles`.
  - An app with no tenants simply never mints tenant-scoped tokens — its tokens carry `roles`/`global_roles` only.

Service Tokens (opaque machine credentials)
- Long-lived, revocable bearer credentials **owned by a tenant** (not a person), for machine/automation callers (CI, operator CLIs, service-to-service). The standard machine-auth primitive (cf. Docker Hub service tokens, Stripe `sk_` keys) — robots should not replay the human password-login path.
- A service token acts **as the tenant**: middleware sets `Claims.Tenant` + `Claims.Permissions` (the token's app-defined permission strings) and a service marker (`Claims.IsService()`), leaving `UserID` empty — so the live-user ban/enrichment gate is skipped. Permissions are opaque to authkit; the embedding app owns the vocabulary and enforces meaning. (Users carry `TenantRoles`; the resource server expands role→permission at request time.)
- Presented as `Authorization: Bearer <app>st_<key_id>_<secret>`, where `<app>` is the host-configured `Config.ServiceTokenPrefix` brand (e.g. `cozy` → `cozy_st_…`; empty → bare `st_`). `key_id` is a non-secret public id for O(1) indexed lookup; only `sha256(secret)` is stored; the full token is shown **once**.
- Resolved in the `Required`/`Optional` middleware *before* JWT verification (constant-time secret compare; revoked/expired/tenant-deleted rejected; non-service-token credentials fall through to JWT). The service token path is separate from the password-login handler, so service tokens **bypass the interactive password-login rate limiter** by design.
- **Mint authorization is native + permission-based:** minting requires `tenant:service_tokens:manage`, and authkit validates the requested permissions against the tenant's effective catalog — each must be a defined permission the caller holds (no escalation; `403 permission_grant_denied`/`400 unknown_permission`), with the reserved write/mint perms (`tenant:roles:manage`, `tenant:members:manage`, `tenant:service_tokens:manage`) and wildcards barred from service tokens (read-only `tenant:read` is service token-grantable). Permissions are frozen at mint time. A service token can never mint/list/revoke service tokens (no user). See "Tenant RBAC" below for the catalog + role→permission model.
- **Resource scopes:** service tokens may carry opaque host-defined resource rows, `resources: [{kind,id}]`, in addition to permissions. AuthKit validates shape/length and duplicate pairs, stores them in `profiles.service_token_resources`, and returns them from list/resolve/middleware claims. AuthKit does not interpret resource kinds or wildcard-looking IDs; the embedding host owns semantics. Hosts that need resource no-escalation can set `Config.ResourceScopeAuthorizer`. Rule: permissions say what; resources say where.
- Manage via `POST/GET/DELETE /tenants/:tenant/service-tokens[/:token_id]`. POST accepts `{name, permissions[], resources?:[{kind,id}], expires_at?}`. Optional `expires_at` (null = non-expiring), capped by `Config.ServiceTokenMaxTTL` when set. Stored in `profiles.service_tokens`.
- **Leak response:** revoke the token (`DELETE …/service-tokens/:id`) — the `<app>st_` prefix is registrable with secret-scanning/push-protection partners so leaked tokens can be auto-detected.

Service JWTs (OIDC/JWKS machine credentials)
- First-party services with their own AuthKit issuer/JWKS should prefer
  short-lived service JWTs over generated opaque service tokens. The caller mints
  a 15-minute JWT with `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`,
  `token_use=service`, and `permissions: []`, caches it in memory until near
  expiry, and sends it as `Authorization: Bearer <jwt>`.
- AuthKit provides `core.MintServiceJWT` / `(*core.Service).MintServiceJWT` and
  `authhttp.Verifier.VerifyServiceJWT` plus `RequiredServiceJWT`. Verification
  uses the same issuer/JWKS registry as delegated access tokens, including
  tenant issuer lazy-load and disabled-issuer fail-closed behavior.
- `permissions: []` is the canonical requested-capability claim. OAuth `scope`
  is accepted only as an explicit compatibility bridge. AuthKit parses requested
  permissions/resources but does not grant them; resource servers such as
  OpenRails must intersect them with server-side grants for the issuer/subject.
- Use service JWTs for callers that can publish an issuer/JWKS, such as
  Doujins/Hentai0 -> OpenRails. Use opaque service tokens for generated
  API-key-like credentials, non-OIDC clients, bootstrap scripts, and manual
  integrations.

Reserved slug policy
- Owner namespaces use explicit states:
  - `restricted_name`: slug is blocked in `profiles.owner_reserved_names` and not publicly registrable.
  - `parked_tenant`: tenant exists and is platform-held (`metadata.namespace_state=parked_tenant`, `metadata.reserved=true`).
  - `registered_tenant`: normal tenant lifecycle (`metadata.namespace_state=registered_tenant`).
- Public lookup endpoint: `GET /owners/{slug}` returns canonical public metadata for the slug:
  - `requested_slug`: normalized slug from the request.
  - `slug` / `canonical_slug`: current canonical slug when the request resolves to a live or held owner; otherwise the requested slug.
  - `enabled` / `state`: `registered_user`, `registered_tenant`, `parked_user`, `parked_tenant`, `restricted_name`, `renamed_user`, `renamed_tenant`, `held_by_deleted_user`, `held_by_deleted_tenant`, `held_by_recent_user_rename`, `held_by_recent_tenant_rename`, or `unregistered`.
  - `claimable`: whether the slug can currently be claimed by a new user/tenant.
  - `renamed`: whether this lookup resolved through rename history.
  - `hold_until`: present for enabled rename reuse holds.
  - `entity_kind`: `none`, `tenant`, `user`, or `tenant_and_user`
  - optional `tenant` and/or `user` payloads when records exist.
- The PostgreSQL baseline schema creates `profiles.owner_reserved_names` and seeds canonical restricted names (`admin`, `superuser`, `root`, `sudo`) directly.
- Public register/create/rename/tenant-create/tenant-rename paths do not use a hardcoded denylist; conflicts are enforced through owner-namespace uniqueness plus reserved-name table checks.
- Reserved users are non-loginable (reserved placeholder credentials/providers are cleared by migration and reserve flows).

Verification delivery and expiry
- Manual entry codes are fixed-length numeric strings (6 digits) generated by core and expire in 15 minutes.
- Verification links use high-entropy link tokens generated by core and expire in 1 hour.
- Password reset link tokens expire in 1 hour.
- Sender integrations receive `core.VerificationMessage{Code, LinkToken}` and must send only provided fields; at least one must be present.
- Code-based and link-based flows are both supported:
  - Email verify code: `POST /email/verify/confirm` with `{"code":"123456"}`
  - Email verify link token: `POST /email/verify/confirm-link` with `{"token":"..."}`
  - Phone verify code: `POST /phone/verify/confirm` with `{"phone_number":"+1...","code":"123456"}`
  - Phone verify link token: `POST /phone/verify/confirm-link` with `{"token":"..."}`
  - Email password reset link handoff: `POST /email/password/reset/confirm-link` with `{"token":"..."}` returns `{"ok":true,"reset_session":"..."}`
  - Email password reset confirm: `POST /email/password/reset/confirm` with `{"reset_session":"...","new_password":"..."}`
- AuthKit API routes are prefix-neutral. Your API can live under a prefix (recommended: `/api/v1`); do not add an extra `/auth` segment when embedding AuthKit.

Identity validation policy
- AuthKit owns identity validation policy. Host applications should not
  duplicate or override username, password, email, or phone validation rules.
- Username rules are fixed: trim whitespace, 4-30 characters, start with an
  ASCII letter, allow only ASCII letters/digits/underscore, no `@`, and no
  leading `+`. AuthKit normalizes the owner slug by lowercasing and converting
  underscore/dash runs to single dashes.
- Username namespace checks reject collisions with users/tenants, renamed or
  recently held slugs, soft-deleted owners, parked namespaces, and restricted
  names. Parked/restricted names return `username_not_allowed`; held/taken
  names return `owner_slug_taken`.
- User rename cooldown is fixed at 72 hours. `PATCH /user/username` returns
  `rename_rate_limited` with the shared action-availability fields when
  blocked (`action`, `allowed`, `reason`, `retry_after_seconds`,
  `next_allowed_at`, `cooldown_seconds`). `time_until_rename_available` is
  still included as a compatibility alias.
- Password policy is fixed in AuthKit and currently requires at least 8
  characters; weak passwords return `password_too_short`.
- Email and phone validation/normalization are fixed in AuthKit. Email is
  trimmed/lowercased and must be address-like. Phone numbers must be E.164-like
  (`+` followed by country code and digits).
- Shared helpers are exported from `core`: `ValidateUsername`,
  `OwnerSlugFromUsername`, `ValidatePassword`, `NormalizeEmail`,
  `ValidateEmail`, `NormalizePhone`, `ValidatePhone`, and
  `ValidationErrorCode`.

Two-Factor Authentication (2FA):
- Optional security feature for admin accounts to prevent account takeover if password is leaked.
- Users can enable 2FA via email or SMS methods.
- When enabled, login requires both password AND a 6-digit code sent via email/SMS.
- Each user gets **10 backup codes** (8-character alphanumeric) for account recovery in case they lose access to their 2FA method.
- **Login flow with 2FA**:
  1. POST `/password/login` with email/password
  2. If 2FA enabled: response has `{"requires_2fa": true, "user_id": "...", "method": "email|sms", "verification_id": "..."}`
  3. User receives 6-digit code via email or SMS
  4. POST `/2fa/verify` with `{"user_id": "...", "code": "123456"}` (or `{"user_id": "...", "code": "ABC123XY", "backup_code": true}` for backup codes)
  5. Response contains access_token and refresh_token as usual
- **Setup flow**:
  1. GET `/user/2fa` to check current enabled
  2. POST `/user/2fa/enable` with `{"method": "email"}` or `{"method": "sms", "phone_number": "+1..."}`
  3. Response includes `backup_codes` array - **show these to user ONCE and tell them to save them**
  4. User can regenerate codes with POST `/user/2fa/regenerate-codes` (invalidates old codes)
  5. User can disable with POST `/user/2fa/disable`
- Backup codes are single-use and removed after verification.
- 2FA codes expire in **15 minutes**.

Operation:
- Key rotation is outside the scope of this library and should be handled by your infrastructure (e.g., External Secrets Operator updating mounted secrets, then restarting pods).
- To rotate keys manually: add the new public key to the map under a new kid, switch the enabled signer, leave the old pub in the map until tokens expire, then remove it.
- For local development, AuthKit auto-generates keys in `.runtime/authkit/` (disabled in production).

Integration requirements (API server)
- Ephemeral auth state (verification codes, resets, SIWS challenges) uses Redis/Garnet when provided; in dev it falls back to memory.
- In production, a Redis-compatible store is required.
- Rate limiting:
  - Enabled by default (in-memory limiter) with per-bucket defaults from `authhttp.DefaultRateLimits()`.
  - Keys: `auth:<bucket>:ip:<client-ip>`; errors fail-open (request allowed).
  - Default client IP strategy uses the immediate `RemoteAddr` peer, including private Docker bridge, loopback, and reverse-proxy peers. This keeps anonymous sensitive endpoints protected in local Compose and embedded deployments instead of silently failing open.
  - Request-code and resend buckets default to a 60-second per-client cooldown and 6 requests per hour for registration, registration resend, email/phone verification, password-reset request, and user email/phone change request/resend.
  - `429` responses include one shared action-availability shape for frontend timers:
    `{"error":"rate_limited","action":"request_email_verification","allowed":false,"reason":"cooldown","retry_after_seconds":N,"next_allowed_at":"...","limit":6,"remaining":5,"window_seconds":3600,"cooldown_seconds":60}`.
  - `429` responses also include `Retry-After: N` plus `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` when the limiter can compute them.
  - **Behind reverse proxies, you must explicitly configure trusted proxies** to safely use `X-Forwarded-For` / `CF-Connecting-IP`. AuthKit will not trust forwarded headers by default (clients can spoof them).
  - For multi-instance production, prefer a Redis/Garnet-backed limiter and a trusted-proxy client IP function, e.g.:
    - `svc.WithRateLimiter(redislimiter.New(redis, authhttp.ToRedisLimits(authhttp.DefaultRateLimits())))`
    - `svc.WithClientIPFunc(authhttp.ClientIPFromForwardedHeaders(trustedProxyCIDRs))` where `trustedProxyCIDRs` are the CIDRs of your ingress/proxy layer (nginx, cloudflared, etc.).
  - Hosts that intentionally want the older public-remote-only fail-open behavior can opt in with `svc.WithClientIPFunc(authhttp.PublicRemoteAddrClientIP())`.
  - To explicitly opt out: `svc.DisableRateLimiter()`.
- Storage: run the SQL migrations in `authkit/migrations/postgres` (includes `profiles.refresh_sessions`).
- Keys/JWKS: host `/.well-known/jwks.json` using `svc.JWKSHandler()` and rotate keys as needed.

---

AuthKit API route specs, and the `APIHandler()` net/http compatibility handler built from those same specs, are shown relative to the host-selected API mount prefix. With the recommended `/api/v1` mount, `GET /user/me` is served at `GET /api/v1/user/me`. Browser OIDC routes are served separately and are usually mounted outside API versioning at `/oidc/*`.
- GET /.well-known/jwks.json
- OIDC:
  - GET /oidc/:provider/login
  - GET /oidc/:provider/callback
  - POST /oidc/:provider/link/start (RouteAccountOIDCLinking API group, requires auth) -> {auth_url}
- Password:
  - POST /password/login (accepts email, phone, or username in identifier field)
  - POST /email/password/reset/request
  - POST /email/password/reset/confirm-link ({token} -> {reset_session})
  - POST /email/password/reset/confirm ({reset_session, new_password})
- Registration (unified - accepts email or phone in identifier field):
  - POST /register (server auto-detects email vs phone based on format)
    - Success response includes `{ok, username, email, phone_number, discord_username, next_action}`
    - `next_action` is one of `none`, `verify_email`, or `verify_phone`
    - When `next_action` is `none`, the response also includes `{access_token, refresh_token, token_type, expires_in}`
  - Set `RegistrationVerification: none|optional|required` in `core.Config`
  - POST /register/resend-email
  - POST /register/resend-phone
  - Registration resend requests now return `invalid_email` / `invalid_phone_number` for malformed input and `pending_registration_not_found` when no matching pending registration exists.
  - Message delivery failures from the configured sender are surfaced as stable `email_delivery_failed` / `sms_delivery_failed` errors after AuthKit attempts provider submission.
- Email verification:
  - POST /email/verify/request
  - POST /email/verify/confirm
  - POST /email/verify/confirm-link
  - Verification request endpoints return explicit target-state errors: `user_not_found`, `email_already_verified`, or `phone_already_verified`.
- Phone verification and password reset:
  - POST /phone/verify/request
  - POST /phone/verify/confirm
  - POST /phone/verify/confirm-link
  - POST /phone/password/reset/request
  - POST /phone/password/reset/confirm ({reset_session, new_password})
- Sessions:
  - POST /token { grant_type: "refresh_token", refresh_token }
  - POST /sessions/current { refresh_token } → { session_id }
  - GET /user/sessions (requires auth)
  - DELETE /user/sessions/:id (requires auth)
  - DELETE /user/sessions (requires auth)
  - DELETE /logout (requires auth; revokes the current session via sid claim)
- User profile:
  - GET /user/me (requires auth)
  - PATCH /user/username (requires auth)
  - POST /user/email/change/request (requires auth)
  - POST /user/email/change/confirm (requires auth)
  - POST /user/email/change/resend (requires auth)
  - PATCH /user/biography (requires auth)
  - POST /user/password (requires auth)
  - DELETE /user (requires auth)
  - DELETE /user/providers/:provider (requires auth)
- Two-Factor Authentication (2FA):
  - GET /user/2fa (requires auth) → {enabled, method, phone_number}
  - POST /user/2fa/start-phone (requires auth) → starts phone 2FA setup, sends code to phone
  - POST /user/2fa/enable (requires auth) →  → {enabled, method, backup_codes}
  - POST /user/2fa/disable (requires auth)
  - POST /user/2fa/regenerate-codes (requires auth) → {backup_codes}
  - POST /2fa/verify (during login) → {access_token, refresh_token}
- Admin roles (admin only):
  - POST /admin/roles/grant
  - POST /admin/roles/revoke
- Admin users (admin only):
  - GET /admin/users
  - GET /admin/users/:user_id
  - POST /admin/users/ban
  - POST /admin/users/unban
  - POST /admin/users/set-email
  - POST /admin/users/set-username
  - POST /admin/users/set-password
  - DELETE /admin/users/:user_id
  - POST /admin/users/:user_id/restore
  - GET /admin/users/deleted
  - GET /admin/users/:user_id/signins
  - POST /admin/users/:user_id/sessions/revoke
- Admin owner-namespace lifecycle (admin only):
  - POST /admin/accounts/restrict (batch add slugs to restricted-name list)
  - POST /admin/accounts/unrestrict (batch remove slugs from restricted-name list)
  - POST /admin/account/park (`{kind:"tenant"|"user",slug}`)
  - POST /admin/account/claim (`{kind:"tenant"|"user",slug,...}`; for `kind:"tenant"`, `owner_user_id` is required)
- Public owner-namespace lookup:
  - GET /owners/:slug → canonical owner metadata + `enabled`/`claimable`
- Solana wallet authentication (SIWS):
  - POST /solana/challenge → {domain, address, nonce, issuedAt, expirationTime, ...}
  - POST /solana/login → {access_token, refresh_token, user}
  - POST /solana/link (requires auth) → {success, solana_address}

---

**Expired Token/Code Cleanup**

AuthKit deletes verification codes when they're consumed. Expired codes are not auto‑purged. Operators should periodically delete expired rows. Example SQL:

```sql
-- Remove expired email verification codes
DELETE FROM profiles.email_verifications WHERE expires_at <= now();

-- Remove expired password reset codes
DELETE FROM profiles.password_resets WHERE expires_at <= now();

-- Remove expired phone verification codes (registration + password reset)
DELETE FROM profiles.phone_verifications WHERE expires_at <= now();

-- Remove expired pending registrations
-- Pending registrations now live in Redis/Garnet; no SQL cleanup needed.
DELETE FROM profiles.pending_phone_registrations WHERE expires_at <= now();

-- Remove expired 2FA verification codes
DELETE FROM profiles.two_factor_verifications WHERE expires_at <= now();
```

Run these from your scheduler (cron, pg_cron, or your job system).

---

Frontend (React) quick guide
- Paths below are relative to the AuthKit API mount. In doujins/hentai0-style hosts mounted at `/api/v1`, call `/api/v1/token`, `/api/v1/user/me`, `/api/v1/admin/users`, etc.
- Tokens
  - Store access_token in memory and refresh_token in IndexedDB/secure storage.
  - Add Authorization: Bearer <access_token> to protected API calls. On 401, call POST /token with refresh_token, then retry.
- Registration (unified)
  - POST /register with `{identifier, username, password}` where identifier is email or phone
  - On success, branch on `next_action`: `none`, `verify_email`, or `verify_phone`
  - If `next_action` is `none`, store the returned access/refresh tokens immediately; do not replay the password
  - Email registration: check email for 6-char code → POST /email/verify/confirm with `{code}`
  - Phone registration: check SMS for 6-char code → POST /phone/verify/confirm with `{phone_number, code}`
  - Successful email/phone code or link confirmation returns access/refresh tokens
  - Resend codes: POST /register/resend-email or POST /register/resend-phone
- Password Login
  - POST /password/login with `{login, password}` where login can be email/phone/username → {id_token, refresh_token}
- Password Reset
  - POST /email/password/reset/request with `{email}` → check email for reset instructions
  - POST /email/password/reset/confirm-link with `{token}` → {reset_session}
  - POST /email/password/reset/confirm with `{reset_session, new_password}` → {ok: true}
  - POST /phone/password/reset/request with `{phone_number}` → check SMS for reset instructions
  - POST /phone/password/reset/confirm with `{reset_session, new_password}` → {ok: true}
- OIDC
  - Start: window.location = `/oidc/${provider}/login`.
  - Link: POST `/api/v1/oidc/:provider/link/start` (with Authorization) → {auth_url}; then window.location = auth_url.
- Unlink
  - DELETE /user/providers/:provider (Authorization). Guard prevents unlinking the last login method.
- Sessions
  - DELETE /logout (current), DELETE /user/sessions (all), DELETE /user/sessions/:id (single), GET /user/sessions (list).
  - POST /sessions/current with `{refresh_token}` → {session_id}.
- Current user
  - GET /user/me → {id, email, pending_email?, phone_number?, username, discord_username?, email_verified, phone_verified, has_password, roles, entitlements, biography}.
  - Email change
    - POST /user/email/change/request with `{email}` (Authorization) → sends verification code
    - POST /user/email/change/confirm with `{code}` (Authorization) → confirms email change
    - POST /user/email/change/resend (Authorization) → resends verification code
  - Phone number change
    - POST /user/phone/change/request with `{phone_number}` (Authorization) → sends verification code
    - POST /user/phone/change/confirm with `{code}` (Authorization) → confirms phone number change
    - POST /user/phone/change/resend (Authorization) → resends verification code
- User profile updates
  - PATCH /user/username with `{username}` (Authorization)
  - PATCH /user/biography with `{biography}` (Authorization)
  - POST /user/password with `{old_password, new_password}` (Authorization)
  - DELETE /user (Authorization) → deletes account
- Solana Wallet (SIWS)
  - Login/Register: POST /solana/challenge → wallet.signIn(input) → POST /solana/login
  - Link wallet: POST /solana/challenge → wallet.signIn(input) → POST /solana/link (with Authorization)

---

### Solana Wallet Authentication (SIWS)

Sign In With Solana allows users to authenticate using their Solana wallet (Phantom, Solflare, Backpack, etc.).
Users can create accounts with just a wallet (no email/password required) or link a wallet to an existing account.

**Frontend Integration (React/TypeScript):**

```typescript
import { useWallet } from '@solana/wallet-adapter-react';

// 1. Request challenge from backend
const requestChallenge = async (address: string, username?: string) => {
  const response = await fetch('/api/v1/solana/challenge', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ address, username }), // username optional for new accounts
  });
  return response.json(); // Returns SignInInput
};

// 2. Sign with wallet
const signIn = async () => {
  const { publicKey, signIn } = useWallet();
  if (!publicKey || !signIn) return;

  // Get challenge from backend
  const input = await requestChallenge(publicKey.toBase58(), 'desired_username');

  // Wallet prompts user to sign
  const output = await signIn(input);

  // 3. Verify signature and get tokens
  const response = await fetch('/api/v1/solana/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      output: {
        account: { address: output.account.address },
        signature: btoa(String.fromCharCode(...output.signature)),
        signedMessage: btoa(String.fromCharCode(...output.signedMessage)),
      },
    }),
  });

  const { access_token, refresh_token, user } = await response.json();
  // Store tokens as usual
};
```

**Link wallet to existing account:**

```typescript
const linkWallet = async (accessToken: string) => {
  const { publicKey, signIn } = useWallet();
  if (!publicKey || !signIn) return;

  // Get challenge
  const input = await requestChallenge(publicKey.toBase58());

  // Sign
  const output = await signIn(input);

  // Link (requires auth)
  const response = await fetch('/api/v1/solana/link', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${accessToken}`,
    },
    body: JSON.stringify({
      output: {
        account: { address: output.account.address },
        signature: btoa(String.fromCharCode(...output.signature)),
        signedMessage: btoa(String.fromCharCode(...output.signedMessage)),
      },
    }),
  });

  return response.json(); // { success: true, solana_address: "..." }
};
```

**Notes:**
- Challenges expire in 15 minutes
- Username is optional - if not provided, a username is derived from the wallet address (e.g., `u_7xKX`)
- Users can change their username later via `PATCH /user/username`
- Wallet address is stored as a provider link (like Google/Discord) in `profiles.user_providers`
- One wallet per user, one user per wallet

---

### Verifier (JWKS, verify‑only)

Use the verifier when a service needs to accept JWTs issued by one or more
AuthKit-powered APIs (e.g., spacex), without mounting any auth routes.

- Create with `authhttp.NewVerifier(opts...)` — options: `WithSkew`, `WithAlgorithms`, `WithHTTPClient`. (`WithTenantMode` is a deprecated no-op shim kept for back-compat; tenant claims are parsed whenever present.)
- Add issuers via `verifier.AddIssuer(issuerID, audiences, opts)` — each may specify a JWKS URL (defaults to `/.well-known/jwks.json`), pre-provided PEM keys, or raw `*rsa.PublicKey` maps.
- For service JWTs, call `verifier.VerifyServiceJWT(ctx, token)` or mount
  `authhttp.RequiredServiceJWT(verifier)`. This returns a machine principal with
  issuer, subject, tenant/resource account, permissions, resources, and JTI; the
  host still owns final authorization.
- Keep route classes explicit: ordinary user/delegated routes use
  `authhttp.Required`, delegated-only resource routes use
  `verifier.VerifyDelegatedAccess`, and first-party machine routes use
  `authhttp.RequiredServiceJWT`. Service JWTs are intentionally rejected by the
  ordinary/delegated entry points, and user/delegated JWTs are intentionally
  rejected by `RequiredServiceJWT`.
- Default skew: 60s. Default algorithms: RS256.
- DB enrichment (recommended):
  - Call `verifier.WithService(coreSvc)` to enable best-effort
    DB enrichment hooks (roles + canonical email + provider usernames) when
    the token lacks those claims.

---

### Accepting Tokens From Multiple Issuers

SpaceX accepts service tokens from multiple issuers; both tesla.com and x.com.

```go

  import (
    "encoding/json"
    "net/http"
    authhttp "github.com/open-rails/authkit/http"
    "time"
  )

  func main() {
    ver := authhttp.NewVerifier(authhttp.WithSkew(60 * time.Second))
    ver.AddIssuer("https://tesla.com", []string{"spacex-app"}, authhttp.IssuerOptions{})
    ver.AddIssuer("https://x.com", []string{"spacex-app"}, authhttp.IssuerOptions{})

    mux := http.NewServeMux()

    // (1) Claims-only: just check JWT (no DB). 401 if missing/invalid.
    mux.Handle("/claims-only", authhttp.Required(ver)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      cl, ok := authhttp.ClaimsFromContext(r.Context())
      if !ok {
        w.WriteHeader(401)
        return
      }
      _ = json.NewEncoder(w).Encode(map[string]any{"user_id": cl.UserID})
    })))

    // (4) Admin-only: require login, then check admin role directly via DB.
    mux.Handle("/admin/report", authhttp.Required(ver)(authhttp.RequireAdmin(pg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
      w.WriteHeader(200)
    }))))

    http.ListenAndServe(":8080", mux)
  }
```

---

### Tenant Issuers & Delegated Access JWTs

AuthKit owns the shared identity primitives for federation: a resource service
registers tenant issuers, verifies their OIDC/JWKS metadata, and records minimal
delegated users as `(tenant_id, issuer, subject)`. Product-specific approval,
quota, billing, and resource policy still belong to the receiving product.

This lets a tenant bring external principals that live in the tenant's own
system. Those principals authenticate via the tenant's **issuer** rather than
local passwords. Two AuthKit-embedding services register with and trust each
other:

- the **platform / IdP** side (e.g. cozy-art) **mints** delegated tokens and
  **sends** its registration;
- the **resource-server** side (e.g. tensorhub) **accepts** registrations and
  **validates** the delegated tokens.

There are three roles, all owned by AuthKit:

| Role | Side | API |
|---|---|---|
| **register** | both | `TenantIssuersClient.RegisterIssuer` (outbound) → `POST /tenant-issuers` (inbound) |
| **mint** | platform | `MintDelegatedAccessToken(ctx, signer, DelegatedAccessParams)` |
| **validate** | resource server | `Verifier.LoadTenantIssuers` + `Verifier.VerifyDelegatedAccess` → `Claims.DelegatedAccess()` |

#### Delegated access JWTs

A **delegated access JWT** is AuthKit's standard primitive for user or
tenant-admin federation: one AuthKit issuer signs a short-lived JWT for an
external delegated actor, and a resource service (OpenRails, Tensorhub,
Gen-Orchestrator, ...) accepts it after issuer/JWKS/audience/resource-account
validation.
Mint it with `MintDelegatedAccessToken` / `DelegatedAccessParams`.

Canonical claim contract:

| Claim | Meaning | Typed accessor |
|---|---|---|
| header `typ=delegated-access+jwt` | identifies a delegated access JWT (`DelegatedAccessTokenType`) | `Claims.TokenTyp` / `IsDelegatedAccessToken()` |
| `iss` | AuthKit issuer that signed the token | `Claims.Issuer` |
| `aud` | target resource API (`openrails`, `tensorhub`, `gen-orchestrator`) | (matched at verify) |
| `tenant` | target resource-service account slug, e.g. `doujins` in OpenRails | `Claims.Tenant` |
| `delegated_sub` | issuer-side actor id, e.g. Paul's Doujins-side subject id; **no local account is implied** | `Claims.DelegatedSubject` |
| `permissions []string` | resource-defined permission strings (NOT OAuth space-delimited scope) — the **authority source** | `Claims.Permissions` / `HasPermission()` |
| `attributes {}` | issuer policy metadata, e.g. `{"tier":"cozy_free"}` (arbitrary JSON) | `Claims.Attributes` / `Attribute(key)` |
| `iat`/`exp`/`nbf`/`jti` | standard timing + token id | `Claims.JTI` |

**Hard invariants** (enforced + tested):

- Ordinary AuthKit access JWTs use header `typ=access+jwt`; delegated access
  tokens use header `typ=delegated-access+jwt`. `Verify()` rejects missing,
  unknown, or cross-profile `typ` values.
- A delegated access JWT **MUST NOT** carry a normal `sub`. `Verify()` rejects
  a `typ=delegated-access+jwt` token that carries `sub`
  (`access_token_has_sub`).
- A token carrying **both** `sub` and `delegated_sub` is rejected
  (`conflicting_subject`).
- `roles` are not part of delegated access JWTs. `MintDelegatedAccessToken`
  does not mint them, and `Verify()` rejects delegated access JWTs carrying a
  `roles` claim (`delegated_access_has_roles`). Receiving services authorize on
  `permissions` + explicit `attributes` policy.
- The `tenant` JWT claim is required and means the target resource-service
  account. Delegated access JWTs MUST NOT carry the legacy AuthKit `org` claim;
  `Verify()` rejects it (`delegated_access_has_org`).
- Tier/plan metadata belongs under `attributes.tier`. Delegated access JWTs
  MUST NOT carry a top-level `user_tier` claim
  (`delegated_access_has_user_tier`).
- Tenant issuers loaded from AuthKit's `tenant_issuers` store are
  also bound to the registered resource account (`tenant_slug` in the storage row):
  delegated access JWTs from that issuer must claim the same resource account,
  or verification rejects them with `resource_account_issuer_mismatch`. This
  prevents one trusted issuer from minting a delegated token for another
  resource account.

Receiving services can install validation hooks:

```go
v := authhttp.NewVerifier(
    authhttp.WithPermissionCatalog(func(perms []string) error { /* check catalog */ }),
    authhttp.WithAttributesPolicy(func(a map[string]json.RawMessage) error { /* check schema */ }),
)
cl, dp, err := v.VerifyDelegatedAccess(token) // requires typ=delegated-access+jwt + runs hooks
// dp.Tenant, dp.DelegatedSubject, dp.Permissions, dp.Attributes, dp.JTI, dp.Issuer
```

Because a delegated access JWT has no `sub`, the resource server's middleware
**skips the local-user gate** (no `user_disabled` lookup) — authorization is by
issuer/resource-account trust + `permissions`, not local-user existence.

Recommended OpenRails permission naming uses a service prefix even though
`aud=openrails` is present, because a host AuthKit permission catalog may carry
permissions for several resource services: self-scoped
`openrails:self:billing:read`, `openrails:self:checkout:create`,
`openrails:self:subscriptions:cancel`; tenant/admin
`openrails:tenant:catalog:write`, `openrails:tenant:payments:refund`,
`openrails:tenant:admin`. Routes must still check scope semantics, not just
string presence.

For browser-direct self-service billing, the host app still has one
authenticated AuthKit touchpoint: a current-user token endpoint owned by the
host app. That endpoint authenticates the normal app session, decides which
self-scoped OpenRails permissions the current user may receive, then calls
`MintDelegatedAccessToken` with `aud=openrails`, `tenant`, `delegated_sub` set
to the current user id, short `TTL`, and permissions such as
`openrails:self:billing:read` or `openrails:self:checkout:create`. The browser
then calls OpenRails directly with that delegated access JWT; the host does
not proxy billing reads or checkout/subscription actions.

#### Registration handshake (both sides)

**Outbound (platform side, e.g. cozy-art)** — publish this tenant's issuer +
JWKS URL to a resource server's accept endpoint:

```go
fc := authhttp.NewTenantIssuersClient(
    authhttp.WithTenantIssuersAuthToken(ownerAccessToken), // tenant owner/admin token
)
err := fc.RegisterIssuer(ctx, "https://tensorhub.example/api/v1/tenant-issuers",
    authhttp.TenantIssuersRegistration{
        Tenant:      "cozy-art",
        Issuer: "https://cozy.art",
        JWKSURI:  "https://cozy.art/.well-known/jwks.json",
    })
```

**Inbound (resource-server side, e.g. tensorhub)** — mount the `RouteTenantIssuers`
group. `POST /tenant-issuers` accepts + stores a registration, authorized by
the **tenant owner/admin** of the registering tenant (global admins may register for
any tenant); `DELETE /tenant-issuers` removes one; `GET /tenant-issuers`
(global-admin) lists them. This is the AuthKit-owned home for what services used
to expose as a bespoke `/api/v1/platform/issuers` endpoint.

#### In-house JWKS — no external push/sync

The resource server loads registered tenant issuers from AuthKit's **own
store** (the `profiles.tenant_issuers` table) and registers each with the
Verifier, whose existing in-house JWKS fetch/refresh then handles the keys.
There is **no external key push or sync** — the resource server pulls JWKS from
each issuer's URL on demand and refreshes per `CacheTTL`.

```go
// At startup (and re-run on a ticker / after a registration) to pick up store changes:
err := verifier.LoadTenantIssuers(ctx, coreSvc /* or any TenantIssuerSource */, []string{"tensorhub"})
```

`LoadTenantIssuers` registers only `enabled` issuers. A newly-accepted
registration is also added to the Verifier immediately by the inbound handler,
so it is usable without waiting for the next store load.
