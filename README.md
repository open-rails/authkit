### AuthKit

Lightweight auth library for Go services.

AuthKit is based on a browser-managed bearer-token model: login/OIDC/Solana
flows issue an `access_token` and `refresh_token`, frontend JavaScript stores
them, protected API calls use `Authorization: Bearer <access_token>`, and
refresh uses `POST /token` with the refresh token. It is not a cookie-session
library: it does not currently provide opaque `session_id` browser cookies,
HttpOnly token-cookie callbacks, or CSRF/session middleware for that model.

Note: This repo ships the HTTP transport as the top-level `http` package (`github.com/open-rails/authkit/http`). First-party router adapters live in `github.com/open-rails/authkit/adapters/gin` and `github.com/open-rails/authkit/adapters/chi`.

HTTP error responses use a **Stripe-style nested envelope** (same shape as
OpenRails), so a client hitting either service sees one error contract:

```json
{ "error": { "type": "invalid_request_error", "code": "password_too_short",
             "message": "Password too short.", "param": "password" } }
```

- `code` — the stable machine code; compare against `authhttp.ErrorCode`
  constants (e.g. `authhttp.ErrInvalidRequest`, `authhttp.ErrPasswordResetRequired`),
  never copied string literals. These values are unchanged from prior releases.
- `type` — error category, derived from the HTTP status:
  `invalid_request_error` (400/404/409), `authentication_error` (401),
  `authorization_error` (403), `rate_limit_error` (429), `api_error` (5xx).
- `message` — human-readable (English); for display/logging, not matching.
- `param` *(optional)* — the offending request field on validation errors.
- `metadata` *(optional)* — machine-readable context (e.g. rate-limit
  `retry_after_seconds`/`limit`/`remaining`, action-availability fields).

The envelope type lives in the core-free `authbase` package
(`authbase.ErrorEnvelope`), so the verify-only middleware emits the identical
shape. **Breaking** as of v0.52.0 (was the flat `{"error":"<code>"}`); migrate
clients from `body.error` (string) to `body.error.code`.

Scope (minimal)
- Asymmetric JWT issuing (RS256) + JWKS endpoint (no persistence yet).
- Password login and email-based password reset tokens.
- OIDC RP (OAuth2/OIDC) with PKCE (Redis/Garnet or in-memory for ephemeral state; no DB table).
- Passkey login/registration (WebAuthn/FIDO2) using host-configured RP ID and origins.
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
- Run them with [migratekit](https://github.com/open-rails/migratekit), name-tracked per app in `public.migrations` so a recorded migration is never re-applied:

  ```go
  ms, _ := migratekit.LoadFromFS(pgmigrations.FS)
  m := migratekit.NewPostgres(sqlDB, "authkit")
  _ = m.ApplyMigrations(ctx, ms)
  ```

  The bundled devserver uses this exact path. `FS` remains available for custom runners.
- PostgreSQL-backed storage requires PostgreSQL 18 or newer. Older PostgreSQL versions are not supported. AuthKit migrations use native `uuidv7()` defaults for AuthKit-owned UUID identifiers; PostgreSQL 17 can store UUIDv7 values but does not provide the required `uuidv7()` function.

Configurable schema (issue 69)
- AuthKit's tables live in the Postgres schema named by `core.Config.Schema` (default `profiles`, the historical name — leaving it unset is fully backward-compatible). Set it when multiple apps embed AuthKit against the same database and must not share auth tables (e.g. one app keeps `profiles`, another uses `openrails_auth`). Names must match `^[a-z_][a-z0-9_]*$` (max 63 bytes).
- AuthKit never touches `search_path` on the host's shared pool; queries stay schema-qualified and the qualifier is rewritten to the configured schema at execution time (see `internal/db/schema.go`).
- Hosts with a non-default schema must run the migrations rendered for it:

  ```go
  fsys, _ := pgmigrations.FSForSchema("openrails_auth") // fs.FS; "profiles"/"" returns the embedded FS unchanged
  ms, _ := migratekit.LoadFromFS(fsys)
  ```

- Pool-parameter helpers default to `profiles`; schema-aware variants take `svc.Schema()`: `authhttp.RequireAdminInSchema`, `authhttp.IsAdminInSchema`, `authhttp.HasRoleDBCheckInSchema`, `identity.NewStoreInSchema`.

Database queries (sqlc)
- All static Postgres queries are written as raw SQL in `internal/db/queries/*.sql` (one file per domain) and compiled to type-safe Go by [sqlc](https://docs.sqlc.dev) into the `internal/db` package (committed, never hand-edited).
- To add or change a query: edit the `.sql` file, run `task sqlc` (runs `sqlc generate` + `sqlc vet` as a pair; vet's `db-prepare` rule PREPAREs every query against a real Postgres — start one with `docker compose up -d postgres` and apply `migrations/postgres/*.up.sql`), then use the generated method on `db.Queries`. (Tasks are defined in `Taskfile.yml`; `task --list` shows them. Install: https://taskfile.dev/installation.)
- The schema source of truth for sqlc is `migrations/postgres/` — generated code is always type-checked against the real migrations. CI fails if `internal/db` drifts from the query files (`task sqlc-check`).
- Escape hatch: queries whose SQL is assembled at runtime stay on raw pgx with a comment explaining why (currently `core.AdminListUsers` and the advisory-lock path in `core.ReconcileOrgManifest`). ClickHouse queries are out of sqlc's scope.

Passkeys
- Configure `core.Config.Passkeys` when enabling passkey routes:

  ```go
  Passkeys: core.PasskeyConfig{
    RPID:           "myapp.com",
    RPDisplayName: "My App",
    Origins:       []string{"https://myapp.com"},
  }
  ```

  Empty passkey config derives `RPID`/origin from `Frontend.BaseURL`.
- Mount the default API or `RoutePasskeys` to expose
  `/passkeys/register/begin`, `/passkeys/register/finish`,
  `/passkeys/login/begin`, `/passkeys/login/finish`, `GET /passkeys`,
  `PATCH /passkeys/{id}`, and `DELETE /passkeys/{id}`.
- The browser should pass AuthKit's `publicKey` response into
  `navigator.credentials.create()` or `navigator.credentials.get()`, then POST
  the returned `PublicKeyCredential` JSON to the matching `finish` route.
- AuthKit requires WebAuthn user verification before minting a session and
  records MFA assurance claims on the access token. Passkeys do not satisfy
  `RoleDef.RequiresMFA` enrollment requirements yet.

Full DB-backed tests
- `go test ./...` is a fast DB-free smoke when `AUTHKIT_TEST_DATABASE_URL` is unset; DB-backed integration tests skip in that mode.
- To run the full suite locally, start the compose issuer so the devserver applies migrations, then run the Taskfile test target:

  ```bash
  docker compose up -d --build issuer
  task test
  ```

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
  // Build core.Config from your app config. Fields are grouped by concern.
  cfg := core.Config{
    Token: core.TokenConfig{
      Issuer:            "https://myapp.com",
      IssuedAudiences:   []string{"myapp"},
      ExpectedAudiences: []string{"myapp"},
    },
    Frontend: core.FrontendConfig{
      BaseURL:      "https://myapp.com",
      CallbackPath: "/login/callback",
    },
    // Registration: core.RegistrationConfig{
    //   Verification:   core.RegistrationVerificationRequired, // none|optional|required
    //   NativeUserMode: core.RegistrationModeOpen,             // open|invite_only|admin_only|admin_bootstrap_only|...
    // },
    // Keys.Source nil => auto-discovery in AuthKit (env/fs/dev fallback)
  }

  // Postgres is REQUIRED (positional). Optional deps are functional options:
  svc, _ := authhttp.NewServer(cfg, pg, // pg: your *pgxpool.Pool
    // authhttp.WithRedis(redis),
    // authhttp.WithEmailSender(email), authhttp.WithSMSSender(sms),
  )

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
`/api/v1/me`, and `/api/v1/admin/users`, while AuthKit's internal route
paths remain `/token`, `/me`, and `/admin/users`.

Hosts can mount only selected route groups or wrap individual handlers:

```go
authkitgin.RegisterAPI(v1, svc, authkitgin.WithRoutes(svc.Routes().Groups(
  authhttp.RoutePublic,
  authhttp.RouteSession,
  authhttp.RouteRegister,
  authhttp.RouteUser,
  authhttp.RouteAdmin,
)))
```

Host-facing JSON API groups are:

- `RoutePublic`: public JSON discovery, such as `/identity-providers`.
- `RouteRegister`: public registration and verification support.
- `RouteSession`: login, refresh, logout, password reset, login-time 2FA, wallet login.
- `RouteUser`: authenticated self-service account routes, reauth, provider linking, wallet linking.
- `RouteAdmin`: intrinsic `/admin/*` root-permission routes.
- `RoutePermissionGroups`: generated per-persona group-management routes.

Browser OIDC routes use `RouteBrowserOIDC` through `svc.Routes().OIDCBrowser()`
and usually mount at `/oidc/*`. JWKS stays as the separate public
`svc.JWKSHandler()` mount at `/.well-known/jwks.json`.

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
It defaults to `open`. Any non-open native-user mode turns off public user
self-registration and auto-registration paths: `POST /register`,
`/register/availability`, `/register/resend-email`, `/register/resend-phone`,
OIDC/social/Solana auto-create, and pending-registration confirmation all return
a stable `registration_disabled` error (`/register/availability` reports every
field as unavailable, never usable). Existing-user authentication is unaffected:
login, refresh, logout, password reset/recovery, token verification, and
sessions all keep working. Embedded bootstrap/admin creation through exported
core APIs (`CreateUser`, `ImportUser`) still works.

Locked-down (e.g. self-hosted OpenRails) pattern: mount only the chosen route
groups, set native registration to `admin_bootstrap_only`, and bootstrap through
embedded core APIs. Bootstrap authority is an operator/deploy action.

```go
cfg := core.Config{
  // ...Token (issuer/audiences) + Keys...
  Registration: core.RegistrationConfig{
    NativeUserMode: core.RegistrationModeAdminBootstrapOnly,
  },
}
svc, _ := authhttp.NewServer(cfg, pg)

// Mount only the route groups this deployment intentionally exposes:
authkitgin.RegisterAPI(v1, svc, authkitgin.WithRoutes(svc.Routes().Groups(
  authhttp.RoutePublic,  // discovery endpoints
  authhttp.RouteSession, // login, refresh, logout, password reset
  authhttp.RouteUser,    // self-service for existing accounts
)))

// Bootstrap declared users/admins internally via AuthKit core APIs
// (unaffected by public registration modes):
core := svc.Core()
_, _ = core.CreateUser(ctx, "ops@example.com", "operator")
```

For a closed-registration deployment, the bootstrap manifest is the standard
machine/bootstrap path. It declares AuthKit-owned authority state: users,
root roles, permission-group personas, memberships, trusted issuers, and
optional generated opaque API keys.

```yaml
users:
  - ref: operator
    email: ops@example.com
    username: operator
    email_verified: true
    password:
      plaintext: "change-this-in-your-secret-renderer"
    global_roles: ["admin"]

global_roles:
  - slug: admin
    name: Admin

permission_groups:
  - persona: merchant
    resource_slug: cozy-art
    issuers:
      - issuer: https://cozy.example
        jwks_uri: https://cozy.example/.well-known/jwks.json
        audiences: ["openrails"]
        enabled: true
    roles:
      - name: operator
        permissions: ["merchant:self:read", "openrails:billing:read"]
    memberships:
      - user_ref: operator
        role: operator
    api_keys:
      - name: openrails-runtime
        role: operator            # the single permission-group role this key holds
        resources:
          - kind: openrails.merchant
            id: cozy-art
        output:
          file: /run/secrets/openrails-runtime.key
```

Bootstrap passwords support three explicit modes: `plaintext` initial password
(hashed by AuthKit), imported `hash` plus `hash_algo`, or `reset_required: true`
for imported accounts that must go through recovery before login. Secret
references and imported API-key hashes are intentionally not built in;
hosts that need Vault/Kubernetes reads should render the manifest or call the
library API with their own secret handling.

The standalone AuthKit devserver exposes this as both an opt-in startup hook and
a one-shot deploy-job command:

```bash
DEVSERVER_ISSUER=https://auth.example \
DB_URL=postgres://... \
DEVSERVER_PERMISSION_CATALOG=openrails:billing:read,openrails:entitlements:read \
DEVSERVER_API_KEY_PREFIX=cozy \
AUTHKIT_BOOTSTRAP_PATH=/manifests/bootstrap.yaml \
/authkit-devserver bootstrap apply --file /manifests/bootstrap.yaml
```

Use `AUTHKIT_BOOTSTRAP_ON_START=true` only for local/dev or
simple self-hosted deployments. Production systems should usually run the
one-shot command as a release job, or call `core.ReconcileBootstrapManifest`
from their own job with host-owned secret handling, so API pods do not need
long-lived secret-write credentials.

Hosted SaaS deployments can later set native registration to `open` and mount
the `RouteRegister` group to enable public signup without code changes.

OpenRails' bootstrap flow should pass its `auth:` section through to AuthKit
bootstrap for users, root roles, permission groups, API keys, and trusted remote
applications, then reconcile OpenRails-owned merchants, catalog, prices,
entitlements, grants, billing, and provider state itself.

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
    Token: core.TokenConfig{
      Issuer:            "https://myapp.com",
      IssuedAudiences:   []string{"myapp"},
      ExpectedAudiences: []string{"myapp"},
    },
    Frontend: core.FrontendConfig{BaseURL: "https://myapp.com", CallbackPath: "/login/callback"},
  }

  svc, _ := authhttp.NewServer(cfg, pg) // pg: your *pgxpool.Pool (required)
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
- AuthKit never reads provider environment variables directly. Host apps load their own config, build the sender, then pass it as a constructor option (`authhttp.WithEmailSender` / `authhttp.WithSMSSender`).
- The SMS provider requires `AccountSID`, `AuthToken`, and `MessagingServiceSID`. It uses Twilio Messaging (`Messages.json`) only; there is no Verify service path and no `From` number fallback path.
- The email provider requires a SendGrid/Twilio Email API key and a verified from address. Hosts can provide link builders or full message builders for branded/localized copy.
- A 2xx response from AuthKit means the message was accepted by the configured sender/provider submission call. It does not prove the recipient mailbox or carrier ultimately delivered, accepted, opened, or displayed the message.

Preferred language
- AuthKit stores an optional preferred language on the user profile as a simple two-letter code such as `en`, `es`, or `zh`. Registration seeds it from the request language.
- Host apps should pass the current site language through AuthKit's language middleware during registration, and should use `PATCH /user/preferred-language` when the user explicitly changes their account preference.
- Ordinary login, token refresh, and browsing a different route language must not rewrite the stored preferred language.
- AuthKit uses the stored language for account, security, verification, password reset, login-code, and welcome messages. Built-in Twilio email/SMS defaults fall back to English when a language is unsupported; host-provided builders can read `lang.LanguageFromContext(ctx)` for custom localized copy.
- Site/content language remains host-app owned. Preferred language is the communication language and a default only when the host has no stronger route/session/browser choice.

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
smsSender, err := smstwilio.New(smstwilio.Config{
    AccountSID:          cfg.TwilioAccountSID,
    AuthToken:           cfg.TwilioAuthToken,
    MessagingServiceSID: cfg.TwilioMessagingServiceSID,
    AppName:             "Example",
})
if err != nil {
    return err
}

// Pass the senders as options when constructing the server:
svc, _ := authhttp.NewServer(cfg, pg,
    authhttp.WithEmailSender(emailSender),
    authhttp.WithSMSSender(smsSender),
)
```

External identity providers
- Built-in providers (`google`, `apple`, `discord`, `github`) can still be enabled with `core.Config.Providers` by passing client IDs/secrets.
- For custom providers, prefer `core.Config.ProviderDescriptors`. OIDC providers are usually pure configuration because identity claims are standardized. OAuth2 providers are pure configuration when their userinfo JSON can be mapped with dot paths.
- Apple uses the same descriptor model, but its client secret is a signed JWT. Use `ClientSecret.Strategy: "apple_jwt"` with Apple team/key/private-key fields.
- `GET /identity-providers` returns the enabled external identity-provider list for frontends.

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

AuthKit can include entitlements (e.g., "premium", "pro") in service JWTs if you provide an `EntitlementsProvider`. This is useful for billing/subscription systems where entitlements are stored outside the `profiles` schema.

**Interface:**
```go
type EntitlementsProvider interface {
    ListEntitlements(ctx context.Context, userID string) ([]string, error)
}
```

Providers return **active entitlement names only** — AuthKit bakes them verbatim
into the JWT `entitlements` claim and admin user views. Filtering expired/revoked
grants is the provider's responsibility.

Optionally implement `BatchEntitlementsProvider` (`ListEntitlementsBatch`) so
`AdminListUsers` can fetch entitlements in one round trip instead of per row.

**Example implementation** (querying a `billing.entitlements` table):

```go
package main

import (
    "context"
    "time"

    "github.com/jackc/pgx/v5/pgxpool"
)

type BillingEntitlementsProvider struct {
    pg *pgxpool.Pool
}

func (p *BillingEntitlementsProvider) ListEntitlements(ctx context.Context, userID string) ([]string, error) {
    rows, err := p.pg.Query(ctx, `
        SELECT entitlement
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

    var out []string
    for rows.Next() {
        var name string
        if err := rows.Scan(&name); err != nil {
            return nil, err
        }
        out = append(out, name)
    }
    return out, rows.Err()
}

// Wire it up (Postgres positional; entitlements as an option):
svc, _ := authhttp.NewServer(cfg, pg,
    authhttp.WithEntitlements(&BillingEntitlementsProvider{pg: pg}),
)
```

**Provider failures.** A billing outage must not block login: if the provider
errors during token issuance, AuthKit still mints the token but omits entitlement
claims and logs loudly (`token issued WITHOUT entitlement claims`). Admin views
degrade to no entitlements rather than failing the request.

**Gating requests.** Use `Claims.HasEntitlement(name)` for ad-hoc checks, or the
`RequireEntitlement("premium")` / `RequireAnyEntitlement("pro", "premium")`
middleware (mount after `Required`) to gate routes; both deny service-principal
(OAT) and delegated tokens, which carry no entitlements.

**Snapshot semantics & revocation lag.** Entitlements are snapshotted into the
JWT at issuance time. Unlike account bans (re-checked live on every request),
entitlements are NOT re-validated per request, so a revocation only takes effect
once the access token expires or is re-issued. Size your access-token TTL
(`AccessTokenDuration`) to your acceptable entitlement-revocation lag, or
re-issue the token when a grant changes.

---

Concepts (concise)

- Service (issuer + storage): built by `authhttp.NewServer(cfg, pg, opts...)` (Postgres required; optional deps are functional options); backs the built-in handlers (sessions, login, OIDC, etc). The full implementation lives in `internal/authcore` (driven by the HTTP transport and not part of the public contract); embedders reach a small curated facade via `svc.Core()` (`*core.Service`) for provisioning, minting, and management — e.g. `svc.Core().CreateUser(...)`, `svc.Core().MintServiceJWT(...)`, `svc.Core().ReconcileBootstrapManifest(...)`.
- Middleware: `github.com/open-rails/authkit/http` provides `Required`/`Optional` (JWT verification) plus helpers like `RequireAdmin(pg)`.
- Verify-only: use `authhttp.NewVerifier()` + `verifier.AddIssuer(...)` to accept tokens from other issuers without issuing tokens yourself.
  - **Lean import for pure verification:** the verification layer (`Verifier`, `NewVerifier`, `Claims`, the `Required`/`Optional` middleware, `RequiredServiceJWT`, etc.) lives in the dependency-light `github.com/open-rails/authkit/verify` package, which imports **no Postgres/Redis/storage** — only `authkit/jwt` + `authkit/authbase`. A service that *only* validates tokens (a typical resource server) should import `authkit/verify` directly to keep `pgx`/`redis` out of its build graph. `authkit/http` re-exports the same names (`authhttp.Verifier`, `authhttp.NewVerifier`, `authhttp.Claims`, …) for apps that also issue tokens, so existing embedders need no changes. Attach DB-backed enrichment (live-user/ban gate, role/email hydration, opaque API-key resolution) only when you want it, via `verifier.WithService(coreSvc)` — `*core.Service` satisfies the `verify.Enricher` interface.

---

Configuration ownership

AuthKit library behavior is host-owned: the embedding app should pass runtime behavior via `core.Config`, not rely on library env/file reads.

| Area | Ownership | Notes |
| --- | --- | --- |
| `Issuer`, `IssuedAudiences`, `ExpectedAudiences` | Host config | Required token contract inputs. |
| `RequireVerifiedRegistrations`, `Environment`, `SolanaNetwork`, `NativeUserRegistrationMode`, `BaseURL` | Host config | Runtime behavior should be deterministic from config. |
| `Keys` provided (`cfg.Keys != nil`) | Host config | Fully disables library key env/filesystem discovery. |
| `Keys` omitted (`cfg.Keys == nil`) | Library exception | Only allowed env/filesystem auto-discovery path (`ACTIVE_KEY_ID`, `ACTIVE_PRIVATE_KEY_PEM`, `PUBLIC_KEYS`, `<KeysPath>/keys.json` (default `/vault/auth`), `.runtime/authkit/*`). |
| `KeysPath` / `AUTHKIT_KEYS_PATH` | Host config | Overrides the filesystem **directory** the local resolver scans for `keys.json`. Default `/vault/auth` (unchanged). See "Signing & key resolution for embedders". |

---

### Signing & key resolution for embedders

**One key per app.** Each embedding app owns exactly **one** JWT signing keypair —
its issuer identity, the only thing on its JWKS (plus retiring keys during
rotation). That single key signs **all** of the app's JWTs: user access tokens,
first-party service JWTs, delegated access tokens, and remote application access
tokens.
They differ only in claims (`aud`, `sub`/`delegated_sub`, `token_use`), never in
key. No app should manage a second JWT key.

**Sign through AuthKit — the host never holds the private key.** The host
delegates the signing *operation* to AuthKit and passes claims/params only.
AuthKit exposes the host exactly two things: (1) **mint/sign** operations
(params in → signed token out) and (2) **public** verification material (JWKS).
There is **no** API that returns a private key, a PEM, or a raw `crypto.Signer`
over the private key — so the host literally cannot read, copy, or persist it.
Mint through the `*core.Service` methods:

```go
svc, _ := core.NewFromConfig(core.Config{
    Token: core.TokenConfig{
        Issuer:            "https://cozy-art.example",
        IssuedAudiences:   []string{"cozy-art"},
        ExpectedAudiences: []string{"cozy-art"},
    },
    // Keys.Source nil => local resolver; point it wherever the host renders keys.json:
    Keys: core.KeysConfig{Path: "/vault/auth"}, // or set AUTHKIT_KEYS_PATH; default is /vault/auth
}, pg) // pg: your *pgxpool.Pool (may be nil for a pure signing/verify-only service)

// Delegated access JWT (cross-service federation) — params only, no key:
tok, _ := svc.MintDelegatedAccessToken(ctx, core.DelegatedAccessParams{
    Audiences:        []string{"tensorhub"},
    DelegatedSubject: userID,
    Permissions:      []string{"repo:create"},
}) // iss defaults to the Service's Issuer

// First-party service JWT (machine-to-machine, e.g. cozy-art -> tensorhub):
sjwt, _, _ := svc.MintServiceJWT(ctx, core.ServiceJWTMintOptions{
    Subject:   "service:cozy-art",
    Audiences: []string{"tensorhub"},
})

// Remote application access token (registered remote_application acting as itself):
rat, _ := svc.MintRemoteApplicationAccessToken(ctx, core.RemoteApplicationAccessParams{
    Audiences: []string{"openrails"},
})

// Arbitrary first-party claims (escape hatch — host owns the claim semantics):
cjwt, _ := svc.MintCustomJWT(ctx, core.CustomJWTMintOptions{
    Type:      "worker-capability+jwt",
    TTL:       10 * time.Minute,
    Subject:   "service:tensorhub",
    Audiences: []string{"cozy.scheduler"},
    Claims: map[string]any{
        "cap_kind":   "worker",
        "grants":     []string{"job:run"},
        "release_id": releaseID,
    },
}) // iss/iat/exp + kid header owned by AuthKit; the host owns everything else
```

**Four mint entry points — pick the most constrained one that fits.** All four
sign through the one internal key (same JWKS, same `kid`/`alg` header); they
differ only in how much of the claim shape AuthKit owns:

| Method | Use when | Claim shape |
| --- | --- | --- |
| `MintServiceJWT` | First-party machine-to-machine call (`service:<app>` → another app). | **Opinionated.** Forces `token_use=service`, `typ=service+jwt`; you supply `sub`/`aud`/`permissions`/`resources` only. |
| `MintDelegatedAccessToken` | Cross-service federation — one issuer signs for a delegated subject a receiver accepts after issuer/JWKS/aud checks. | **Opinionated.** Forces `typ=delegated-access+jwt`, writes `delegated_sub`, NEVER sets `sub`. |
| `MintRemoteApplicationAccessToken` | Registered remote_application acting as itself through stored AuthKit authority. | **Opinionated.** Forces `typ=remote-application-access+jwt`, writes neither `sub` nor `delegated_sub`; verifier resolves authority from the registered issuer row. |
| `MintCustomJWT` | **Escape hatch** — token shapes the two above can't express (e.g. tensorhub capability/worker tokens with `cap_kind`/`grants`/`release_id`, or a worker variant with `aud:["cozy.scheduler"]`). | **Host-owned.** You pass an arbitrary `Claims` map (+ optional `Type`/`Subject`/`Audiences`/`Issuer`). AuthKit owns ONLY `iss`/`iat`/`exp` and the `kid`/`alg` header. |

`MintCustomJWT` is the blessed alternative to reaching for the low-level
`jwtkit.Signer.Sign` — the host stops hand-assembling `kid`/`iss`/`exp` and never
risks holding a signer it shouldn't. **You own the claim semantics; the verifier
side must understand them.** Precedence is enforced: the host `Claims` map may NOT
set `iss`/`iat`/`exp` (returns `ErrCustomClaimsReserved`) — `iss` is overridable
only via the explicit `Issuer` option (defaults to the Service issuer); the
explicit `Subject`/`Audiences` options win over any `sub`/`aud` in the map. TTL is
required and capped at `MaxCustomJWTLifetime` (1h); empty and oversized claim sets
are rejected.

**Local-backend key resolution precedence** (used when `cfg.Keys == nil`),
identical for the convenience auto-resolver and the explicit constructors:

1. **Env** — `ACTIVE_KEY_ID` + `ACTIVE_PRIVATE_KEY_PEM` (+ optional `PUBLIC_KEYS`).
2. **File** — `<dir>/keys.json` where `dir` = `cfg.KeysPath` → `AUTHKIT_KEYS_PATH`
   → `/vault/auth` (default, unchanged). The file uses the
   `{active_key_id, active_private_key_pem, public_keys}` envelope.
3. **Dev-gen** — auto-generates and persists a keypair under `.runtime/authkit/`.
   **Non-prod only**: when `ENV`/`APP_ENV`/`ENVIRONMENT` is `production`/`prod`
   and neither env nor file yields a key, resolution **hard-fails** — no
   throwaway key in production.

Compose it yourself with the exported `jwtkit` constructors instead of the
convenience resolver:

- `jwtkit.EnvKeySource()` — env loader (returns `nil` when unset).
- `jwtkit.FileKeySource(dir)` — `<dir>/keys.json` loader (returns `nil` when absent; empty dir defaults to `/vault/auth`).
- `jwtkit.NewGeneratedKeySourceInDir(dir)` — dev-gen under a chosen dir (defaults to `.runtime/authkit`).
- `jwtkit.NewAutoKeySource()` / `jwtkit.NewAutoKeySourceWithPath(dir)` — the composed env → file → dev-gen ladder above.

**Pluggable backend (future remote signer).** Because `jwt.Signer` is an
interface, the local backend (RSA key in memory, from a `KeySource`) and a
future **remote Vault-Transit backend** (where the private key never enters the
app's memory/disk/container) are interchangeable. AuthKit selects the backend at
init; call sites (`svc.MintDelegatedAccessToken(...)` etc.) are unchanged and
never see key material. The remote `VaultTransitSigner` is tracked as a
forward-looking follow-up — **authkit future #72** — and drops in behind this
same `Signer` seam with zero host changes.

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
- Full-page OIDC login accepts an optional app-relative `return_to` query
  parameter, for example `/oidc/google/login?return_to=/subscribe?plan=pro`.
  AuthKit stores it in OIDC state and returns it as `return_to` in the callback
  fragment after rejecting absolute/external URLs, `//host`, backslashes, and
  CR/LF.
- JSON/SPAs flows such as password login, registration, in-app 2FA, and POST
  verification/reset return tokens or status in JSON and do not navigate away;
  the client owns any `return_to` state there.
- AuthKit stores refresh-session records server-side for refresh-token lifecycle
  and revocation, but it does not provide an opaque `session_id` browser-cookie
  mode or HttpOnly cookie token mode.
- Apps that want cookie/session authentication need a separate integration mode:
  cookie parsing in middleware, CSRF protection, cookie-setting callback
  behavior, and different frontend refresh/logout assumptions.

Token taxonomy

| Credential | Wire signal | Authority source |
| --- | --- | --- |
| User access token | JWT `typ=access+jwt` | Local user identity, session id, and authoritative short-lived entitlements in the token; profile and permission-group data comes from `/me` and live DB lookups. |
| Delegated access token | JWT `typ=delegated-access+jwt` + `delegated_sub` | Concrete `permissions` claim, validated against the issuer remote application's stored authority. |
| Remote application access token | JWT `typ=remote-application-access+jwt`, no `sub` or `delegated_sub` | Stored authority for the registered remote_application resolved from validated `iss`. |
| Service JWT | JWT `typ=service+jwt` + `token_use=service` | Receiver intersects requested permissions/resources with server-side grants for the issuer/subject. |
| API key | Opaque `<prefix>_st_<key_id>_<secret>` bearer string | Stored DB permissions/resources resolved by hashing and looking up the presented secret. |

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

Permission groups
- The old static organization route plane was removed. AuthKit now exposes
  resource-scoped membership, roles, and credentials through generated
  permission-group routes derived from the host's configured schema.
- Terminology: a configured permission-group persona is the public route and
  permission namespace. For example, a `merchant` persona generates
  `/merchant/:resource_slug/...` routes and `merchant:<area>:<action>`
  permissions.
- Generated permission-group routes:
  - GET /me/groups
  - GET /:persona/:resource_slug/members
  - POST /:persona/:resource_slug/members
  - DELETE /:persona/:resource_slug/members/:user
  - PUT /:persona/:resource_slug/members/:user/roles/:role
  - GET /:persona/:resource_slug/roles
  - POST /:persona/:resource_slug/roles
  - DELETE /:persona/:resource_slug/roles/:role
  - GET /:persona/:resource_slug/api-keys
  - POST /:persona/:resource_slug/api-keys
  - DELETE /:persona/:resource_slug/api-keys/:key
  - GET /:persona/:resource_slug/remote-applications
  - POST /:persona/:resource_slug/remote-applications
  - DELETE /:persona/:resource_slug/remote-applications/:app
  - GET /:persona/:resource_slug/invites
  - POST /:persona/:resource_slug/invites
  - DELETE /:persona/:resource_slug/invites/:invite
  - Each persona emits only the route families enabled by its management
    profile. Built-in `root` emits member-management plus role-list routes.
- Token claim shape (uniform; no mode):
  - A user access token includes registered JWT claims, `sub`, `sid`, and
    authoritative short-lived `entitlements`.
  - User access tokens do not include `global_roles`, `roles`, `org_roles`,
    `email`, `email_verified`, `username`, or `discord_username`.
  - Membership, role, permission, and profile data are resolved server-side
    from `/me`, route resource state, and stored memberships.

API Keys (opaque machine credentials)
- Long-lived, revocable shared-secret bearer credentials owned by a permission
  group, for machine/automation callers (CI, operator CLIs, service-to-service).
  Robots should not replay the human password-login path. These are symmetric
  secrets with assigned permissions/resources; they are not JWKS URLs, public
  keys, or issuer registrations.
- An API key acts as a service principal for its permission group: middleware
  sets `Claims.Permissions`, `Claims.Resources`, and a service marker
  (`Claims.IsService()`), leaving `UserID` empty so the live-user ban/enrichment
  gate is skipped. Permissions are opaque to authkit; the embedding app owns the
  vocabulary and enforces meaning.
- Current wire format is `Authorization: Bearer <prefix>_st_<key_id>_<secret>`, where `<prefix>` is the host-configured `Config.APIKeyPrefix` brand. `key_id` is a non-secret public id for indexed lookup; only `sha256(secret)` is stored; the full key is shown **once**.
- Resolved in the `Required`/`Optional` middleware *before* JWT verification (constant-time secret compare; revoked/expired/group-deleted rejected; non-API-key credentials fall through to JWT). The API-key path is separate from the password-login handler, so API keys **bypass the interactive password-login rate limiter** by design.
- **An API key holds exactly ONE permission-group role:** its effective permissions are resolved FROM that role at use time, so editing the role updates every key that holds it. The bespoke-permission use case is served by creating a custom group role. Resource-scope (`resources: [{kind,id}]`) stays a SEPARATE binding, orthogonal to the role.
- **Mint authorization is native + role-based:** minting requires the generated `<persona>:api-keys:manage` permission; the body field is `role` (a single role slug). AuthKit validates the role exists in the group and enforces no-escalation. Permissions are NEVER frozen; they re-resolve from the role at verify time. An API key can never mint/list/revoke API keys because it has no user principal.
- **Resource scopes:** API keys may carry opaque host-defined resource rows, `resources: [{kind,id}]`, in addition to permissions. AuthKit validates shape/length and duplicate pairs, stores them in `profiles.api_key_resources`, and returns them from list/resolve/middleware claims. AuthKit does not interpret resource kinds or wildcard-looking IDs; the embedding host owns semantics. Hosts that need resource no-escalation can set `Config.ResourceScopeAuthorizer`. Rule: permissions say what; resources say where.
- Manage via `POST/GET/DELETE /:persona/:resource_slug/api-keys[/:token_id]`. POST accepts `{name, role, resources?:[{kind,id}], expires_at?}`; the mint response also surfaces the role's resolved `permissions` for convenience. Optional `expires_at` (null = non-expiring), capped by `Config.APIKeyMaxTTL` when set. Stored in `profiles.api_keys` with `permission_group_id` plus a role; no per-key permission table.
- **Leak response:** revoke the key (`DELETE …/api-keys/:id`) — the application prefix is registrable with secret-scanning/push-protection partners so leaked keys can be auto-detected.

Service JWTs (OIDC/JWKS machine credentials)
- First-party services with their own AuthKit issuer/JWKS should prefer
  short-lived service JWTs over generated opaque API keys. The caller mints
  a 15-minute JWT with `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`,
  `token_use=service`, and `permissions: []`, caches it in memory until near
  expiry, and sends it as `Authorization: Bearer <jwt>`.
- AuthKit provides `core.MintServiceJWT` / `(*core.Service).MintServiceJWT` and
  `authhttp.Verifier.VerifyServiceJWT` plus `RequiredServiceJWT`. Verification
  uses the same issuer/JWKS registry as delegated access tokens, including
  remote-application issuer lazy-load and disabled-issuer fail-closed behavior.
- `permissions: []` is the canonical requested-capability claim. OAuth `scope`
  is accepted only as an explicit compatibility bridge. AuthKit parses requested
  permissions/resources but does not grant them; resource servers such as
  OpenRails must intersect them with server-side grants for the issuer/subject.
- Use service JWTs for callers that can publish an issuer/JWKS, such as
  Doujins/Hentai0 -> OpenRails. Use opaque API keys for generated
  API-key-like credentials, non-OIDC clients, bootstrap scripts, and manual
  integrations.

Reserved slug policy
- Owner namespaces use explicit states:
  - `restricted_name`: slug is blocked in `profiles.owner_reserved_names` and not publicly registrable.
  - `parked_org`: org exists and is platform-held (`metadata.namespace_state=parked_org`, `metadata.reserved=true`).
  - `registered_org`: normal org lifecycle (`metadata.namespace_state=registered_org`).
- Public lookup endpoint: `GET /namespaces/{slug}` returns public namespace metadata for the slug:
  - `requested_slug`: normalized slug from the request.
  - `slug`: current canonical slug when the request resolves to a live or held namespace; otherwise the requested slug.
  - `claimable`: `{user, org}` booleans.
  - `renamed`: whether this lookup resolved through rename history.
  - `hold_until`: present for rename reuse holds.
  - optional `org` and/or `user` payloads when records exist.
- The PostgreSQL baseline schema creates `profiles.owner_reserved_names` and seeds canonical restricted names (`admin`, `superuser`, `root`, `sudo`) directly.
- Public register/create/rename/org-create/org-rename paths do not use a hardcoded denylist; conflicts are enforced through owner-namespace uniqueness plus reserved-name table checks.
- Reserved users are non-loginable (reserved placeholder credentials/providers are cleared by migration and reserve flows).

Verification delivery and expiry
- Email verification codes and links expire in 60 minutes.
- Phone/SMS verification codes and links expire in 15 minutes.
- Password reset link tokens expire in 1 hour.
- Sender integrations receive `core.VerificationMessage{Code, LinkToken}` and must send only provided fields; at least one must be present.
- Code-based and link-based flows are both supported:
  - Email verify code: `POST /email/verify/confirm` with `{"code":"123456"}`
  - Email verify link token: `POST /email/verify/confirm` with `{"token":"..."}`
  - Phone verify code: `POST /phone/verify/confirm` with `{"phone_number":"+1...","code":"123456"}`
  - Phone verify link token: `POST /phone/verify/confirm` with `{"token":"..."}`
  - Email password reset confirm: `POST /email/password/reset/confirm` with `{"token":"...","new_password":"..."}`
  - Phone password reset confirm: `POST /phone/password/reset/confirm` with `{"token":"...","new_password":"..."}`
- AuthKit API routes are prefix-neutral. Your API can live under a prefix (recommended: `/api/v1`); do not add an extra `/auth` segment when embedding AuthKit.

Identity validation policy
- AuthKit owns identity validation policy. Host applications should not
  duplicate or override username, password, email, or phone validation rules.
- Username rules are fixed: trim whitespace, 4-30 characters, start with an
  ASCII letter, allow only ASCII letters/digits/underscore, no `@`, and no
  leading `+`. AuthKit normalizes the owner slug by lowercasing and converting
  underscore/dash runs to single dashes.
- Username namespace checks reject collisions with users, renamed or
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

Password hash policy (verification whitelist):
- AuthKit verifies exactly two hash formats: **argon2id** (native) and
  **bcrypt** (legacy-but-sound; verified, then lazily re-hashed to argon2id on
  the first successful login). This is the designed migration path for hosts
  importing password hashes: import bcrypt via `UpsertPasswordHash`, and
  accounts upgrade themselves transparently.
- Anything else is deliberately NOT verified, even when an implementation
  would be easy. Rationale, learned from the doujins legacy migration (1,255
  unimportable hashes): DES `crypt()` truncates passwords to 8 significant
  characters with a 12-bit salt — accepting a DES match as proof of identity
  keeps a trivially crackable credential live in the auth path; md5-crypt is
  fast and memory-unhardened; and corrupted/mangled stored hashes (22% of that
  cohort) can never verify under any algorithm, so a refuse-and-reset
  mechanism is needed regardless. A short whitelist is itself the invariant:
  every additional accepted format lowers the floor of what counts as
  authentication.
- For unverifiable imports, hosts store the row with
  `hash_algo = "legacy-reset-required"` (`core.HashAlgoLegacyResetRequired`),
  preserving the raw legacy hash for forensics only. Every password-verify
  path (login, reauth, change-password) then returns
  `core.ErrPasswordResetRequired`, surfaced over HTTP as a 401 with the stable
  body code `password_reset_required`, so clients can tell the user to reset
  instead of showing generic invalid-credentials.
- Recovery root of trust: these accounts fall back to **email (or phone)
  mailbox control as the sole proof of ownership** — the same trust model as
  any forgot-password flow (reset links expire in 1 hour, and the flow does
  not require the address to be pre-verified: receiving the link is the
  proof). Completing the reset writes an argon2id hash, which clears the flag
  permanently. Accounts with no reachable email/phone are support cases by
  design.
- Email and phone validation/normalization are fixed in AuthKit. Email is
  trimmed/lowercased and must be address-like. Phone numbers must be E.164-like
  (`+` followed by country code and digits).
- Shared helpers are exported from `core`: `ValidateUsername`,
  `OwnerSlugFromUsername`, `ValidatePassword`, `NormalizeEmail`,
  `ValidateEmail`, `NormalizePhone`, `ValidatePhone`, and
  `ValidationErrorCode`.

Two-Factor Authentication (2FA):
- Optional security feature for admin accounts to prevent account takeover if password is leaked.
- Users can enable multiple primary 2FA factors via email, SMS, or TOTP authenticator-app methods.
- When enabled, login requires both password AND a 6-digit second-factor code.
- AuthKit challenges the default factor first and returns `available_factors` so the frontend can let the user choose another enrolled factor.
- Each user gets **10 backup codes** (8-character alphanumeric) for account recovery in case they lose access to their 2FA method. Backup codes are recovery codes, not primary factors.
- **Login flow with 2FA**:
  1. POST `/password/login` with email/password
  2. If 2FA enabled: response has `{"requires_2fa": true, "user_id": "...", "method": "email|sms|totp", "challenge": "...", "default_factor": {...}, "available_factors": [...]}`
  3. User receives the default factor's code, or the frontend posts `/2fa/challenge` with `{user_id, challenge, factor_id}` to start a different factor.
  4. POST `/2fa/verify` with `{"user_id": "...", "challenge": "...", "factor_id": "...", "code": "123456"}` (or `{"user_id": "...", "challenge": "...", "code": "ABC123XY", "backup_code": true}` for backup codes)
  5. Response contains access_token and refresh_token as usual
- **Setup flow**:
  1. GET `/user/2fa` to check enabled factors, default factor, allowed methods, and backup-code count.
  2. POST `/user/2fa` with `{"method": "email"}` to enable email 2FA, `{"method": "sms", "phone_number": "+1..."}` then `{"method": "sms", "phone_number": "+1...", "code": "123456"}` for SMS, or `{"method": "totp"}` then `{"method": "totp", "code": "123456"}` for TOTP. Adding a factor does not delete other enrolled factors. Add `"default": true` while enrolling/confirming to make that factor the default, or later post `{"factor_id":"...","default":true}`.
  3. First enable responses include `backup_codes` array - **show these to user ONCE and tell them to save them**
  4. User can regenerate codes with POST `/user/2fa/backup-codes` (invalidates old codes)
  5. User can delete one factor with `DELETE /user/2fa?factor_id=...` or disable all 2FA with `DELETE /user/2fa`
- Hosts can require 2FA for selected permission-group roles with
  `core.RoleDef{RequiresMFA: true}`. AuthKit rejects assigning or accepting that
  role until the user has account MFA enabled with at least one factor. If the
  user later disables MFA, AuthKit removes those MFA-required user role
  assignments.
- Backup codes are single-use and removed after verification.
- Server-sent 2FA codes expire in **10 minutes**.

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
    `{"error":{"type":"rate_limit_error","code":"rate_limited","message":"Too many requests. Please try again later.","metadata":{"action":"request_email_verification","allowed":false,"reason":"cooldown","retry_after_seconds":N,"next_allowed_at":"...","limit":6,"remaining":5,"window_seconds":3600,"cooldown_seconds":60}}}` — the action-availability fields ride in `error.metadata`.
  - `429` responses also include `Retry-After: N` plus `RateLimit-Limit`, `RateLimit-Remaining`, and `RateLimit-Reset` when the limiter can compute them.
  - **Behind reverse proxies, you must explicitly configure trusted proxies** to safely use `X-Forwarded-For` / `CF-Connecting-IP`. AuthKit will not trust forwarded headers by default (clients can spoof them).
  - For multi-instance production, prefer a Redis/Garnet-backed limiter and a trusted-proxy client IP function, e.g.:
    - `authhttp.WithRateLimiter(redislimiter.New(redis, authhttp.ToRedisLimits(authhttp.DefaultRateLimits())))`
    - `authhttp.WithClientIPFunc(authhttp.ClientIPFromForwardedHeaders(trustedProxyCIDRs))` where `trustedProxyCIDRs` are the CIDRs of your ingress/proxy layer (nginx, cloudflared, etc.).
  - These are constructor options — pass them to `authhttp.NewServer(cfg, pg, ...)`.
  - Hosts that intentionally want the older public-remote-only fail-open behavior can opt in with `authhttp.WithClientIPFunc(authhttp.PublicRemoteAddrClientIP())`.
  - To explicitly opt out of rate limiting: `authhttp.WithoutRateLimiter()`.
- Storage: run the SQL migrations in `authkit/migrations/postgres` (includes `profiles.refresh_sessions`).
- Keys/JWKS: host `/.well-known/jwks.json` using `svc.JWKSHandler()` and rotate keys as needed.

---

AuthKit API route specs, and the `APIHandler()` net/http compatibility handler built from those same specs, are shown relative to the host-selected API mount prefix. With the recommended `/api/v1` mount, `GET /me` is served at `GET /api/v1/me`. Browser OIDC routes are served separately and are usually mounted outside API versioning at `/oidc/*`.
- GET /.well-known/jwks.json
- OIDC:
  - GET /oidc/:provider/login?return_to=/app/path
  - GET /oidc/:provider/callback
  - POST /oidc/:provider/link/start (RouteUser API group, requires auth) -> {auth_url}
- Password:
  - POST /password/login (accepts email, phone, or username in identifier field)
  - POST /email/password/reset/request
  - POST /email/password/reset/confirm ({token, new_password})
- Registration (unified - accepts email or phone in identifier field):
  - POST /register (server auto-detects email vs phone based on format)
    - Success response includes `{ok, username, email, phone_number, discord_username, next_action}`
    - `next_action` is one of `none`, `verify_email`, or `verify_phone`
    - When `next_action` is `none`, the response also includes `{access_token, refresh_token, token_type, expires_in}`
  - Set `RegistrationVerification: none|optional|required` in `core.Config`. AuthKit's
    library interface is this tri-state enum (third-party embedders may legitimately want
    `none` — no verification artifacts at all). See "Registration verification: the
    `AUTH_REQUIRE_VERIFIED_REGISTRATIONS` embedder convention" below for the canonical
    first-party config knob and the graceful no-sender behavior.
  - POST /register/resend-email
  - POST /register/resend-phone
  - Registration resend requests now return `invalid_email` / `invalid_phone_number` for malformed input and `pending_registration_not_found` when no matching pending registration exists.
  - Message delivery failures from the configured sender are surfaced as stable `email_delivery_failed` / `sms_delivery_failed` errors after AuthKit attempts provider submission.

#### Registration verification: the `AUTH_REQUIRE_VERIFIED_REGISTRATIONS` embedder convention

AuthKit's library interface for registration verification is the tri-state enum
`core.RegistrationVerification` (`none` | `optional` | `required`), set on `core.Config`.
The enum is the stable contract: third-party embedders may legitimately want `none`
(create users immediately, no verification artifacts ever).

First-party / canonical embedders, however, expose **one bool knob**, not a tri-state enum,
so new hosts don't re-invent config names (doujins alone has cycled through
`AUTH_VERIFICATION_REQUIRED`, `AUTH_REGISTRATION_VERIFICATION`, and back). The recommended
convention is:

- Config key `auth.require_verified_registrations` / env `AUTH_REQUIRE_VERIFIED_REGISTRATIONS`
- Type: bool, **default `true`**
- Mapping, applied at the app's config boundary:
  - `true`  ⇒ `core.RegistrationVerificationRequired` (verification gates login)
  - `false` ⇒ `core.RegistrationVerificationOptional` (a verification email/SMS is still
    sent on signup when a sender is configured, but never blocks login)

This bool intentionally cannot reach `none`; `none` stays available only via the raw enum
for third-party embedders that want it. (doujins, hentai0, tensorhub, and cozy-art all map
the bool at their config boundary.)

**Graceful degrade under `optional` with no sender.** If the policy is `optional` and no
email/SMS sender is configured, AuthKit does not error and does not leave the user dangling:
it creates the user **already verified** and sends nothing (the core decision is
`verified := s.email == nil` in `CreatePendingRegistrationWithLanguage`). So a host can flip
`AUTH_REQUIRE_VERIFIED_REGISTRATIONS=false` before wiring up a mail provider and registration
keeps working end-to-end. (`required` with no sender is rejected at startup by
`ValidateVerificationConfiguration`.)

- Email verification:
  - POST /email/verify/request
  - POST /email/verify/confirm ({code} or {token})
  - Verification request endpoints return explicit target-state errors: `user_not_found`, `email_already_verified`, or `phone_already_verified`.
- Phone verification and password reset:
  - POST /phone/verify/request
  - POST /phone/verify/confirm ({phone_number, code} or {token})
  - POST /phone/password/reset/request
  - POST /phone/password/reset/confirm ({token, new_password})
- Sessions:
  - POST /token { grant_type: "refresh_token", refresh_token }
  - POST /sessions/current { refresh_token } → { session_id }
  - GET /user/sessions (requires auth)
  - DELETE /user/sessions/:id (requires auth)
  - DELETE /user/sessions (requires auth)
  - DELETE /logout (requires auth; revokes the current session via sid claim)
- User profile:
  - GET /me (requires auth)
  - PATCH /user/username (requires auth)
  - POST /user/email (requires auth)
  - POST /user/phone (requires auth)
  - PATCH /user/biography (requires auth)
  - POST /user/password (requires auth)
  - DELETE /user (requires auth)
  - DELETE /user/providers/:provider (requires auth)
- Two-Factor Authentication (2FA):
  - GET /user/2fa (requires auth) → {enabled, method, default_factor, available_factors, backup_codes_remaining}
  - POST /user/2fa (requires auth) → starts or confirms email/SMS/TOTP enrollment; optional `default: true`; `{factor_id, default:true}` changes the default
  - DELETE /user/2fa (requires auth) → disables all 2FA, or deletes one factor with `factor_id`
  - POST /user/2fa/backup-codes (requires auth) → {backup_codes}
  - POST /2fa/challenge (during login) → starts a selected non-default factor from an existing password challenge
  - POST /2fa/verify (during login) → {access_token, refresh_token}
- Reauth:
  - POST /reauth/password with `{password}` (requires auth) → {access_token, token_type, expires_in, fresh_auth}
  - POST /reauth/2fa with optional `{method:"email|sms|totp"}` starts selected/default 2FA reauth; final `{code, method?, backup_code?}` returns {access_token, token_type, expires_in, fresh_auth}. Reauth is a hard-cut method-name API: it does not accept or return `factor_id`.
  - Reauth does not rotate refresh tokens; clients retry sensitive actions with the returned access token. Refresh-token rotation remains `POST /token`.
- Admin roles (admin only):
  - POST /admin/roles/grant
  - POST /admin/roles/revoke
- Admin users (root permission required):
  - GET /admin/users (`root:users:read`; query supports `root_role` and `status=deleted`)
  - GET /admin/users/:user_id (`root:users:read`)
  - POST /admin/users/ban (`root:users:ban`)
  - POST /admin/users/unban (`root:users:ban`)
  - POST /admin/users/:user_id/recover (`root:users:update`; body has exactly one of `{email}` or `{phone_number}`; revokes sessions, deletes password/provider/2FA factors, replaces the primary recovery identifier, and sends a password-reset request)
  - DELETE /admin/users/:user_id (`root:users:delete`)
  - POST /admin/users/:user_id/restore (`root:users:delete`)
  - GET /admin/users/:user_id/signins (`root:users:read`)
  - POST /admin/users/:user_id/sessions/revoke (`root:sessions:revoke`)
- There is no admin org recovery flow; org routes were removed with the old org plane.
- Public owner-namespace lookup:
  - GET /namespaces/:slug → typed public namespace metadata + per-kind `claimable`
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

-- 2FA verification codes live in Redis/Garnet or the in-memory ephemeral store;
-- no SQL cleanup is needed.
```

Run these from your scheduler (cron, pg_cron, or your job system).

---

Frontend (React) quick guide
- Paths below are relative to the AuthKit API mount. In doujins/hentai0-style hosts mounted at `/api/v1`, call `/api/v1/token`, `/api/v1/me`, `/api/v1/admin/users`, etc.
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
  - POST /email/password/reset/confirm with `{token, new_password}` → {ok: true}
  - POST /phone/password/reset/request with `{phone_number}` → check SMS for reset instructions
  - POST /phone/password/reset/confirm with `{token, new_password}` → {ok: true}
- OIDC
  - Start: window.location = `/oidc/${provider}/login`.
  - Link: POST `/api/v1/oidc/:provider/link/start` (with Authorization) → {auth_url}; then window.location = auth_url.
- Unlink
  - DELETE /user/providers/:provider (Authorization). Guard prevents unlinking the last login method.
- Sessions
  - DELETE /logout (current), DELETE /user/sessions (all), DELETE /user/sessions/:id (single), GET /user/sessions (list).
  - POST /sessions/current with `{refresh_token}` → {session_id}.
- Current user
  - GET /me → {id, email, pending_email?, phone_number?, username, user_aliases?, discord_username?, email_verified, phone_verified, has_password, roles, entitlements, biography, preferred_language?}.
  - Email change
    - POST /user/email with `{new_email,password?}` (Authorization) → sends verification code
    - POST /user/email with `{code}` (Authorization) → confirms email change
  - Phone number change
    - POST /user/phone with `{phone_number,password?}` (Authorization) → sends verification code
    - POST /user/phone with `{phone_number,code}` (Authorization) → confirms phone number change
- User profile updates
  - PATCH /user/username with `{username}` (Authorization)
  - PATCH /user/preferred-language with `{preferred_language}` (Authorization)
  - PATCH /user/biography with `{biography}` (Authorization)
  - POST /user/password with `{old_password, new_password}` (Authorization)
  - DELETE /user (Authorization) → deletes account
  - Sensitive-action `reauth_required` errors include `reauth_methods` and, when 2FA is enabled, `reauth_2fa` with available methods/default method/display-safe destinations. Call `/reauth/password` or `/reauth/2fa`, replace the in-memory access token with the returned `access_token`, then retry. Do not call `/token` just to finish reauth.
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

- Create with `authhttp.NewVerifier(opts...)` — options: `WithSkew`, `WithAlgorithms`, `WithHTTPClient`.
- Add issuers via `verifier.AddIssuer(issuerID, audiences, opts)` — each may specify a JWKS URL (defaults to `/.well-known/jwks.json`), pre-provided PEM keys, or raw `*rsa.PublicKey` maps.
- For service JWTs, call `verifier.VerifyServiceJWT(ctx, token)` or mount
  `authhttp.RequiredServiceJWT(verifier)`. This returns a machine principal with
  issuer, subject, remote-application slug, permissions, resources, and JTI; the
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

SpaceX accepts JWTs from multiple issuers; both tesla.com and x.com.

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

### Remote Application Issuers & Delegated Access JWTs

AuthKit owns the shared identity primitives for federation: a resource service
registers remote applications, verifies their OIDC/JWKS metadata, and accepts
delegated users as `(issuer, delegated_sub)`. Product-specific approval, quota,
billing, and resource policy still belong to the receiving product.

This lets an external system bring principals that live in its own identity
store. Those principals authenticate through the remote application's issuer
rather than local passwords. Two AuthKit-embedding services register with and
trust each other:

- the **platform / IdP** side (e.g. cozy-art) mints delegated tokens and sends
  its remote-application issuer registration;
- the **resource-server** side (e.g. tensorhub) accepts registrations and
  validates delegated tokens.

There are three roles, all owned by AuthKit:

| Role | Side | API |
|---|---|---|
| **register** | both | `RemoteApplicationIssuersClient.RegisterIssuer` (outbound) -> `POST /:persona/:resource_slug/remote-applications` (inbound) |
| **mint** | platform | `MintDelegatedAccessToken(ctx, signer, DelegatedAccessParams)` |
| **validate** | resource server | `Verifier.LoadRemoteApplications` + `Verifier.VerifyDelegatedAccess` -> `Claims.DelegatedAccess()` |

#### Delegated access JWTs

A **delegated access JWT** is AuthKit's standard primitive for federation: one
AuthKit issuer signs a short-lived JWT for an external delegated subject, and a
resource service (OpenRails, Tensorhub, Gen-Orchestrator, ...) accepts it after
issuer/JWKS/audience validation. Mint it with `MintDelegatedAccessToken` /
`DelegatedAccessParams`.

Canonical claim contract:

| Claim | Meaning | Typed accessor |
|---|---|---|
| header `typ=delegated-access+jwt` | identifies a delegated access JWT (`DelegatedAccessTokenType`) | `Claims.TokenTyp` / `IsDelegatedAccessToken()` |
| `iss` | AuthKit issuer that signed the token | `Claims.Issuer` |
| `aud` | target resource API (`openrails`, `tensorhub`, `gen-orchestrator`) | matched at verify |
| `delegated_sub` | issuer-side subject id; no local account is implied | `Claims.DelegatedSubject` |
| `permissions []string` | resource-defined permission strings, not OAuth scope | `Claims.Permissions` / `HasPermission()` |
| `attributes {}` | issuer policy metadata, e.g. `{"tier":"cozy_free"}` | `Claims.Attributes` / `Attribute(key)` |
| `iat`/`exp`/`nbf`/`jti` | standard timing + token id | `Claims.JTI` |

**Hard invariants** (enforced + tested):

- Ordinary AuthKit access JWTs use header `typ=access+jwt`; delegated access
  tokens use header `typ=delegated-access+jwt`. `Verify()` rejects missing,
  unknown, or cross-profile `typ` values.
- A delegated access JWT must not carry a normal `sub`; the receiving service
  authorizes by trusted issuer plus delegated subject, not by a local user row.
- Delegated access JWTs must not carry legacy AuthKit organization claims;
  `Verify()` rejects them (`delegated_access_has_org`,
  `delegated_access_has_org_id`).
- `roles` are not a top-level delegated access JWT claim. Receiving services
  authorize on `permissions` plus explicit `attributes` policy.
- Tier/plan metadata belongs under `attributes.tier`; a top-level `user_tier`
  claim is rejected.
- Remote applications loaded from AuthKit's registry are bound to the permission
  group that registered them; downstream authorization should intersect token
  permissions with that stored authority.

Receiving services can install validation hooks:

```go
v := authhttp.NewVerifier(
    authhttp.WithPermissions(func(perms []string) error { /* check permissions */ }),
    authhttp.WithAttributesPolicy(func(a map[string]json.RawMessage) error { /* check schema */ }),
)
cl, dp, err := v.VerifyDelegatedAccess(token) // requires typ=delegated-access+jwt + runs hooks
// dp.Issuer, dp.DelegatedSubject, dp.Permissions, dp.Attributes, dp.JTI
```

Because a delegated access JWT has no `sub`, the resource server's middleware
skips the local-user gate. Authorization is by issuer trust plus `permissions`,
not local-user existence.

For browser-direct self-service billing, the host app still has one
authenticated AuthKit touchpoint: a current-user token endpoint owned by the
host app. That endpoint authenticates the normal app session, decides which
self-scoped OpenRails permissions the current user may receive, then calls
`MintDelegatedAccessToken` with `aud=openrails`, `delegated_sub` set to the
current user id, short `TTL`, and permissions such as
`openrails:self:billing:read` or `openrails:self:checkout:create`. The browser
then calls OpenRails directly with that delegated access JWT; the host does not
proxy billing reads or checkout/subscription actions.

#### Registration handshake

**Outbound (platform side, e.g. cozy-art)** — publish this remote application's
issuer + JWKS URL to a resource server's accept endpoint:

```go
fc := authhttp.NewRemoteApplicationIssuersClient(
    authhttp.WithRemoteApplicationIssuersAuthToken(ownerAccessToken),
)
err := fc.RegisterIssuer(ctx, "https://tensorhub.example/api/v1/remote-applications",
    authhttp.RemoteApplicationIssuerRegistration{
        Slug:           "cozy-art",
        Issuer:         "https://cozy.art",
        JWKSURI:        "https://cozy.art/.well-known/jwks.json",
        AllowedOrigins: []string{"https://cozy.art"},
    })
```

`AllowedOrigins` is an exact browser-Origin allow-list for delegated browser
requests signed by that issuer. CORS preflight can only use the union of enabled
remote-application origins because it has no JWT; mount
`authhttp.RequireDelegatedOrigin` after `authhttp.Required` to enforce the real
request's `Origin` against the verified token issuer.

**Inbound (resource-server side, e.g. tensorhub)** — use the generated
remote-application management routes. `POST /:persona/:resource_slug/remote-applications`
accepts and stores a registration authorized by the controlling permission
group; `DELETE /:persona/:resource_slug/remote-applications/:app` removes one;
`GET /:persona/:resource_slug/remote-applications` lists that group's apps.

#### In-house JWKS — no external push/sync

The resource server loads registered remote applications from AuthKit's own
store and registers each with the Verifier, whose existing in-house JWKS
fetch/refresh then handles the keys. There is no external key push or sync; the
resource server pulls JWKS from each issuer's URL on demand and refreshes per
`CacheTTL`.

```go
// At startup (and re-run on a ticker / after a registration) to pick up store changes:
err := verifier.LoadRemoteApplications(ctx, coreSvc, []string{"tensorhub"})
```

`LoadRemoteApplications` registers only `enabled` issuers. A newly-accepted
registration is also added to the Verifier immediately by the inbound handler,
so it is usable without waiting for the next store load.
