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
    // OrgMode: "single" (default) | "multi"
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

Coarse policy switches (locked-down hosts)

Route-group selection is the primary host control: a locked-down host should
mount only the `svc.Routes().Groups(...)` subset it intentionally exposes
instead of `DefaultAPI()`. As a defense-in-depth backstop (for hosts that
accidentally mount more than intended), AuthKit also provides two coarse
runtime switches on `core.Config`:

- `PublicRegistrationDisabled` — turns off ALL public user self-registration and
  auto-registration paths. When set, `POST /register`, `/register/availability`,
  `/register/resend-email`, `/register/resend-phone`, OIDC/social/Solana
  auto-create, and pending-registration confirmation all return a stable
  `registration_disabled` error (`/register/availability` reports every field
  as unavailable, never usable). Existing-user authentication is unaffected:
  login, refresh, logout, password reset/recovery, token verification, and
  sessions all keep working. Embedded bootstrap/admin creation through the
  exported core APIs (`CreateUser`, `ImportUser`) still works.
- `PublicOrgManagementDisabled` — denies the public org-facing onboarding and
  management routes (org creation/rename, invites, member changes, role
  changes, OAT management routes) with a stable `org_management_disabled`
  error. Read-only org routes and the org-scoped token exchange (`POST
  /token/org`) stay available for existing members. Embedded core/bootstrap
  code can still ensure the initial orgs, roles, admins, and OATs through the
  exported core APIs (`CreateOrg`, `DefineRole`, `AddMember`, `AssignRole`,
  `MintOrgAccessToken`, ...).

Both default to `false`, preserving current behavior for existing consumers.

Locked-down (e.g. self-hosted OpenRails) pattern: mount only the chosen route
groups, set both switches, and bootstrap through embedded core APIs.

```go
cfg := core.Config{
  // ...issuer/audiences/keys...
  PublicRegistrationDisabled:  true, // no public signup
  PublicOrgManagementDisabled: true, // no public org onboarding/management
}
svc, _ := authhttp.NewService(cfg)

// Mount only the route groups this deployment intentionally exposes:
authkitgin.RegisterAPI(v1, svc, authkitgin.WithRoutes(svc.Routes().Groups(
  authhttp.RouteCore,     // /token, /sessions/current, /logout
  authhttp.RoutePassword, // login + password reset for existing users
  authhttp.RouteUser,     // self-service for existing accounts
)))

// Bootstrap the default tenant/operator org, roles, admin user, and OATs
// internally via the AuthKit core APIs (unaffected by the switches above):
core := svc.Core()
admin, _ := core.CreateUser(ctx, "ops@example.com", "operator")
org, _ := core.CreateOrg(ctx, "operator")
_ = core.DefineRole(ctx, org.Slug, "owner")
_ = core.AddMember(ctx, org.Slug, admin.ID)
_ = core.AssignRole(ctx, org.Slug, admin.ID, "owner")
oat, secret, _ := core.MintOrgAccessToken(ctx, org.Slug, "ci", []string{"*"}, admin.ID, nil)
_ = oat
_ = secret
```

Hosted SaaS deployments can later flip both switches to `false` and mount the
`RouteRegister` / `RouteOrganizations` groups to enable public signup and org
onboarding without code changes.

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

AuthKit can include entitlements (e.g., "premium", "pro") in JWT access tokens if you provide an `EntitlementsProvider`. This is useful for billing/subscription systems where entitlements are stored outside the `profiles` schema.

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
| `RequireVerifiedRegistrations`, `Environment`, `SolanaNetwork`, `OrgMode`, `BaseURL` | Host config | Runtime behavior should be deterministic from config. |
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
  JWKSURL: "https://my-issuer.com/.well-known/jwks.json",
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

Organizations (org_mode)
- AuthKit supports orgs + org-scoped RBAC when `OrgMode: "multi"`:
  - Shared owner namespace: user slugs and org slugs should be treated as one namespace (no collisions).
  - Every user has a personal org (non-transferable ownership) keyed by `owner_user_id`.
  - Users can belong to 0, 1, or many orgs simultaneously.
  - Org slug renames create aliases; handlers accept either current slug or alias on `:org`.
  - Username renames preserve old owner paths via user slug aliases; personal org slug aliases are also retained.
  - Default access tokens do **not** embed org membership or org roles; apps check membership/roles server-side.
  - `GET /user/me` returns `orgs` (membership list) plus org-scoped roles for the user.
  - `GET /user/bootstrap` returns canonical personal org + org memberships in one call.
  - Org-scoped access tokens include `org` + `roles` (single org only), and are rejected when the user is not a member.
    - Mint explicitly: `POST /token/org`
    - Or mint at login/refresh by providing `org` in the request body.
  - Invitation workflow:
    - Org owners create/list/revoke invites with `/orgs/:org/invites`.
    - Users list their invites via `GET /me/invites` (cross-org).
    - Users accept/decline via `/me/invites/:invite_id/accept|decline`.
  - Org management is **permission-based RBAC** (a role = a set of permissions). authkit is the generic engine: it ships **base permissions** in the reserved `org:` namespace (`org:roles:manage`, `org:members:manage`, `org:tokens:manage`, `org:read`) that gate all org-management endpoints, stores per-org role→permission assignments, computes `EffectivePermissions`, and enforces no-escalation + catalog validation. The embedding app declares its own permission catalog (`Config.PermissionCatalog`) + optional default roles (`Config.DefaultRoles`, e.g. an `admin` = `*` minus `{org:roles:manage, org:members:manage}`); effective catalog = base ∪ app. The `owner` role is hardcoded and seeded with `*` (all), protected, and cannot be removed as the last owner. Permissions are opaque to authkit — the app owns their meaning and enforces them at its own endpoints via `core.EffectivePermissions`. Introspection endpoints complement the management API: `GET /orgs/:org/me` (self-read of `{roles, permissions}`, membership only — no `org:read`) and `POST /orgs/:org/permissions/check` (a `testIamPermissions`-style "does this principal hold X?" → `{granted[]}`). Roles are RESTful resources: `GET /orgs/:org/roles/:role` (detail), `PUT /orgs/:org/roles/:role` (idempotent create-or-replace, body `{permissions[]}`), `DELETE /orgs/:org/roles/:role`; members likewise (`DELETE /orgs/:org/members/:user_id`). Invitee self-routes live at top-level `/me/invites` (cross-org — the invitee isn't a member yet).
- In `OrgMode: "single"` (default), AuthKit behaves like a single-tenant app:
  - Access tokens include `roles` (string[]) and there are no org-related claims/fields.

Organization Access Tokens (OATs)
- Long-lived, revocable bearer credentials **owned by an org** (not a person), for machine/automation callers (CI, operator CLIs, service-to-service). The standard machine-auth primitive (cf. Docker Hub OATs, Stripe `sk_` keys) — robots should not replay the human password-login path.
- An OAT acts **as the org**: middleware sets `Claims.Org` + `Claims.Permissions` (the token's app-defined permission strings) and a service marker (`Claims.IsService()`), leaving `UserID` empty — so the live-user ban/enrichment gate is skipped. Permissions are opaque to authkit; the embedding app owns the vocabulary and enforces meaning. (Users carry `OrgRoles`; the resource server expands role→permission at request time.)
- Presented as `Authorization: Bearer <app>oat_<key_id>_<secret>`, where `<app>` is the host-configured `Config.TokenPrefix` brand (e.g. `cozy` → `cozy_oat_…`; empty → bare `oat_`). `key_id` is a non-secret public id for O(1) indexed lookup; only `sha256(secret)` is stored; the full token is shown **once**.
- Resolved in the `Required`/`Optional` middleware *before* JWT verification (constant-time secret compare; revoked/expired/org-deleted rejected; non-OAT tokens fall through to JWT). The OAT path is separate from the password-login handler, so OATs **bypass the interactive password-login rate limiter** by design.
- **Mint authorization is native + permission-based:** minting requires `org:tokens:manage`, and authkit validates the requested permissions against the org's effective catalog — each must be a defined permission the caller holds (no escalation; `403 permission_grant_denied`/`400 unknown_permission`), with the reserved write/mint perms (`org:roles:manage`, `org:members:manage`, `org:tokens:manage`) and wildcards barred from OATs (read-only `org:read` is OAT-grantable). Permissions are frozen at mint time. An OAT can never mint/list/revoke OATs (no user). See "Org RBAC" below for the catalog + role→permission model.
- Manage via `POST/GET/DELETE /orgs/:org/access-tokens[/:token_id]`. Optional `expires_at` (null = non-expiring), capped by `Config.OrgAccessTokenMaxTTL` when set. Stored in `profiles.org_access_tokens`.
- **Leak response:** revoke the token (`DELETE …/access-tokens/:id`) — the `<app>oat_` prefix is registrable with secret-scanning/push-protection partners so leaked tokens can be auto-detected.

Reserved slug policy
- Owner namespaces use explicit states:
  - `restricted_name`: slug is blocked in `profiles.owner_reserved_names` and not publicly registrable.
  - `parked_org`: org exists and is platform-held (`metadata.namespace_state=parked_org`, `metadata.reserved=true`).
  - `registered_org`: normal org lifecycle (`metadata.namespace_state=registered_org`).
- Public lookup endpoint: `GET /owners/{slug}` returns canonical public metadata for the slug:
  - `requested_slug`: normalized slug from the request.
  - `slug` / `canonical_slug`: current canonical slug when the request resolves to a live or held owner; otherwise the requested slug.
  - `status` / `state`: `registered_user`, `registered_org`, `parked_user`, `parked_org`, `restricted_name`, `renamed_user`, `renamed_org`, `held_by_deleted_user`, `held_by_deleted_org`, `held_by_recent_user_rename`, `held_by_recent_org_rename`, or `unregistered`.
  - `claimable`: whether the slug can currently be claimed by a new user/org.
  - `renamed`: whether this lookup resolved through rename history.
  - `hold_until`: present for active rename reuse holds.
  - `entity_kind`: `none`, `org`, `user`, or `org_and_user`
  - optional `org` and/or `user` payloads when records exist.
- The PostgreSQL baseline schema creates `profiles.owner_reserved_names` and seeds canonical restricted names (`admin`, `superuser`, `root`, `sudo`) directly.
- Public register/create/rename/org-create/org-rename paths do not use a hardcoded denylist; conflicts are enforced through owner-namespace uniqueness plus reserved-name table checks.
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
- Username namespace checks reject collisions with users/orgs, renamed or
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
  1. GET `/user/2fa` to check current status
  2. POST `/user/2fa/enable` with `{"method": "email"}` or `{"method": "sms", "phone_number": "+1..."}`
  3. Response includes `backup_codes` array - **show these to user ONCE and tell them to save them**
  4. User can regenerate codes with POST `/user/2fa/regenerate-codes` (invalidates old codes)
  5. User can disable with POST `/user/2fa/disable`
- Backup codes are single-use and removed after verification.
- 2FA codes expire in **15 minutes**.

Operation:
- Key rotation is outside the scope of this library and should be handled by your infrastructure (e.g., External Secrets Operator updating mounted secrets, then restarting pods).
- To rotate keys manually: add the new public key to the map under a new kid, switch the active signer, leave the old pub in the map until tokens expire, then remove it.
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
  - POST /admin/account/park (`{kind:"org"|"user",slug}`)
  - POST /admin/account/claim (`{kind:"org"|"user",slug,...}`; for `kind:"org"`, `owner_user_id` is required)
- Public owner-namespace lookup:
  - GET /owners/:slug → canonical owner metadata + `status`/`claimable`
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

Use the verifier when a service needs to accept access tokens issued by one or more
AuthKit‑powered APIs (e.g., spacex), without mounting any auth routes.

- Create with `authhttp.NewVerifier(opts...)` — options: `WithSkew`, `WithAlgorithms`, `WithHTTPClient`, `WithOrgMode`.
- Add issuers via `verifier.AddIssuer(issuerID, audiences, opts)` — each may specify a JWKS URL (defaults to `/.well-known/jwks.json`), pre-provided PEM keys, or raw `*rsa.PublicKey` maps.
- Default skew: 60s. Default algorithms: RS256.
- DB enrichment (recommended):
  - Call `verifier.WithService(coreSvc)` to enable best-effort
    DB enrichment hooks (roles + canonical email + provider usernames) when
    the token lacks those claims.

---

### Accepting Tokens From Multiple Issuers

SpaceX accepts access tokens from multiple issuers; both tesla.com and x.com.

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

### Federated Orgs & Platform Delegation

AuthKit owns the full platform-delegation lifecycle so an **org can bring in
federated users** — users who live in the org's own system and authenticate via
the org's **issuer** rather than local passwords. Two AuthKit-embedding services
register with and trust each other:

- the **platform / IdP** side (e.g. cozy-art) **mints** delegated tokens and
  **sends** its registration;
- the **resource-server** side (e.g. tensorhub) **accepts** registrations and
  **validates** the delegated tokens.

There are three roles, all owned by AuthKit:

| Role | Side | API |
|---|---|---|
| **register** | both | `FederationClient.RegisterIssuer` (outbound) → `POST /federated-issuers` (inbound) |
| **mint** | platform | `MintDelegatedToken(ctx, signer, DelegatedTokenParams)` |
| **validate** | resource server | `Verifier.LoadFederatedIssuers` + `Verifier.Verify` → `Claims.Delegated()` |

#### The delegated-token contract

A delegated platform token is signed by the org's platform issuer key and
carries:

- `delegated_sub` — the **federated user id**. A delegated token **never** sets
  `sub`. The invariant is: a token carries EITHER `sub` (native user) **XOR**
  `delegated_sub` (federated user), never both. AuthKit refuses to mint both,
  and `Verify()` rejects any token presenting both (`conflicting_subject`).
- `org` / `tenant` — the federated org slug. `Claims.Tenant` reads `tenant`,
  falling back to `org`.
- `user_tier` — the platform's tier for this user (`Claims.UserTier`).
- `roles` — platform-scoped roles for the federated user.
- `aud` — the resource servers this token targets.
- `exp` — expiry (defaults to 15m).

Because a delegated token has no `sub`, the resource server's middleware
**skips the local-user gate** (no `user_disabled` lookup) — authorization is by
issuer/tenant trust, not local-user existence. Validated delegated tokens are
read via:

```go
cl, _ := verifier.Verify(token)
if dp, ok := cl.Delegated(); ok {
    // dp.Tenant, dp.DelegatedSubject, dp.UserTier, dp.Roles, dp.Issuer
}
```

#### Registration handshake (both sides)

**Outbound (platform side, e.g. cozy-art)** — publish this org's issuer +
JWKS URL to a resource server's accept endpoint:

```go
fc := authhttp.NewFederationClient(
    authhttp.WithFederationAuthToken(ownerAccessToken), // org owner/admin token
)
err := fc.RegisterIssuer(ctx, "https://tensorhub.example/api/v1/federated-issuers",
    authhttp.FederationRegistration{
        Org:      "cozy-art",
        IssuerID: "https://cozy.art",
        JWKSURL:  "https://cozy.art/.well-known/jwks.json",
    })
```

**Inbound (resource-server side, e.g. tensorhub)** — mount the `RouteFederation`
group. `POST /federated-issuers` accepts + stores a registration, authorized by
the **org owner/admin** of the registering org (global admins may register for
any org); `DELETE /federated-issuers` removes one; `GET /federated-issuers`
(global-admin) lists them. This is the AuthKit-owned home for what services used
to expose as a bespoke `/api/v1/platform/issuers` endpoint.

#### In-house JWKS — no external push/sync

The resource server loads registered federated issuers from AuthKit's **own
store** (the `profiles.federated_org_issuers` table) and registers each with the
Verifier, whose existing in-house JWKS fetch/refresh then handles the keys.
There is **no external key push or sync** — the resource server pulls JWKS from
each issuer's URL on demand and refreshes per `CacheTTL`.

```go
// At startup (and re-run on a ticker / after a registration) to pick up store changes:
err := verifier.LoadFederatedIssuers(ctx, coreSvc /* or any FederatedIssuerSource */, []string{"tensorhub"})
```

`LoadFederatedIssuers` registers only `active` issuers. A newly-accepted
registration is also added to the Verifier immediately by the inbound handler,
so it is usable without waiting for the next store load.
