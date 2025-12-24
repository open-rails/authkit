### AuthKit

Lightweight auth library for Go services.

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

Migrations
- Postgres SQL migrations live in `migrations/postgres/` and are embedded via `go:embed`.
- Import `github.com/PaulFidika/authkit/migrations/postgres` and register `Migrations` with your runner, or use `FS`.

---

Quick Start (Gin)

- Setup keys and service

```go
  package main

  import (
      "crypto/rsa"
      "time"

      core "github.com/PaulFidika/authkit/core"
      authgin "github.com/PaulFidika/authkit/adapters/gin"
      oidckit "github.com/PaulFidika/authkit/oidc"
      jwtkit "github.com/PaulFidika/authkit/jwt"
      smstwilio "github.com/PaulFidika/authkit/adapters/sms"
      // In dev, AuthKit logs codes to stdout if no email/SMS senders are configured
      "github.com/gin-gonic/gin"
      // plus your postgres package; Redis/Garnet recommended for ephemeral auth state
      "os"
  )

  func main() {
      // 1) Minimal config (like go-pkgz/auth)
      signer, _ := jwtkit.NewRSASigner(2048, "kid-1")
      // Load configuration from your app (config file, env vars, etc.)
      authCfg := core.Config{
          Keys:             jwtkit.StaticKeySource{Active: signer, Pubs: map[string]*rsa.PublicKey{"kid-1": signer.PublicKey()}},
          AccessTokenDuration:  time.Hour,
          RefreshTokenDuration: 14*24*time.Hour,
          Issuer:           cfg.Auth.Issuer,           // e.g., "https://myapp.com"
          IssuedAudiences:  cfg.Auth.IssuedAudiences,  // e.g., []string{"myapp", "spacex-app"}
          ExpectedAudience: cfg.Auth.ExpectedAudience, // e.g., "myapp"
          BaseURL:          cfg.Auth.BaseURL,          // Used to build reset/verify links in emails
          // Identity providers by name (OIDC or OAuth2). Only client id/secret required.
          // Apple can use a dynamic client_secret minted per request via ES256.
          Providers:    map[string]oidckit.RPConfig{
              "google":       {ClientID: cfg.OAuth.Google.ClientID, ClientSecret: cfg.OAuth.Google.ClientSecret},
              // Discord uses OAuth2 (no OIDC discovery). Scopes typically: identify, email.
              "discord":      {ClientID: cfg.OAuth.Discord.ClientID, ClientSecret: cfg.OAuth.Discord.ClientSecret, Scopes: []string{"identify","email"}},
              "apple":        oidckit.AppleWithKey(cfg.OAuth.Apple.TeamID, cfg.OAuth.Apple.KeyID, []byte(cfg.OAuth.Apple.PrivateKeyP8), cfg.OAuth.Apple.ClientID, 5*time.Minute),
          },
      }

      // 2) Gin setup and route mounting
      r := gin.Default()

      // pg: *pgxpool.Pool
      // redisClient (optional): *redis.Client – used for OIDC state cache and rate limiting

      // Optional: Implement your own email sender for email-based auth (codes + welcome emails)
      // Must implement core.EmailSender interface with methods:
      //   - SendPasswordResetCode(ctx, email, username, code) - AuthKit looks up user data
      //   - SendEmailVerificationCode(ctx, email, username, code) - no user exists yet
      //   - SendLoginCode(ctx, email, username, code) - 2FA login code, AuthKit looks up user data
      //   - SendWelcome(ctx, email, username) - AuthKit looks up user data
      var emailSender core.EmailSender = ... // your custom implementation

      // Optional: Twilio Verify SMS sender for phone-based auth
      // Load these from your app's config (not environment variables directly)
      twilioSMS := smstwilio.New(
          cfg.Twilio.AccountSID,
          cfg.Twilio.AuthToken,
          cfg.Twilio.VerifyServiceSID,
          cfg.AppName, // App name shown in SMS (e.g., "MyApp Login")
      )

      svc := authgin.NewService(authCfg).
          WithPostgres(pg).
          WithRedis(redisClient).
          WithEmailSender(emailSender).
          WithSMSSender(twilioSMS).
          WithSolanaDomain("myapp.com") // Optional: for SIWS sign-in messages

      // Split registration: JWKS at root, browser flows at /auth, JSON API under /api/v1
      api := r.Group("/api/v1")
      svc.GinRegisterJWKS(r)
      svc.GinRegisterOIDC(r)  // /auth/oidc/* and /auth/oauth/discord/*
      svc.GinRegisterAPI(api)

      // 3) Middleware: construct from Service
      auth := authgin.MiddlewareFromSVC(svc)

      // Decodes user claims from JWT and attaches them to the context
      api.Use(auth.Optional())

      // (1) Reads user info from JWT claims (no database lookup)
      api.GET("/claims", func(c *gin.Context) {
        if u, ok := authgin.CurrentUser(c); ok { c.JSON(200, u); return }
        c.AbortWithStatus(401)
      })

      // (2) Extra middleware looks up user info from DB, which overwrites user JWT claims
      api.GET("/my-info",
        authgin.LookupDBUser(pg),
        func(c *gin.Context) {
          if u, ok := authgin.CurrentUser(c); ok { c.JSON(200, u); return }
          c.AbortWithStatus(401)
        },
      )

      // (3) Restrict based on role (admin and discord examples)
      api.GET("/admin/dashboard", auth.RequireAdmin(pg), func(c *gin.Context) {
        c.JSON(200, gin.H{"ok": true})
      })

      api.GET("/discord", auth.RequireRole("discord"), func(c *gin.Context) {
        c.JSON(200, gin.H{"ok": true})
      })

      // (4) Require auth for a sub-group
      protected := api.Group("/protected").Use(auth.Required())
      protected.GET("/hello", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

      // (5) Restrict based on entitlement
      premium := api.Group("/premium").Use(auth.RequireEntitlement("premium"))
      premium.GET("/area", func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) })

      // Fresh entitlement check (bypass JWT claim) using DB-backed user context
      api.GET("/billing/status",
        auth.Required(),
        authgin.LookupDBUser(pg),
        func(c *gin.Context) {
          if u, ok := authgin.CurrentUser(c); ok {
            c.JSON(200, gin.H{"entitlements": u.Entitlements})
            return
          }
          c.AbortWithStatus(401)
        },
      )

  // Run server
  r.Run(":8080")
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

    entpg "github.com/PaulFidika/authkit/entitlements"
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
svc := authgin.NewService(cfg).
    WithPostgres(pg).
    WithEntitlements(&BillingEntitlementsProvider{pg: pg})
```

Entitlements are snapshotted into the JWT at token issuance time. For fresh entitlements, re-issue the token.

---

Concepts: Service vs Middleware (concise)

- Service (issuer + storage)
  - When you want to issue and manage tokens and sessions: IssueAccessToken, IssueRefreshSession, ExchangeRefreshToken (rotation, reuse detection, session limits/eviction).
  - When you need password/OIDC sign‑in and email flows: password login, reset, email verify, OIDC link/callback.
  - When you need DB‑backed, always‑fresh roles/entitlements in middleware and handlers.
  - When you host your own JWKS (`/.well-known/jwks.json`) for consumers to verify your tokens.
  - Construct with `authgin.NewService(cfg)`, wire deps (`WithPostgres/WithRedis/WithEmailSender/WithSMSSender/WithEntitlements`), then register: `GinRegisterJWKS`, `GinRegisterOIDC`, `GinRegisterAPI`.

- Middleware (verify and/or enrich on requests)
  - Gate (auth): validates the access token on requests (Required/Optional/RequireRole/RequireEntitlement/RequireAdmin).
    - Full issuer: `auth := authgin.MiddlewareFromSVC(svc)`.
    - Verify‑only: `auth := authgin.MiddlewareFromConfig(accept)`.
  - Enricher (user context): computes `UserContext` (roles, entitlements, email, language) and attaches it to Gin context.
    - DB‑backed: `r.Use(authgin.LookupDBUser(pg))`.
  - Compose the two in order so tokens are verified once, then enriched.

---

Notes
- No extra app code needed for OIDC state or user linking — handled internally with Redis (if provided) or a built-in in-memory cache, plus the default resolver.
- Apple: prefer `oidckit.AppleWithKey(...)` which mints a fresh ES256 client_secret JWT per request; no manual rotation needed.

Admin Gate (DB-backed)
- Use `auth.RequireAdmin(pg)` to strictly enforce admin access using the database.
- It verifies the JWT, extracts `user_id`, and checks `profiles.user_roles` joined to `profiles.roles` for slug `admin`.
- Example:

```go
  // Verify-only wiring
  auth := authgin.MiddlewareFromConfig(accept)
  r := gin.Default()

  // Admin route guarded by DB check (no need to attach full user context)
  r.GET("/admin/reports/monthly", auth.RequireAdmin(pg), func(c *gin.Context) {
    c.JSON(200, gin.H{"ok": true})
  })
```

Verification Codes:
- All verification flows (email/phone registration, password reset, email verification) use **6-digit numeric codes** (000000-999999).
- Codes expire in **15 minutes** for better security.
- Email codes are sent via email (e.g., `123456`), SMS codes via Twilio Verify API (e.g., `789012`).
- Frontend should POST the code to the appropriate confirm endpoint:
  - Email password reset: `/auth/password/reset/confirm` with `{"code": "123456", "new_password": "..."}`
  - Email verification: `/auth/email/verify/confirm` with `{"code": "123456"}`
  - Phone registration: `/auth/phone/verify/confirm` with `{"phone_number": "+1...", "code": "789012"}`
  - Phone password reset: `/auth/phone/password/reset/confirm` with `{"phone_number": "+1...", "code": "456789", "new_password": "..."}`
- Your API can live under a prefix (e.g., `/api/v1`); configure this when registering routes with `GinRegisterAPI(api)`.

Two-Factor Authentication (2FA):
- Optional security feature for admin accounts to prevent account takeover if password is leaked.
- Users can enable 2FA via email or SMS methods.
- When enabled, login requires both password AND a 6-digit code sent via email/SMS.
- Each user gets **10 backup codes** (8-character alphanumeric) for account recovery in case they lose access to their 2FA method.
- **Login flow with 2FA**:
  1. POST `/auth/password/login` with email/password
  2. If 2FA enabled: response has `{"requires_2fa": true, "user_id": "...", "method": "email|sms", "verification_id": "..."}`
  3. User receives 6-digit code via email or SMS
  4. POST `/auth/2fa/verify` with `{"user_id": "...", "code": "123456"}` (or `{"user_id": "...", "code": "ABC123XY", "backup_code": true}` for backup codes)
  5. Response contains access_token and refresh_token as usual
- **Setup flow**:
  1. GET `/auth/user/2fa` to check current status
  2. POST `/auth/user/2fa/enable` with `{"method": "email"}` or `{"method": "sms", "phone_number": "+1..."}`
  3. Response includes `backup_codes` array - **show these to user ONCE and tell them to save them**
  4. User can regenerate codes with POST `/auth/user/2fa/regenerate-codes` (invalidates old codes)
  5. User can disable with POST `/auth/user/2fa/disable`
- Backup codes are single-use and removed after verification.
- 2FA codes expire in **15 minutes**.

Operation:
- Key rotation is outside the scope of this library and should be handled by your infrastructure (e.g., External Secrets Operator updating mounted secrets, then restarting pods).
- To rotate keys manually: add the new public key to the map under a new kid, switch the active signer, leave the old pub in the map until tokens expire, then remove it.
- For local development, AuthKit auto-generates keys in `.runtime/authkit/` (disabled in production).

Integration requirements (API server)
- Ephemeral auth state (verification codes, resets, SIWS challenges) uses Redis/Garnet when provided; in dev it falls back to memory.
- In production, a Redis-compatible store is required.
- Rate limiting: if you provide Redis via `WithRedis`, AuthKit enables a default Redis-backed rate limiter automatically.
  - Keys: `auth:<bucket>:ip:<client-ip>`; errors fail-open (request allowed).
  - Buckets include: `auth_token`, `auth_logout`, `auth_sessions_current`, `auth_oidc_start`, `auth_oidc_callback`,
    `auth_password_login`, `auth_pwd_reset_request`, `auth_pwd_reset_confirm`, `auth_user_*`, and `auth_admin_*`.
  - These are set to sensible defaults and are not configurable.
- Storage: run the SQL migrations in `authkit/migrations/postgres` (includes `profiles.refresh_sessions`).
- Keys/JWKS: host `/.well-known/jwks.json` from `authgin.RegisterGin` and rotate keys as needed.

---

Endpoints mounted automatically:
- GET /.well-known/jwks.json
- OIDC:
  - GET /auth/oidc/:provider/login
  - GET /auth/oidc/:provider/callback
  - POST /auth/oidc/:provider/link/start (requires auth) → {auth_url}
  - GET /auth/oauth/discord/login (if Discord provider configured)
  - GET /auth/oauth/discord/callback (if Discord provider configured)
  - POST /auth/oauth/discord/link/start (if Discord provider configured, requires auth)
- Password:
  - POST /auth/password/login (accepts email, phone, or username in identifier field)
  - POST /auth/password/reset/request (accepts email or phone in identifier field)
  - POST /auth/password/reset/confirm (code + optional identifier)
- Registration (unified - accepts email or phone in identifier field):
  - POST /auth/register (server auto-detects email vs phone based on format)
  - POST /auth/register/resend-email
  - POST /auth/register/resend-phone
- Email verification:
  - POST /auth/email/verify/request
  - POST /auth/email/verify/confirm
- Phone verification and password reset:
  - POST /auth/phone/verify/confirm
  - POST /auth/phone/password/reset/request
  - POST /auth/phone/password/reset/confirm
- Sessions:
  - POST /auth/token { grant_type: "refresh_token", refresh_token }
  - POST /auth/sessions/current { refresh_token } → { session_id }
  - GET /auth/user/sessions (requires auth)
  - DELETE /auth/user/sessions/:id (requires auth)
  - DELETE /auth/user/sessions (requires auth)
  - DELETE /auth/logout (requires auth; revokes the current session via sid claim)
- User profile:
  - GET /auth/user/me (requires auth)
  - PATCH /auth/user/username (requires auth)
  - POST /auth/user/email/change/request (requires auth)
  - POST /auth/user/email/change/confirm (requires auth)
  - POST /auth/user/email/change/resend (requires auth)
  - PATCH /auth/user/biography (requires auth)
  - POST /auth/user/password (requires auth)
  - DELETE /auth/user (requires auth)
  - DELETE /auth/user/providers/:provider (requires auth)
- Two-Factor Authentication (2FA):
  - GET /auth/user/2fa (requires auth) → {enabled, method, phone_number}
  - POST /auth/user/2fa/start-phone (requires auth) → starts phone 2FA setup, sends code to phone
  - POST /auth/user/2fa/enable (requires auth) →  → {enabled, method, backup_codes}
  - POST /auth/user/2fa/disable (requires auth)
  - POST /auth/user/2fa/regenerate-codes (requires auth) → {backup_codes}
  - POST /auth/2fa/verify (during login) → {access_token, refresh_token}
- Admin roles (admin only):
  - POST /auth/admin/roles/grant
  - POST /auth/admin/roles/revoke
- Admin users (admin only):
  - GET /auth/admin/users
  - GET /auth/admin/users/:user_id
  - POST /auth/admin/users/ban
  - POST /auth/admin/users/unban
  - POST /auth/admin/users/set-email
  - POST /auth/admin/users/set-username
  - DELETE /auth/admin/users/:user_id
  - GET /auth/admin/users/:user_id/signins
- Solana wallet authentication (SIWS):
  - POST /auth/solana/challenge → {domain, address, nonce, issuedAt, expirationTime, ...}
  - POST /auth/solana/login → {access_token, refresh_token, user}
  - POST /auth/solana/link (requires auth) → {success, solana_address}

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
- Tokens
  - Store access_token in memory and refresh_token in IndexedDB/secure storage.
  - Add Authorization: Bearer <access_token> to protected API calls. On 401, call POST /auth/token with refresh_token, then retry.
- Registration (unified)
  - POST /auth/register with `{identifier, username, password}` where identifier is email or phone
  - Email registration: check email for 6-char code → POST /auth/email/verify/confirm with `{code}`
  - Phone registration: check SMS for 6-char code → POST /auth/phone/verify/confirm with `{phone_number, code}`
  - Resend codes: POST /auth/register/resend-email or POST /auth/register/resend-phone
- Password Login
  - POST /auth/password/login with `{login, password}` where login can be email/phone/username → {id_token, refresh_token}
- Password Reset (Unified - supports both email and phone)
  - POST /auth/password/reset/request with `{identifier}` → check email/SMS for code
  - POST /auth/password/reset/confirm with `{code, new_password, identifier?}` → {ok: true}
    - `identifier` is optional for email resets, required for phone resets
  - Legacy phone endpoints still available: `/auth/phone/password/reset/*`
- OIDC
  - Start: window.location = `/auth/oidc/${provider}/login`.
  - Link: POST /auth/oidc/:provider/link/start (with Authorization) → {auth_url}; then window.location = auth_url.
  - Discord: Use `/auth/oauth/discord/login` and `/auth/oauth/discord/link/start` for Discord OAuth2.
- Unlink
  - DELETE /auth/user/providers/:provider (Authorization). Guard prevents unlinking the last login method.
- Sessions
  - DELETE /auth/logout (current), DELETE /auth/user/sessions (all), DELETE /auth/user/sessions/:id (single), GET /auth/user/sessions (list).
  - POST /auth/sessions/current with `{refresh_token}` → {session_id}.
- Current user
  - GET /auth/user/me → {id, email, pending_email?, phone_number?, username, discord_username?, email_verified, phone_verified, has_password, roles, entitlements, biography}.
  - Email change
    - POST /auth/user/email/change/request with `{email}` (Authorization) → sends verification code
    - POST /auth/user/email/change/confirm with `{code}` (Authorization) → confirms email change
    - POST /auth/user/email/change/resend (Authorization) → resends verification code
  - Phone number change
    - POST /auth/user/phone/change/request with `{phone_number}` (Authorization) → sends verification code
    - POST /auth/user/phone/change/confirm with `{code}` (Authorization) → confirms phone number change
    - POST /auth/user/phone/change/resend (Authorization) → resends verification code
- User profile updates
  - PATCH /auth/user/username with `{username}` (Authorization)
  - PATCH /auth/user/biography with `{biography}` (Authorization)
  - POST /auth/user/password with `{old_password, new_password}` (Authorization)
  - DELETE /auth/user (Authorization) → deletes account
- Solana Wallet (SIWS)
  - Login/Register: POST /auth/solana/challenge → wallet.signIn(input) → POST /auth/solana/login
  - Link wallet: POST /auth/solana/challenge → wallet.signIn(input) → POST /auth/solana/link (with Authorization)

---

### Solana Wallet Authentication (SIWS)

Sign In With Solana allows users to authenticate using their Solana wallet (Phantom, Solflare, Backpack, etc.).
Users can create accounts with just a wallet (no email/password required) or link a wallet to an existing account.

**Frontend Integration (React/TypeScript):**

```typescript
import { useWallet } from '@solana/wallet-adapter-react';

// 1. Request challenge from backend
const requestChallenge = async (address: string, username?: string) => {
  const response = await fetch('/api/v1/auth/solana/challenge', {
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
  const response = await fetch('/api/v1/auth/solana/login', {
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
  const response = await fetch('/api/v1/auth/solana/link', {
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
- Users can change their username later via `PATCH /auth/user/username`
- Wallet address is stored as a provider link (like Google/Discord) in `profiles.user_providers`
- One wallet per user, one user per wallet

---

### Verifier (JWKS, verify‑only)

Use the verifier when a service needs to accept access tokens issued by one or more
AuthKit‑powered APIs (e.g., spacex), without mounting any auth routes.

- AcceptConfig:
  - Issuers: list of issuers you accept; each may specify allowed audiences and an optional JWKS URL (defaults to `/.well-known/jwks.json`).
  - Skew: allowed clock drift for exp/nbf (default ~60s).
  - Algorithms: allow‑list of JWS algs (defaults to RS256).
- DB enrichment (recommended):
  - Call `NewVerifier(...).WithService(svc)` to enrich requests from the database
    after verification. This sets roles and canonical email from `profiles.*`
    (not from JWT claims), matching the behavior of the standard middleware.
  - For language/entitlements/provider usernames, also attach
    `LookupDBUser(pg)`.

---

### Accepting Tokens From Multiple Issuers

SpaceX accepts access tokens from multiple issuers; both tesla.com and x.com.

```go

  import (
    core "github.com/PaulFidika/authkit/core"
    authgin "github.com/PaulFidika/authkit/adapters/gin"
    "github.com/gin-gonic/gin"
    "time"
  )

  func main() {
    accept := core.AcceptConfig{
      Issuers: []core.IssuerAccept{
        { Issuer: "https://tesla.com", Audience: "spacex-app" },
        { Issuer: "https://x.com", Audience: "spacex-app" },
      },
      Skew: 60 * time.Second,
    }

    // Minimal, verify-only middleware; add DB enrichment per-route with LookupDBUser(pg).
    auth := authgin.MiddlewareFromConfig(accept)

    r := gin.Default()
    r.Use(auth.Optional())

    // (1) Claims-only: just check JWT (no DB). 401 if missing/invalid.
    r.GET("/claims-only", func(c *gin.Context) {
      if u, ok := authgin.CurrentUser(c); ok { c.JSON(200, u); return }
      c.AbortWithStatus(401)
    })

    // (2) DB-enhanced: enrich from Postgres, then read claims/user info.
    r.GET("/me-db",
      auth.Required(),              // must be logged in
      authgin.LookupDBUser(pg),     // overwrite/augment from DB in one query
      func(c *gin.Context) {
        if u, ok := authgin.CurrentUser(c); ok { c.JSON(200, u); return }
        c.AbortWithStatus(401)
      },
    )

    // (3) Require login (no DB): gate only.
    r.GET("/auth-required",
      auth.Required(),
      func(c *gin.Context) {
        if u, ok := authgin.CurrentUser(c); ok { c.JSON(200, gin.H{"user": u.UserID}); return }
        c.AbortWithStatus(401)
      },
    )

    // (4) Admin-only: require login, then check admin role directly via DB.
    r.GET("/admin/report",
      auth.RequireAdmin(pg),
      func(c *gin.Context) { c.JSON(200, gin.H{"ok": true}) },
    )
  }
```
