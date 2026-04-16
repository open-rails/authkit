### AuthKit

Lightweight auth library for Go services.

Note: This repo ships only the `net/http` adapter (`adapters/http`). The old Gin adapter has been removed (breaking change); bump your module version/tag accordingly when releasing.

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
- Import `github.com/open-rails/authkit/migrations/postgres` and register `Migrations` with your runner, or use `FS`.

---

Quick Start (net/http)

```go
package main

import (
  "net/http"

  authhttp "github.com/open-rails/authkit/adapters/http"
  core "github.com/open-rails/authkit/core"
)

func main() {
  // Build core.Config from your app config.
  cfg := core.Config{
    Issuer:            "https://myapp.com",
    IssuedAudiences:   []string{"myapp"},
    ExpectedAudiences: []string{"myapp"},
    BaseURL:           "https://myapp.com",
    // RegistrationVerification: core.RegistrationVerificationRequired, // none|optional|required
    // OrgMode: "single" (default) | "multi"
    // Keys: nil => auto-discovery in AuthKit (env/fs/dev fallback)
  }

  svc, _ := authhttp.NewService(cfg)
  // svc = svc.WithPostgres(pg).WithRedis(redis).WithEmailSender(email).WithSMSSender(sms)...

  mux := http.NewServeMux()
  mux.Handle("/.well-known/jwks.json", svc.JWKSHandler())

  // Browser flows (redirect/popup): /oidc/*
  mux.Handle("/oidc/", svc.OIDCHandler())

  // JSON API: mount under a prefix (example: /api/v1/auth/*).
  mux.Handle("/api/v1/", http.StripPrefix("/api/v1", svc.APIHandler()))

  http.ListenAndServe(":8080", mux)
}
```

Optional Twilio adapters
- Core is provider-agnostic and only depends on `core.EmailSender` / `core.SMSSender`.
- Optional convenience adapters are available:
  - `github.com/open-rails/authkit/adapters/email` (`emailtwilio`) for Twilio Email API (SendGrid endpoint).
  - `github.com/open-rails/authkit/adapters/sms` (`smstwilio`) for Twilio Messaging API.
- The SMS adapter requires `AccountSID`, `AuthToken`, and `MessagingServiceSID`. There is no `From` number fallback path.

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
- Middleware: `adapters/http` provides `Required`/`Optional` (JWT verification) plus helpers like `RequireAdmin(pg)`.
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
- Apple: prefer `oidckit.AppleWithKey(...)` which mints a fresh ES256 client_secret JWT per request; no manual rotation needed.

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
  - `GET /auth/user/me` returns `orgs` (membership list) plus org-scoped roles for the user.
  - `GET /auth/user/bootstrap` returns canonical personal org + org memberships in one call.
  - Org-scoped access tokens include `org` + `roles` (single org only), and are rejected when the user is not a member.
    - Mint explicitly: `POST /auth/token/org`
    - Or mint at login/refresh by providing `org` in the request body.
  - Invitation workflow:
    - Org owners create/list/revoke invites with `/auth/orgs/:org/invites`.
    - Users list their invites via `GET /auth/org-invites`.
    - Users accept/decline via `/auth/org-invites/:invite_id/accept|decline`.
  - Org management endpoints require the reserved `owner` role; `owner` is protected and cannot be deleted or removed as the last owner.
- In `OrgMode: "single"` (default), AuthKit behaves like a single-tenant app:
  - Access tokens include `roles` (string[]) and there are no org-related claims/fields.

Reserved slug policy
- Owner namespaces use explicit states:
  - `restricted_name`: slug is blocked in `profiles.owner_reserved_names` and not publicly registrable.
  - `parked_org`: org exists and is platform-held (`metadata.namespace_state=parked_org`, `metadata.reserved=true`).
  - `registered_org`: normal org lifecycle (`metadata.namespace_state=registered_org`).
- Public lookup endpoint: `GET /auth/owners/{slug}` returns canonical public metadata for the slug:
  - `state`: `restricted_name`, `parked_org`, `registered_org`, `registered_user`, or `unregistered`
  - `entity_kind`: `none`, `org`, `user`, or `org_and_user`
  - optional `org` and/or `user` payloads when records exist.
- Migration `012_owner_namespace_states.up.sql` introduces the reserved-name table, backfills legacy reserved rows, and converts legacy reserved personal placeholder orgs to non-personal parked orgs.
- Public register/create/rename/org-create/org-rename paths do not use a hardcoded denylist; conflicts are enforced through owner-namespace uniqueness plus reserved-name table checks.
- Reserved users are non-loginable (reserved placeholder credentials/providers are cleared by migration and reserve flows).

Verification delivery and expiry
- Manual entry codes are fixed-length numeric strings (6 digits) generated by core and expire in 15 minutes.
- Verification links use high-entropy link tokens generated by core and expire in 1 hour.
- Password reset link tokens expire in 1 hour.
- Sender integrations receive `core.VerificationMessage{Code, LinkToken}` and must send only provided fields; at least one must be present.
- Code-based and link-based flows are both supported:
  - Email verify code: `POST /auth/email/verify/confirm` with `{"code":"123456"}`
  - Email verify link token: `POST /auth/email/verify/confirm-link` with `{"token":"..."}`
  - Phone verify code: `POST /auth/phone/verify/confirm` with `{"phone_number":"+1...","code":"123456"}`
  - Phone verify link token: `POST /auth/phone/verify/confirm-link` with `{"token":"..."}`
  - Password reset link handoff: `POST /auth/password/reset/confirm-link` with `{"token":"..."}` returns `{"ok":true,"reset_session":"..."}`
  - Password reset confirm: `POST /auth/password/reset/confirm` with `{"reset_session":"...","new_password":"..."}`
- Your API can live under a prefix (e.g., `/api/v1`); mount the JSON API using `http.StripPrefix("/api/v1", svc.APIHandler())`.

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
- Rate limiting:
  - Enabled by default (in-memory limiter) with per-bucket defaults from `authhttp.DefaultRateLimits()`.
  - Keys: `auth:<bucket>:ip:<client-ip>`; errors fail-open (request allowed).
  - Client IP strategy is conservative by default: it uses `RemoteAddr` only when it's a public IP; if `RemoteAddr` is private (common behind proxies), rate limiting fails open to avoid accidentally rate-limiting the proxy as a single client.
  - **Behind reverse proxies, you must explicitly configure trusted proxies** to safely use `X-Forwarded-For` / `CF-Connecting-IP`. AuthKit will not trust forwarded headers by default (clients can spoof them).
  - For multi-instance production, prefer a Redis/Garnet-backed limiter and a trusted-proxy client IP function, e.g.:
    - `svc.WithRateLimiter(redislimiter.New(redis, authhttp.ToRedisLimits(authhttp.DefaultRateLimits())))`
    - `svc.WithClientIPFunc(authhttp.ClientIPFromForwardedHeaders(trustedProxyCIDRs))` where `trustedProxyCIDRs` are the CIDRs of your ingress/proxy layer (nginx, cloudflared, etc.).
  - To explicitly opt out: `svc.DisableRateLimiter()`.
- Storage: run the SQL migrations in `authkit/migrations/postgres` (includes `profiles.refresh_sessions`).
- Keys/JWKS: host `/.well-known/jwks.json` using `svc.JWKSHandler()` and rotate keys as needed.

---

Endpoints mounted automatically:
- GET /.well-known/jwks.json
- OIDC:
  - GET /oidc/:provider/login
  - GET /oidc/:provider/callback
  - POST /auth/oidc/:provider/link/start (requires auth) → {auth_url}
  - POST /auth/oidc/discord/link/start (if Discord provider configured, requires auth)
- Password:
  - POST /auth/password/login (accepts email, phone, or username in identifier field)
  - POST /auth/password/reset/request (accepts email or phone in identifier field)
  - POST /auth/password/reset/confirm-link ({token} -> {reset_session})
  - POST /auth/password/reset/confirm ({reset_session, new_password})
- Registration (unified - accepts email or phone in identifier field):
  - POST /auth/register (server auto-detects email vs phone based on format)
  - Set `RegistrationVerification: none|optional|required` in `core.Config`
  - POST /auth/register/resend-email
  - POST /auth/register/resend-phone
- Email verification:
  - POST /auth/email/verify/request
  - POST /auth/email/verify/confirm
  - POST /auth/email/verify/confirm-link
- Phone verification and password reset:
  - POST /auth/phone/verify/request
  - POST /auth/phone/verify/confirm
  - POST /auth/phone/verify/confirm-link
  - POST /auth/phone/password/reset/request
  - POST /auth/phone/password/reset/confirm ({reset_session, new_password})
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
- Admin owner-namespace lifecycle (admin only):
  - POST /auth/admin/accounts/restrict (batch add slugs to restricted-name list)
  - POST /auth/admin/accounts/unrestrict (batch remove slugs from restricted-name list)
  - POST /auth/admin/account/park (`{kind:"org"|"user",slug}`)
  - POST /auth/admin/account/claim (`{kind:"org"|"user",slug,...}`; for `kind:"org"`, `owner_user_id` is required)
- Public owner-namespace lookup:
  - GET /auth/owners/:slug
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
  - Start: window.location = `/oidc/${provider}/login`.
  - Link: POST /auth/oidc/:provider/link/start (with Authorization) → {auth_url}; then window.location = auth_url.
  - Discord: Use `/oidc/discord/login` and `/auth/oidc/discord/link/start`.
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
    authhttp "github.com/open-rails/authkit/adapters/http"
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
