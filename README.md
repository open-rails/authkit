### AuthKit

Lightweight auth library for Go services.

AuthKit is based on a browser-managed bearer-token model: login/OIDC/Solana
flows issue an `access_token` and `refresh_token`, frontend JavaScript stores
them, protected API calls use `Authorization: Bearer <access_token>`, and
refresh uses `POST /token` with the refresh token. It is not a cookie-session
library: it does not currently provide opaque `session_id` browser cookies,
HttpOnly token-cookie callbacks, or CSRF/session middleware for that model.

Note: This repo ships the HTTP transport as the top-level `http` package (`github.com/open-rails/authkit/http`). The old Gin adapter has been removed (breaking change); bump your module version/tag accordingly when releasing.

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

  authhttp "github.com/open-rails/authkit/http"
  core "github.com/open-rails/authkit/core"
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

  mux := http.NewServeMux()
  mux.Handle("/.well-known/jwks.json", svc.JWKSHandler())

  apiPrefix := "/api/v1"
  apiH := http.StripPrefix(apiPrefix, svc.APIHandler())

  // AuthKit handlers are prefix-neutral. Mount JSON API routes at your app's
  // API prefix; this exposes /api/v1/token, /api/v1/user/me, and /api/v1/admin/users.
  mux.Handle(apiPrefix+"/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    apiH.ServeHTTP(w, r)
  }))

  // Browser OIDC routes are not JSON API routes. Mount them wherever the app
  // wants browser redirects; the recommended public routes are /oidc/*.
  mux.Handle("/oidc/", svc.OIDCHandler())

  http.ListenAndServe(":8080", mux)
}
```

Optional Twilio providers
- Core is provider-agnostic and only depends on `core.EmailSender` / `core.SMSSender`.
- Optional convenience providers are available:
  - `github.com/open-rails/authkit/providers/email/twilio` for Twilio Email API (SendGrid endpoint).
  - `github.com/open-rails/authkit/providers/sms/twilio` for Twilio Messaging API.
- The SMS provider requires `AccountSID`, `AuthToken`, and `MessagingServiceSID`. There is no `From` number fallback path.

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
- Apple: prefer `oidckit.AppleWithKey(...)` which mints a fresh ES256 client_secret JWT per request; no manual rotation needed.

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
    - Users list their invites via `GET /org-invites`.
    - Users accept/decline via `/org-invites/:invite_id/accept|decline`.
  - Org management endpoints require the reserved `owner` role; `owner` is protected and cannot be deleted or removed as the last owner.
- In `OrgMode: "single"` (default), AuthKit behaves like a single-tenant app:
  - Access tokens include `roles` (string[]) and there are no org-related claims/fields.

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
- Migration `012_owner_namespace_states.up.sql` introduces the reserved-name table, backfills legacy reserved rows, and converts legacy reserved personal placeholder orgs to non-personal parked orgs.
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
  - Client IP strategy is conservative by default: it uses `RemoteAddr` only when it's a public IP; if `RemoteAddr` is private (common behind proxies), rate limiting fails open to avoid accidentally rate-limiting the proxy as a single client.
  - **Behind reverse proxies, you must explicitly configure trusted proxies** to safely use `X-Forwarded-For` / `CF-Connecting-IP`. AuthKit will not trust forwarded headers by default (clients can spoof them).
  - For multi-instance production, prefer a Redis/Garnet-backed limiter and a trusted-proxy client IP function, e.g.:
    - `svc.WithRateLimiter(redislimiter.New(redis, authhttp.ToRedisLimits(authhttp.DefaultRateLimits())))`
    - `svc.WithClientIPFunc(authhttp.ClientIPFromForwardedHeaders(trustedProxyCIDRs))` where `trustedProxyCIDRs` are the CIDRs of your ingress/proxy layer (nginx, cloudflared, etc.).
  - To explicitly opt out: `svc.DisableRateLimiter()`.
- Storage: run the SQL migrations in `authkit/migrations/postgres` (includes `profiles.refresh_sessions`).
- Keys/JWKS: host `/.well-known/jwks.json` using `svc.JWKSHandler()` and rotate keys as needed.

---

Endpoints mounted automatically by `APIHandler()` are shown relative to the host-selected API mount prefix. With the recommended `/api/v1` mount, `GET /user/me` is served at `GET /api/v1/user/me`. Browser OIDC routes are served by `OIDCHandler()` and are usually mounted outside API versioning at `/oidc/*`.
- GET /.well-known/jwks.json
- OIDC:
  - GET /oidc/:provider/login
  - GET /oidc/:provider/callback
  - POST /oidc/:provider/link/start (APIHandler, requires auth) → {auth_url}
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
- Email verification:
  - POST /email/verify/request
  - POST /email/verify/confirm
  - POST /email/verify/confirm-link
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
