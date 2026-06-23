# AuthKit API Endpoints Reference

AuthKit HTTP handlers are prefix-neutral. The paths below are handler paths; when a host mounts AuthKit API routes at `/api/v1`, `GET /me` becomes public route `GET /api/v1/me`.

Downstream applications that embed AuthKit should mount the AuthKit API at `/api/v1` and should not add an extra `/auth` segment. Browser OIDC routes should usually be mounted outside API versioning at `/oidc/*`.

AuthKit's exported route specs are the canonical source of truth for JSON API
routes. Host apps should mount `svc.Routes().DefaultAPI()` or explicit
`svc.Routes().Groups(...)` selections through the built-in Gin/Chi adapters or
their own router registration loop, not maintain duplicated route allowlists.
Host-facing JSON route groups are `RoutePublic`, `RouteRegister`,
`RouteSession`, `RouteUser`, `RoutePasskeys`, `RouteAdmin`, and
`RoutePermissionGroups`.
Browser OIDC login/callback routes are `RouteBrowserOIDC` and usually mount
outside the JSON API prefix. Account provider linking is self-service user API:
`POST /oidc/:provider/link/start` under the host-selected API prefix.

AuthKit is opinionated about identity validation. Host apps should not
reimplement or customize username, password, email, or phone validation rules.
AuthKit returns stable error codes, exported from the `authhttp` package as
typed `ErrorCode` constants, such as `username_too_short`,
`username_must_start_with_letter`, `username_invalid_characters`,
`owner_slug_taken`, `username_not_allowed`, `rename_rate_limited`,
`invalid_email`, `invalid_phone_number`, and `password_too_short`.

**Error envelope (Stripe-style, nested — same shape as OpenRails; breaking as of
v0.52.0).** Every error response is:

```json
{ "error": { "type": "invalid_request_error", "code": "password_too_short",
             "message": "Password too short.", "param": "password",
             "metadata": { "...": "optional machine-readable context" } } }
```

- `code` is the stable machine code (the `authhttp.ErrorCode` value — unchanged);
  match on `error.code`, not `error` (which was a bare string before v0.52.0).
- `type` is derived from the HTTP status: `invalid_request_error` (400/404/409),
  `authentication_error` (401), `authorization_error` (403),
  `rate_limit_error` (429), `api_error` (5xx).
- `message` is human-readable (English); `param` names the offending field on
  validation errors; `metadata` carries rate-limit/availability context
  (e.g. `retry_after_seconds`, and username rename's `time_until_rename_available`).

Closed/private deployments should seed AuthKit-owned authority through the
library/CLI bootstrap path, not a public HTTP admin route:
`core.LoadBootstrapManifestFile`, `core.ParseBootstrapManifestYAML`, and
`(*Service).ReconcileBootstrapManifest(ctx, manifest, store, opts)`, or
`authkit bootstrap apply --file ./bootstrap.yaml`. Host applications layer their
own domain bootstrap after AuthKit has reconciled users, root roles, trusted
issuers, and API keys.

## Authentication Levels

| Level | Description |
|-------|-------------|
| **PUBLIC** | No authentication required. |
| **AUTH** | Requires valid JWT token (logged-in user). |
| **ADMIN** | Requires valid JWT with admin role. |

---

## JWKS (Root)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/.well-known/jwks.json` | PUBLIC | JWKS public keys |

---

## OIDC Browser Flows

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/oidc/:provider/login` | PUBLIC | Start browser login (Google, Apple, Discord, etc.); optional app-relative `return_to` |
| GET | `/oidc/:provider/callback` | PUBLIC | OIDC/OAuth callback |

Notes:
- Browser OIDC routes are served by `OIDCHandler()`, not `APIHandler()`, and should usually be public routes such as `/oidc/:provider/login` and `/oidc/:provider/callback`.
- After AuthKit handles the provider callback, full-page login redirects to `{BaseURL}{FrontendCallbackPath}`. The default frontend callback path is `/login/callback`; host apps may configure another app-relative path.
- `GET /oidc/:provider/login?return_to=/subscribe?plan=pro` preserves the app-relative path through the provider redirect and returns it as `return_to` in the callback URL fragment. AuthKit rejects absolute URLs, protocol-relative URLs, backslashes, and CR/LF before storing it.
- JSON/SPAs flows such as password login, registration, in-app 2FA, and POST-based verification/reset do not navigate away; the client owns any `return_to` state for those flows.

---

## Registration & Login

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/identity-providers` | PUBLIC | List enabled external identity providers |
| POST | `/password/login` | PUBLIC | Password login |
| POST | `/passkeys/login/begin` | PUBLIC | Begin passkey login; optional `{ "login": "email-or-username-or-phone" }` for username-scoped options, omitted for discoverable/usernameless login |
| POST | `/passkeys/login/finish` | PUBLIC | Finish passkey login by POSTing the `PublicKeyCredential` JSON returned by `navigator.credentials.get()` |
| POST | `/register` | PUBLIC | Unified registration (email or phone); success returns `next_action`: `none`, `verify_email`, or `verify_phone`; `none` includes access/refresh tokens |
| POST | `/register/resend-email` | PUBLIC | Resend email verification |
| POST | `/register/resend-phone` | PUBLIC | Resend phone verification |
| POST | `/token` | PUBLIC | Refresh user access token |
| POST | `/sessions/current` | PUBLIC | Get current session info |
| POST | `/reauth/password` | AUTH | Reauthenticate with password; returns fresh `access_token`, `token_type`, `expires_in`, and `fresh_auth` |
| POST | `/reauth/2fa` | AUTH | Start or complete selected/default 2FA reauth; final `{code, factor_id?, backup_code?}` call returns fresh `access_token`, `token_type`, `expires_in`, and `fresh_auth` |

Token taxonomy:
- User access token: JWT `typ=access+jwt`; carries `sub`, `sid`, and
  authoritative short-lived `entitlements`, not profile or role claims.
- Delegated access token: JWT `typ=delegated-access+jwt`; carries
  `delegated_sub` and concrete `permissions` validated against the issuer
  remote application's stored authority.
- Remote application access token: JWT
  `typ=remote-application-access+jwt`; carries neither `sub` nor
  `delegated_sub`; identity and authority come from validated
  `iss -> remote_application`.
- Service JWT: JWT `typ=service+jwt` plus `token_use=service`; receiver
  intersects requested permissions/resources with server-side grants.
- API key: opaque bearer secret; it holds one permission-group role and its permissions resolve from that role at verify time; resources are a separate per-key binding.

Reauth updates the current refresh-session auth state but does not rotate the refresh token. Clients should retry sensitive actions with the returned access token; `POST /token` remains the refresh-token rotation route.

Passkeys:
- Configure `core.Config.Passkeys` with `RPID`, `RPDisplayName`, and `Origins`;
  empty values derive from `Frontend.BaseURL`/`Token.Issuer`.
- Registration is authenticated and freshness-gated:
  `POST /passkeys/register/begin`, then POST the `PublicKeyCredential` JSON from
  `navigator.credentials.create()` to `/passkeys/register/finish`.
- Management routes are authenticated: `GET /passkeys`, `PATCH /passkeys/:id`
  with `{ "label": "..." }`, and `DELETE /passkeys/:id`.
- Login sessions require WebAuthn user verification and mint normal
  access/refresh tokens with MFA assurance claims. Passkeys do not satisfy
  `RoleDef.RequiresMFA` enrollment requirements unless that policy is explicitly
  extended later.
- Frontends should use `navigator.credentials.create({ publicKey })` and
  `navigator.credentials.get({ publicKey })`; for conditional UI, render the
  username input with `autocomplete="username webauthn"` and call
  `navigator.credentials.get({ publicKey, mediation: "conditional" })`.

Reserved slug policy:
- Reserved owner slugs are seeded in DB migrations as reserved user placeholders.
- Public APIs do not use a hardcoded slug denylist; reserved slug claims are rejected by normal in-use/owner-namespace conflicts.

---

## Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/email/password/reset/request` | PUBLIC | Request password reset by email |
| POST | `/email/password/reset/confirm` | PUBLIC | Confirm email password reset using `token` + `new_password` |
| POST | `/phone/password/reset/request` | PUBLIC | Request password reset (phone) |
| POST | `/phone/password/reset/confirm` | PUBLIC | Confirm phone password reset using `token` + `new_password` |

Request-code endpoints are rate-limited by default: one request per client every 60 seconds and 6 per hour for registration, registration resend, email/phone verification, password reset, and email/phone change flows. `429` responses include `Retry-After` and `retry_after_seconds` when AuthKit can compute the reset time.

Registration resend and email/phone verification request endpoints are honest about malformed input and target state. They return validation errors for malformed identifiers, `pending_registration_not_found` for missing pending registration resend targets, `user_not_found` for missing verification targets, and `email_already_verified` / `phone_already_verified` for already-verified accounts.

---

## Email/Phone Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/email/verify/request` | PUBLIC | Request email verification |
| POST | `/email/verify/confirm` | PUBLIC | Confirm email verification using `code` or `token` |
| POST | `/phone/verify/request` | PUBLIC | Request phone verification (sends SMS) |
| POST | `/phone/verify/confirm` | PUBLIC | Confirm phone verification using `phone_number` + `code`, or `token` |

---

For verification, registration resend, and 2FA send operations, a 2xx response means AuthKit submitted the message to the configured email/SMS provider. Provider submission failures return stable public errors such as `email_delivery_failed` or `sms_delivery_failed`; downstream mailbox/carrier delivery is outside AuthKit's synchronous confirmation boundary.

## User Management (Authenticated)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/me` | AUTH | Get current user — includes global roles, entitlements, linked provider metadata, username aliases, and preferred language |
| PATCH | `/user/username` | AUTH | Change username |
| PATCH | `/user/preferred-language` | AUTH | Change preferred language |
| PATCH | `/user/biography` | AUTH | Update biography |
| POST | `/user/password` | AUTH | Change password |
| POST | `/user/email` | AUTH | Start/restart or confirm email change |
| POST | `/user/phone` | AUTH | Start/restart or confirm phone number change |
| DELETE | `/user` | AUTH | Delete own account |
| DELETE | `/user/providers/:provider` | AUTH | Unlink OAuth provider |

---

## Permission Groups

The old static organization route group was removed. Hosts expose resource-scoped
management through generated permission-group routes instead.

Terminology: a configured permission-group persona is the public route and
permission namespace. For example, a `merchant` persona generates
`/merchant/:resource_slug/...` routes and `merchant:<area>:<action>` permissions.

Always:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/me/groups` | AUTH | List the caller's direct `{persona, resource_slug, role}` memberships |

For each configured persona, AuthKit emits only the route families enabled by
that persona's management profile:

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/:persona/:resource_slug/members` | PERM | List members |
| POST | `/:persona/:resource_slug/members` | PERM | Add member role |
| DELETE | `/:persona/:resource_slug/members/:user` | PERM | Remove member from group |
| PUT | `/:persona/:resource_slug/members/:user/roles/:role` | PERM | Assign or replace the member's role |
| GET | `/:persona/:resource_slug/roles` | PERM | List role catalog |
| POST | `/:persona/:resource_slug/roles` | PERM | Define custom role |
| DELETE | `/:persona/:resource_slug/roles/:role` | PERM | Delete custom role |
| GET | `/:persona/:resource_slug/api-keys` | PERM | List API keys |
| POST | `/:persona/:resource_slug/api-keys` | PERM | Mint API key |
| DELETE | `/:persona/:resource_slug/api-keys/:key` | PERM | Revoke API key |
| GET | `/:persona/:resource_slug/remote-applications` | PERM | List remote applications |
| POST | `/:persona/:resource_slug/remote-applications` | PERM | Register remote application |
| DELETE | `/:persona/:resource_slug/remote-applications/:app` | PERM | Delete remote application |
| GET | `/:persona/:resource_slug/invites` | PERM | List invites |
| POST | `/:persona/:resource_slug/invites` | PERM | Create invite |
| DELETE | `/:persona/:resource_slug/invites/:invite` | PERM | Revoke invite |

Built-in `root` emits member-management plus role-list routes by default.

---

## API keys (opaque machine credentials)

Long-lived, revocable bearer credentials owned by a permission group, for
machine/automation callers (CI, operator CLIs, service-to-service). An API key
acts as a service principal for that permission group: middleware sets
`Claims.Permissions`, `Claims.Resources`, and a service marker
(`Claims.IsService()`), with no `UserID`. Permissions are opaque to AuthKit; the
embedding app owns the vocabulary and enforces meaning.

**Presentation.** `Authorization: Bearer <prefix>_st_<key_id>_<secret>`. `<prefix>` is
the host's configured `APIKeyPrefix` brand ( e.g. `cozy` → `cozy_st_…`); empty →
bare `st_`. `key_id` is a non-secret public id for O(1) indexed lookup; only
`sha256(secret)` is stored. The full token is shown **once** at creation.

**Resolution** happens in the `Required`/`Optional` middleware *before* JWT
verification: tokens carrying the configured marker are looked up by `key_id`,
the secret is compared in constant time, and revoked/expired/group-deleted tokens
are rejected. Non-API-key credentials fall through to normal JWT verification. The API key
path is distinct from the password-login handler, so API keys **bypass the
interactive password-login rate limiter by design** (a robot must not use the
human login path).

**Mint authorization (native, role-based).** Minting requires the generated
`<persona>:api-keys:manage` permission. The request body supplies one `role`;
AuthKit validates that the role exists in the target group and enforces
no-escalation. Permissions resolve from that role at verify time rather than
being frozen into the key. An API key carries no user, so it can never
mint/list/revoke API keys.

**Resource scopes.** API keys may also carry `resources: [{kind, id}]`. AuthKit
stores these as opaque exact-match Kind/ID pairs and returns them from
`ListAPIKeys`, `ResolveAPIKeyWithResources`, and API key middleware
`Claims.Resources`. AuthKit validates only shape/length and duplicate pairs; it
does not interpret resource kinds or grant wildcards by itself. A host may use
literal IDs such as `"*"` if that host wants wildcard semantics. Hosts that need
resource no-escalation install `core.Config.ResourceScopeAuthorizer`; otherwise
any caller who passes the normal API key management and permission checks may attach
valid resource scopes. The rule is: **permissions say what; resources say
where**.

## Service JWTs (OIDC/JWKS machine credentials)

First-party services that have their own AuthKit issuer/JWKS should mint
short-lived service JWTs instead of receiving generated opaque API keys
from the resource service. The canonical token shape is `iss`, `sub`, `aud`,
`iat`, `nbf`, `exp`, `jti`, `token_use=service`, and `permissions: []`, with
optional `resources: [{kind,id}]`. AuthKit's default mint lifetime is 15 minutes.

Use `core.MintServiceJWT` or `(*core.Service).MintServiceJWT` on the caller side,
and `authhttp.Verifier.VerifyServiceJWT` or `authhttp.RequiredServiceJWT` on the
receiver side. Verification uses registered issuers/JWKS, including
remote-application issuer lazy-load; disabled issuer rows fail closed. AuthKit parses requested
permissions/resources but does not grant them. The resource service must
intersect requested permissions with server-side grants for the issuer/subject.

Recommended pattern for Doujins/Hentai0 -> OpenRails: caller caches a 15-minute
service JWT in memory until near expiry, sends `Authorization: Bearer <jwt>`,
OpenRails verifies the issuer/JWKS and audience, then authorizes using
OpenRails-owned service grants. Generated opaque API keys remain for
non-OIDC clients, manual API-key-like credentials, and bootstrap/admin scripts.

Example:

```json
{
  "name": "cozy-spend",
  "permissions": ["openrails:credits:spend"],
  "resources": [
    {"kind": "openrails.org", "id": "0190a1b2-c3d4-7e5f-8a6b-9c0d1e2f3a4b"},
    {"kind": "openrails.org_subject", "id": "0190a1b2-c3d4-7e5f-8a6b-9c0d1e2f3a4c"}
  ]
}
```

Resource IDs are opaque to authkit, but hosts must use **durable identifiers**
(uuids), never mutable slugs — a slug-keyed resource scope silently detaches
from its target on rename.

**Lifetime.** Optional `expires_at` (null = non-expiring). A host may set a max
TTL that caps the effective expiry. Revoke at any time; expiry + revocation are
checked on every request.

**Storage.** `profiles.api_keys` (`key_id` unique, `secret_hash` bytea,
single `role`, `created_by` audit-only & `ON DELETE SET NULL` so a token
outlives its minter, nullable `expires_at`/`revoked_at`, `last_used_at` touched
best-effort/async) plus `profiles.api_key_resources` for opaque
Kind/ID scope rows.

**Configuration.** `core.Config.APIKeyPrefix` (lowercase alnum, ≤16 chars; empty
→ `st_`), `core.Config.APIKeyMaxTTL` (0 = no cap), and optional
`core.Config.ResourceScopeAuthorizer`.

---

## Sessions

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/user/sessions` | AUTH | List user sessions |
| DELETE | `/user/sessions/:id` | AUTH | Revoke specific session |
| DELETE | `/user/sessions` | AUTH | Revoke all sessions |
| DELETE | `/logout` | AUTH | Logout current session |

---

## Two-Factor Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/user/2fa` | AUTH | Get 2FA status, default factor, available factors, allowed methods, and backup-code count |
| POST | `/user/2fa` | AUTH | Start or confirm email/SMS/TOTP 2FA enrollment; optional `default: true` makes the factor default; `{factor_id, default:true}` changes the default |
| DELETE | `/user/2fa` | AUTH | Disable all 2FA, or delete one factor with `factor_id` |
| POST | `/user/2fa/backup-codes` | AUTH | Regenerate backup codes |
| POST | `/2fa/challenge` | PUBLIC | Start a selected non-default factor from an existing password-login 2FA challenge |
| POST | `/2fa/verify` | PUBLIC | Verify 2FA code during login; accepts `factor_id` for selected factors or `backup_code: true` for recovery codes |

Hosts may require 2FA for permission-group roles with
`core.RoleDef{RequiresMFA: true}`. Assigning that role, or accepting an invite
for it, returns `2fa_enrollment_required` until account MFA is enabled with at
least one factor. Disabling MFA removes those MFA-required user role assignments.

---

## Provider Linking

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/oidc/:provider/link/start` | AUTH | Start OIDC/OAuth provider linking through `APIHandler()`; with the recommended API mount, public route is `/api/v1/oidc/:provider/link/start` |

---

## Solana (Sign-In With Solana)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/solana/challenge` | PUBLIC | Get SIWS challenge nonce |
| POST | `/solana/login` | PUBLIC | Login with signed Solana message |
| POST | `/solana/link` | AUTH | Link Solana wallet to account |

---

## Admin

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/admin/roles/grant` | ADMIN | Grant role to user |
| POST | `/admin/roles/revoke` | ADMIN | Revoke role from user |
| GET | `/admin/users` | `root:users:read` | Dashboard user list. Query: `page`, `page_size`, `search`, `root_role`, `status=active\|banned\|deleted\|any`, `sort=created_at\|last_login\|username\|email`, `order=asc\|desc`, `entitlement` |
| GET | `/admin/users/:user_id` | `root:users:read` | Get user details |
| POST | `/admin/users/ban` | `root:users:ban` | Ban user |
| POST | `/admin/users/unban` | `root:users:ban` | Unban user |
| POST | `/admin/users/:user_id/recover` | `root:users:update` | Recover a compromised account. Body has exactly one of `{email}` or `{phone_number}`; AuthKit revokes sessions, deletes password/provider/2FA factors, replaces the primary recovery identifier, and sends a password-reset request. |
| DELETE | `/admin/users/:user_id` | `root:users:delete` | Delete user |
| POST | `/admin/users/:user_id/restore` | `root:users:delete` | Restore (undelete) user |
| GET | `/admin/users/:user_id/signins` | `root:users:read` | List recent signin events for a user |
| POST | `/admin/users/:user_id/sessions/revoke` | `root:sessions:revoke` | Revoke all refresh sessions for a target user |
| GET | `/namespaces/:slug` | PUBLIC | Fetch public user-namespace metadata: `requested_slug`, `slug`, `renamed`, optional `hold_until`, optional `user`, and `claimable` |

Namespace lookup returns the user namespace plus rename/claimability metadata.

## Remote Application Issuers (resource-server side)

The inbound accept-side of the platform-delegation handshake. The resource
server stores trusted remote applications; delegated tokens minted by those
issuers (carrying `delegated_sub`) are then validated by the Verifier with
in-house JWKS fetch/refresh (no external push/sync). The outbound side is the
Go `authhttp.RemoteApplicationIssuersClient`.

Delegated access JWTs are minted with `authhttp.MintDelegatedAccessToken`.
They carry `typ=delegated-access+jwt`, `delegated_sub`, resource-defined
`permissions`, optional JSON `attributes`, and no normal `sub`. The validated
`iss` is the remote-application identity. `delegated_sub` must be the issuer's **immutable, never-reassigned**
subject identifier (OIDC `sub` semantics) — never a username, slug, or email.
All authkit identifiers are opaque strings that happen to be uuidv7; consumers
must not parse them or branch on their format. Ordinary AuthKit access JWTs carry `typ=access+jwt`; resource servers
reject missing, unknown, or cross-profile `typ` values. Delegated access JWTs
should be authorized from `permissions` and namespaced `attributes`. Resource servers should validate them
with `Verifier.VerifyDelegatedAccess`, optionally installing
permissions and attributes-policy hooks. Remote applications loaded from this
store are bound to the permission group that registered them; downstream
authorization should intersect token permissions with that stored authority.
For browser-direct OpenRails billing, a host app should expose its own
authenticated current-user token endpoint, mint a short-lived `aud=openrails`
delegated access JWT for its resource account with self-scoped permissions such as
`openrails:self:billing:read` or `openrails:self:checkout:create`, and let the
browser call OpenRails directly; the host does not need to proxy billing routes.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/:persona/:resource_slug/remote-applications` | PERM | Register/upsert a remote application issuer |
| DELETE | `/:persona/:resource_slug/remote-applications/:app` | PERM | Remove a remote application issuer registration |
| GET | `/:persona/:resource_slug/remote-applications` | PERM | List registered remote applications for a permission group |
