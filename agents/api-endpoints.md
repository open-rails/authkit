# AuthKit API Endpoints Reference

AuthKit HTTP handlers are prefix-neutral. The paths below are handler paths; when a host mounts AuthKit API routes at `/api/v1`, `GET /user/me` becomes public route `GET /api/v1/user/me`.

Downstream applications that embed AuthKit should mount the AuthKit API at `/api/v1` and should not add an extra `/auth` segment. Browser OIDC routes should usually be mounted outside API versioning at `/oidc/*`.

AuthKit's exported route specs are the canonical source of truth for JSON API
routes. Host apps should mount `svc.Routes().DefaultAPI()` or explicit
`svc.Routes().Groups(...)` selections through the built-in Gin/Chi adapters or
their own router registration loop, not maintain duplicated route allowlists.
Browser OIDC login/callback routes are a separate browser group. Account
provider linking is an API group, `RouteAccountOIDCLinking`, and is exposed as
`POST /oidc/:provider/link/start` under the host-selected API prefix.

AuthKit is opinionated about identity validation. Host apps should not
reimplement or customize username, password, email, or phone validation rules.
AuthKit returns stable error codes such as `username_too_short`,
`username_must_start_with_letter`, `username_invalid_characters`,
`owner_slug_taken`, `username_not_allowed`, `rename_rate_limited`,
`invalid_email`, `invalid_phone_number`, and `password_too_short`.
Username rename cooldown responses include `time_until_rename_available`.

Closed/private deployments should seed AuthKit-owned authority through the
library/CLI bootstrap path, not a public HTTP admin route:
`core.LoadBootstrapManifestFile`, `core.ParseBootstrapManifestYAML`, and
`(*Service).ReconcileBootstrapManifest(ctx, manifest, store, opts)`, or
`authkit bootstrap apply --file ./bootstrap.yaml`. Host applications layer their
own domain bootstrap after AuthKit has reconciled users, orgs, roles, trusted
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
| GET | `/oidc/:provider/login` | PUBLIC | Start browser login (Google, Apple, Discord, etc.) |
| GET | `/oidc/:provider/callback` | PUBLIC | OIDC/OAuth callback |

Notes:
- Browser OIDC routes are served by `OIDCHandler()`, not `APIHandler()`, and should usually be public routes such as `/oidc/:provider/login` and `/oidc/:provider/callback`.
- After AuthKit handles the provider callback, full-page login redirects to `{BaseURL}{FrontendCallbackPath}`. The default frontend callback path is `/login/callback`; host apps may configure another app-relative path.

---

## Registration & Login

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/identity-providers` | PUBLIC | List enabled external identity providers |
| POST | `/password/login` | PUBLIC | Password login |
| POST | `/register` | PUBLIC | Unified registration (email or phone); success returns `next_action`: `none`, `verify_email`, or `verify_phone`; `none` includes access/refresh tokens |
| POST | `/register/resend-email` | PUBLIC | Resend email verification |
| POST | `/register/resend-phone` | PUBLIC | Resend phone verification |
| POST | `/token` | PUBLIC | Refresh user access token |
| POST | `/sessions/current` | PUBLIC | Get current session info |

Reserved slug policy:
- Reserved owner slugs are seeded in DB migrations as reserved user + personal-org placeholders.
- Public APIs do not use a hardcoded slug denylist; reserved slug claims are rejected by normal in-use/owner-namespace conflicts.

---

## Password Reset

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/email/password/reset/request` | PUBLIC | Request password reset by email |
| POST | `/email/password/reset/confirm-link` | PUBLIC | Consume email reset token and return one-time `reset_session` |
| POST | `/email/password/reset/confirm` | PUBLIC | Confirm email password reset using `reset_session` + `new_password` |
| POST | `/phone/password/reset/request` | PUBLIC | Request password reset (phone) |
| POST | `/phone/password/reset/confirm-link` | PUBLIC | Consume phone reset token and return one-time `reset_session` |
| POST | `/phone/password/reset/confirm` | PUBLIC | Confirm phone password reset using `reset_session` + `new_password` |

Request-code endpoints are rate-limited by default: one request per client every 60 seconds and 6 per hour for registration, registration resend, email/phone verification, password reset, and email/phone change flows. `429` responses include `Retry-After` and `retry_after_seconds` when AuthKit can compute the reset time.

Registration resend and email/phone verification request endpoints are honest about malformed input and target state. They return validation errors for malformed identifiers, `pending_registration_not_found` for missing pending registration resend targets, `user_not_found` for missing verification targets, and `email_already_verified` / `phone_already_verified` for already-verified accounts.

---

## Email/Phone Verification

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/email/verify/request` | PUBLIC | Request email verification |
| POST | `/email/verify/confirm` | PUBLIC | Confirm email verification |
| POST | `/email/verify/confirm-link` | PUBLIC | Confirm email verification (expects `token`) |
| POST | `/phone/verify/request` | PUBLIC | Request phone verification (sends SMS) |
| POST | `/phone/verify/confirm` | PUBLIC | Confirm phone verification |
| POST | `/phone/verify/confirm-link` | PUBLIC | Confirm phone verification (expects `token`) |

---

For verification, registration resend, and 2FA send operations, a 2xx response means AuthKit submitted the message to the configured email/SMS provider. Provider submission failures return stable public errors such as `email_delivery_failed` or `sms_delivery_failed`; downstream mailbox/carrier delivery is outside AuthKit's synchronous confirmation boundary.

## User Management (Authenticated)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/user/me` | AUTH | Get current user — includes global roles plus a `orgs` membership list with per-org roles (empty for org-free users) |
| GET | `/me/bootstrap` | AUTH | Get canonical personal org + org memberships/roles for bootstrap |
| PATCH | `/user/username` | AUTH | Change username |
| PATCH | `/user/biography` | AUTH | Update biography |
| POST | `/user/password` | AUTH | Change password |
| POST | `/user/email/change/request` | AUTH | Request email change |
| POST | `/user/email/change/confirm` | AUTH | Confirm email change |
| POST | `/user/email/change/resend` | AUTH | Resend email change verification |
| POST | `/user/phone/change/request` | AUTH | Request phone number change |
| POST | `/user/phone/change/confirm` | AUTH | Confirm phone number change |
| POST | `/user/phone/change/resend` | AUTH | Resend phone number change verification |
| DELETE | `/user` | AUTH | Delete own account |
| DELETE | `/user/providers/:provider` | AUTH | Unlink OAuth provider |

---

## Orgs (always registered; mount the orgs route group to expose)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/me/orgs` | AUTH | List orgs for current user (includes each org's single `role`) |
| POST | `/orgs` | AUTH | Public org registration. Requires an authenticated user and creates the org, seeds baseline roles, adds the caller as the initial `owner`, and never creates ownerless public orgs. Disabled by non-open org registration policy. Ownerless orgs are privileged bootstrap/admin only. |
| GET | `/orgs/:org` | AUTH | Get org metadata plus caller membership `{role, permissions}` (`:org` accepts slug or alias) |
| POST | `/orgs/:org/rename` | AUTH | Rename org slug (keeps old slug as alias) |
| GET | `/orgs/:org/members` | AUTH | List members (`org:read`) |
| POST | `/orgs/:org/members` | AUTH | Add member (`org:members:manage`) |
| DELETE | `/orgs/:org/members/:user_id` | AUTH | Remove member (`org:members:manage`) |
| GET | `/orgs/:org/invites` | AUTH | List org invites (`org:read`) |
| POST | `/orgs/:org/invites` | AUTH | Create invite (`org:members:manage`) |
| POST | `/orgs/:org/invites/:invite_id/revoke` | AUTH | Revoke pending invite (`org:members:manage`) |
| GET | `/me/org-invites` | AUTH | List org invites for current user (cross-org — invitee isn't a member yet) |
| POST | `/me/org-invites/:invite_id/accept` | AUTH | Accept org invite as current user |
| POST | `/me/org-invites/:invite_id/decline` | AUTH | Decline org invite as current user |
| GET | `/orgs/:org/roles` | AUTH | List defined roles (`org:read`) |
| GET | `/orgs/:org/roles/:role` | AUTH | A role's detail: name + permissions (`org:read`); 404 if undefined |
| PUT | `/orgs/:org/roles/:role` | AUTH | Create-or-replace a role: body `{permissions[]}` (`org:roles:manage`; catalog-validated + no-escalation). Idempotent — defines the role name and sets its perms in one call |
| DELETE | `/orgs/:org/roles/:role` | AUTH | Delete a role (`org:roles:manage`; `owner` protected) |
| GET | `/orgs/:org/members/:user_id/roles` | AUTH | Read member roles (`org:read`) |
| POST | `/orgs/:org/members/:user_id/roles` | AUTH | Assign role to member (`org:members:manage`; no-escalation: the role's permissions must be ⊆ the assigner's, so granting `owner` requires owner) |
| DELETE | `/orgs/:org/members/:user_id/roles` | AUTH | Unassign role (`org:members:manage`; cannot remove last owner) |
| GET | `/permissions` | AUTH | The permission catalog: authkit base permissions ∪ the app-declared catalog |
| GET | `/orgs/:org/members/:user_id/permissions` | AUTH | A member's effective permissions (`org:read`) |
| POST | `/orgs/:org/api-keys` | AUTH | Mint an API key (`org:api_keys:manage`). Body `{name, permissions[], resources?:[{kind,id}], expires_at?}`; perms catalog-validated + no-escalation, reserved write/mint `org:*` perms + wildcards barred (read-only `org:read` allowed). Resource scopes are shape-validated only and optionally host-authorized. Full key shown ONCE. |
| GET | `/orgs/:org/api-keys` | AUTH | List the org's API keys (`org:api_keys:manage`; metadata only, includes `resources[]`, never secrets) |
| DELETE | `/orgs/:org/api-keys/:token_id` | AUTH | Revoke an API key (`org:api_keys:manage`) |

> **Org RBAC (permission-based).** A role is a set of permissions. Org-management
> endpoints are gated by authkit's **base permissions** (reserved `org:`
> namespace): `org:roles:manage`, `org:members:manage`, `org:api_keys:manage`,
> `org:read`. The embedding app declares its own permission catalog
> (`core.Config.PermissionCatalog`) + optional default roles
> (`core.Config.DefaultRoles`); the effective catalog = base ∪ app. The `owner`
> role is hardcoded and seeded with `*` (all permissions); other roles are
> app/org-defined. Permission tokens in a role: a concrete permission, `*` (all),
> or `!perm` (exclude). All assignment/grant is **no-escalation** (you can only
> confer permissions you hold) and **catalog-validated** (unknown permissions
> rejected). A platform global admin bypasses. Permissions are opaque to
> authkit — the app owns their meaning and enforces them at its own endpoints
> via `core.EffectivePermissions(ctx, org, userID)`.

---

## API keys (opaque machine credentials)

Long-lived, revocable bearer credentials **owned by an org** (not a person), for
machine/automation callers (CI, the e2e operator CLI, service-to-service). An
API key acts **as the org**: middleware sets `Claims.OrgID`
(immutable org uuid — the canonical identifier to persist) + `Claims.Org`
(mutable slug, presentation/logging only) + `Claims.Permissions`
(the token's app-defined permission strings) and a service marker
(`Claims.IsService()`), with **no** `UserID`, mirroring the delegated-principal
pattern. Permissions are opaque to authkit — the embedding app owns the
vocabulary and enforces meaning. (Users, by contrast, carry `OrgRoles`; the
resource server expands role→permission at request time.)

**Presentation.** `Authorization: Bearer <prefix>_st_<key_id>_<secret>`. `<prefix>` is
the host's configured `APIKeyPrefix` brand ( e.g. `cozy` → `cozy_st_…`); empty →
bare `st_`. `key_id` is a non-secret public id for O(1) indexed lookup; only
`sha256(secret)` is stored. The full token is shown **once** at creation.

**Resolution** happens in the `Required`/`Optional` middleware *before* JWT
verification: tokens carrying the configured marker are looked up by `key_id`,
the secret is compared in constant time, and revoked/expired/org-deleted tokens
are rejected. Non-API-key credentials fall through to normal JWT verification. The API key
path is distinct from the password-login handler, so API keys **bypass the
interactive password-login rate limiter by design** (a robot must not use the
human login path).

**Mint authorization (native, permission-based).** Minting requires
`org:api_keys:manage`. authkit validates the requested permissions itself against
the org's effective catalog: each must be a defined permission (else `400
unknown_permission`) the caller themselves holds (else `403
permission_grant_denied`, offending named) — no privilege escalation. The
reserved **write/mint** management permissions (`org:roles:manage`,
`org:members:manage`, `org:api_keys:manage`) and wildcards/exclusions are barred
from API keys (`403 permission_not_grantable_to_api_key`) — an API key does machine work,
not org management. The read-only `org:read` IS grantable (escalation-harmless,
for monitoring/audit automation), still subject to no-escalation. Permissions
are frozen at mint time (revoke to reduce). An API key
carries no user, so it can never mint/list/revoke API keys.

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
receiver side. Verification uses registered issuers/JWKS, including org issuer
lazy-load; disabled issuer rows fail closed. AuthKit parses requested
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
`permissions text[]`, `created_by` audit-only & `ON DELETE SET NULL` so a token
outlives its minter, nullable `expires_at`/`revoked_at`, `last_used_at` touched
best-effort/async) plus `profiles.service_token_resources` for opaque
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
| GET | `/user/2fa` | AUTH | Get 2FA enabled |
| POST | `/user/2fa/start-phone` | AUTH | Start phone-based 2FA enrollment |
| POST | `/user/2fa/enable` | AUTH | Enable 2FA |
| POST | `/user/2fa/disable` | AUTH | Disable 2FA |
| POST | `/user/2fa/regenerate-codes` | AUTH | Regenerate backup codes |
| POST | `/2fa/verify` | PUBLIC | Verify 2FA code during login |

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
| GET | `/admin/users` | ADMIN | List users |
| GET | `/admin/users/:user_id` | ADMIN | Get user details |
| POST | `/admin/users/ban` | ADMIN | Ban user |
| POST | `/admin/users/unban` | ADMIN | Unban user |
| POST | `/admin/users/set-email` | ADMIN | Set user email |
| POST | `/admin/users/set-username` | ADMIN | Set user username |
| POST | `/admin/users/set-password` | ADMIN | Set user password |
| DELETE | `/admin/users/:user_id` | ADMIN | Delete user |
| POST | `/admin/users/:user_id/restore` | ADMIN | Restore (undelete) user |
| GET | `/admin/users/deleted` | ADMIN | List deleted users |
| GET | `/admin/users/:user_id/signins` | ADMIN | List recent signin events for a user |
| POST | `/admin/users/:user_id/sessions/revoke` | ADMIN | Revoke all refresh sessions for a target user |
| POST | `/admin/accounts/restrict` | ADMIN | Restrict owner namespace slugs (`{slugs:[...]}`) |
| POST | `/admin/accounts/unrestrict` | ADMIN | Remove owner namespace restrictions (`{slugs:[...]}`) |
| POST | `/admin/account/park` | ADMIN | Park account namespace (`{kind:"org"|"user",slug}`) |
| POST | `/admin/account/claim` | ADMIN | Claim account namespace (`{kind:"org"|"user",slug,...}`; `owner_user_id` required when `kind="org"`) |
| GET | `/namespaces/:slug` | PUBLIC | Fetch public namespace metadata: `requested_slug`, `slug`, `renamed`, optional `hold_until`, typed `user`/`org`, and `claimable.user`/`claimable.org` |

Namespace lookup returns typed resources instead of one owner winner; a same-slug user and org can both appear in the response.

## Org Issuers (RouteOrgIssuers, resource-server side)

The inbound accept-side of the platform-delegation handshake. The resource
server stores trusted org issuers; delegated tokens minted by those
issuers (carrying `delegated_sub`) are then validated by the Verifier with
in-house JWKS fetch/refresh (no external push/sync). The outbound side is the
Go `authhttp.OrgIssuersClient` (no route).

Delegated access JWTs are minted with `authhttp.MintDelegatedAccessToken`.
They carry `typ=delegated-access+jwt`, `delegated_sub`, resource-defined
`permissions`, optional JSON `attributes`, and no normal `sub`. They carry NO
org claims of any kind: the VALIDATED `iss` IS the org identity — the
receiving service's issuer registry maps the issuer to exactly one internal
org record (slug + uuid), so neither identifier ever rides in the token and
a host's complete identity is its issuer URL + signing key. Verification
rejects tokens carrying the legacy claims (`delegated_access_has_org`,
`delegated_access_has_org_id`). `delegated_sub` must be the issuer's **immutable, never-reassigned**
subject identifier (OIDC `sub` semantics) — never a username, slug, or email.
All authkit identifiers are opaque strings that happen to be uuidv7; consumers
must not parse them or branch on their format. Ordinary AuthKit access JWTs carry `typ=access+jwt`; resource servers
reject missing, unknown, or cross-profile `typ` values. Delegated access JWTs
must not carry legacy claims such as `org`, `roles`, or
top-level `user_tier`; those are rejected. Resource servers should validate them
with `Verifier.VerifyDelegatedAccess`, optionally installing
permission-catalog and attributes-policy hooks. Org issuers loaded from
this store are bound to their registered `org_slug`; delegated tokens claiming
another resource account are rejected with `resource_account_issuer_mismatch`.
For browser-direct OpenRails billing, a host app should expose its own
authenticated current-user token endpoint, mint a short-lived `aud=openrails`
delegated access JWT for its resource account with self-scoped permissions such as
`openrails:self:billing:read` or `openrails:self:checkout:create`, and let the
browser call OpenRails directly; the host does not need to proxy billing routes.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/org-issuers` | AUTH (org owner/admin) | Register/upsert a org issuer (`{org, issuer, jwks_uri, enabled?}`); also added to the live Verifier |
| DELETE | `/org-issuers` | AUTH (org owner/admin) | Remove a org issuer registration (`{org, issuer}`) |
| GET | `/org-issuers` | ADMIN | List registered org issuers |
