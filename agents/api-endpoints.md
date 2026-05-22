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
| POST | `/password/login` | PUBLIC | Password login (org_mode=multi: optional `org` in body to mint org-scoped access token) |
| POST | `/register` | PUBLIC | Unified registration (email or phone); success returns `next_action`: `none`, `verify_email`, or `verify_phone`; `none` includes access/refresh tokens |
| POST | `/register/resend-email` | PUBLIC | Resend email verification |
| POST | `/register/resend-phone` | PUBLIC | Resend phone verification |
| POST | `/token` | PUBLIC | Refresh access token (org_mode=multi: optional `org` in body to mint org-scoped access token) |
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
| GET | `/user/me` | AUTH | Get current user (org_mode=multi: includes `orgs` list with per-org roles) |
| GET | `/user/bootstrap` | AUTH | Get canonical personal org + org memberships/roles for bootstrap |
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

## Organizations (org_mode=multi only)

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/orgs` | AUTH | List orgs for current user (includes per-org roles) |
| POST | `/orgs` | AUTH | Create an org (creator is bootstrapped as `owner`) |
| GET | `/orgs/:org` | AUTH | Get org metadata (`:org` accepts slug or alias) |
| POST | `/orgs/:org/rename` | AUTH | Rename org slug (keeps old slug as alias) |
| GET | `/orgs/:org/members` | AUTH | List members (org owner) |
| POST | `/orgs/:org/members` | AUTH | Add member (org owner) |
| DELETE | `/orgs/:org/members` | AUTH | Remove member (org owner) |
| GET | `/orgs/:org/invites` | AUTH | List org invites (org owner) |
| POST | `/orgs/:org/invites` | AUTH | Create invite (org owner) |
| POST | `/orgs/:org/invites/:invite_id/revoke` | AUTH | Revoke pending invite (org owner) |
| GET | `/org-invites` | AUTH | List invites for current user |
| POST | `/org-invites/:invite_id/accept` | AUTH | Accept invite as current user |
| POST | `/org-invites/:invite_id/decline` | AUTH | Decline invite as current user |
| GET | `/orgs/:org/roles` | AUTH | List defined roles (org owner) |
| POST | `/orgs/:org/roles` | AUTH | Define role (org owner; `owner` is protected) |
| DELETE | `/orgs/:org/roles` | AUTH | Delete role (org owner; `owner` is protected) |
| GET | `/orgs/:org/members/:user_id/roles` | AUTH | Read member roles (org owner) |
| POST | `/orgs/:org/members/:user_id/roles` | AUTH | Assign role to member (org owner; only owner can grant `owner`) |
| DELETE | `/orgs/:org/members/:user_id/roles` | AUTH | Unassign role from member (org owner; cannot remove last owner) |
| POST | `/token/org` | AUTH | Mint org-scoped access token (`org` + `roles`) |

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
| GET | `/user/2fa` | AUTH | Get 2FA status |
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
| GET | `/owners/:slug` | PUBLIC | Fetch public owner metadata and availability status (`requested_slug`, canonical `slug`, `status`, `claimable`, `renamed`, optional `hold_until`, plus org/user info) |

Owner lookup statuses: `registered_user`, `registered_org`, `parked_user`, `parked_org`, `restricted_name`, `renamed_user`, `renamed_org`, `held_by_deleted_user`, `held_by_deleted_org`, `held_by_recent_user_rename`, `held_by_recent_org_rename`, `unregistered`.

## Federated Orgs (RouteFederation, resource-server side)

The inbound accept-side of the platform-delegation handshake. The resource
server stores trusted federated-org issuers; delegated tokens minted by those
issuers (carrying `delegated_sub`) are then validated by the Verifier with
in-house JWKS fetch/refresh (no external push/sync). The outbound side is the
Go `authhttp.FederationClient` (no route).

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/federated-issuers` | AUTH (org owner/admin) | Register/upsert a federated org's issuer (`{org, issuer_id, jwks_url, status?}`); also added to the live Verifier |
| DELETE | `/federated-issuers` | AUTH (org owner/admin) | Remove a federated org's issuer registration (`{org, issuer_id}`) |
| GET | `/federated-issuers` | ADMIN | List registered federated-org issuers |
