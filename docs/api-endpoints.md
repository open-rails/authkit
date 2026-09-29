# AuthKit API Endpoints Reference

The route table below documents AuthKit's route registry (each route's auth tier, rate-limit bucket and requirements). `(*authkit.Auth).Routes()` is the source of truth for mounted routes.

`(*authkit.Auth).Handler()` requires `Content-Type: application/json` for JSON API request
bodies. Cookie-enabled mounts validate origin and fetch metadata before JSON
mutations execute; browser OIDC callbacks keep their separate state-bound
form-post protocol. See the [refresh-cookie contract](../README.md#refresh-cookie).

AuthKit HTTP handlers are prefix-neutral. The paths below are handler paths; when a host mounts AuthKit API routes at `/api/v1`, `GET /me` becomes public route `GET /api/v1/me`.

Downstream applications that embed AuthKit should mount the AuthKit API at `/api/v1` and should not add an extra `/auth` segment. Browser OIDC routes should usually be mounted outside API versioning at `/oidc/*`.

AuthKit's route registry is the canonical source of truth. `authkit.New`
builds the whole surface once from `Config.HTTP`; hosts mount `Handler()` at
the root, call `Mount(mux)`, or use the `authkitgin`/`authkitfiber` adapters.
`HTTPConfig.Groups` selects route groups (`auth`, `registration`, `account`,
`device_keys`, `admin`, `permission_groups`, `browser_oidc`, `applications`,
`delegated`, `documents`) and `HTTPConfig.Exclude` drops routes the host
shadows (`"GET /api/v1/me"`) — never a duplicated allowlist. Browser OIDC login/callback routes mount under
`/oidc`; account provider linking is self-service user API
(`POST {api}/oidc/{provider}/link/start`).

AuthKit is opinionated about identity validation. Host apps should not
reimplement or customize username, password, email, or phone validation rules.
AuthKit returns stable error codes — listed with their HTTP statuses in
`sdk/auth-ui/src/client/generated/error-codes.ts` — such as `username_too_short`,
`username_must_start_with_letter`, `username_invalid_characters`,
`username_in_use`, `username_not_allowed`, `rename_rate_limited`,
`invalid_email`, `invalid_phone_number`, `password_too_short`, `password_too_long`,
`password_requirements_unmet`, `password_contains_identifier` and `password_too_common`.
Password and username policies are host-configured and published in
`GET {api}/capabilities` (see [capabilities](capabilities.md)).

**Success shapes (#313):** session routes return `iam.TokenSet`
(`{access_token, token_type, expires_in, refresh_token?}`) alone, or under `token_set` beside
route fields (registration `{next_action, user, token_set?}`, step-up `{token_set, fresh_auth}`,
device keys `{token_set, device_key}`, passwordless/SIWS/OIDC-json extras). Lists are
`{object:"list", data:[...], next_cursor?}` and take `?cursor=&limit=`; `GET {api}/admin/users/{user_id}/signins`
lists `iam.SessionEvent` sign-ins and failed sign-ins, newest first. `POST {api}/admin/users/{user_id}/sessions/revoke` returns
`iam.AccountSessionRevocation`. Mutations with nothing to return answer `204`;
anti-enumeration sends answer `202` with an empty body. Pending challenges are `403` error
envelopes (`2fa_required`, `2fa_enrollment_required`, `verification_required`) with the
challenge in `metadata`. `GET /me` returns the account profile.

**Error envelope (Stripe-style, nested, same shape as OpenRails).** Every error
response is:

```json
{ "error": { "type": "invalid_request_error", "code": "password_too_short",
             "message": "Password too short.", "param": "password",
             "metadata": { "...": "optional machine-readable context" } } }
```

- `code` is the stable machine code; every 500 is `internal_error`. Match on
  `error.code`. In Go, `iam.AsError(err)` returns the `iam.Error` (`Code`,
  `Status`, `Param`, `Metadata`) and `errors.Is` matches the `iam.Err*`
  sentinels; `iam.WriteError`, `authkitgin.Error` and `authkitfiber.Error`
  write the envelope, and a Go client reads it back with
  `iam.DecodeError(resp)`.
- `type` is derived from the HTTP status: `invalid_request_error` (400/404/409),
  `authentication_error` (401), `authorization_error` (403),
  `rate_limit_error` (429), `api_error` (5xx).
- `message` is human-readable (English); `param` names the offending field on
  validation errors; `metadata` carries rate-limit/availability context
  (e.g. `retry_after_seconds`, and username rename's `time_until_rename_available`).

Closed/private deployments should seed AuthKit-owned authority through the
library/CLI bootstrap path, not a public HTTP admin route:
`authkit.LoadBootstrapManifestFile`, `authkit.ParseBootstrapManifestYAML`, and
`(*authkit.Auth).ApplyBootstrapManifest(ctx, iam.OperatorActor(), manifest, opts)`, or
`EnsureUserRole` for a single first admin. Bootstrap uses an existing account only through a
verified email or phone the manifest names; it never adopts one by username, alias or unverified
contact. Host applications layer their own domain bootstrap after AuthKit has applied users,
root role assignments and remote applications.

## Route table

<!-- routes:begin -->
`{api}` is the mount's `APIPrefix` (default `/api/v1`); `{oidc}` is `/oidc`. Bucket = the per-IP rate-limit bucket the registry applies before the handler (per-identifier and branch buckets live in the handler). Mounted when = the configuration that enables the route (blank = always).

| Method | Path | Group | Auth | Bucket | Mounted when |
|---|---|---|---|---|---|
| GET, HEAD | `/.well-known/authkit/documents/{digest}` | root | reader application (`Documents.Readers`) |  | Documents.Readers |
| GET | `/.well-known/jwks.json` | root | public |  |  |
| POST | `{api}/2fa/challenge` | auth | public | `auth_2fa_verify` | TwoFactor.Mode != disabled |
| POST | `{api}/2fa/verify` | auth | public | `auth_2fa_verify` | TwoFactor.Mode != disabled |
| GET | `{api}/capabilities` | auth | public |  |  |
| DELETE | `{api}/logout` | auth | required | `auth_logout` |  |
| POST | `{api}/passkeys/login/begin` | auth | public | `auth_passkey_login` | Passkeys.RPID |
| POST | `{api}/passkeys/login/finish` | auth | public | `auth_passkey_login` | Passkeys.RPID |
| POST | `{api}/password/login` | auth | public | `auth_password_login` |  |
| POST | `{api}/account/recovery/confirm` | auth | public | `auth_password_login` |  |
| POST | `{api}/password/reset/confirm` | auth | public | `auth_pwd_reset_confirm` |  |
| POST | `{api}/password/reset/request` | auth | public | `auth_pwd_reset_request` |  |
| POST | `{api}/passwordless/confirm` | auth | public | `auth_passwordless_confirm` | Registration.PasswordlessLogin |
| POST | `{api}/passwordless/start` | auth | public | `auth_passwordless_start` | Registration.PasswordlessLogin |
| POST | `{api}/solana/challenge` | auth | public | `auth_solana_challenge` | SolanaNetwork |
| POST | `{api}/solana/login` | auth | public | `auth_solana_login` | SolanaNetwork |
| POST | `{api}/token` | auth | public | `auth_token` |  |
| POST | `{api}/register` | registration | public | `auth_register` | Registration.NativeUserMode != closed |
| POST | `{api}/register/abandon` | registration | public | `auth_register_abandon` | Registration.NativeUserMode != closed |
| GET | `{api}/register/availability` | registration | public | `auth_register_availability` |  |
| GET | `{api}/me` | account | required | `auth_user_me` |  |
| GET | `{api}/me/groups` | account | required |  |  |
| GET | `{api}/me/permissions` | account | required |  |  |
| POST | `{api}/oidc/{provider}/link/start` | account | required |  | Identity.Providers |
| POST | `{api}/oidc/{provider}/step-up/start` | account | required |  | Identity.Providers |
| GET | `{api}/passkeys` | account | required |  | Passkeys.RPID |
| POST | `{api}/passkeys/register/begin` | account | required | `auth_passkey_register` | Passkeys.RPID |
| POST | `{api}/passkeys/register/finish` | account | required | `auth_passkey_register` | Passkeys.RPID |
| DELETE | `{api}/passkeys/{id}` | account | required |  | Passkeys.RPID |
| PATCH | `{api}/passkeys/{id}` | account | required |  | Passkeys.RPID |
| POST | `{api}/solana/link` | account | required | `auth_solana_link` | SolanaNetwork |
| POST | `{api}/step-up/2fa` | account | required |  | TwoFactor.Mode != disabled |
| POST | `{api}/step-up/password` | account | required |  |  |
| DELETE | `{api}/user` | account | required | `auth_user_delete` |  |
| DELETE | `{api}/user/2fa` | account | required | `auth_2fa_disable` | TwoFactor.Mode != disabled |
| GET | `{api}/user/2fa` | account | required | `auth_user_me` | TwoFactor.Mode != disabled |
| POST | `{api}/user/2fa` | account | required | `auth_2fa_enable` | TwoFactor.Mode != disabled |
| POST | `{api}/user/2fa/backup-codes` | account | required | `auth_2fa_regenerate_codes` | TwoFactor.Mode != disabled |
| POST | `{api}/user/password` | account | required | `auth_user_password_change` |  |
| PATCH | `{api}/user/preferred-language` | account | required | `auth_user_preferred_language` |  |
| DELETE | `{api}/user/providers/{provider}` | account | required | `auth_user_unlink_provider` |  |
| DELETE | `{api}/user/sessions` | account | required | `auth_sessions_revoke_all` |  |
| GET | `{api}/user/sessions` | account | required | `auth_sessions_list` |  |
| DELETE | `{api}/user/sessions/{id}` | account | required | `auth_sessions_revoke` |  |
| PATCH | `{api}/user/username` | account | required | `auth_user_update_username` |  |
| POST | `{api}/verify/confirm` | account | optional | `auth_verify_confirm` |  |
| POST | `{api}/verify/request` | account | optional | `auth_verify_request` |  |
| GET | `{api}/device-keys` | device_keys | required | `auth_device_keys_manage` | DeviceKeys.Enabled |
| POST | `{api}/device-keys/enroll/begin` | device_keys | public | `auth_device_key_enroll_begin` | DeviceKeys.Enabled |
| POST | `{api}/device-keys/enroll/finish` | device_keys | public | `auth_device_key_enroll_finish` | DeviceKeys.Enabled |
| POST | `{api}/device-keys/login/begin` | device_keys | public | `auth_device_key_login_begin` | DeviceKeys.Enabled |
| POST | `{api}/device-keys/login/finish` | device_keys | public | `auth_device_key_login_finish` | DeviceKeys.Enabled |
| POST | `{api}/device-keys/revoke-others` | device_keys | required | `auth_device_keys_manage` | DeviceKeys.Enabled |
| DELETE | `{api}/device-keys/{id}` | device_keys | required | `auth_device_keys_manage` | DeviceKeys.Enabled |
| GET | `{oidc}/{provider}/callback` | browser_oidc | public | `auth_oidc_callback` | Identity.Providers |
| POST | `{oidc}/{provider}/callback` | browser_oidc | public | `auth_oidc_callback` | Identity.Providers |
| GET | `{oidc}/{provider}/login` | browser_oidc | public |  | Identity.Providers |
| POST | `{oidc}/{provider}/login` | browser_oidc | public |  | Identity.Providers |
| GET | `{oidc}/{provider}/step-up/callback` | browser_oidc | public | `auth_oidc_callback` | Identity.Providers |
| POST | `{oidc}/{provider}/step-up/callback` | browser_oidc | public | `auth_oidc_callback` | Identity.Providers |
| POST | `{api}/delegated/token` | delegated | required | `delegated_token_mint` | Delegated.Audiences |
| POST | `{api}/applications/register` | applications | signed request (domain proof) | `application_register` | Applications.SelfRegistration |
| POST | `{api}/admin/users/{user_id}/restore` | admin | required (engine: `root:users:delete` + account coverage) | `auth_admin_user_sessions_revoke_all` |  |
| GET | `{api}/admin/users` | admin | `root:users:read` | `auth_admin_user_sessions_list` |  |
| DELETE | `{api}/admin/users/{user_id}` | admin | required (engine: `root:users:delete` + account coverage) | `auth_admin_user_sessions_revoke_all` |  |
| GET | `{api}/admin/users/{user_id}` | admin | `root:users:read` |  |  |
| POST | `{api}/admin/users/{user_id}/ban` | admin | required (engine: `root:users:ban` + account coverage) | `auth_admin_user_sessions_revoke_all` |  |
| POST | `{api}/admin/users/{user_id}/sessions/revoke` | admin | required (engine: `root:users:manage` + account coverage) | `auth_admin_user_sessions_revoke_all` |  |
| GET | `{api}/admin/users/{user_id}/signins` | admin | `root:users:read` |  |  |
| GET | `{api}/admin/roles` | admin | `root:members:read` |  |  |
| PUT | `{api}/admin/users/{user_id}/roles/{role}` | admin | required (engine: `root:members:manage` + role coverage) | `auth_admin_user_sessions_revoke_all` |  |
| DELETE | `{api}/admin/users/{user_id}/roles/{role}` | admin | required (engine: `root:members:manage` + role coverage) | `auth_admin_user_sessions_revoke_all` |  |
| POST | `{api}/admin/users/{user_id}/unban` | admin | required (engine: `root:users:ban` + account coverage) | `auth_admin_user_sessions_revoke_all` |  |
| POST | `{api}/invites/redeem` | permission_groups | required |  | Roles.Personas |
| POST | `{api}/org` | permission_groups | required |  | Creation.Enabled |
| GET | `{api}/org/{instance_slug}` | permission_groups | `org:self:read` |  | Roles.Personas |
| PATCH | `{api}/org/{instance_slug}` | permission_groups | `org:self:update` |  | Roles.Personas |
| DELETE | `{api}/org/{instance_slug}` | permission_groups | `org:self:delete` |  | Roles.Personas |
| GET | `{api}/org/{instance_slug}/api-keys` | permission_groups | `org:credentials:read` |  | Roles.Personas |
| POST | `{api}/org/{instance_slug}/api-keys` | permission_groups | `org:credentials:manage` |  | Roles.Personas |
| DELETE | `{api}/org/{instance_slug}/api-keys/{key}` | permission_groups | `org:credentials:manage` |  | Roles.Personas |
| GET | `{api}/org/{instance_slug}/invites/links` | permission_groups | `org:members:read` |  | Roles.Personas |
| POST | `{api}/org/{instance_slug}/invites/links` | permission_groups | `org:members:manage` |  | Roles.Personas |
| DELETE | `{api}/org/{instance_slug}/invites/links/{link}` | permission_groups | `org:members:manage` |  | Roles.Personas |
| GET | `{api}/org/{instance_slug}/members` | permission_groups | `org:members:read` |  | Roles.Personas |
| POST | `{api}/org/{instance_slug}/members` | permission_groups | `org:members:manage` |  | Roles.Personas |
| DELETE | `{api}/org/{instance_slug}/members/{user}` | permission_groups | `org:members:manage` |  | Roles.Personas |
| PUT | `{api}/org/{instance_slug}/members/{user}/roles/{role}` | permission_groups | `org:members:manage` |  | Roles.Personas |
| GET | `{api}/org/{instance_slug}/remote-applications` | permission_groups | `org:credentials:read` |  | Roles.Personas |
| POST | `{api}/org/{instance_slug}/remote-applications` | permission_groups | `org:credentials:manage` |  | Roles.Personas |
| DELETE | `{api}/org/{instance_slug}/remote-applications/{app}` | permission_groups | `org:credentials:manage` |  | Roles.Personas |
| PUT | `{api}/org/{instance_slug}/remote-applications/{app}/roles/{role}` | permission_groups | `org:credentials:manage` |  | Roles.Personas |
| GET | `{api}/org/{instance_slug}/roles` | permission_groups | `org:members:read` or `org:roles:manage` |  | Roles.Personas |
| POST | `{api}/org/{instance_slug}/roles` | permission_groups | `org:roles:manage` |  | Roles.Personas |
| DELETE | `{api}/org/{instance_slug}/roles/{role}` | permission_groups | `org:roles:manage` |  | Roles.Personas |
<!-- routes:end -->

## Authentication Levels

| Level | Description |
|-------|-------------|
| **PUBLIC** | No authentication required. |
| **AUTH** | Requires valid JWT token (logged-in user). |
| **PERM** | Requires the listed permission through AuthKit's permission-group engine. |
| **LIVE** | AUTH plus a per-request account-liveness lookup (ak#267). See below. |

**AUTH is stateless by design** (ak#215): `verify.Required` / `VerifyRequest` do
zero DB lookups on the native-user path, so a banned or deleted user keeps a
valid access token until it expires (≤1 access TTL). Ban/deleted is enforced at
token mint (login + refresh).

**LIVE is the opt-in stateful twin** (ak#267, v0.92.0).
`authkit.New` supplies the engine as its verifier's liveness source.
Standalone `verify.NewVerifier()` users wire `verifier.WithLiveness(auth)`
explicitly. Mount `verify.RequiredLive` (or `authkitgin.RequiredLive`,
`auth.RequireLive`) instead of `Required`. It denies
banned, deleted, reserved and unknown accounts on the user's NEXT request, and hands the handler `Username`/`Email`/`EmailVerified`
FRESH as of that lookup — **do not read the account per request to refresh
display fields.** Roles and entitlements are not re-enriched. `verifier.IsLive`
is the bare predicate; the batch read underneath is `Auth.Users(ctx, ids)`
(`iam.User.Live`).

Fail-closed, no cache: a lookup error denies, and there is exactly one liveness
lookup per gated request with no memoization (any cache reintroduces the window
the gate closes). Building `RequiredLive` on a verifier with no source returns
`verify.ErrLivenessUnconfigured` from the constructor, never a 401.

`verify.OptionalLive` is the anonymous-capable opt-in: missing Authorization
passes without a lookup; presented credentials must verify and native users
must be live. It has the same startup source requirement and failure behavior
as `RequiredLive`. Mount either live middleware per route, on a group/subtree,
or globally at the application handler. Ordinary `Required` and `Optional`
remain stateless; there is no automatic admin-role inference or global flag.

AuthKit's root-permission routes also require current liveness for an
authorized native user before running the elevated operation. This covers the
admin directory, ban, recovery and deletion endpoints. Credential-based checks
for non-user principals remain unchanged; ordinary AUTH routes stay stateless.

**Rendering users to other users**: use `Auth.PublicUsers(ctx, ids) →
map[string]iam.PublicUser`, never `Users` (whose `iam.User` carries contact
details) and never a direct read of `profiles.users`. `iam.PublicUser` is
`{ID, Username, AvatarURL, CreatedAt, Deleted}`. Soft-deleted users return as
TOMBSTONES (`Deleted` set, display fields blank); banned users return normally
(a ban is an access decision, not a visibility one); unknown ids are absent.
`u.DisplayName()` / `iam.PublicDisplayName(users, id)` render `user-<id8>` for
tombstoned and unresolved ids, so no caller needs a fallback
branch. Derived assets (extra avatar sizes, CDN rewrites) stay host-owned.

---

## OIDC Browser Flows

Provider-link callbacks are mutations: `format=json` returns an empty 204;
browser completion redirects with `flow=link&result=success&provider=...` in the
fragment. Neither creates a session or replaces tokens/cookies. The initiating
session must still be live and fresh. See [credential grants](security/credential-grants.md).

Notes:
- After AuthKit handles the provider callback, full-page login redirects to `{BaseURL}{OIDCReturnPath}`. The default OIDC return path is `/login/callback`; host apps may configure another app-relative path.
- `GET /oidc/:provider/login?return_to=/subscribe?plan=pro` preserves the app-relative path through the provider redirect and returns it as `return_to` in the callback URL fragment. AuthKit rejects absolute URLs, protocol-relative URLs, backslashes, and CR/LF before storing it.
- JSON/SPAs flows such as password login, registration, in-app 2FA, and POST-based verification/reset do not navigate away; the client owns any `return_to` state for those flows.

---

## Registration & Login

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

Step-up updates the current refresh-session auth state but does not rotate the refresh token. Clients should retry sensitive actions with the returned access token; `POST /token` remains the refresh-token rotation route.

## Authentication continuation

- Password login, contact verification, passwordless login, and provider callbacks
  use the same first-factor decision: session, MFA challenge, or restricted
  enrollment. Confirming an email/SMS proof does not bypass MFA.
- `403 2fa_required` carries `error.metadata` with `user_id`, `challenge`,
  `method`, `verification_id`, `default_factor`, and `available_factors`.
  Submit `{user_id, challenge, code, factor_id?, backup_code?}` to `POST /2fa/verify`;
  success returns a flat `TokenSet`. Use `POST /2fa/challenge` with the same
  `user_id`, `challenge` and chosen `factor_id` to resend/select a factor.
- An email/SMS code (login or `POST /step-up/2fa`) lasts ten minutes and is
  spent only by a correct submission; a wrong code returns `401 invalid_code`
  and the same code can be retried. The fifth wrong code invalidates it and
  returns `401 code_expired`, as does any submission while no code is live
  (expired, never sent, already spent). Resend on `code_expired`; a resend
  issues a new code with a fresh budget. `auth_2fa_verify` also caps attempts
  per `user_id`.
- `403 2fa_enrollment_required` includes `user_id`, `allowed_methods`, and
  `token_set` containing an enrollment-only access token with no refresh token.
  Use it only to enroll at `POST /user/2fa`; it does not authorize normal account
  use or factor management. Confirmed enrollment returns
  `{enabled, method, backup_codes?, token_set}` with the completed session.
- AMR records the actual proofs (`pwd`, `email`, `sms`, `oauth`, `totp`,
  `backup_code`). An email/SMS first factor cannot use that same channel again
  as its second factor. A usable different factor or unused backup code is
  required; otherwise that passwordless attempt fails closed.
- Challenges are single-use, account/version/issuer bound, and expire after ten
  minutes from the first factor. A new first factor replaces the account's
  pending login continuation. Recovery, provider unlink, and source-session
  revocation cannot leave an earlier continuation usable.
- Browser provider callbacks use the same fields in the frontend URL fragment
  (objects/arrays are JSON encoded). Enrollment uses `enrollment_token` and
  `enrollment_expires_in`; popup results carry native objects/arrays.

Passwordless login:

- Enable `Registration.PasswordlessLogin`; unknown-contact signup additionally
  needs `PasswordlessAutoRegistration`. Under InviteOnly, email and SMS both
  require an unbound `account_invite_token` at start, consumed with creation of
  the account and any invitation role in one transaction. Existing contacts can
  still authenticate without an invitation.
- `POST /passwordless/start` returns `202` for an eligible request. With automatic
  signup disabled, unknown contacts receive the same response without delivery.
- Code and link are alternate representations of one proof: only one may finish.
  Resending invalidates previous representations. Confirm returns
  `{token_set, return_to?}` for an issued session or the continuation above.
  Automatic signup creates no password row.
- Verification, reset, and passwordless links target the configured frontend
  landing path directly with `#status=ready&channel=...&token=...`.
  The frontend parses the fragment and POSTs the token to the confirm endpoint.
  Verification/reset use `email|phone`; passwordless uses `email|sms`.
  A spent, expired or unknown link answers `400 invalid_link` (the session is
  untouched; `invalid_token` is only for bearer and refresh tokens); a wrong or
  spent code answers `401 invalid_code`.
  Absolute or protocol-relative `return_to` values are dropped. There are no
  GET confirmation bridges. Invitation links carry `#account_invite_token=...`.

Passkeys:
- Configure `authkit.Config.Passkeys` with `RPID`, `RPDisplayName`, and `Origins`;
  empty values derive from `Frontend.BaseURL`/`Token.Issuer`.
- Registration is authenticated and freshness-gated:
  `POST /passkeys/register/begin`, then POST the `PublicKeyCredential` JSON from
  `navigator.credentials.create()` to `/passkeys/register/finish`.
- Management routes are authenticated: `GET /passkeys`, `PATCH /passkeys/:id`
  with `{ "label": "..." }`, and `DELETE /passkeys/:id`.
- Login begins with an empty body or `{}` at `POST /passkeys/login/begin`;
  assertions are discoverable and accept no identifier. A verified UV assertion
  mints `swk,mfa` assurance and satisfies both Required mode and an already-held
  MFA-required role without an unrelated traditional-factor enrollment.
- Frontends should use `navigator.credentials.create({ publicKey })` and
  `navigator.credentials.get({ publicKey })`; for conditional UI, render the
  username input with `autocomplete="username webauthn"` and call
  `navigator.credentials.get({ publicKey, mediation: "conditional" })`.

Reserved names: an account whose metadata sets `reserved: true` (an import can)
is a placeholder that holds its username, cannot sign in and grants nothing.
There is no hardcoded denylist: a reserved name answers the normal in-use
conflict, and hosts refuse names with `Deps.NameAdmission`.

---

## Password Reset

Request-code endpoints are rate-limited by default: one request per client every 60 seconds and 6 per hour for registration, email/phone verification, passwordless start, password reset, and email/phone change flows. `429` responses include `Retry-After` and `retry_after_seconds` when AuthKit can compute the reset time.

`POST /verify/request` without a session answers `202` for every well-formed identifier, like `POST /password/reset/request`, and sends a code only to an account or pending registration whose address is unproven; it never reveals whether an account exists or is verified; it is also how a pending registration's code is resent. It returns validation errors for malformed identifiers.

---

For verification and 2FA send operations, a 2xx response means AuthKit submitted the message to the configured email/SMS provider. Provider submission failures return stable public errors such as `email_delivery_failed` or `sms_delivery_failed`; downstream mailbox/carrier delivery is outside AuthKit's synchronous confirmation boundary.

---

## Permission Groups

A persona is the route and permission namespace: a `merchant` persona generates
`/merchant/{instance_slug}/...` routes gated by `merchant:<resource>:<action>`
permissions ([roles](roles.md)). Every persona but root gets the group's own
`GET`/`PATCH`/`DELETE`, members, invite links and the role list;
`Creation.Enabled` adds `POST /merchant`, `CustomRoles` the custom-role routes,
`APIKeys` the API-key routes and `RemoteApplications` the application routes.
Root's roles are managed under `/admin`. Every generated route checks `Can`
live for the calling actor and refuses delegated tokens.

`POST /<persona>/<slug>/members` with `email` never adds an account: every
address gets the same `202` role-carrying invitation, accepted by registering
with it or by redeeming it at `POST /invites/redeem` signed in to the account
that verified that address.

---

## API keys (opaque machine credentials)

Long-lived, revocable bearer credentials owned by a permission group, for
machine/automation callers (CI, operator CLIs, service-to-service). A key acts
as `iam.APIKeyActor(id)` in its own group only: middleware sets `Claims.APIKeyID`
and `TokenType = verify.APIKeyPrincipalType`, with no `UserID`. Its permissions
are those of its role, from the persona's catalog.

**Presentation.** `Authorization: Bearer <prefix>_st_<lookup_id>_<secret>`. `<prefix>` is
the host's configured `authkit.Config.APIKeys.Prefix` brand (e.g. `cozy` → `cozy_st_…`); empty →
bare `st_`. `lookup_id` is a non-secret public id for O(1) indexed lookup; only
`sha256(secret)` is stored. The full token is shown **once** at creation.

**Resolution** happens in the `Required`/`Optional` middleware *before* JWT
verification: tokens carrying the configured marker are looked up by `lookup_id`,
the secret is compared in constant time, and revoked/expired/group-deleted tokens
and tokens of a banned or deleted creator are rejected. Non-API-key credentials fall through to normal JWT verification. The API key
path is distinct from the password-login handler, so API keys **bypass the
interactive password-login rate limiter by design** (a robot must not use the
human login path).

**Mint authorization (native, role-based).** Minting requires the generated
`<persona>:credentials:manage` permission. The request body supplies one `role`;
AuthKit validates that the role exists in the target group and enforces
no-escalation. Permissions resolve from that role at verify time rather than
being frozen into the key. No key may hold a role that needs MFA; a role that
comes to need it (a `RequireMFA` change) confers nothing and the key is revoked
at the next boot. A persona without `APIKeys` has no keys, even from the
operator. Only a user
(or the host's operator actor, whose keys have no creator) issues keys and
invite links; machine actors never do. The JSON field for the public id is
`lookup_id`, and lists use the standard list envelope.
Revoking a key, or an invite link, needs the same authority as minting its
role. A key or link is revoked automatically once its creator can no longer
mint its role, including after a role-catalog change at boot.

## Service JWTs (OIDC/JWKS machine credentials)

First-party services that have their own AuthKit issuer/JWKS should mint
short-lived service JWTs instead of receiving generated opaque API keys
from the resource service. The canonical token shape is `iss`, `sub`, `aud`,
`iat`, `nbf`, `exp`, `jti`, `token_use=service` and `permissions: []`. An OAuth
`scope` claim grants nothing. AuthKit's default mint lifetime is 15 minutes.

Use `authkit.MintServiceJWT` or `(*authkit.Auth).MintServiceJWT` on the caller side,
and `(*verify.Verifier).VerifyServiceJWT` on the receiver side. Verification uses registered issuers/JWKS, including
remote-application issuer lazy-load; disabled issuer rows fail closed. AuthKit parses requested
permissions but does not grant them. The resource service must
intersect requested permissions with server-side grants for the issuer/subject.

Recommended pattern for Doujins/Hentai0 -> OpenRails: caller caches a 15-minute
service JWT in memory until near expiry, sends `Authorization: Bearer <jwt>`,
OpenRails verifies the issuer/JWKS and audience, then authorizes using
OpenRails-owned service grants. Generated opaque API keys remain for
non-OIDC clients, manual API-key-like credentials, and bootstrap/admin scripts.

API-key mint body:

```json
{
  "name": "cozy-spend",
  "role": "spender",
  "expires_at": "2027-01-01T00:00:00Z"
}
```

**Lifetime.** Optional `expires_at` (null = non-expiring). A host may set a max
TTL that caps the effective expiry. Revoke at any time; expiry + revocation are
checked on every request.

**Storage.** `profiles.api_keys` (`key_id` unique, `secret_hash` bytea,
single `role`, `created_by` NULL only for operator-issued keys and
`ON DELETE CASCADE` so no key outlives its creator, nullable
`expires_at`/`revoked_at`, `last_used_at` touched best-effort/async). A key of a
banned, deleted or reserved creator is refused.

**Configuration.** `authkit.Config.APIKeys.Prefix` (lowercase alnum, ≤16 chars; empty
→ `st_`) and `authkit.Config.APIKeys.MaxTTL` (0 = no cap).

---

## Two-Factor Authentication

`POST /user/2fa` enrolls a factor in two steps. `{method}` starts it: TOTP
returns `{secret, otpauth_uri}`; email and SMS (`phone_number` required) send a
setup code and return `202`. `{method, code}` confirms it; for an email setup
code a miss is `401 invalid_code` and, on the fifth miss or with no live code,
`401 code_expired`. Every factor is
proven before it is stored, and an email or SMS factor stays bound to the
address or number it was proven for; only the account's own confirmed email
change (`POST /verify/request` with a session, then `/verify/confirm`) moves an
email factor to the new address. `GET /user/2fa` lists each factor with its
phone number or masked address (`email`, as `a***@example.com`). A full
session must be fresh (`step_up_required` otherwise; MFA-fresh once any factor
exists).

For an account with a second factor, fresh means that factor within the
window: `POST /step-up/password`, a provider step-up and an inline password all
answer `step_up_required` with `mfa_required`, and the token's `auth_time` is
when the session last proved the factor. Device keys pass the same session MFA
gate as every login: a key counts as a second factor only when its enrollment
proved one independent of the emailed enrollment code (`code_2fa`: a TOTP or
SMS code or a backup code, never the email factor), so a key enrolled before
the account had a factor is refused (`2fa_required`) until re-enrolled with it.
An account that needs MFA (an MFA-required role, or Required 2FA) and has a
passkey but no factor signs in with the passkey; any other first factor answers
`403 passkey_required`, never an enrollment token; if the passkey is lost, the
operator's `Auth.ResetAccountMFA` clears the account's second factors so its
next sign-in enrolls one. Device-key enrollment refuses a revoked key or one
bound to another account before asking for a second factor, and spends a
backup code only when the key is enrolled. A password change or reset revokes
every device key but the one making the change. See [device keys](device-keys.md) for the
protocol and the Go client.

The confirming session becomes 2FA-verified: its refresh session gains
`<method>, otp, mfa` and a fresh authentication time, exactly as
`POST /step-up/2fa` with the new factor would. The response then carries
`{enabled, method, backup_codes?, token_set, fresh_auth}`; `token_set` has only
an access token with the new `amr`/`acr`, and later `POST /token` refreshes
return tokens, not `2fa_required`. An email/SMS factor on the channel that was
the session's first factor is not independent and verifies nothing. Other
sessions keep their proofs: their next refresh returns `2fa_required`, or
`step_up_required` when older than ten minutes.

Hosts mark permissions that need 2FA with `Persona.RequireMFA`; any role reaching
one needs MFA ([roles](roles.md)). Assigning that role, or redeeming an invite
link for it, returns `2fa_enrollment_required` until account MFA is enabled with
at least one factor. Disabling MFA removes those MFA-required user role
assignments.

---

## Remote Application Issuers (resource-server side)

The inbound accept-side of the platform-delegation handshake. The resource
server stores trusted remote applications; delegated tokens minted by those
issuers (carrying `delegated_sub`) are then validated by the Verifier with
in-house JWKS fetch/refresh (no external push/sync).

Delegated access JWTs are minted with `(*authkit.Auth).MintDelegatedAccessToken`.
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
