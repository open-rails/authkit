# AuthKit Breaking Changes

This records the breaking API changes from the recent `v0.54.1` to `v0.56.2`
cut. Use it when updating host apps to the current AuthKit API.

## Versions Covered

- `v0.56.0`: finalized the smaller public AuthKit API.
- `v0.56.1`: restored host facade methods needed by consumers.
- `v0.56.2`: restored imported-user update facade support.

## Go API

### Public facade was collapsed

The old faceted API was removed:

- `svc.Users()`
- `svc.Roles()`
- `svc.APIKeys()`
- `svc.Tokens()`
- `svc.TwoFactor()`
- `svc.Sessions()`
- `svc.Identity()`
- `svc.Bootstrap()`

Use the direct `*core.Service` facade methods instead, for example:

- `svc.AdminListUsers(...)`
- `svc.GetUserByEmail(...)`
- `svc.ImportUsers(...)`
- `svc.UpdateImportedUser(...)`
- `svc.AssignGroupRole(...)`
- `svc.ListSubjectGroups(...)`
- `svc.MintAPIKeyWithOptions(...)`
- `svc.LinkProviderByIssuer(...)`
- `svc.ReconcileBootstrapManifest(...)`

Many old facet helpers were intentionally not re-exposed. If code still calls a
removed helper, replace it with the current HTTP flow or one of the direct
facade methods above instead of re-expanding the facade.

Common removed helpers include:

- `ConfirmPendingRegistration(...)`
- `ConfirmEmailVerification(...)`
- `ConfirmPendingPhoneRegistrationByToken(...)`
- `ConfirmPhoneVerificationByToken(...)`
- `GetPendingRegistrationByEmail(...)`
- `GetPendingPhoneRegistrationByPhone(...)`
- `BeginPasswordReset(...)`
- `ConfirmPasswordReset(...)`
- `PasswordLogin(...)`
- low-level 2FA helpers such as `Create2FAChallenge(...)`,
  `Verify2FACode(...)`, and `RegenerateBackupCodes(...)`

### Permission groups were renamed to personas/resource slugs

The permission-group model now uses persona/resource-slug names consistently.

- `GroupTypeDef` -> `PersonaDef`
- `IntrinsicRootType(...)` -> `IntrinsicRootPersona(...)`
- `RootType` -> `RootPersona`
- `CreatePermissionGroupRequest.Type` -> `Persona`
- `CreatePermissionGroupRequest.ResourceRef` -> `ResourceSlug`
- `CreatePermissionGroupRequest.ParentType` -> `ParentPersona`
- `ResolveGroupIDForRef(...)` -> `ResolveGroupIDForSlug(...)`
- `SubjectGroupMembership.ResourceRef` -> `ResourceSlug`
- API-key methods now take `(persona, resourceSlug, ...)`, not
  `(groupType, resourceRef, ...)`.

### Org naming was removed from machine credentials

The old org-shaped fields are gone from AuthKit-owned credentials.

- `ResolvedAPIKey.OrgID` -> `PermissionGroupID`
- `ResolvedAPIKey.OrgSlug` was removed.
- `RemoteApplication.OrgID` -> `PermissionGroupID`
- `authbase/org.go` was removed.

### Remote application issuer client was renamed

- `NewOrgIssuersClient` -> `NewRemoteApplicationIssuersClient`
- `WithOrgIssuersHTTPClient` -> `WithRemoteApplicationIssuersHTTPClient`
- `WithOrgIssuersAuthToken` -> `WithRemoteApplicationIssuersAuthToken`
- `OrgIssuersRegistration` -> `RemoteApplicationIssuerRegistration`

### Config shape changed

- `RBACConfig.DefaultRoles` was removed.
- `RBACConfig.OwnerOwnsAppResources` was removed.
- `RBACConfig.Groups []GroupTypeDef` -> `RBACConfig.Groups []PersonaDef`
- `FrontendConfig` added:
  - `VerifyPath`
  - `PasswordResetPath`
- `Config` added:
  - `Passkeys PasskeyConfig`
- `TwoFactorConfig.Mandatory` was removed from config; mandatory 2FA policy is
  represented on persona roles with `RoleDef.RequiresMFA`.

`RoleDef` added:

- `RequiresMFA bool`

### Verification and password-reset senders changed

AuthKit now builds final scanner-safe URLs. Senders receive final URLs instead
of raw tokens plus host URL builders.

`VerificationMessage` changed:

```go
type VerificationMessage struct {
    Code    string
    LinkURL string
}
```

Old field removed:

- `VerificationMessage.LinkToken`

Sender signatures changed:

- `EmailSender.SendPasswordResetLink(ctx, email, username, token)` ->
  `EmailSender.SendPasswordResetLink(ctx, email, username, resetURL)`
- `SMSSender.SendPasswordResetLink(ctx, phone, token)` ->
  `SMSSender.SendPasswordResetLink(ctx, phone, resetURL)`

Twilio provider config changed:

- `VerificationLinkURL` was removed.
- `ResetLinkURL` was removed.
- email `VerificationBuilder` no longer receives a separate verification URL.
- email `PasswordResetBuilder` now receives only the final `resetURL`.
- SMS reset builders likewise receive final URLs from AuthKit.

### Import API changed

- `ImportUser(...)` was removed.
- Use `ImportUsers(ctx, []core.ImportUserInput{...})`.
- `UpdateImportedUser(...)` remains available for reconciliation.

New import result types:

- `ImportUsersResult`
- `ImportUserResult`
- `ImportUserStatus`
- `ImportStatusInserted`
- `ImportStatusSkipped`
- `ImportStatusRejected`

### New public auth/security types

The current public API includes token-assurance, 2FA, and passkey types:

- `SessionFreshness`
- `AssuranceLevelPassword`
- `AssuranceLevelMFA`
- `TwoFactorFactor`
- `TwoFactorSettings`
- `MFAStatus`
- `Passkey`
- `PasskeyConfig`
- `PasskeyLoginResult`
- `ErrPasskeyUserVerificationRequired`

### Database migration layout changed

The Postgres migration history was compacted into the baseline migration:

- `migrations/postgres/001_auth_schema.up.sql` is the current baseline.
- Old incremental files `002` through `012` were removed.

Existing deployed databases need an explicit migration plan; new installs should
start from the compacted baseline.

## HTTP / Frontend API

### Password reset and verification links are scanner-safe

GET landings were added. GET does not consume the token; it redirects/lands the
frontend with the token so the frontend can POST to confirm.

New GET routes:

```http
GET /email/password/reset/confirm
GET /phone/password/reset/confirm
GET /email/verify/confirm
GET /phone/verify/confirm
```

The consuming routes remain POST:

```http
POST /email/password/reset/confirm
POST /phone/password/reset/confirm
POST /email/verify/confirm
POST /phone/verify/confirm
```

### Frontend verification/reset paths are now configurable

AuthKit builds links from:

- `Frontend.BaseURL`
- `Frontend.VerifyPath`
- `Frontend.PasswordResetPath`

Host apps should stop building verification/reset URLs in Twilio sender config.

### OIDC browser login preserves return targets

Browser OIDC login supports `return_to`. The callback returns it to the
frontend result route; host frontends must same-origin validate before
redirecting.

Browser OIDC routes:

```http
GET /{provider}/login
GET /{provider}/callback
GET /{provider}/reauth/callback
```

Account-link/reauth start routes:

```http
POST /oidc/{provider}/link/start
POST /oidc/{provider}/reauth/start
```

OIDC reauth now requests a fresh provider authentication where supported.

### Contact-change routes are collapsed

Use the current single-route shape:

```http
POST /email/verify/request
POST /email/verify/confirm
POST /phone/verify/request
POST /phone/verify/confirm
```

Old `/user/email`, `/user/phone`, `/user/email/change/...`, and
`/user/phone/change/...` flows should not be used. Starting a contact change is
an authenticated verification request and may return a reauth/step-up error; the
frontend should complete reauth and retry the original request.

### Reauth / step-up routes

```http
POST /reauth/password
POST /reauth/2fa
```

Use these when AuthKit says the current session is too old or not MFA-backed
enough for a sensitive action.

### 2FA routes were collapsed

Current 2FA route shape:

```http
GET    /user/2fa
POST   /user/2fa
DELETE /user/2fa
POST   /user/2fa/backup-codes
POST   /2fa/challenge
POST   /2fa/verify
```

Do not use the old names:

```http
POST /user/2fa/start-phone
POST /user/2fa/enable
POST /user/2fa/disable
POST /user/2fa/regenerate-codes
```

### Passkey routes were added

```http
POST   /passkeys/login/begin
POST   /passkeys/login/finish
POST   /passkeys/register/begin
POST   /passkeys/register/finish
GET    /passkeys
PATCH  /passkeys/{id}
DELETE /passkeys/{id}
```

Host apps using passkeys must configure `Config.Passkeys`.

### Route groups changed

New route group:

- `RoutePasskeys`

Permission-group routes are config-derived and exposed through:

- `Routes.PermissionGroups()`
- `Service.PermissionGroupRoutes()`

### Permission-group HTTP routes use persona/resource slugs

Generated group-management routes are derived from configured `PersonaDef`
management profiles. Disabled capabilities emit no route.

Route shape:

```http
GET    /me/groups
GET    /{persona}/{resource_slug}/members
POST   /{persona}/{resource_slug}/members
DELETE /{persona}/{resource_slug}/members/{user}
PUT    /{persona}/{resource_slug}/members/{user}/roles/{role}
GET    /{persona}/{resource_slug}/roles
POST   /{persona}/{resource_slug}/roles
DELETE /{persona}/{resource_slug}/roles/{role}
GET    /{persona}/{resource_slug}/api-keys
POST   /{persona}/{resource_slug}/api-keys
DELETE /{persona}/{resource_slug}/api-keys/{key}
GET    /{persona}/{resource_slug}/remote-applications
POST   /{persona}/{resource_slug}/remote-applications
DELETE /{persona}/{resource_slug}/remote-applications/{app}
GET    /{persona}/{resource_slug}/invites
POST   /{persona}/{resource_slug}/invites
DELETE /{persona}/{resource_slug}/invites/{invite}
```

### Admin routes are root-persona permission gated

Admin routes still exist, but authorization is through root persona permissions,
not a separate admin tier:

```http
GET    /admin/users
GET    /admin/users/{user_id}
GET    /admin/users/{user_id}/signins
POST   /admin/users/{user_id}/ban
POST   /admin/users/{user_id}/unban
POST   /admin/users/{user_id}/recover
POST   /admin/users/{user_id}/sessions/revoke
DELETE /admin/users/{user_id}
POST   /admin/users/{user_id}/restore
```

## Consumer Migration Checklist

1. Bump to `github.com/open-rails/authkit v0.56.2`.
2. Replace facet calls like `svc.Users().X(...)` with direct `svc.X(...)`
   calls, where still public.
3. Rename group/type/resource fields to persona/resource-slug names.
4. Replace org credential fields with permission-group fields.
5. Remove Twilio URL-builder config and consume AuthKit-provided final URLs.
6. Update frontend confirmation pages to handle scanner-safe GET landings and
   POST confirmations.
7. Update frontend account security UI to the collapsed 2FA, reauth, contact,
   and passkey routes.
8. Same-origin validate OIDC `return_to` before redirecting.
