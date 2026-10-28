# Changelog

## Unreleased

- **Breaking:** `Migrate` no longer converts a schema built by AuthKit v0.125.0 to v0.148.x; upgrade such a database through v1.43.x first. This release refuses a v0.148-era schema and changes nothing. `Migrate` also no longer removes `authkit_account_finalize` River jobs left by releases before v1.33.0: in a database that skipped v1.33, they stay in `river_job` as inert rows no worker reads, and can be deleted by hand. Deletions still complete from `account_deletions`. Migration 0023 still removes waiting `authkit_account_delivery` jobs as before.
- **Breaking:** tenants have a name (#471). `CreateTenant` requires `iam.Tenant.Slug`, a public name (lowercase letters, digits and hyphens, at most 63 characters) that stays beside the stable UUID. `RenameTenant` renames a tenant without touching its ID, accounts, tokens or grants, and its old name keeps forwarding and blocks other tenants for `Config.Tenants.FormerNames` (90 days by default). `ResolveTenant` finds the tenant a current or former name belongs to, and `Tenant` reads one by ID. The same operations are served at `/admin/tenants` under the new `root:tenants:read` and `root:tenants:manage` permissions. Migration 0026 names existing tenants `tenant-<UUID hex>`; rename them once. See [tenant names](docs/tenant-directories.md#tenant-names).
- `OAuthClientConfig.RenewableCapabilities` (jwt-bearer clients): the workload a capability binds redeems it again, with a fresh assertion and DPoP proof of its key, until the capability expires, so it renews its access without the user's device (RFC 7523's repeated assertions). Each redemption is a whole grant: the device key live, the user usable, and the grant authorizer deciding again, whose `MaxLifetime` sets each token's life. Without it a capability still redeems once. A capability's `authorization_details` may hold 64 entries (was 16; still at most 8 KiB). See [Workloads](docs/authorization-server.md#workloads).
- Registration no longer reveals whether an email address or phone number has an account. `GET /register/availability` answers for the username only and ignores `email` and `phone_number`. When verification is required, signing up with a taken address answers 202 like a fresh sign-up, and moving an account onto another account's address (`PUT /me/email`, `PUT /me/phone`) answers 202 like a free one. The address's owner gets the new `iam.MessageAccountExists` with a password reset link; a host sender that refuses that kind gets `MessagePasswordReset` with the same link instead, so hosts keep working before they add copy. The attempt leaves the same pending sign-up a fresh one does (its username is held, it can be abandoned, and its password answers `verification_required` at sign-in), but its code is never sent; a re-send renews it as it renews a real one. Signing in with a pending sign-up's password re-sends at most six times an hour per address, and a password sign-in that finds no account now spends one password check, so its time matches one that does. A second sign-up while one is pending still answers `email_in_use` or `phone_in_use`, which only says that someone tried. A taken username is now reported before a taken address. Without required verification a fresh sign-up signs in, so a taken address still answers `email_in_use` or `phone_in_use`. The registration form no longer checks the address as you type.
- When verification is required, a password sign-in for an account with an unproven email or phone and no proven contact is refused with the new `verification_unavailable` (503) while no channel can send its code, and the refusal is logged. Before, a missing or unhealthy sender let such an account sign in on its password alone. Accounts with a proven contact are unaffected. auth-ui shows "We couldn't send your verification code. Please try again shortly."
- `Deps.RequestTenant` lets a host select an existing native account directory before HTTP guards consume DPoP proofs. Unknown directories and lookup failures refuse the request, fixed tenant views cannot be redirected, and omitted selectors preserve existing behavior.

- **Breaking (coordinated notification upgrade):** account notification types and PostgreSQL storage now live in `github.com/open-rails/authkit/notify` and `notify/postgres`. `Client.Notifications` and remote delivery factories return one `notify.Publisher` with `Publish(ctx, []Publication, tx...)` and `Withdraw(ctx, []Withdrawal, tx...)`; replace producer `Apply`/`ApplyTx` calls and let the configured AuthKit publisher bind origin, tenant and app visibility. Remote operations always enqueue in the source database, including when no transaction is supplied. Existing SQL, receipt identities and wire envelopes remain unchanged. A previously revisioned envelope with workflow status or source-subject metadata still requires a higher source revision for a semantic change; same-revision content conflicts are not waived.
- AuthKit UI owns the account inbox and notification bell, with shared refresh, cursor pagination, read/archive actions and identity-switch fencing. See the notification configuration and migration guide before replacing an older writer cohort.

- `adapters/smtp`: every built-in email has an HTML layout (the app's name over a card and a short footer; tables and inline styles only, following the client's light or dark scheme) beside a concise text part. Code emails show the code large and monospaced, say what it is for and close with "If you didn't request this, you can ignore this email." A device-key enrollment or passwordless code is a login code ("Your <App> login code"), not "Verify your <App> account"; contact-change and two-step setup codes have their own subject. Every built-in email is in Spanish for `es`.
- Live MFA-policy and enrollment-state database failures remain server errors during request verification. Embedded authenticators report authentication unavailable rather than incorrectly challenging a valid session to sign in again.
- Recent sign-in checks allow up to five seconds of future `auth_time` for small database/application clock differences. The 15-minute freshness window and second-factor requirements are unchanged (#462).
- Required MFA accepts UV passkeys/security keys, TOTP, or SMS. Presence-only keys and email do not satisfy privileged policy. Restricted first-passkey enrollment binds the primary proof, account, tenant, RP, nonce, and credential generation; key creation and sign-in commit together.
- Passkey-only accounts can generate hashed single-use backup codes after strong step-up and recover through an independent primary proof plus a code. Recovery sets are account-scoped and survive individual factor replacement while MFA remains. Migration 0020 removes detached historical sets; removing the final factor/key clears its set, and later enrollment cannot revive it.
- Second-factor step-up checks live policy and records the proven method under the account lock. Recovery-code consumption commits with session freshness. Verified-account password reset preserves enrolled MFA; first-contact-proof protection for unproven registrations remains intact.

## v1.30.0

### Coordinated upgrade

- Accounts belong to one canonical `TenantID` in shared tables. Configure `DefaultTenantID` for fixed-tenant deployments and pass the explicit original owner as `MigrationOptions.LegacyTenantID` when migrating existing data. An empty default is now an unbound authority, not an implicit shared directory. Account operations require a trusted `ForTenant` view. Coordinate all writers; older unscoped binaries must not write the migrated schema. Existing account IDs, passwords, MFA material, and explicitly mapped sessions are retained. See [tenant directories](docs/tenant-directories.md).

### Changes

- Per-tenant identifier uniqueness and lookup for email, phone, username, provider links, registration, imports, recovery, and sessions. Trusted native tenant views and fixed HTTP mounts select account ownership; request data never grants access to another tenant.
- Built-in tenant roles inherit into that tenant's app and merchant groups. Root authority remains global within the configured authority; every session, key, and remote-application credential keeps its scope and permission ceiling.
- Tenant-bound cookies, shared proof callbacks, OIDC, MFA, provisioning, lifecycle events and deletion receipts retain the actual target owner, including after purge. An unbound central portal can restore its last active directory using a non-authoritative cookie hint plus a valid refresh proof; fixed app mounts ignore that hint.
- Optional `AuthAdmin` composition and tenant-targeted `UsersAdmin` reuse the existing guarded panels. Explicit tenant transport, cache and resumed-action scopes prevent stale account data or actions crossing directory changes.
- `MigrateGroupPersona` offers a read-only plan and fingerprinted explicit apply, retaining IDs/secrets while refusing expanded grants and stale plans. No automatic role renaming or owner promotion. See [group persona migration](docs/group-persona-migration.md).
- Optional `TransactionalUserInfo.GetTx` lets native and remote lookups share the host's transaction while retaining their fixed directory and restoring its search path.

## v1.29.2

### Changes

- DPoP proofs to the host's routes behind `Client.Authenticator()` are checked against `HTTPConfig.PublicURL`'s origin, where browsers reach the deployment, falling back to the issuer's origin as before. A site whose issuer origin differs from its public one (a dev server or proxy in front) can require DPoP-bound sessions.
- `Client.PublicAPIBase()`: `APIBase` as clients reach it (`HTTPConfig.PublicURL`), what DPoP proofs to the API name.
- authtest: `SignIn` binds the session to a DPoP key when the deployment requires one (capabilities `dpop: required`), as a browser does; `call`-based helpers sign with it. `authtest.Authorize(t, auth, r, token)` sets a request's credential as a browser sends it: a bound token as DPoP with a proof naming the public origin and the request's path, anything else as Bearer. `Identity` uses it.

## v1.28.0

### Changes

- Survivable boot (#456): `New` fails only when AuthKit can't run safely: PostgreSQL unreachable after a bounded wait (30 seconds, or `ctx`; it is pinged with backoff first), migrations failing, no usable signing key (now also a `Deps.KeySource` without an active signer, unless `Keys.VerifyOnly`), token identity, and structural or security-posture configuration. Survivable problems are logged and switch off only what they concern: an identity provider that fails validation, repeats a name or issuer, claims an account issuer or needs HTTPS for `form_post` is disabled alone; a `Config.RemoteApplications` entry that is invalid is disabled (its tokens refused); a role needing MFA with no enrollable factor keeps the gate closed; registration verification without a sender, invalid languages, frontend paths, Solana network, Redis key prefix and intervals fall back to defaults; a misconfigured provisioning target keeps its changes pending.
- `Client.Ready(ctx)` (PostgreSQL, River, signing key) and `Client.Probes()` (`authkit_config`, `authkit_email`, `authkit_sms`, `authkit_redis`, `authkit_two_factor`, `authkit_issuer_keys`, `authkit_provider_<name>`), in OpenRails' Ready/Probes shape. Hosts register the probes with their dependency supervisor instead of wrapping `EmailHealth`/`SMSHealth`.
- A flow that must deliver with no sender configured answers 503 `email_unavailable` or `sms_unavailable` instead of an internal error; a password reset is refused before the account lookup.
- An OIDC provider's discovery failure and recovery are logged once each.
- auth-ui names transport failures instead of "Something went wrong": a request that reached no server (a fetch rejection, offline) is `network_error`, "Couldn't reach the server. Check your connection and try again."; a gateway's 502, 503, 504 or 520–524 without AuthKit's error envelope, or a `TimeoutError`, is the new local code `server_unavailable`, "The server isn't responding right now. Please try again in a moment." Coded AuthKit errors are unchanged; a code the bundle doesn't know shows AuthKit's own message. `transportFailure(error)` (`@openrails/auth-ui/client`) is the classifier, for hosts' own requests too. The duplicate `errors.network` key is removed, and a `TypeError` that isn't a fetch failure is `unknown_error`.

## v1.26.0

### Breaking

- `verify.IssuerOptions.CacheTTL` and `MaxStale` are removed (#454): AuthKit sets every read cache's policy in one place (`internal/cachepolicy`). A JWKS issuer's keys refresh every 10 minutes and keep verifying while fetches fail for up to 4 hours, as the defaults did; delete the fields from `AddIssuer` calls.

### Changes

- JWKS keys and OIDC discovery are cached by `github.com/open-rails/helpers/cache` (#454) instead of AuthKit's own refresh loops; bounds are unchanged: keys refresh after 10 minutes (an unknown kid or failed signature refetches at once, at most every 30 seconds), discovery after an hour, both fail closed 4 hours after the last success. A failing issuer or IdP is retried, at most every 5 seconds, by the next token or login that needs it or by its health probe (`CheckIssuerKeys`, a provider's `CheckHealth`), which reads through the same cache, rather than by a background loop.
- `Verifier.Close` releases the issuer-key cache's background work; the engine closes its own on `Close`.
- Every Verified of `Client.Authenticator()`, `Verifier.Authenticator()` and `verify.AuthenticateRequest` or `AuthenticateSession` has `Entitlements() []string` (#455): the verified token's `entitlements` claim, its issuer's snapshot at mint (`Token.EntitlementAllowlist` for this deployment's own tokens). A token without the claim, an API key and a client's own token have none. ContentKit's Gate reads it as `access.Entitled`, answering a token-claim tier without a billing read.

## v1.25.0

- auth-ui `UsersAdmin` and `UserAccountSummary` (#453) in `@openrails/auth-ui/admin`, over AuthKit's existing account routes (`/admin/users…`) and the root group's membership: the user directory with its filters in the URL, and each account's page (profile edit, ban with an end, delete and restore, sessions, sign-in history, root role, root invitations). For hosts composing their own admin area and the standalone OpenRails server's console (its users tab), which add panels and ban or delete warnings through `userPanels` and `confirmWarnings`; `UserAccountSummary` is for another page, such as OpenRails' billing customer. No route changed.

## v1.24.0

### Breaking

- Authentication and user-directory contracts now live in `github.com/open-rails/authkit/auth` and `github.com/open-rails/authkit/userinfo`, including `auth/authtest` and `userinfo/userinfotest`. Replace the corresponding helpers import prefixes in every host and library and update them together: `Identity`, `Scope`, `Credential`, `User` and interfaces using them have new Go package identities. There are no forwarding aliases. Both contract packages depend only on the standard library; custom host implementations still work without initializing AuthKit. See [contract packages and migration](docs/contract-packages.md).

## v1.23.0

- A resource access token's Verified at `Client.Authenticator()` has `Asserted() bool`: true when this deployment minted it from a remote application's RFC 7523 assertion (a backend's customer token), false for session tokens, API keys, exchanged tokens and a trusted issuer's own tokens. A library tells a customer token from a staff one without comparing `ClientID()` with the issuer.
- Group remote applications over HTTP (#453): `GET` and `POST /groups/{group_id}/remote-applications`, `PATCH` and `DELETE /groups/{group_id}/remote-applications/{id}`, under `<persona>:credentials:read` and `:manage`, with a recent sign-in for changes. A person registers the group's backend signing keys (a `jwks_uri` or `public_keys`, each with a kid); an issuer registered anywhere already is `remote_application_issuer_conflict`, another group's application is 404, an API key registers none, and an update keeps the `role_map` and keys it does not name. auth-ui's `RemoteApplicationsAdmin` drives them ([resource server](docs/resource-server.md#trusted-issuers)).
- Group remote applications over HTTP (#453): `GET` and `POST /groups/{group_id}/remote-applications`, `PATCH` and `DELETE /groups/{group_id}/remote-applications/{id}`, under `<persona>:credentials:read` and `:manage`, with a recent sign-in for changes. A person registers the group's backend signing keys (a `jwks_uri` or `public_keys`, each with a kid); an issuer registered anywhere already is `remote_application_issuer_conflict`, another group's application is 404, an API key registers none, and an update keeps the `role_map` and keys it does not name. auth-ui's `RemoteApplicationsAdmin` drives them ([resource server](docs/resource-server.md#trusted-issuers)).
- auth-ui group admins (#453): `MembersAdmin`, `RolesAdmin`, `ApiKeysAdmin` and `OAuthClientsAdmin` in `@openrails/auth-ui/admin`, over AuthKit's own group routes. Each shows only what the caller's permissions allow, routes by the host's `navigation` (the history API without it), steps up through `guard` and inherits the host's theme.
- auth-ui: `@openrails/auth-ui/admin` (#453), the staff entry: `createAdminClient` over AuthKit's group routes and `GET /me/permissions`, `useGroupAdminAccess`, the router and theme conventions every admin component follows, and six languages. Step-up resume: `guard(action, { resume })` keeps a write across a provider step-up and `guard.onResume` replays it once on return, after checking the person, a nonce and a 15-minute lifetime.

## v1.22.3

- One account per contact (#449, owner ruling): an email or phone is tied to one account at a time, as before by a unique constraint. Proving one an account holds signs into that account, never a second one; changing to another releases the old one at once, and another account may then sign up with it or move to it by proving it; of two accounts moving to one contact at once, exactly one gets it. A reassigned phone number stays its account's until the account changes it, as a mailbox would ([identity](docs/identity.md#network-accounts)). `TestSecurityContactOwnership` pins it for both kinds against PostgreSQL.

## v1.22.2

- auth-ui: `ResourceRequest.group` asks for a token bound to one group (`group_id` in the token exchange), cached apart per group, for `getResourceToken` and `resourceFetch`. A DPoP-bound session is exchanged with its own key (AuthKit requires it since v1.22.0), and its resource tokens are bound to that key.

## v1.22.1

- A remote application's static key without a kid is refused at registration with `invalid_remote_application`, as are a duplicate kid and a kid with surrounding whitespace. Before, such a key list was registered and never verified: every assertion was `invalid_grant` and every token failed as unavailable. Each of `PublicKeys` has a distinct kid, its `KID` or else its JWK's, so a PEM key needs `KID`; registration and the verifier check the list by one rule. An assertion or token naming no kid is still verified with the application's only key (RFC 7515 §4.1.4).

## v1.22.0

Tokens bound to one group, for a library acting on one tenant at a time (OpenRails #1197: the merchant is the one the request's token is bound to). helpers v1.9.0.

- **Token exchange naming a group** (RFC 8693): `group_id` on a token exchange binds the access token to that group (its `group_id` claim, `BoundScope` at `Client.Authenticator()`). The group must be live and not root, and the user must hold a role in it or a root role, else `invalid_target`. The token keeps `sid`, `auth_time`, `amr` and `acr`, has no `act`, and ends with its session or its group. Its `CheckRecentSignIn` is the person's own: `auth_time` within 15 minutes, with a second factor when the account has one (now also for any of this deployment's resource tokens on a session). Its `Can` holds what the person holds in the group and, on root, the person's `root:` permissions (helpers v1.9.0's `Bound` exception); nothing elsewhere. API keys and applications stay strictly bound ([authorization server](docs/authorization-server.md#group-bound-tokens)).
- **DPoP-bound subject tokens** are exchanged only with a proof of their own key, and the new token is bound to it; before, they were refused.
- **Group-bound mint**: `iam.AccessTokenOptions.Group` makes `MintAccessToken` a customer token for one group: an `access+jwt` with `group_id` and no session, holding no permissions, at most `iam.MaxGroupAccessTokenTTL` (15 minutes). It stands while its user is usable and its group live; `CheckRecentSignIn` is `auth.ErrForbidden`. `SessionID` with `Group` is refused, and AuthKit's own API refuses the token.
- **Lifetimes**: `AuthorizationServer.AccessTokenTTL` may be up to 15 minutes (default still 5), and a resource server (`Config.Resource`) may set it with no clients, for the tokens it mints from remote applications' assertions. A remote application's RFC 7523 assertion may expire at most 2 minutes ahead (was 5).
- **Resource ceilings**: a resource's `Permissions` and `Resource.Scopes` ceilings may hold the app's own `root:` permissions (`root:billing:*`), never AuthKit's built-in ones; a client's `Permissions` still hold none.
- A revoked session behind a resource access token is `auth.ErrRevoked` (was only `auth.ErrUnauthenticated`).
- [RBAC](docs/rbac.md#a-librarys-permissions-in-two-personas): a library's permissions in two personas, one role per persona from the library's constants.

## v1.21.0

- `Client.Authenticator()` and `Verifier.Authenticator()` are helpers/auth `Root` (helpers v1.8.0): `RootScope(ctx)` is `Scope(ctx, iam.RootGroup())`, where root roles hold their `root:` permissions. A library given `root:` permissions checks them there, so the host passes only the Authenticator: `openrails.Routes{Auth: ak.Authenticator(), …}`, no scope ([RBAC](docs/rbac.md#a-library-that-guards-its-own-routes)).

## v1.20.0

### Network accounts

Accounts for a customer network such as openrails.dev (#449, [docs/identity.md](docs/identity.md#network-accounts)): contact-first sign-in by email or SMS code or passkey, agreements accepted at sign-up, phone-only accounts proving their phone on every new device, and SMS bound to allowed countries, send limits and its origin.

- `Config.Agreements` declares documents; `Registration.Agreements` names those every sign-up accepts, by password, code or identity provider (`agreements` on `POST /register`, `POST /passwordless/confirm` and the JSON provider start). Without them: `agreement_required` (409), naming each with its version and URL; a passwordless code stays good for the retry. A Solana or device-key sign-up carries none, so it creates no account while they are set.
- Acceptances are append-only (`user_agreements`): `Client.UserAgreements`, `AgreementsDue`, `AcceptAgreements`; `GET` and `POST /me/agreements`. A completed sign-in's `AuthResult.agreements_due` lists what is due: a required document never accepted, or a new version marked `reaccept`. `OAuthClientConfig.Agreements` must be accepted before the client's approval; `GET /oauth2/authorizations/{id}` lists them. `GET /capabilities` publishes `agreements`, `registration.agreements` and `sms.countries`. Each newly accepted version records `user.agreement_accepted`, with `iam.Event.Agreement` and the version as `Current`.
- A phone-only account (no proven email, no passkey) proves its phone on every new device, whatever `SignIn.NewDevicesPerAccount` says. With an SMS sender, sign-ins carry their device and the device-verification routes are mounted even with the sign-in limits off.
- On HTTPS the device cookie is also issued `SameSite=None; Partitioned` (`__Host-authkit_device_p`), so a sign-in inside a third-party iframe is recognized again under that top-level site.
- `SMS.AllowedCountries` refuses other regions with `phone_country_not_allowed` before any lookup or send. Every text message spends the new `sms_number`, `sms_account`, `sms_address` and `sms_country` buckets (`HTTPConfig.RateLimits`). `iam.SMSMessage` gains `UserID` and `Domain` (`Frontend.BaseURL`'s host) and `OriginBoundLine()`; the Twilio adapter's built-in code messages end with `@<domain> #<code>`.
- `Deps.DeletionCheck` may refuse a user's own deletion with `iam.RefuseDeletion(reason)`: `deletion_refused` (409, `metadata.reason`). A failing check refuses too.
- Error codes `agreement_required`, `deletion_refused` and `phone_country_not_allowed`.

### Group OAuth clients

Merchants sign their customers in with the network (#450, [docs/authorization-server.md](docs/authorization-server.md#group-clients)): a group registers its own OAuth clients at run time, each user consents per scope, and the client's tokens act only in its group.

- `authkit.OAuthClients` on a persona lets its groups register clients by RFC 7591 metadata under `<persona>:credentials:manage`: `Client.CreateGroupOAuthClient`, `GroupOAuthClients`, `GroupOAuthClient`, `UpdateGroupOAuthClient` (`Disabled`), `RotateGroupOAuthClientSecret`, `DeleteGroupOAuthClient`; HTTP `/groups/{group_id}/oauth-clients[/{client_id}]`, `POST .../secret`. At most 10 per group (`iam.MaxGroupOAuthClients`).
- Authorization code with PKCE and refresh tokens; `client_secret_basic`, `private_key_jwt` (RFC 7523 assertions against the client's `jwks_uri`) or `none`. `AuthorizationServer.GroupClients` names the scopes beyond OpenID's they may request (each with its resource and consent text) and the agreements a user accepts before approving one.
- Consent (`oauth_consents`): approving answers `consent_required` with the scopes still to consent to, and `{"consent": true}` gives it; later requests ask only for new scopes, `prompt=consent` asks again. `GET /oauth2/authorizations/{id}` adds `third_party`. `GET` and `DELETE /me/oauth-consents[/{client_id}]` and `Client.OAuthConsents`, `RevokeConsent`: withdrawing ends the client's refresh tokens for the user, sends its OIDC Back-Channel Logout token, and records `oauth_consent.revoked`.
- Group clients get `sub`, `email` and `phone_number` only once proven, nothing for `profile`, and no `permissions` or `roles`. `Client.Authenticator()` binds their tokens to their group; a disabled or deleted client, or a deleted group, is refused at once. The `phone` scope and `phone_number` claims are new for every client.
- `Deps.ConsentRevocationCheck` may refuse a user's own withdrawal of consent with `iam.RefuseConsentRevocation(reason)`: `consent_revocation_refused` (409, `metadata.reason`); `Client.RevokeConsent` skips it.
- `Client.VerifyIDToken` verifies an ID token this server issued, in process, and returns `iam.IDToken` (user, client, owning group, nonce, `auth_time`, `amr`); else `invalid_id_token`. A resource access token's Verified has `ClientID()` and `Scopes()`.
- authtest: `Attach` drives a Client a host serves; `CodeFlow.Consent` and `AuthorizationServer.ApproveConsent` approve a group client's consent screen.
- `Deps.GroupName` names a group on the consent screen. Events `oauth_client.created`, `.updated`, `.deleted`, `oauth_consent.revoked`, with `iam.Event.ClientID`. Error codes `consent_required`, `consent_revocation_refused`, `invalid_id_token`, `invalid_oauth_client`, `oauth_client_limit_reached`, `oauth_client_not_found`, `oauth_consent_not_found`.
- A declared client's id may not start with `goc_`, which group clients' ids do.

### Migrations

- 0016: `user_agreements`.
- 0017: `group_oauth_clients`, `oauth_consents`, and `account_events.client_id` and `.agreement`.

## v1.19.0

Custom roles (#448): a group defines least-privilege roles of its own at run time, from its persona's permissions, and gives them to members, API keys and remote applications like declared roles ([docs/rbac.md](docs/rbac.md#custom-roles)).

### Breaking

| Removed or changed | Use instead |
|---|---|
| A declared role named `custom-…` | Another name: `<persona>:custom-<name>` is a group's custom role, so the two never clash |
| A host-declared `<persona>:roles:read` or `<persona>:roles:manage` | The built-ins of those names, registered with `CustomRoles` |
| auth-ui's generated `RoleInfo` | `GroupRole`: the same members, plus `grants`, `custom`, `requires_mfa`, `created_at` and `updated_at` |

### Custom roles

- `authkit.CustomRoles` on a persona, root included, lets its groups define roles. It registers `<persona>:roles:read` and `<persona>:roles:manage` (`PersonaDef.Roles`).
- `Client.ListGroupRoles`, `GroupRole`, `CreateGroupRole`, `UpdateGroupRole` and `DeleteGroupRole`. `Client.Role` resolves a custom role's name.
- HTTP: `GET /groups/{group_id}/roles/{role}`; with `CustomRoles`, `POST /groups/{group_id}/roles` and `PATCH` and `DELETE /groups/{group_id}/roles/{role}`. `GET /groups/{group_id}/roles` lists a group's custom roles after its declared ones.
- A check reads a custom role in the same query as its assignment, so a change applies at the next request. Changing one is a grant: covering its permissions before and after, and handing it out while it is held. Deleting one takes it from every holder and revokes the keys and invitations carrying it.
- Events `group.role_created`, `group.role_updated` and `group.role_deleted`, with `iam.Event.Role`.
- Error codes `role_not_found`, `role_exists`, `role_not_editable` and `role_limit_reached`.

### Migrations

- 0015: `group_custom_roles`, and `account_events.role`.

## v1.18.0

The owner approved shipping these breaking changes in a minor release. AuthKit verifies every credential a service accepts: with `Config.Resource`, `Client.Authenticator()` admits its own sessions and API keys, the RFC 9068 access tokens its own authorization server mints and those its trusted issuers mint (#447, [docs/resource-server.md](docs/resource-server.md)). A group keeps a directory of its trusted issuers' users ([docs/scim.md](docs/scim.md#directory)).

### Breaking

| Removed or changed | Use instead |
|---|---|
| `RemoteApplicationConfig.RootRole` | `RemoteApplicationConfig.Role`, with `RoleMap` mapping the role names its tokens carry |
| An access token's `client_id` as the invoker (`verify.Claims.Invoker`, the Identity's `Invoker`) | The invoker comes only from RFC 8693 `act`: `Invoker` is `act.sub`, and a token without `act` is its subject acting itself. Token exchange without an `actor_token` carries none |
| auth-ui's issuer client binding tokens to a DPoP key by default | `createIssuerClient({ dpop: true })` and `createAuthClient({ dpop: true })` ask for it; bearer is the default, and the client binds anyway when the issuer requires it |
| Upgrading from v1.16.0 or earlier: `verify.WithDPoP(replay func(ctx, key, ttl) (bool, error))` (v1.17.0) | `verify.WithDPoP(rdb)`: Redis, or nil for memory (one node) |

- JWT-bearer workload tokens (Tensorhub's) keep `act`, so their `verify.Claims.Invoker` is still `act.sub`.

### Resource server

- `Config.Resource`: `id` (RFC 8707, an accepted token's `aud`), `public_url` (what a DPoP proof's `htu` names; default the id's origin) and `scopes`, each scope's permission ceiling (RFC 6749 §3.3).
- A trusted issuer is a remote application: one issuer acts for one group, holding its role there. `Client.DeclareRemoteApplications(ctx, group, apps)` declares a group's issuers from configuration. Keys come from `PublicKeys`, `JWKSURI` or the issuer's RFC 8414 metadata.
- `Verified.BoundScope()` (helpers v1.7.0 `auth.Bound`) is an API key's or a trusted issuer's group; `Can` is false outside it. The Authenticator lists its credential headers for CORS (`auth.Headers`).
- `CheckRecentSignIn` reads a trusted token's `auth_time`: older than 15 minutes is RFC 9470's step-up.
- Federated grants: a trusted issuer's user accepts a group's email invitation (`RemoteInvitations`, `AcceptRemoteInvitation`) and holds its role there (`RemoteUserRoles`, `RemoveRemoteUserRole`).
- RFC 7523 §2.1: a trusted application without an authorization server signs an assertion for its user, and its frontend redeems it at the token endpoint for a customer token, DPoP-bound when it proves a key.

### DPoP

- `sign_in.dpop: optional | required`, default optional, sets how this instance issues tokens to its own users. It never changes how tokens are validated: a bound token needs its proof, an unbound token is a bearer token, whoever issued it. API keys, client credentials and service tokens are never covered.
- Sign-in sessions bind to a DPoP key (RFC 9449 §5): password and passwordless sign-in, refresh, and OIDC through `dpop_jkt` (§10). `GET {api}/capabilities` reports `dpop`.
- A resource server's nonces live in the replay store (`verify.WithStoredDPoPNonces`); `verify.WithPublicHosts` and `Deps.ResourceHosts` admit a proof naming a tenant's API host.
- Spent JWT-bearer assertions (RFC 7523 §3) are kept with spent DPoP proofs, in `Deps.Redis` or memory, no longer in the PostgreSQL ephemeral store. A capability's `jti` stays in PostgreSQL. The Redis keys are `authkit:spent:`, formerly `authkit:dpop:`.

### Directory

- `{issuer}/directory/scim/v2`: `/Users` create, read, replace, patch and delete, `/Bulk`, filters on `externalId`, `userName`, `id` and `emails.value`, and discovery (RFC 7644). It takes Okta's and Entra's PATCH shapes, and answers RFC 7644 §3.12 errors.
- The credential names the tenant (RFC 7644 §6.1): one issuer's users in one group. An API key bound to a remote application of its group (`iam.NewAPIKey.ProvisionsFor`, `provisions_for`), or the application's own client-credentials token, provisions that application's users.
- New built-ins with `RemoteApplications`: `<persona>:directory:read` and `<persona>:directory:manage` (`PersonaDef.Directory`). A host that declared a permission of that name must drop it.
- `Client.RemoteUserInfo(ref, issuer)` reads the directory as a `helpers/userinfo.Lookup` keyed by the issuer's subject.
- Another AuthKit's push reaches it unchanged: point a `Config.Provisioning` target at the URL with the bound key as its `BearerToken`.
- A trusted issuer's user tokens record their contact claims (OIDC Core §5.1) as they are verified.

### Configuration

- `Config` decodes from YAML with snake_case keys, so a host passes its `auth:` section through.

### Migrations

- 0013: `remote_users`, keyed by group, issuer and subject, and `api_keys.provisions_for`.
- 0014: `remote_applications.role_map`, `refresh_sessions.dpop_jkt`, `group_remote_user_roles`, and a jwks-mode application without a `jwks_uri`.

## v1.17.0

The owner approved shipping this breaking change in a minor release. Rate limits and spent DPoP proofs are kept in Redis or in memory, never in PostgreSQL (#446), and a resource server no longer supplies its own DPoP replay store. This reverses v1.16.0's PostgreSQL limiter.

### Breaking

| Removed | Use instead |
|---|---|
| `verify.WithDPoP(replay func(ctx, key, ttl) (bool, error))` | `verify.WithDPoP(rdb)`: the verifier spends proofs in the given Redis, shared by every replica, or with nil in its process's memory (one node) |

- With `Deps.Redis`, every replica spends the same rate-limit budgets and records the same spent DPoP proofs there (token endpoint, userinfo, SCIM, `Client.NewVerifier`). Without it, each process keeps its own in memory: one node only.
- While a declared Redis fails, each process keeps its own with the same limits until Redis answers again; AuthKit logs the fallback and the recovery once each. A request is never refused 503 for it.
- The in-memory limiter keeps at most 100,000 buckets and sweeps expired ones every minute; the in-memory proof store keeps at most 100,000 proofs and sweeps expired ones as it goes.
- Migration 0012 drops `rate_limits`. AuthKit no longer records DPoP proofs in its PostgreSQL ephemeral store.

## v1.16.0

Rate limits are shared by every replica without Redis (#445).

- Budgets are counted in PostgreSQL (`rate_limits`, migration 0011, which `New` applies), so replicas spend the same ones with or without `Deps.Redis`. Before, without Redis each process counted on its own, and N replicas allowed N times each limit.
- A declared Redis stays the fast path. While it fails, budgets are counted in PostgreSQL, not per process; AuthKit logs the fallback and the recovery once each.
- If PostgreSQL fails too, a limited request is refused 503 `server_busy` with `Retry-After`.
- The semantics are unchanged: at most `Limit` requests per sliding `Window`, `Cooldown` after each admitted one, and a refused request counts nothing.
- A row is keyed by its bucket and a SHA-256 of the client key, so no address or identifier is stored. The maintenance job deletes dead rows in bounded batches.
- The in-process limiter is deleted.

## v1.15.0

The owner approved shipping this breaking change in a minor release. A library that guards its own routes takes a narrow `auth.Authenticator` that only says who a request is, and builds its own gates (helpers v1.6.0 replaces the `auth.Auth` middleware contract).

### Breaking

| Removed | Use instead |
|---|---|
| `*Client` as helpers/auth `Auth`: `Client.Required()`, `RequirePermission(p)`, `Sensitive()`, `Identity(ctx)` | `Client.Authenticator()` for a library (OpenRails' `Routes.Auth`); for a host's own routes, `verify.RequireSession(client)`, `verify.RequirePermissionOn(client, ref, p)`, `verify.Sensitive(client)` (or `authkitgin`/`authkitfiber`) and `verify.VerifiedIdentity(ctx, client)` |
| `Config.Merchant`, `MerchantConfig` | `Client.Scope(ctx, ref)`, given to the library: `Scope(ctx, iam.RootGroup())` for root roles, `Scope(ctx, iam.GroupByID(id))` for a merchant's group |
| `step_up_required` answered 403 | 401, with RFC 9470's `WWW-Authenticate: Bearer error="insufficient_user_authentication", max_age="900"`, on AuthKit's routes and at `verify.Sensitive`; the code and metadata are unchanged, the `type` is `authentication_error`. auth-ui handles it; a client of its own that keyed step-up on 403, or signs out on any 401, checks the code first |

- `Client.Authenticator()` is a `helpers/auth` `Authenticator` and `PermissionCatalog`; the Client itself is neither.
  - `Authenticate(r)` is `verify.AuthenticateSession` over the Client. It admits people and applications (API keys) and reuses a gate's verification of the same request.
  - Its `Verified` has `Can` (`Client.Can` in the scope's group) and `CheckRecentSignIn`.
  - A user acting for themself carries their email and username, read from the account.
  - It passes `helpers/auth/authtest.Check` against a real AuthKit (`TestSecurityAuthenticatorConformance`).
- `Verifier.Authenticator()` is the same for a resource server's audiences (`Client.NewVerifier`). It also admits the resource access tokens minted for them, so an OAuth client's own token (client credentials) authenticates as an application. That token holds nothing in a group.
- `verify.AuthenticateRequest` and `AuthenticateSession` return an `*auth.Challenge` for a DPoP refusal, carrying the `WWW-Authenticate` and `DPoP-Nonce` that `verify.DPoPChallenge` writes. A missing DPoP nonce is `auth.ErrSenderProofRequired`.
- Their `CheckRecentSignIn` returns an `*auth.Challenge` for a stale sign-in, with `MaxAge` and the step-up methods as `Metadata`.
- auth-ui: `authFetch` does not refresh on a step-up 401, from AuthKit or a host.
- auth-ui is published to npm as `@openrails/auth-ui@1.15.0`, with provenance, instead of attached to the release (#409).
- The client IP reads every `X-Forwarded-For` line (#408). Behind a proxy that appends its own line (HAProxy's `option forwardfor`), only the first line was read, so a client could pick its own rate-limit key.
- helpers v1.6.0.

## v1.14.0

The owner approved shipping this breaking change in a minor release. A library takes a read-only user lookup, not the whole Client, named after OIDC's UserInfo (helpers v1.5.0 replaces `helpers/contacts` with `helpers/userinfo`).

### Breaking

| Removed | Use instead |
|---|---|
| `Client.Contacts(ctx, ids)`, `Client.SearchContacts(ctx, query, limit)`: the Client as a `helpers/contacts.Source` | `Client.UserInfo()`, a `userinfo.Lookup`: `Get(ctx, ids)` and `Search(ctx, query, limit)`, with the same answers. An embedded OpenRails takes `Deps.UserInfo: auth.UserInfo()` |
| `contactstest.Check(t, auth, contactstest.Fixtures{Contacts: …})` | `userinfotest.Check(t, auth.UserInfo(), userinfotest.Fixtures{Users: …})` |

## v1.13.0

The owner approved shipping this breaking change in a minor release. Email goes through any SMTP server (#443): the provider is configuration, not code.

### Breaking

| Removed | Use instead |
|---|---|
| `twilio.NewEmail`, `twilio.EmailConfig`, `twilio.EmailContent`, `twilio.Email` (SendGrid's API) | `smtp.New(smtp.Config{Server: smtp.Server{Host, Port, Username, Password, From}, AppName, Render})`, `smtp.Content` |
| `EmailConfig.Categories`, `CustomArgs` | nothing: SendGrid-only tags |

- `adapters/smtp` builds on `helpers/smtp` (helpers v1.4.0): port 465 is implicit TLS, any other STARTTLS (required before credentials leave loopback); PLAIN or LOGIN; multipart text and HTML. The built-in templates and `Render` are unchanged. SendGrid keeps working: host `smtp.sendgrid.net`, port 587, username `apikey`, password an API key with `mail.send`. Hosts name the settings `EMAIL_SMTP_HOST`, `EMAIL_SMTP_PORT`, `EMAIL_SMTP_USERNAME`, `EMAIL_SMTP_PASSWORD`, `EMAIL_SMTP_FROM`.
- `CheckHealth` connects, negotiates TLS and authenticates without sending, instead of reading SendGrid's scopes and sender verification.
- `adapters/twilio` sends text messages only.

## v1.12.0

The owner approved shipping this breaking change in a minor release. It deletes the OAuth grant extensions of v1.6.0–v1.6.1 (#433) that only Tensorhub's retired CLI grant flow used (#442). The JWT-bearer capability grant (v1.10.0) replaced that flow. These stay: the jwt-bearer grant and its authorizer (`Deps.OAuthGrants`), `authorization_details`, `act`, DPoP and `dpop_jkt`, the code flow with PKCE, refresh tokens, token exchange and client credentials.

### Breaking

| Removed | Use instead |
|---|---|
| `OAuthClientConfig.Offline`, offline grants, the `offline_access` scope (now `invalid_scope` again) | refresh tokens that stand on the session; a workload acting for a user without the user present uses a jwt-bearer capability |
| `Client.RevokeOAuthGrant`, `iam.OAuthGrantRequest.GrantID` | `Client.RevokeSession` or `RevokeAccountSessions`; revoking a device key ends the tokens its capabilities minted |
| `OAuthClientConfig.KeyBound` | `dpop_jkt` on the authorization request binds the code to a key; a public client always proves one; a jwt-bearer token is always bound to the workload key |
| `OAuthClientConfig.AccessTokenTTL`, `OAuthClientConfig.RefreshTokenTTL` | `AuthorizationServerConfig.AccessTokenTTL` and `RefreshTokenTTL`; a jwt-bearer token lasts until its capability expires, or the decision's `MaxLifetime` |
| approving an authorization request, or exchanging a token, with a device-key sign-in (now 403 and `invalid_grant`) | a session sign-in; a device key signs jwt-bearer capabilities |
| the grant authorizer for consent, refresh, token exchange and client credentials: `iam.OAuthGrantConsent`, `OAuthGrantRefresh`, `OAuthGrantTokenExchange`, `OAuthGrantClientCredentials`; `OAuthGrantRequest.SessionID`, `Scopes`, `Offline`; `OAuthGrantDecision.Permissions` | `Deps.OAuthGrants` decides only `iam.OAuthGrantJWTBearer`. Token exchange and client credentials carry the user's (or the client's) permissions within the resource's ceiling |
| `authorization_details` on the authorization request, token exchange and client credentials (now `invalid_request`), and in the pending request (`GET /oauth2/authorizations/{id}`) | the `authorization_details` of a jwt-bearer capability |
| `OAuthClientConfig.AuthorizationDetailsTypes` on a client without the jwt-bearer grant | declare it on jwt-bearer clients only; `New` refuses it anywhere else |
| `consent_required` for `prompt=none`; the consent step of auth-ui's `OAuthAuthorize` (unreleased) | nothing: every client is first-party |
| error code `oauth_grant_authorizer_unavailable` | nothing: the token endpoint answers `temporarily_unavailable` |
| `authtest`: `AuthorizationServer.Consent`, `RequestClientCredentials`, `ClientCredentialsRequest`; `CodeFlow.AuthorizationDetails`, `TokenExchange.AuthorizationDetails` | `AuthorizeAs`, or `BeginAuthorization` then `Approve`; `ClientCredentials`; `JWTBearer` with `DeviceKey.Capability` |

Unchanged: `OAuthGrantDecision.AuthorizationDetails`, `MaxLifetime`, `Claims` and `Invoker`; `verify.Claims.AuthorizationDetails`, `Invoker` and `CustomClaims`.

Host migration: remove any of these fields from your configuration and tests. A refresh family or code issued for an offline grant, or to a device-key sign-in, stops redeeming (`invalid_grant`). Its client signs in again.

## v1.11.0

Additive. AuthKit is a SCIM 2.0 directory both ways (#441, [docs/scim.md](docs/scim.md)).

- **Push** (`Config.Provisioning`): every account reaches each target (a SCIM base URL, or an in-process `Handler`, with a bearer token or client credentials) and stays current. Triggers on `users` record every change a SCIM User shows in the change's transaction; every `Interval` (5 minutes) a River job sends each target its pending accounts' latest state in `POST /Bulk` requests within the target's limits (single requests without bulk), retrying with backoff. Resources carry `meta.lastModified`. A new target gets an initial sync; a daily reconciliation, resumable across runs, repairs drift. `Client.ProvisioningTargets` and `GET /api/v1/admin/provisioning/targets` report each target's status.
- **Pull**: a read-only SCIM service provider at `{issuer}/scim/v2` (`/Users`, `/Users/{id}`, filters on `id`, `userName` and `emails.value`, discovery), for client-credentials tokens with scope `scim:read`. AuthKit declares the resource `{issuer}/scim/v2` itself; writes answer 501. Route group `iam.RouteSCIM`.
- **Contacts**: `*authkit.Client` is a `helpers/contacts.Source` (`Contacts`, `SearchContacts`; helpers v1.3.0).
- **Contact claims**: `ResourceServerConfig.ContactClaims` puts `email`, `email_verified`, `preferred_username`, `name` and `updated_at` in that resource's user tokens; `verify.Claims` gains `Name` and `UpdatedAt`, and `Username` reads `preferred_username`.
- Migration 0010: `users.profile_updated_at` and the provisioning tables.

## v1.10.1

- A TOTP key file readable by its group (0440, as a Kubernetes secret volume with `fsGroup` mounts it) loads without a warning (#439). World-read still warns; any group or world write bit is still refused.
- Building a client without `Deps.OnEvent` no longer turns account events off for its issuer (#440). A verify-only, ops or test client on the same database and issuer used to stop the server's events until it restarted. `New` with `OnEvent` subscribes the issuer; `New` without it changes nothing. `Start` of the client running the issuer's fleet sets the subscription to whether it handles events: a fleet run without a handler unsubscribes and drains what is pending.

## v1.10.0

Additive.

- **JWT-bearer grant with device-key capabilities** (#437, RFC 7523). A workload acts for a user only through a capability the user's device key signs offline with `devicekey.SignCapability`. The capability names the resource, the operations (`authorization_details`), the workload's P-256 key (`cnf.jkt`) and an expiry of at most 24 hours. The workload posts an ES256 `assertion` signed by its own key (`jwk` header, `iss` the client, `aud` the token endpoint, a single-use `jti`) that carries the capability, with a DPoP proof of the same key.
  - A client opts in with `GrantJWTBearer` and its `AuthorizationDetailsTypes`. It may be public, and it needs `DeviceKeys.Enabled` and `Deps.OAuthGrants`.
  - AuthKit verifies both signatures, the device key's liveness and the key binding. The grant authorizer then sees `iam.OAuthGrantJWTBearer` with `UserID`, `DeviceKeyID`, the operations, `JWKThumbprint`, `iam.OAuthAssertion` and `iam.OAuthCapability`. It may refuse, or narrow the operations by dropping entries. `OAuthGrantDecision.Invoker` names the workload in `act`.
  - The `at+jwt` lasts until the capability expires and carries `device_key_id`, with no refresh token. `Client.CheckSession` and `verify.RequireSession` now check that device key for this issuer's jwt-bearer tokens, so revoking the key ends them at once. `verify.Claims.DeviceKeyID` is now kept for a local issuer's resource tokens.
  - Refusals carry a `reason` beside the OAuth `error`. Discovery lists the grant type. See [Workloads](docs/authorization-server.md#workloads).
- `authtest`: `DeviceKey.UserID`, `DeviceKey.Capability`, `RevokeDeviceKey`, `DPoPKey.Assertion`, `AuthorizationServer.JWTBearer`, `JWTBearerToken` and `TokenEndpoint`.

## v1.9.0

The owner approved shipping this breaking change in a minor release. `Client.RequirePermission` infers the group from the permission.

### Breaking

| Removed | Use instead |
|---|---|
| `MerchantConfig.Root` | nothing: a `root:` permission is checked on the root group with no configuration |

- A `root:` permission is checked on root even when `Config.Merchant.Group` is set; `Config.Merchant.Group` is only for a persona permission (such as `merchant:billing:read` in one group per merchant).
- A persona permission without `Config.Merchant.Group` still refuses everyone.
- `RequirePermission` panics on a pattern or an unregistered permission whatever the configuration (before, only when a group was configured).

Host migration: delete `Merchant: authkit.MerchantConfig{Root: true}` and pass `root:` permissions of your own to the library (for OpenRails, `Routes.Staff`). A host with one group per merchant keeps `Config.Merchant.Group`.

## v1.8.0

The owner approved shipping this breaking change in a minor release, before any external consumer exists. The delegated-token and service-JWT systems are removed. The authorization server (v1.5–v1.6) replaces them, and there is no compatibility path.

### Breaking

| Removed | Use instead |
|---|---|
| `POST /delegated/token`, `iam.RouteDelegated` | the authorization server's token endpoint: token exchange (`GrantTokenExchange`) for a signed-in user, or a code flow |
| `Client.MintDelegatedAccessToken`, `iam.DelegatedAccess` | token exchange; for a delegate acting for days, a code-flow client with `Offline`, `KeyBound` and its own `RefreshTokenTTL` |
| `Config.Delegated`, `DelegatedConfig` | `Config.AuthorizationServer`: clients, resources and per-client lifetimes |
| `Deps.DelegatedAuthorization`, `iam.DelegationAuthorizer`, `DelegationRequest`, `DelegationGrant`, `ErrDelegationRefused` | `Deps.OAuthGrants`, `iam.OAuthGrantAuthorizer`, `OAuthGrantRequest`, `OAuthGrantDecision`, `ErrOAuthGrantRefused` |
| a requested grant, the `attributes` claim | `authorization_details` (RFC 9396); the decision's URI-named `Claims` |
| a delegate certificate (`cnf.x5t#S256`) | a `KeyBound` client's DPoP key (`cnf.jkt`), which the authorizer sees as `JWKThumbprint` |
| `Client.MintServiceJWT`, `iam.ServiceJWT`, `ServiceJWTClaims`, `ServiceJWTTokenUse`, `DefaultServiceJWTLifetime`, `ErrInvalidServiceJWT` | client credentials (`GrantClientCredentials`) |
| `Client.VerifyServiceJWT`, `Verifier.VerifyServiceJWT`, `verify.Verifier.VerifyServiceJWT`, `verify.WithServiceJWTMaxLifetime`, `ServiceJWTVerifyOption` | verify the client-credentials `at+jwt` with `verify.Verifier` (`Claims.Kind` is `iam.ActorOAuthClient`) |
| the `delegated-access+jwt`, `remote-application-access+jwt` and `service+jwt` token types | `at+jwt`: AuthKit's `verify` refuses the old types |
| `iam.DelegatedIdentity`, `iam.DelegatedGrant`, `CredentialState.Delegated`, `DelegatedIssuer` | `iam.InSession(iam.UserIdentity(id), ref)`; a resource token's authority is `verify.Claims.Permissions` |
| `verify.Claims.DelegatedSubject`, `Attributes`, `RemoteApplicationID`; `verify.TokenDelegated`, `TokenRemoteApplication` | `Subject`, `AuthorizationDetails`, `CustomClaims`, `Invoker` |
| AuthKit authenticating a remote application's own tokens | a resource server's own `verify.Verifier`, fed from `Client.RemoteApplication` (keys or JWKS URI; `Permissions` is the ceiling). The remote-application registry stays. |
| `Client.CheckIssuerKeys`, `Client.IssuerKeyStatuses`, `Verifier.CheckIssuerKeys`, `Verifier.IssuerKeyStatuses` | nothing: AuthKit's own verifier trusts only its own keys. A resource server's `verify.Verifier.CheckIssuerKeys` still reports its issuers. |
| the `delegated_token_mint` rate-limit bucket | nothing: `Config.RateLimits` now refuses that name |
| error codes `access_token_has_sub`, `access_token_wrong_typ`, `conflicting_subject`, `delegated_access_wrong_typ`, `delegation_authorizer_unavailable`, `delegation_refused`, `invalid_audiences`, `invalid_delegate_certificate`, `invalid_requested_grant`, `invalid_service_jwt`, `malformed_permissions`, `missing_delegated_sub`, `missing_iat`, `missing_nbf`, `not_delegated_access_token`, `permission_not_granted`, `remote_application_access_has_subject`, `service_jwt_lifetime_exceeded`, `ttl_exceeds_delegate_certificate` | `oauth_grant_refused` / `oauth_grant_authorizer_unavailable`, or the OAuth error a token endpoint answers |

Also breaking, from #397:
- **Migrations**: `authkit.Migrate`, `MigrateOptions` and `RuntimePool` are deleted, along with the runtime-role grants. `New` now migrates AuthKit's and River's tables through `Deps.Postgres`, whose role owns and uses them. `Config.Schema` and `Config.RiverSchema` move to `Config.Database` (`DatabaseConfig`). The `cmd/authkit-migrate` command is gone.
