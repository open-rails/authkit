# Changelog

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
