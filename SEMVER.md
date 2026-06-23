# AuthKit — Semantic Versioning Contract (v1.0.0)

This document defines the **public contract** of AuthKit: everything an embedding
application is allowed to depend on, and therefore everything whose change forces a
version bump. It is written as if we were cutting `v1.0.0` from the current tree.

Module path: `github.com/open-rails/authkit` · Go: `1.26`

> **Status:** proposed v1.0.0 contract. The current line is `v0.52.x`. Nothing here
> is frozen until `v1.0.0` is tagged. The [Pre-1.0 freeze risks](#11-pre-10-freeze-risks-advisory)
> section flags surfaces to shrink *before* we commit.

---

## 1. Versioning policy

AuthKit follows [Semantic Versioning 2.0.0](https://semver.org). Given `MAJOR.MINOR.PATCH`:

- **MAJOR** — a change that can break a conforming consumer: removing/renaming any
  covered symbol, route, field, constant value, or error code; tightening accepted
  input; changing a response shape, a JWT claim, an HTTP status, or a stored-schema
  invariant; or any change requiring a destructive/irreversible migration.
- **MINOR** — backward-compatible additions: new packages, exported symbols, optional
  config fields, new routes, new *optional* response fields, new error codes on paths
  that could already fail, additive forward-only migrations.
- **PATCH** — backward-compatible bug fixes that do not change any covered surface.

A change is **breaking** if a consumer who only used the covered contract — compiling
against the Go API, calling the documented routes, parsing the documented wire shapes,
and running the published migrations — could stop compiling, stop parsing, or observe a
different documented result.

### 1.1 The four contract planes

AuthKit is consumed in four distinct ways, each with its own rules:

| Plane | Consumed by | Covered by §|
|---|---|---|
| **A. Go library API** | apps that `import` AuthKit packages | [§4](#4-plane-a--go-library-api) |
| **B. HTTP route surface** | browsers/clients hitting mounted routes | [§5](#5-plane-b--http-route-surface) |
| **C. Wire formats** | any client parsing JSON / verifying tokens | [§6](#6-plane-c--wire-formats) |
| **D. Persistence & operations** | operators running migrations / configuring keys | [§7](#7-plane-d--persistence--operations) |

Compatibility is judged **per plane**. A purely additive Go method (Plane A minor) is
still minor even if it touches code behind a frozen route. Conversely, an internal
refactor that changes a JSON field name (Plane C) is **major** even though no Go symbol
changed.

### 1.2 What is explicitly NOT covered

See [§9](#9-explicitly-out-of-contract). In short: `internal/`, the devserver binary,
`*_test.go` helpers (except package `testing`), unexported behavior, log lines, exact
error *messages* (the `message` field), wall-clock timing, and any symbol/field marked
*Experimental* or *Deprecated*.

---

## 2. Conventions for this document

- "Covered symbol" = an exported (capitalized) Go identifier in a non-`internal`
  package listed in [§4.1](#41-packages--import-path--package-name).
- "Wire field" = a JSON key in a request or response body, an HTTP status code, a route
  method+path, a JWT claim, or an error `code`.
- The authoritative live enumeration of Plane A is `go doc ./<pkg>`; CI should diff it
  (see [§10](#10-enforcement)). The lists in this file are a snapshot for review.

---

## 3. Stability tiers

Not every exported symbol carries the same weight. Each package is assigned a tier; the
tier sets the *default* promise. Individual symbols may be annotated otherwise in their
doc comment.

| Tier | Meaning | Change discipline |
|---|---|---|
| **Stable** | Primary embedding surface. | Full semver; breaking = MAJOR. |
| **Stable (verify-only)** | Dependency-light verification surface. | Full semver; extra care: resource servers depend on it without pgx. |
| **Provided** | Optional first-party plug-ins (adapters, providers, stores). | Full semver, but may evolve with their upstream (gin/chi/redis/twilio). |
| **Advanced** | Low-level building blocks (key sources, signers, raw stores). | Covered, but intended for power users; prefer the Stable facade. |
| **Experimental** | Marked in doc comments. | **Not covered.** May change in MINOR. |

---

## 4. Plane A — Go library API

### 4.1 Packages — import path → package name

Several import paths bind a differently-named package; the **package name** is what
appears in consumer code. Renaming either is breaking.

| Import path | Package name | Tier | Role |
|---|---|---|---|
| `…/core` | `core` | Stable | Service, config, domain types, mint APIs |
| `…/http` | `authhttp` | Stable | HTTP transport, middleware, routes, error codes |
| `…/verify` | `verify` | Stable (verify-only) | Token verification, `Claims`, middleware — no pgx/redis |
| `…/authbase` | `authbase` | Stable (verify-only) | Shared primitives: error envelope, opaque-key parsing, sentinels |
| `…/jwt` | `jwtkit` | Advanced | Key management, signers, JWKS |
| `…/identity` | `identity` | Stable | Slug/identity store |
| `…/authprovider` | `authprovider` | Stable | Provider descriptors / claim mapping |
| `…/oidc` | `oidckit` | Stable | OIDC RP client manager |
| `…/password` | `password` | Stable | argon2id/bcrypt hash + verify |
| `…/siws` | `siws` | Stable | Sign In With Solana |
| `…/roles` | `roles` | Stable | Deterministic role-ID derivation |
| `…/lang` | `lang` | Stable | Language context helpers |
| `…/riverjobs` | `riverjobs` | Provided | River background workers |
| `…/testing` | `testing` | Stable | Test issuer for consumers |
| `…/ratelimit` | `ratelimit` | Stable | Rate-limit result types |
| `…/ratelimit/memory` | `memorylimiter` | Provided | In-memory limiter |
| `…/ratelimit/redis` | `redislimiter` | Provided | Redis limiter |
| `…/storage/memory` | `memorystore` | Provided | In-memory ephemeral stores |
| `…/storage/redis` | `redisstore` | Provided | Redis ephemeral stores |
| `…/adapters/gin` | `authkitgin` | Provided | Gin route registration |
| `…/adapters/chi` | `authkitchi` | Provided | Chi route registration |
| `…/providers/email/twilio` | `twilio` | Provided | SendGrid/Twilio email sender |
| `…/providers/sms/twilio` | `twilio` | Provided | Twilio SMS sender |
| `…/migrations/postgres` | `migrations` | Stable | Embedded Postgres migrations (`FS`, `FSForSchema`) |
| `…/migrations/clickhouse` | `migrations` | Stable | Embedded ClickHouse migrations (`FS`) |
| `…/internal/db` | `db` | **Out of contract** | sqlc-generated; never import |

**Adding a package** is MINOR. **Removing or renaming** a package, or changing its
package name, is MAJOR.

### 4.2 `core` — exported surface

`core` is the public, embedder-facing package. The full service implementation lives in
**`internal/authcore`** (driven by the `authkit/http` transport) and is **out of
contract** (§9). `core` re-exports the public data types, config, constants, sentinel
errors, and helper functions, and exposes a deliberately small **`Service` facade**: a
curated ~66-method surface (down from the former ~230 flat methods, #126) covering
provisioning, minting, management, and queries. Auth-flow plumbing that exists only to
serve the HTTP handlers stays internal and is **not** covered.

**Constructors & options**
```
func NewFromConfig(cfg Config, pg *pgxpool.Pool, extraOpts ...Option) (*Service, error)
func NewService(opts Options, keys Keyset, coreOpts ...Option) *Service
type Option func(*Service)
  WithAuthLogger, WithDBTXWrapper, WithEmailSender, WithEntitlements,
  WithEphemeralStore, WithPostgres, WithResourceScopeAuthorizer, WithSMSSender,
  WithSolanaSNSResolver
```

**Config types** (every field is covered; see [§7.3](#73-config-surface)):
`Config`, `TokenConfig`, `FrontendConfig`, `RegistrationConfig`, `KeysConfig`,
`IdentityConfig`, `APIKeysConfig`, `TwoFactorConfig`, `PasskeyConfig`, `RBACConfig`,
`SolanaConfig`, `Options`, `Keyset`.

**Mint APIs** (free functions + `*Service` facade methods — wire-shape owners):
```
MintServiceJWT, MintDelegatedAccessToken, MintRemoteApplicationAccessToken, MintCustomJWT
```
with params `ServiceJWTMintOptions`, `DelegatedAccessParams`, `RemoteApplicationAccessParams`,
`CustomJWTMintOptions`. `MaxCustomJWTLifetime = 1h` is a covered ceiling.

**Service facade methods** (covered) — the curated ~66-method embedder surface, reached
via `svc.Core()` from the HTTP service or directly from `core.NewFromConfig`. Grouped by
concern: user lifecycle/admin (`CreateUser`, `ImportUser`, `UpdateImportedUser`,
`GetUserBy{Email,Username,Phone,SolanaAddress}`, `BanUser`/`UnbanUser`,
`{Soft,Hard}DeleteUser`, `RestoreUser`, `AdminListUsers`/`AdminGetUser`/…); tokens
(`Mint*`, `IssueAccessToken`); passwords (`VerifyUserPassword`, `ChangePassword`,
`UpsertPasswordHash`); RBAC/groups (`Can`, `AssignRoleBySlug`/`RemoveRoleBySlug`/
`UpsertRoleBySlug`, `CreatePermissionGroup`, `EnsureRootGroup`); API keys
(`MintAPIKey`, `ListAPIKeys`, `RevokeAPIKey`, `ResolveAPIKey[WithResources]`); remote
apps; identity linking; sessions; bootstrap; and accessors (`JWKS`, `Postgres`, `Schema`,
`Options`, `PublicKeysByKID`, `Keyfunc`, …). Every method on the facade is covered; the
229 implementation methods on `internal/authcore.Service` are **not**.

**Domain & result types** (covered): `User`, `AdminUser`, `AdminUserStatus`,
`AdminUserSort`, `AdminListUsersResult`, `AdminUserListOptions`, `AdminRecoverUserInput`,
`ImportUserInput`, `Session`, `SessionFreshness`, `SessionRevokeReason`,
`SessionEventType`, `AuthSessionEvent`, `PendingRegistration`, `PendingChangeKind`,
`PreferredLanguage`, `Passkey`, `PasskeyLoginResult`, `APIKey`, `APIKeyMintOptions`, `APIKeyResource` (alias),
`ResolvedAPIKey` (alias), `TwoFactorSettings`, `TwoFactorFactor`, `MFAStatus`,
`RemovedMFARoleAssignment`, `VerificationMessage`, `SolanaLinkedAccount`, `ValidationError`.

**Permission-group / RBAC types** (covered): `GroupSchema`, `PersonaDef`, `RoleDef`,
`PermissionDef`, `ManagementProfile`, `GeneratedRoute`, `GroupAssignment`,
`GroupMember`, `GroupInvite`, `GroupInviteStatus*` consts, `SubjectGroupMembership`,
`CreatePermissionGroupRequest`, `CustomRoleResolver`, `PermissionGroupStore`,
`SubjectKindUser`/`SubjectKind*` consts, `RootPersona`, the `PermRoot*` constants, and the
`Perm*(t string) string` / `OwnerGrant` / `PermissionPersona` permission-builder funcs.

**Interfaces consumers implement** (covered — adding a method is MAJOR for an interface
consumers implement): `EmailSender`, `SMSSender`, `SMSHealthChecker`,
`EntitlementsProvider`, `BatchEntitlementsProvider`, `EntitlementFilterProvider`,
`EphemeralStore`, `AuthEventLogger`, `AuthEventLogReader`, `SolanaSNSResolver`,
`ResourceScopeAuthorizer`, `CustomRoleResolver`.

**Bootstrap types** (covered): `BootstrapManifest`, `BootstrapManifestUser`,
`BootstrapManifestGlobalRole`, `BootstrapManifestResult`, `BootstrapReconcileOptions`,
`BootstrapUserPassword`, `LoadBootstrapManifestFile`, `ParseBootstrapManifestYAML`,
`DefaultBootstrapManifestPath`. The **YAML manifest schema** is itself a wire contract
(see [§6.6](#66-bootstrap-manifest-yaml)).

**Validation helpers** (covered — these are AuthKit's identity policy, deliberately not
overridable): `ValidateUsername`, `OwnerSlugFromUsername`, `ValidatePassword`,
`NormalizeEmail`, `ValidateEmail`, `NormalizePhone`, `ValidatePhone`,
`NormalizePreferredLanguage`, `ValidatePermission`, `ValidateGrantPattern`,
`ValidationErrorCode`, plus the `ErrCode*` validation-code constants.

**Sentinel errors** (covered — consumers compare with `errors.Is`): `ErrUserBanned`,
`ErrPasswordResetRequired` (→ HTTP `password_reset_required`), `ErrReauthenticationRequired`,
`ErrTwoFAEnrollmentRequired`, `ErrRenameRateLimited`, `ErrOwnerSlugTaken`,
`ErrPasskeyNotFound`, `ErrPasskeyUserVerificationRequired`, `ErrPasskeyCloneDetected`,
`ErrGroupNotFound`, `ErrNotGroupMember`, `ErrInviteNotFound`, `ErrUserRoleNotFound`,
`ErrReservedRoleSlug`, `ErrCannotRemoveLastAdminRole`, `ErrEntitlementFilterUnavailable`,
`ErrInvalidBootstrapManifest`, `ErrEmptyCustomClaims`, `ErrRemoteApplicationNotFound`,
`ErrAttributeDefNotFound`, and the `ErrInvalid*` re-exports from `authbase`.
`HashAlgoLegacyResetRequired = "legacy-reset-required"` is a covered stored value.

> **Done (#126):** the former dual API (a ~230-method flat `*core.Service` plus an unused
> 166-method facet mirror) has been collapsed. The facet layer is deleted; the
> implementation moved to `internal/authcore`; the public `core.Service` is now the
> curated ~66-method facade above. This *is* the Stable core.

### 4.3 `verify` & `authbase` — the verify-only surface

These import **no** Postgres/Redis/storage. A pure resource server depends on them
directly to keep `pgx`/`redis` out of its build graph. `authhttp` re-exports every name
below, so token-issuing apps need no change.

**`verify`** (Stable, verify-only):
```
type Verifier; NewVerifier(opts ...VerifierOption) *Verifier
  WithAPIKeyPrefix, WithAlgorithms, WithAttributeHydration, WithAttributesPolicy,
  WithHTTPClient, WithPermissions, WithSSRFGuard, WithSkew
type Claims (see §6.4); ClaimsFromContext, GetClaims, SetClaims
Middleware: Required, Optional, RequiredServiceJWT, RequireACR, RequireAMR, RequireMFA,
  RequireFreshAuth, RequireEntitlement, RequireAnyEntitlement, RequireDelegatedOrigin,
  RemoteApplicationCORS, Sensitive
Helpers: SensitiveClaims, SensitiveOptions, NewSSRFGuardedClient, SetRequestContextHook
Principals: DelegatedPrincipal, ServiceJWTPrincipal (+FromContext), Enricher,
  RemoteApplicationSource, IssuerKey, IssuerOptions (+RemoteAppOptions)
Service-JWT verify: ServiceJWTVerifyOption (WithServiceJWTMaxLifetime,
  WithServiceJWTReplayChecker), ServiceJWTReplayChecker
Policy callbacks: AttributeDefResolver, AttributesValidator, PermissionValidator
Consts: AccessTokenType, ServicePrincipalType="service", RemoteApplicationTokenType,
  DefaultSensitiveMaxAge=15m, DefaultOutboundTimeout=30s
```
`Enricher` is satisfied by `*core.Service`; attaching DB-backed enrichment is opt-in via
`verifier.WithService(coreSvc)`.

**`authbase`** (Stable, verify-only): `ErrorEnvelope`, `ErrorObject`, `NewErrorEnvelope`
(see [§6.1](#61-error-envelope)); `APIKeyResource`, `RemoteApplication`,
`RemoteAppKey`, `RemoteAppAttributeDef`, `ResolvedAPIKey`, `ServiceJWTClaims`; opaque-key
funcs `APIKeyMarker`, `FormatAPIKey`, `ParseAPIKey`, `HasAPIKeyPrefix`; permission match
funcs `PermMatches`, `PermissionTokenCovers`, `PermWildcard="*"`; origin funcs
`NormalizeAllowedOrigin(s)`, `OriginAllowed`; error helpers `ErrorMessage`,
`ErrorTypeForStatus`, `ErrorTypeInvalidRequest…` consts; mode consts `RemoteAppModeJWKS`,
`ServiceJWTTokenUse="service"`; sentinels `ErrInvalidAccessToken="invalid_token"`,
`ErrInvalidServiceJWT`, `ErrInvalidRemoteApplication`, `ErrAttributeDefNotFound`.

### 4.4 Other packages — exported surface (snapshot)

- **`jwtkit`** (Advanced): `Signer`/`HeaderSigner`/`PublicKeySigner`/`ClaimsBuilder`
  interfaces; `RSASigner`, `ECDSASigner`, `Ed25519Signer`, `KeyRing`; `KeySource` +
  `EnvKeySource`, `FileKeySource`, `NewAutoKeySource(WithPath)`,
  `NewGeneratedKeySource(InDir)`, `ReloadableKeySource`, `StaticKeySource`; `JWK`, `JWKS`,
  `ServeJWKS`, conversion funcs; token-type consts (`AccessTokenType="access+jwt"`, …);
  `DefaultAuthKeysPath="/vault/auth"`, `DefaultGeneratedKeysDir=".runtime/authkit"`;
  `BaseRegisteredClaims`, `AlgorithmForPublicKey`, `SetLogger`, `ErrUnsupportedJWK`.
  **No API returns a private key or PEM** — that absence is a deliberate, covered invariant.
- **`identity`**: `Store`, `NewStore`, `NewStoreInSchema`, `User`, `ErrSlugNotFound`.
- **`authprovider`**: `Provider`, `Kind` (`KindOIDC`/`KindOAuth2`), `ClientSecret`,
  `AppleJWTSecret`, `UserMapping`, `FieldMapping`, `Identity`, `FallbackLookup`,
  `BuiltIns`, `BuiltIn`, `Clone`, `MapIdentity`, `MapFallbackEmail`, `ErrClientSecretEnvEmpty`.
- **`oidckit`**: `Manager` (+`NewManager*`), `RPClient`, `RPConfig`, `Claims`,
  `StateCache`, `StateData`, `AppleSecretConfig`, `AppleWithKey`,
  `NewAppleClientSecretProvider`, `GeneratePKCE`, `DefaultExchanger`, TTL consts.
- **`password`**: `HashArgon2id`, `VerifyArgon2id`, `VerifyBcrypt`, `IsBcryptHash`,
  `Validate`, `Params`, `DefaultParams`. **Accepted hash formats (argon2id, bcrypt) are a
  covered whitelist** — see [§6.7](#67-password-hash-policy).
- **`siws`**: `SignInInput`/`SignInOutput`, `NewSignInInput`, `ParseMessage`,
  `ConstructMessage`, `Verify`, `VerifySignature`, `ValidateAddress`, `ValidateDomain`,
  `ValidateTimestamps`, `GenerateNonce`, base58 funcs, `ChallengeCache`, `ChallengeData`,
  `AccountInfo`, `InputOption` (+`With*`).
- **`roles`**: `IDFromSlug(slug) uuid.UUID`, `NamespaceRoleIDs`. **Role IDs are
  deterministic UUIDv5 from slug** — the derivation is a covered invariant (rows must stay
  stable across environments).
- **`lang`**: `LanguageFromContext`, `WithLanguage`.
- **`testing`**: `TestIssuer`, `NewTestIssuer(WithAudience|WithSigner)`.
- **`ratelimit`**: `Result`, `Reason*` consts. **`memorylimiter`/`redislimiter`**: `Limit`,
  `Limiter`, `New`. **`memorystore`/`redisstore`**: `KV`, `SIWSCache`, `StateCache` + `New*`.
- **`authkitgin`/`authkitchi`**: `RegisterAPI`, `RegisterJWKS`, `RegisterOIDC`,
  `RegisterRoutes`, `APIOption` (`WithRoutes`, `WithRouteWrapper`), `APIOptions`.
- **`twilio` (email/sms)**: `Sender`, `New`, `Config`, and the builder func types.
- **`riverjobs`**: `PurgeDeletedUsersWorker`/`Args`, `RegisterPurgeDeletedUsersWorker`,
  `AddPurgeDeletedUsersPeriodicJob`, `BeforeUserHardDeleteFunc`.

### 4.5 `authhttp` re-exports & server surface

`authhttp` is the integration entry point. Covered:
```
type Server = Service; NewServer(cfg core.Config, pg *pgxpool.Pool, opts ...Option) (*Server, error)
Option: WithRedis, WithEmailSender, WithSMSSender, WithEntitlements, WithEphemeralStore,
  WithRateLimiter, WithoutRateLimiter, WithClientIPFunc, WithLanguageConfig,
  WithAuthLogger, WithAuthLogReader, WithErrorLogger, WithResourceScopeAuthorizer,
  WithSolanaDomain, WithSolanaSNSResolver
Handlers / mounts: svc.APIHandler(), svc.JWKSHandler(), svc.OIDCHandler(),
  svc.Routes() (DefaultAPI/Groups/OIDCBrowser/PermissionGroups), svc.Core()
Re-exports from verify: Verifier, NewVerifier, Claims, Enricher, IssuerOptions, IssuerKey,
  DelegatedPrincipal, ServiceJWTPrincipal, SensitiveOptions, the policy/validator aliases,
  Required/Optional/RequiredServiceJWT/Sensitive/Require* middleware
  (admin authorization is permission-based via the root permission group — there is no
   bespoke RequireAdmin gate; the /admin/* routes gate on root:* perms — see §5.3)
Rate limiting: RateLimiter, RateLimiterWithResult, RateLimiterWithRetryAfter, Limit,
  RateLimitResult, DefaultRateLimits(), AllowNamed, ToMemoryLimits, ToRedisLimits, RL* consts
Client IP: ClientIPFunc, DefaultClientIP, ClientIPFromForwardedHeaders, PublicRemoteAddrClientIP
Language: LanguageConfig, LanguageMiddleware
Routing: RouteGroup (+consts), RouteSpec, Routes
Errors: ErrorCode (+the full constant set, §6.2), InternalErrorEvent
Remote-application issuers client: RemoteApplicationIssuersClient (+options/registration)
```

---

## 5. Plane B — HTTP route surface

### 5.1 Mounting model (covered behavior)

- Routes are **prefix-neutral**. The host chooses the mount point; AuthKit's internal
  paths (`/token`, `/me`, `/admin/users`, …) are fixed. Mounting `RegisterAPI` under
  `/api/v1` yields `/api/v1/token`, etc.
- Hosts select capability subsets via `svc.Routes().Groups(...)`. The set of
  `RouteGroup` values and their membership is covered.
- `RouteSpec{Method, Path, Group, Handler}` shape is covered. Path params use net/http
  `{param}` syntax.
- JWKS mounts separately at `svc.JWKSHandler()` (conventionally `/.well-known/jwks.json`).
- Browser OIDC routes mount via `svc.Routes().OIDCBrowser()` (conventionally `/oidc`).

**Adding a route** to an existing group is MINOR. **Removing/renaming a route, changing
its method, moving it between groups, or changing its auth requirement** is MAJOR.

### 5.2 Route groups (covered constants)

`RoutePublic`, `RouteRegister`, `RouteSession`, `RouteUser`, `RoutePasskeys`, `RouteAdmin`,
`RouteBrowserOIDC`, `RoutePermissionGroups`.

### 5.3 Static API route table (covered)

| Method | Path | Group | Auth |
|---|---|---|---|
| GET | `/identity-providers` | public | none |
| POST | `/token` | session | none (refresh token in body) |
| POST | `/sessions/current` | session | none |
| DELETE | `/logout` | session | required |
| POST | `/password/login` | session | none |
| POST | `/passkeys/login/begin` | passkeys | none |
| POST | `/passkeys/login/finish` | passkeys | none |
| POST | `/email/password/reset/request` | session | none |
| POST | `/email/password/reset/confirm` | session | none |
| POST | `/phone/password/reset/request` | session | none |
| POST | `/phone/password/reset/confirm` | session | none |
| POST | `/2fa/challenge` | session | none |
| POST | `/2fa/verify` | session | none |
| POST | `/solana/challenge` | session | none |
| POST | `/solana/login` | session | none |
| POST | `/register` | register | none |
| GET | `/register/availability` | register | none |
| POST | `/register/resend-email` | register | none |
| POST | `/register/resend-phone` | register | none |
| POST | `/register/abandon` | register | none |
| POST | `/email/verify/request` | register | none |
| POST | `/email/verify/confirm` | register | none |
| POST | `/phone/verify/request` | register | none |
| POST | `/phone/verify/confirm` | register | none |
| GET | `/me` | user | required |
| POST | `/user/password` | user | required |
| GET | `/user/sessions` | user | required |
| DELETE | `/user/sessions/{id}` | user | required |
| DELETE | `/user/sessions` | user | required |
| PATCH | `/user/username` | user | required |
| PATCH | `/user/preferred-language` | user | required |
| PATCH | `/user/biography` | user | required |
| POST | `/user/email` | user | required |
| POST | `/user/phone` | user | required |
| DELETE | `/user` | user | required |
| DELETE | `/user/providers/{provider}` | user | required |
| POST | `/passkeys/register/begin` | passkeys | required |
| POST | `/passkeys/register/finish` | passkeys | required |
| GET | `/passkeys` | passkeys | required |
| PATCH | `/passkeys/{id}` | passkeys | required |
| DELETE | `/passkeys/{id}` | passkeys | required |
| POST | `/reauth/password` | user | required |
| POST | `/reauth/2fa` | user | required |
| POST | `/oidc/{provider}/link/start` | user | required |
| POST | `/oidc/{provider}/reauth/start` | user | required |
| GET | `/user/2fa` | user | required |
| POST | `/user/2fa` | user | required |
| DELETE | `/user/2fa` | user | required |
| POST | `/user/2fa/backup-codes` | user | required |
| POST | `/solana/link` | user | required |
| GET | `/admin/users` | admin | `root:users:read` |
| GET | `/admin/users/{user_id}` | admin | `root:users:read` |
| GET | `/admin/users/{user_id}/signins` | admin | `root:users:read` |
| POST | `/admin/users/ban` | admin | `root:users:ban` |
| POST | `/admin/users/unban` | admin | `root:users:ban` |
| POST | `/admin/users/{user_id}/recover` | admin | `root:users:update` |
| POST | `/admin/users/{user_id}/sessions/revoke` | admin | `root:sessions:revoke` |
| DELETE | `/admin/users/{user_id}` | admin | `root:users:delete` |
| POST | `/admin/users/{user_id}/restore` | admin | `root:users:delete` |

### 5.4 Generated permission-group routes (covered, schema-derived)

For each configured permission-group persona, AuthKit **generates** routes
addressed by resource slug. A capability a profile disables emits **no** route (calling it
404s — stronger than 403). The cross-persona `GET /me/groups` is always present.

| Method | Path shape | Wired |
|---|---|---|
| GET | `/me/groups` | yes |
| GET | `/{persona}/{resource_slug}/members` | yes |
| POST | `/{persona}/{resource_slug}/members` | yes |
| DELETE | `/{persona}/{resource_slug}/members/{user}` | yes |
| PUT | `/{persona}/{resource_slug}/members/{user}/roles/{role}` | yes |
| GET | `/{persona}/{resource_slug}/roles` | yes (catalog read) |
| POST | `/{persona}/{resource_slug}/roles` | **501 stub** |
| DELETE | `/{persona}/{resource_slug}/roles/{role}` | **501 stub** |
| GET | `/{persona}/{resource_slug}/api-keys` | yes |
| POST | `/{persona}/{resource_slug}/api-keys` | yes |
| DELETE | `/{persona}/{resource_slug}/api-keys/{key}` | yes |
| GET | `/{persona}/{resource_slug}/remote-applications` | yes |
| POST | `/{persona}/{resource_slug}/remote-applications` | yes |
| DELETE | `/{persona}/{resource_slug}/remote-applications/{app}` | yes |
| GET | `/{persona}/{resource_slug}/invites` | yes |
| POST | `/{persona}/{resource_slug}/invites` | yes |
| DELETE | `/{persona}/{resource_slug}/invites/{invite}` | yes |

> The custom-role **define/delete** routes return `501 not_implemented`. Promoting them
> from 501 to a working response is **not** breaking; the `not_implemented` code on those
> two paths is therefore *not* a frozen guarantee. All other generated routes are covered.

### 5.5 Browser OIDC routes (covered, group `browser_oidc`)

| Method | Path | Notes |
|---|---|---|
| GET | `/{provider}/login` | begins OIDC, redirects to provider; optional app-relative `return_to` |
| GET | `/{provider}/callback` | full-page callback → `{BaseURL}{CallbackPath}#access_token=…&refresh_token=…&return_to=…` |
| GET | `/{provider}/reauth/callback` | reauth variant |

The fragment-callback contract (tokens in the URL `#fragment`, default callback
`/login/callback`) is covered. `return_to`, when supplied at login start, is
validated as an app-relative path and emitted in the callback fragment; absolute,
protocol-relative, backslash, and CR/LF values are dropped.

---

## 6. Plane C — Wire formats

Every JSON request/response body of a covered route is part of the contract. The
cross-cutting shapes below are pinned exactly; per-route bodies follow the
[response-evolution rules](#68-requestresponse-body-evolution-rules).

### 6.1 Error envelope

All error responses use the **Stripe-style nested envelope** (`authbase.ErrorEnvelope`):

```json
{ "error": { "type": "invalid_request_error", "code": "password_too_short",
             "message": "Password too short.", "param": "password",
             "metadata": { "retry_after_seconds": 30 } } }
```

| Field | Covered guarantee |
|---|---|
| `error.code` | Stable machine code; one of [§6.2](#62-error-codes). **Frozen string value.** |
| `error.type` | Category derived from status: `invalid_request_error` (400/404/409), `authentication_error` (401), `authorization_error` (403), `rate_limit_error` (429), `api_error` (5xx). |
| `error.message` | Human-readable English. **NOT covered** — for display/logging, never matching. |
| `error.param` | Optional offending field on validation errors. |
| `error.metadata` | Optional machine-readable context (rate-limit `retry_after_seconds`/`limit`/`remaining`, action-availability fields). |

> This envelope was **breaking as of v0.52.0** (was flat `{"error":"<code>"}`). At v1.0.0
> the nested shape is the frozen contract; reverting it would be MAJOR.

### 6.2 Error codes (covered enumeration)

The `ErrorCode` constants in `authhttp` are the wire-code contract. The **string value**
of each is frozen; removing a code or changing its value is MAJOR. Adding a new code is
MINOR (a client must already tolerate unknown codes). Compare against the constants
(e.g. `authhttp.ErrPasswordResetRequired`), never copied literals.

The full set is enumerated in `http/error_codes.go` (~260 codes). Notable stable codes
referenced by behavior elsewhere in this contract: `invalid_request`, `not_found`,
`unauthorized`, `forbidden`, `rate_limited`, `database_error`, `invalid_credentials`,
`password_too_short`, `password_reset_required`, `registration_disabled`,
`reauth_required`, `2fa_enrollment_required`,
`rename_rate_limited`, `owner_slug_taken`, `username_not_allowed`,
`permission_grant_denied`, `unknown_permission`, `unknown_role`,
`role_not_grantable_to_api_key`, `resource_scope_denied`.

### 6.3 Token-pair response (covered)

Login, refresh, OIDC, Solana, registration-confirm, and verification endpoints that
establish a session return the OAuth-style pair:

```json
{ "access_token": "<jwt>", "token_type": "Bearer",
  "expires_in": 900, "refresh_token": "<opaque>" }
```

The 2FA-gated login variant instead returns:
```json
{ "requires_2fa": true, "user_id": "...", "method": "email|sms|totp",
  "challenge": "...", "default_factor": {...}, "available_factors": [...] }
```
A mandatory-2FA-but-unenrolled login returns `2fa_enrollment_required` with an
enrollment-only bearer token scoped to `GET/POST /user/2fa`.

### 6.4 JWT token taxonomy & claims (covered)

AuthKit signs all token classes with the app's single keypair (one `kid` on JWKS); they
differ only in claims/`typ`. The **`typ` header values and claim semantics are frozen**:

| Credential | `typ` / marker | Authority source |
|---|---|---|
| User access token | `access+jwt` | local user identity + `sid` + short-lived `entitlements` |
| Delegated access token | `delegated-access+jwt` + `delegated_sub` | `permissions`, validated vs issuer's stored authority |
| Remote application access token | `remote-application-access+jwt` (no `sub`/`delegated_sub`) | stored authority resolved from validated `iss` |
| Service JWT | `service+jwt` + `token_use=service` | receiver intersects requested perms with server grants |
| API key | opaque `<prefix>_st_<key_id>_<secret>` | DB perms/resources resolved by hashing secret |

**User access-token claims** are uniform: registered claims + `sub` + `sid` +
authoritative short-lived `entitlements`. They **do not** carry `global_roles`, `roles`,
`org_roles`, `email`, `email_verified`, `username`, or `discord_username` — that data is
resolved server-side via `/me` and route state. This exclusion is a covered invariant.

The Go view is `verify.Claims` (covered struct). Removing/retyping a field is MAJOR;
adding a field is MINOR. Key fields: `UserID`, `SessionID`, `Entitlements`, `AMR`, `ACR`,
`AuthTime`, `TwoFAEnrollment`, `Issuer`, `JTI`, `TokenTyp`, `TokenType`, `Permissions`,
`Resources`, `DelegatedSubject`, `DelegatedRoles`, `Attributes`, `UserTier`,
`RemoteApplicationID`/`Slug`. `Attributes` (the `attributes` claim) is the namespaced,
opaque escape hatch AuthKit transports but never interprets.

### 6.5 API key format (covered)

`Authorization: Bearer <prefix>_st_<key_id>_<secret>`, where `<prefix>` is
`Config.APIKeys.Prefix`. `key_id` is a non-secret indexed id; only `sha256(secret)` is
stored; the full key is shown once at mint. Parsing is via `authbase.ParseAPIKey` /
`FormatAPIKey`. An API key holds exactly **one** permission-group role; its permissions re-resolve
from that role at verify time. The format and resolution semantics are covered.

### 6.6 Bootstrap manifest YAML

The bootstrap manifest schema (`users`/`global_roles`, and the three password modes:
`plaintext`, `hash`+`hash_algo`,
`reset_required`) is a covered wire contract parsed by `LoadBootstrapManifestFile` /
`ParseBootstrapManifestYAML`. Removing/renaming a field is MAJOR.

### 6.7 Password hash policy (covered)

Verification accepts exactly **argon2id** (native) and **bcrypt** (legacy, lazily
re-hashed to argon2id on first login). The whitelist itself is the invariant; *narrowing*
it is breaking, and adding a format is a deliberate security decision, not a routine
minor. Unverifiable imports use `hash_algo = "legacy-reset-required"` and surface
`password_reset_required`. Minimum password length is 8 (`password_too_short`).

### 6.8 Request/response body evolution rules

- **Removing or renaming** a request field that was honored, or a response field, → MAJOR.
- **Adding a required request field**, or tightening validation on an existing field, → MAJOR.
- **Adding an optional request field** (with backward-compatible default) → MINOR.
- **Adding a response field** → MINOR (clients must ignore unknown fields).
- **Changing a field's JSON type, or an HTTP status code** for a given outcome → MAJOR.
- Fields tagged `omitempty` may be absent; their presence/absence semantics are covered.

Action-availability responses (e.g. `rename_rate_limited`) carry the shared fields
`action`, `allowed`, `reason`, `retry_after_seconds`, `next_allowed_at`,
`cooldown_seconds`; these are covered. (`time_until_rename_available` is retained as a
covered compatibility alias.)

---

## 7. Plane D — Persistence & operations

### 7.1 Database schema & migrations

- Postgres migrations are embedded at `migrations/postgres` (`FS`, `FSForSchema(schema)`)
  and ClickHouse at `migrations/clickhouse` (`FS`). They are run with
  [migratekit](https://github.com/open-rails/migratekit), name-tracked in
  `public.migrations` so a recorded migration is never re-applied.
- **Migrations are forward-only and append-only after v1.0.0.** Published migration files
  are immutable; schema evolution ships as *new* migrations. A migration that drops a
  column/table relied on by a prior release, or that is destructive/irreversible, is MAJOR.
- AuthKit's tables live in the schema named by `Config.Schema` (default `profiles`).
  Non-default schemas must run `FSForSchema`-rendered migrations. The configurable-schema
  behavior and the `^[a-z_][a-z0-9_]*$` (≤63 byte) name rule are covered.
- **PostgreSQL 18+ is required** (native `uuidv7()` defaults). Raising the floor is MAJOR.
- Tables/columns are *operationally* observable but the **canonical interface is the Go
  API + routes**, not direct SQL. Stable, externally-relied-upon invariants that ARE
  covered: deterministic UUIDv5 role IDs (`roles.IDFromSlug`), the `legacy-reset-required`
  hash-algo value, the owner-namespace states (`restricted_name`/`parked_org`/
  `registered_org`), and seeded restricted names (`admin`, `superuser`, `root`, `sudo`).

### 7.2 Key resolution & environment variables (covered)

When `Config.Keys.Source == nil`, the local resolver precedence is fixed:
1. **Env** — `ACTIVE_KEY_ID` + `ACTIVE_PRIVATE_KEY_PEM` (+ optional `PUBLIC_KEYS`).
2. **File** — `<dir>/keys.json` where `dir` = `Config.Keys.Path` → `AUTHKIT_KEYS_PATH` →
   `/vault/auth` (default). Envelope: `{active_key_id, active_private_key_pem, public_keys}`.
3. **Dev-gen** — auto-generates under `.runtime/authkit/`; **hard-fails in production**
   (`ENV`/`APP_ENV`/`ENVIRONMENT` = `production`/`prod`).

These env var names, the default path, the file envelope shape, and the prod hard-fail
are covered. AuthKit reads **no** provider env vars directly — hosts inject senders.

### 7.3 Config surface (covered, field by field)

`core.Config` carries data/policy only (deps are injected via options). Every field below
is covered; removing/renaming a field, or changing a documented default, is MAJOR. Adding
an optional field with a backward-compatible zero-value default is MINOR.

- **`Token`** `TokenConfig`: `Issuer`, `IssuedAudiences`, `ExpectedAudiences`,
  `AccessTokenDuration`, `RefreshTokenDuration`, `SessionMaxPerUser` (0 ⇒ default 3).
- **`Frontend`** `FrontendConfig`: `BaseURL` (defaults to issuer if empty),
  `CallbackPath` (default `/login/callback`; `/reset` & `/verify` are fixed, not configurable).
- **`Registration`** `RegistrationConfig`: `Verification` (`none`|`optional`|`required`,
  default `none`), `NativeUserMode` (`open` default; non-open disables public signup).
  The `RegistrationMode` & `RegistrationVerificationPolicy` enum value sets are covered.
- **`Keys`** `KeysConfig`: `Source`, `Path`, `VerifyOnly` (no-signer mode: minting returns
  `ErrMissingSigner`, verification/JWKS still work).
- **`Identity`** `IdentityConfig`: `Providers` (`map[string]oidckit.RPConfig`),
  `ProviderDescriptors` (`map[string]authprovider.Provider`).
- **`APIKeys`** `APIKeysConfig`: `Prefix` (lowercase alnum 1–16; empty ⇒ bare `st_`),
  `MaxTTL` (0 ⇒ uncapped).
- **`TwoFactor`** `TwoFactorConfig`: `TOTPSecretKey` (16/24/32 bytes). Role-level
  MFA requirements live on `RoleDef.RequiresMFA`.
- **`RBAC`** `RBACConfig`: `Permissions` (`[]PermissionDef`), `Groups` (`[]PersonaDef`).
- **Top-level**: `Environment`, `Schema`, `SolanaNetwork`.

The constructor-injected dependencies (`WithPostgres`/`WithRedis`/`WithEmailSender`/
`WithSMSSender`/`WithEntitlements`/…) are covered as Plane A options.

### 7.4 Fixed policy constants (covered)

These are intentionally non-configurable and part of the contract: email verification &
reset link/code TTLs (email verify 60m, phone verify 15m, password reset 1h, server-sent
2FA codes 10m); username rules (4–30 chars, ASCII-letter start, `[A-Za-z0-9_]`, no `@`,
no leading `+`); user rename cooldown 72h; 10 backup codes (8-char alphanumeric);
`SensitiveActionFreshAuthWindow = 15m`; SNS lookup timeout 3s / cache TTL 24h.
Default rate-limit buckets come from `DefaultRateLimits()`.

---

## 8. Compatibility quick-reference

A change is **MAJOR (breaking)** if it does any of:

- removes/renames a covered package, symbol, route, JSON field, config field, or constant;
- changes a constant's value, an enum's accepted set, a JSON field's type, or an HTTP status;
- changes a JWT `typ`, claim name/semantics, or the API-key/token-pair/error-envelope shape;
- changes an error `code` string (the `message` is exempt);
- adds a method to an interface that consumers implement;
- adds a required request field, or tightens accepted input / validation;
- raises the Postgres floor, mutates a published migration, or ships a destructive migration;
- changes a documented default, fixed TTL, or key-resolution precedence.

A change is **MINOR** if it: adds a package/symbol/route/optional-field/error-code,
relaxes validation, or ships an additive forward-only migration. **PATCH** = behavior-
preserving fixes.

---

## 9. Explicitly out of contract

- `internal/db` and anything under `internal/` (sqlc-generated; may change any release).
- The devserver (`authkit-devserver.go`, `DEVSERVER.md`, `Dockerfile.devserver`,
  `docker-compose.devserver.yaml`) and its env vars (`DEVSERVER_*`,
  `AUTHKIT_BOOTSTRAP_*`) — an operational tool, not a library contract.
- `*_test.go` files and test-only helpers (package `testing` IS covered).
- Error `message` strings (the human-readable `error.message`); log lines; metrics names.
- Exact DB table/column layout beyond the invariants pinned in [§7.1](#71-database-schema--migrations).
- Wall-clock timing, ordering of unordered collections, and unspecified internal behavior.
- Any symbol/field/route whose doc comment marks it **Experimental** or **Deprecated**
  (deprecated items remain for one MAJOR cycle, then may be removed).
- The `501 not_implemented` response on the custom-role define/delete generated routes
  ([§5.4](#54-generated-permission-group-routes-covered-schema-derived)).
- Transitive third-party dependency types re-exposed only incidentally (e.g. `pgxpool`,
  `gin`, `chi`, `redis`, `river` types in signatures) follow their own upstream semver;
  we cover *our* signatures, not their internals.

---

## 10. Enforcement

To keep this document honest, CI should gate the contract mechanically:

1. **Go API diff** — snapshot `go doc ./...` (or `gorelease` / `apidiff`) for every
   non-`internal` package; fail the build if a symbol is removed/changed without a MAJOR
   bump. This is the source of truth for Plane A.
2. **Route table diff** — assert `svc.Routes().DefaultAPI()` + `OIDCBrowser()` +
   `PermissionGroups()` against a golden list ([§5](#5-plane-b--http-route-surface)).
3. **Error-code diff** — assert the `ErrorCode` constant set against a golden list.
4. **Wire-shape tests** — golden JSON for the error envelope, token-pair, `/me`, and the
   2FA login responses.
5. **Migration immutability** — checksum published migration files; forbid edits.

---

## 11. Pre-1.0 freeze risks (advisory)

The original list is mostly **resolved** by #126 (the public-surface shrink). Remaining
items are advisory — resolve before tagging v1.0.0:

1. ~~`*core.Service`'s ~230 flat methods + the unused 166-method facet mirror.~~ **DONE
   (#126):** facets deleted; implementation moved to `internal/authcore`; the public
   `core.Service` is now a curated ~66-method facade. This is the Stable core.
2. ~~Empty `OrgsFacet`.~~ **DONE (#126):** removed with the facet layer.
3. ~~Legacy `RBACConfig` fields (`DefaultRoles`, `OwnerOwnsAppResources`) + the orphaned
   `DefaultRole` type.~~ **DONE (#126):** removed.
4. ~~`MaxDelegatedRoles = maxDelegatedRoles` re-export.~~ **DONE (#126):** collapsed to a
   single exported `verify.MaxDelegatedRoles = 64`.
5. **Duplicate-shaped 2FA variants** (`Enable2FA`/`Enable2FADefault`,
   `Require2FAForLogin`/`…Factor`, etc.). DEFERRED in #126 (overlapped #125's live 2FA
   rewrite); now *internal* to `authcore`, so **no longer a public-contract risk** — tidy
   at leisure.
6. **Curate the facade further (or add facets).** The ~66-method facade is the floor for
   what embedders need today; trim any that prove unused, or add a grouped accessor layer
   (`svc.Core().Users().…`) if the flat list grows unwieldy. Cheap to do on the small
   surface.
7. **Advanced `jwtkit` surface.** Confirm which signer/key-source types are meant for
   consumers vs. internal-only, and consider moving the latter behind `internal/`.
