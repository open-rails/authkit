# AuthKit — Semantic Versioning Contract

What an embedding application may depend on, and therefore what forces a
version bump. Module `github.com/open-rails/authkit` · Go 1.26 · Postgres 18+.

> **Status:** pre-1.0. Nothing is frozen until `v1.0.0`; until
> then breaking changes ship as MINOR bumps with a migration note, and
> [§9](#9-pre-10-freeze-list) lists what shrinks first.

## 1. Versioning policy

[Semantic Versioning 2.0.0](https://semver.org):

- **MAJOR** — anything that can break a conforming consumer: removing or
  renaming a covered symbol, route, field, constant value or error code;
  tightening input; changing a response shape, JWT claim, HTTP status,
  documented default, fixed TTL or schema invariant; adding a method to an
  interface consumers implement; raising the Postgres floor; a destructive
  migration.
- **MINOR** — compatible additions: packages, symbols, optional fields,
  routes, error codes, additive forward-only migrations, relaxed validation.
- **PATCH** — behaviour-preserving fixes.

A consumer is conforming when it only compiles against the Go API, calls the
documented routes, parses the documented wire shapes and runs the published
migrations.

Compatibility does not require accepting credentials, origins, signatures or
grants that violate the documented security rules. Correcting such acceptance
is a security fix. Changes to valid workflows, supported algorithms or documented
limits still require the version bump described above.

### 1.1 The four planes

| Plane | Consumed by | Section |
|---|---|---|
| **A. Go library API** | apps that `import` AuthKit | [§3](#3-plane-a--go-library-api) |
| **B. HTTP routes** | clients hitting mounted routes | [§4](#4-plane-b--http-route-surface) |
| **C. Wire formats** | anything parsing JSON or verifying tokens | [§5](#5-plane-c--wire-formats) |
| **D. Persistence & operations** | operators running migrations, configuring keys | [§6](#6-plane-d--persistence--operations) |

Compatibility is judged per plane: an additive Go method is MINOR even behind
a frozen route; a renamed JSON field is MAJOR even when no Go symbol changed.
Symbol lists, route tables, code catalogs and config fields live in the
generated or canonical sources named below, not here.

## 2. Stability tiers

| Tier | Meaning | Discipline |
|---|---|---|
| **Stable** | Primary embedding surface | Full semver |
| **Stable (verify-only)** | Verification surface with no pgx/redis | Full semver |
| **Provided** | First-party plug-ins (adapters, providers, backends) | Full semver, may move with their upstream |
| **Advanced** | Key sources, signers, raw stores | Covered; prefer the engine surface |
| **Experimental** | Marked in doc comments | Not covered; may change in MINOR |

## 3. Plane A — Go library API

### 3.1 Packages

| Import path | Package | Tier | Role |
|---|---|---|---|
| `github.com/open-rails/authkit` | `authkit` | Stable | `Client` interface, domain/wire types, typed identifiers, error catalog, verify-only primitives |
| `…/embedded` | `embedded` | Stable | The engine: `New(cfg, deps) (*Client, error)` |
| `…/authhttp` | `authhttp` | Stable | HTTP transport: `New(client, Config)`, `MountHandler` |
| `…/verify` | `verify` | Stable (verify-only) | Verifier, `Claims`, middleware, permission/liveness gates |
| `…/dpop` | `dpop` | Stable (verify-only) | RFC 9449 sender-proof verification and atomic replay callback |
| `…/documents` | `documents` | Stable | Signed-document envelopes, publisher/resolver, service |
| `…/authprovider` | `authprovider` | Stable | `Provider` interface + built-in IdPs |
| `…/oidckit` | `oidckit` | Stable | Browser-flow state, PKCE |
| `…/password` | `password` | Stable | argon2id/bcrypt |
| `…/ratelimit` (+ `/memory`, `/redis`) | `ratelimit` | Stable / Provided | `Limit`/`Result` and the two backends |
| `…/migrations/postgres` | `migrations` | Stable | Embedded migration source |
| `…/authtest` | `authtest` | Stable | Test issuer for consumers |
| `…/jwtkit` | `jwtkit` | Advanced | Key sources, signers, JWKS |
| `…/adapters/gin`, `…/adapters/riverjobs` | `authkitgin`, `riverjobs` | Provided | Own modules |
| `…/adapters/twilio/{email,sms}` | `twilio` | Provided | Senders |

Renaming an import path or package name is MAJOR; adding a package is MINOR.
`go doc` is the live enumeration; the compatibility comparison in §8 checks
exported signatures as well as the documented host compile fixtures.

**Nested modules.** `adapters/gin` and `adapters/riverjobs` are their own
modules so gin and river never enter the root `go.mod`. Tags: `vX.Y.Z` (root),
`adapters/gin/vX.Y.Z`, `adapters/riverjobs/vX.Y.Z`. Release order: tag the
root, bump each nested `require github.com/open-rails/authkit` to it, tag the
adapters.

### 3.2 Rules

- **Use `*embedded.Client` or a consumer-owned interface.** The constructor,
  configuration, trusted host operations, bootstrap/import, document store and
  passkey ceremonies documented in README and the host compile fixtures are
  covered. `authkit.Client` is a convenient subset, not the stability boundary.
  Methods used only to compose AuthKit's transport are implementation seams;
  an exported helper alone does not establish a supported host workflow.
- **`Client` membership.** Adding a method is MAJOR (fakes implement it). A
  method belongs only when a server calls it in-process; browser flows belong
  to the HTTP layer. Lifecycle pairs stay together (`MintAPIKeyWithOptions` ⇒
  `RevokeAPIKey`).
- **Operation shape.** Collection reads are `(ctx, []ID) (map[ID]T, error)`
  with missing ids absent; bulk mutations return per-item `[]OpResult` or are
  documented all-or-nothing; single-subject auth primitives are never batched.
- **Typed identifiers.** `Persona`/`Role`/`Perm`, `GroupRef`/`Subject`; groups
  are identified by immutable UUID and a resolved name never transfers
  authority (`docs/naming-policy.md`).
- **Interfaces consumers implement** — `EmailSender`, `SMSSender`,
  `EntitlementsProvider`, `EphemeralStore`, `CustomRoleResolver`,
  `authprovider.Provider`, `authhttp.DocumentProvider`, `verify.LivenessSource`,
  `verify.PermissionChecker` — adding a method is MAJOR.
- **Verify-only build graph.** Root and `verify` import no Postgres, Redis or
  engine package (`deps_guard_test.go`).
- **No API returns a private key or PEM.**

**Caller authority.** Trusted host commands accept identities already selected
and authorized by the host. A host must authenticate the caller, authorize the
operation and retain the resolved immutable IDs before calling them. `*As`
methods apply documented actor-dependent mutation constraints; they do not replace
the host's operation-level authorization. `Genesis()` is for explicitly trusted
bootstrap/import/provisioning, never for forwarding an untrusted role request.
The host owns this boundary even when it obtains the client through an interface.

**Concrete host families.** In addition to `authkit.Client`: `New`/`NewWithKeys`,
`Config`/`Deps`, `Genesis`, manifest loading/parsing, document publication via
`DocumentStore`, and the passkey begin/finish/list/rename/delete operations are
supported. AuthKit keeps the signer/key-source extension points in `jwtkit`:
document signing and host-managed keys consume them directly. Their external
types are part of the compile contract; upstream changes cannot silently break
an otherwise compatible AuthKit release.

## 4. Plane B — HTTP route surface

- Routes are prefix-neutral. `authhttp.MountHandler(svc, MountOptions)` serves
  the whole surface: JSON API under `APIPrefix` (default `/api/v1`), browser
  OIDC at `/oidc`, JWKS at `/.well-known/jwks.json`, documents at
  `/.well-known/authkit/documents/{digest}`.
- Covered: `MountOptions{Groups, APIPrefix, ExcludeRoutes, Wrap, RefreshCookie}`,
  `RouteRef`, `RouteSpec`, the `RouteGroup` constants and their membership, and
  `svc.JWKSHandler()` / `APIRoutes()` / `OIDCBrowserRoutes()` /
  `PermissionGroupRoutes()`.
- **The route table is `docs/api-endpoints.md`**, generated from the registry
  by `TestAPIEndpointsDoc`; CI fails when stale. Method, path, group, auth,
  rate-limit bucket and mount condition of every row are covered.
- Permission-group routes are generated per persona and addressed by
  `{instance_slug}`; a capability the persona does not enable emits no route
  (404).
- The browser OIDC fragment contract (README, "Browser OIDC") is covered.

Adding a route is MINOR. Removing or renaming one, or changing its method,
group or auth requirement, is MAJOR.

## 5. Plane C — Wire formats

### 5.1 Error envelope

Every error response is the nested envelope written by `authkit.WriteError`:

```json
{ "error": { "type": "invalid_request_error", "code": "password_too_short",
             "message": "Password too short.", "param": "password",
             "metadata": { "retry_after_seconds": 30 } } }
```

| Field | Guarantee |
|---|---|
| `code` | Stable machine code from the catalog (§5.2). Frozen string. |
| `type` | From status: `invalid_request_error` (400/404/409), `authentication_error` (401), `authorization_error` (403), `rate_limit_error` (429), `api_error` (5xx). |
| `message` | English, **not covered** — never match on it. |
| `param` | Optional offending field on validation errors. |
| `metadata` | Optional machine-readable context (rate-limit fields, pending-challenge state). |

Every failure is a `*authkit.Error{Code, Status, Param, Meta}`; `errors.Is`
compares codes. Every status-500 failure is `internal_error` on the wire;
502/503 keep their codes.

### 5.2 Error codes

The catalog is `authkit.Codes()` (root `errors.go`), pinned by
`errors_test.go` and `authhttp/error_catalog_integration_test.go`. A code's
string and status are frozen; removing one is MAJOR, adding one is MINOR
(clients must tolerate unknown codes). Compare against `authkit.Code*`
values.

### 5.3 Success shapes

- **`authkit.TokenSet`** `{access_token, token_type: "Bearer", expires_in,
  refresh_token?}` is the whole body of every session-establishing route, or
  sits under `token_set` beside route fields (registration, step-up, device
  keys). `refresh_token` is omitted under the refresh cookie.
- **Pending challenges are 403 envelopes** (`2fa_required`,
  `2fa_enrollment_required`, `verification_required`) with the challenge in
  `metadata`, never a 200 with an error field.
- **`authkit.ListPage`** `{object: "list", data, next_cursor?}` for every list.
- `204` for mutations with nothing to return; `202` empty for anti-enumeration
  sends. No `{"ok": true}` bodies.
- **`authkit.UserProfile`** is `GET /me`.

### 5.4 JWT taxonomy & claims

All token classes are signed with the deployment's keypair and differ only in
claims and `typ`; the `typ` values and claim semantics are frozen:

| Credential | `typ` / marker | Authority |
|---|---|---|
| User access token | `access+jwt` | local identity + `sid` + short-lived `entitlements` |
| Delegated access token | `delegated-access+jwt` + `delegated_sub` (+ exactly one of `cnf.x5t#S256` or `cnf.jkt` when bound) | `permissions` vs the issuer's stored authority; certificate or DPoP proof must match its binding |
| Remote application token | `remote-application-access+jwt`, no `sub` | stored authority from validated `iss` |
| Service JWT | `service+jwt` + `token_use=service` | receiver intersects requested perms with its grants |
| API key | opaque `<prefix>_st_<key_id>_<secret>` | one group role, resolved at verify time |

The opt-in browser profile returns `{token, expires_at, token_type: "DPoP"}`
from the existing delegated-token route and binds that token through `cnf.jkt`.
Protected requests require the `DPoP` authorization scheme and a fresh proof;
neither detached verification nor `Bearer` presentation can bypass the binding.
Certificate delegation retains `{token, expires_at}` and `cnf.x5t#S256`.
The exact proof, replay, URL and error-header contract is defined in
[browser delegation](docs/browser-delegation.md), not a separate symbol catalog.

User access tokens carry registered claims + `sub` + `sid` + `entitlements`;
profile and group state are never claimed. `attributes` is the namespaced,
opaque escape hatch AuthKit never interprets; `documents` is the validated
`type -> sha256:<digest>` map. The Go view is `verify.Claims`: removing or
retyping a field is MAJOR, adding one is MINOR.

### 5.5 API key format

`Authorization: Bearer <prefix>_st_<key_id>_<secret>`; `<prefix>` is
`Config.APIKeys.Prefix` (empty ⇒ bare `st_`). `key_id` is a non-secret index,
only `sha256(secret)` is stored, the full key is shown once. A key holds one
role; its permissions re-resolve at verify time.

### 5.6 Bootstrap manifest

The YAML schema (`users`, `remote_applications`, password modes `plaintext` /
`hash`+`hash_algo` / `reset_required`, `root_role`) parsed by
`LoadBootstrapManifestFile` / `ParseBootstrapManifestYAML` is a wire contract;
removing or renaming a field is MAJOR.

`ApplyBootstrapManifest` commits the complete manifest in one transaction.
`StartupOnly` is once per database schema: names label completion receipts,
and another name does not run an additional genesis. Failed or canceled seed
writes roll back with the receipt; a corrected attempt can retry. Separate
schemas remain independent. `DryRun` validates without writing; ordinary
reconciliation remains atomic and preserves the password seed-once and
owner seed-if-absent rules.

### 5.7 Password hash policy

Exactly argon2id (native) and bcrypt (legacy, re-hashed on first login) are
accepted. Narrowing is MAJOR; adding a format is a security decision, not a
routine MINOR. Unverifiable imports use `hash_algo = "legacy-reset-required"`
and surface `password_reset_required`. Minimum length 8.

### 5.8 Body evolution rules

- Removing or renaming an honoured request field, or any response field → MAJOR.
- Adding a required request field, tightening validation, changing a field's
  JSON type or an outcome's status → MAJOR.
- Adding an optional request field with a compatible default, or any response
  field → MINOR; clients must ignore unknown fields.
- `omitempty` fields may be absent; their presence semantics are covered.

## 6. Plane D — Persistence & operations

### 6.1 Schema & migrations

- Embedded at `migrations/postgres` (`FS`), applied directly through
  migratekit, keyed by numeric sequence with filename and content identity checks.
- Forward-only and append-only after v1.0.0: published files are immutable;
  evolution ships as new migrations. A destructive migration is MAJOR.
- Tables live in `Config.Schema` (default `profiles`; `^[a-z_][a-z0-9_]*$`,
  ≤63 bytes). Postgres 18+ (native `uuidv7()`); raising the floor is MAJOR.
- The interface is the Go API and routes, not SQL. Covered invariants:
  immutable user/group UUIDs, the `legacy-reset-required` hash-algo value,
  owner-namespace states and seeded restricted names. Roles are scoped names;
  no role UUID contract exists.
- Pre-v1 databases are disposable. The fresh `0001_schema.up.sql` baseline
  replaces old AuthKit histories; no data or migration compatibility is offered
  for those histories. `migratekit.ApplyMigrations` establishes readiness;
  `ValidateAllApplied` is the read-only migration check.

### 6.2 Keys & environment

The library reads no environment variables (`env_doctrine_test.go`); a binary
reads env once and passes explicit config. With `Keys.Source == nil` the
resolver loads `<Keys.Path>/keys.json` (default `/vault/auth`; envelope
`{active_key_id, active_private_key_pem, public_keys}`, hot-reloaded), else
generates an in-memory dev keypair only with `Keys.AllowEphemeralDevKeys`,
else construction fails. `<Keys.Path>/totp.key` encrypts TOTP secrets.

### 6.3 Config surface

`embedded.Config`, `embedded.Deps` and `authhttp.Config` are covered field by
field; each field's godoc is the canonical description and default. Removing
or renaming a field, or changing a documented default, is MAJOR; adding an
optional field with a compatible zero value is MINOR. Every dev behaviour is an
explicit field with the safe default, and `authhttp.Config` requires a
client-IP posture.

### 6.4 Fixed policy constants

Non-configurable and covered: email verify 60m, phone verify 15m, password
reset 1h, server-sent 2FA codes 10m; username rules (4–30 chars, letter start,
`[A-Za-z0-9_]`); 10 backup codes; 15m sensitive-action freshness;
invite-link default TTL 72h, hard ceiling 30d (clamped).
Default rate limits: `authhttp.DefaultRateLimits()`.

## 7. Explicitly out of contract

- Anything under `internal/`; migration command wiring and its env vars; the root
  `docker-compose.yaml`.
- `*_test.go` and test-only helpers (`authtest` IS covered).
- Error `message` strings, log lines, metrics names.
- Table/column layout beyond §6.1; timing; ordering of unordered collections.
- Anything marked **Experimental**. Deprecation alone does not remove an
  existing compatibility promise.
- Third-party behavior beyond the types required by supported signatures.

## 8. Enforcement

Mechanical today:

1. **Route table** — `TestAPIEndpointsDoc` regenerates `docs/api-endpoints.md`;
   a stale file fails CI.
2. **Error catalog** — `errors_test.go` and
   `authhttp/error_catalog_integration_test.go` pin every code's status and
   envelope.
3. **Env doctrine** — `TestLibraryCodeReadsNoEnvironment` guards the library;
   the migration command reads its explicit database configuration at startup.
4. **Build graph** — `TestRootAndVerifyArePgxFree`, `TestSharedLeavesAreStdlibOnly`.

5. **Go API and migration compatibility** — `scripts/check-compatibility.sh`
   compares all three modules against `compatibility/base-ref`, requires every
   baseline migration to remain byte-identical, and compiles host examples with
   `GOWORK=off`. The baseline is still a reviewed candidate before v1.
6. **Wire and browser workflows** — `TestSessionWireWorkflow` reads maintained
   HTTP/JWT goldens while allowing additive fields. `task test-browser` runs the
   actual two-site Chrome cookie lifecycle in CI. Route-specific MFA and failure
   assertions remain in the corresponding workflow suites.

## 9. Pre-1.0 freeze list

1. Finish the tracked registration/MFA and role-lifecycle repairs and qualify
   current consumer workflows against the coordinated release.
2. Establish Go/wire/migration compatibility checks (§8) and freeze their
   baseline when the owner approves v1. The current baseline remains a candidate.
