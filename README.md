# AuthKit

Embedded auth library for Go services: users, sessions, MFA, passkeys, device
keys, OAuth/OIDC and Solana login, RBAC permission groups, API keys, signed
documents and delegated tokens, running in your process against your Postgres
(18+) and Redis. Tests exercise the embedded HTTP handlers directly; AuthKit
owns its PostgreSQL migration source and runs it through migratekit.

Modules: `github.com/open-rails/authkit`, plus `adapters/gin`, `adapters/fiber`
and `adapters/riverjobs` as separate modules. The embedded engine uses River
for PostgreSQL maintenance; the root and `verify` packages remain engine-free.

For local tests, run `scripts/check.sh`. Applications call
`embedded.ApplyMigrations` with migration credentials before constructing the
engine, then call `runtime.Start(ctx)` before serving and `runtime.Close()` at shutdown.

See [verification trust and key ownership](docs/verification.md) for local versus
external identity, application delegation boundaries, and key rotation.
See [authentication workflows](docs/security/authentication-workflows.md) for
first-factor continuations, atomic registration, and workflow test coverage.

Redis-compatible stores must support atomic `GETDEL` and atomic Lua
(`EVAL`/`EVALSHA`); proof claims and counters depend on those guarantees.
For Garnet, enable both `--lua true` and `--lua-transaction-mode true`.
Garnet's [configuration reference](https://microsoft.github.io/garnet/docs/getting-started/configuration)
describes the transaction mode that locks script keys for execution.

## Migrations

```go
import (
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/embedded"
)

ownerPool, _ := pgxpool.New(ctx, migrationDSN)
runtimePool, _ := pgxpool.New(ctx, applicationDSN)
err := embedded.ApplyMigrations(ctx, ownerPool, "profiles", embedded.MigrationOptions{
	RuntimePool: runtimePool,
})
// Pass runtimePool to embedded.Deps{Postgres: runtimePool} when constructing the runtime.
```

AuthKit owns the embedded migration source, migratekit runner, migration
ledger and target schema creation. The call is idempotent and must complete
before `embedded.New`; consumers do not import AuthKit migrations or
migratekit. Pre-v1 schemas must be rebuilt for the
[fresh baseline](docs/maintenance/fresh-schema-baseline.md); AuthKit never drops
existing application data automatically.

`RuntimePool` identifies the application's existing database user through its
active connection. Both pools must connect to the same database. Initialization
grants that user AuthKit's schema, table, sequence and function permissions
directly, plus the runtime objects of managed River. AuthKit creates no database
roles or memberships, and the host needs no AuthKit-specific `GRANT` script.
The same normal application login and pool can serve other embedded libraries.
Both pools remain host-owned. Omit `RuntimePool` for migration-only setup with
access provisioned separately; runtime credentials never need migration rights.

## PostgreSQL maintenance

AuthKit runs `CleanupExpiredAuthState` through River on startup and hourly.
It removes expired sessions, terminal credentials and expired retained history;
Redis and in-memory TTL state keep their local expiry behavior. User hard-delete
purging remains an explicit `adapters/riverjobs` integration with retention,
erasure acknowledgements and the host's `BeforeUserHardDelete` policy.

With no River dependency supplied, `ApplyMigrations` also applies River's own
migrations to `public`. `New` constructs an owned worker client without starting
it or running DDL. Call `runtime.Start(ctx)` before serving; `runtime.Close()`
cancels its workers and releases only AuthKit-owned resources. Runtime pools
need data access, while initialization uses separate migration credentials.
`Config.River.Schema` and `MigrationOptions.RiverSchema` select a custom managed
River schema; `Config.River.CleanupInterval` defaults to one hour.

Applications sharing River with other libraries compose one worker configuration:

```go
ownership := embedded.RiverFromHost()
err := embedded.ApplyMigrations(ctx, ownerPool, "profiles", embedded.MigrationOptions{
	River: ownership, RuntimePool: runtimePool,
})
// The host initializes its River schema through River's migrator.
runtime, err := embedded.New(cfg, embedded.Deps{Postgres: runtimePool, Redis: rdb, River: ownership})
jobs, err := riverhelpers.New(ctx, runtimePool, &river.Config{Schema: "public"},
    runtime.RiverJobs(), billing.RiverJobs())
err = runtime.Start(ctx) // checks composition; never starts the host client
err = jobs.Start(ctx)
// On shutdown: stop jobs before runtime.Close().
```

`RiverJobs` contributes AuthKit's worker, queue and periodic schedule to the
neutral `github.com/open-rails/helpers/river` composer. Producer binding happens inside
composition; no per-library binding call or hand-written host cron is needed.
The passed host configuration owns the River schema. The
registry supports one AuthKit engine; duplicate registration fails explicitly.
With `RiverFromHost`, the host also owns River database permissions; AuthKit
provisions only its identity schema, leaving the shared fleet's access unchanged.

**Every replica sharing a River schema must carry the same complete periodic
schedule set.** River's elected leader alone schedules periodic jobs. Separate
managed AuthKit and OpenRails clients with different schedules in the same
`public` fleet can starve each other's maintenance. Use the composed host client
above, or explicitly separate their River schemas. A managed AuthKit fleet is
appropriate when its replicas all run the same AuthKit workers and schedules.

## Construction

`embedded.New(cfg, deps)` returns the local `*embedded.Runtime`, which owns
pools, keys, River and lifecycle. `runtime.Client()` returns the engine-free
`authkit.Client` operation view. That view does not expose local configuration,
bootstrap or resource access. Creating it starts no additional engine.

Configure HTTP once after provisioning, then obtain and mount its routes:

```go
runtime, err := embedded.New(cfg, embedded.Deps{Postgres: pg, Redis: rdb, Email: mailer})
if err != nil {
    return err
}
defer runtime.Close()
client := runtime.Client() // application user/group/token operations

err = runtime.ConfigureHTTP(authhttp.Config{
    TrustedProxies: []string{"10.0.0.0/8"}, // or DirectPeerIP when no proxy is present
    Mount: authhttp.MountOptions{APIPrefix: "/api/v1", RefreshCookie: true},
})
if err != nil {
    return err
}
routes, err := authkitgin.Routes(runtime)
if err != nil {
    return err
}
router := gin.New()
if err := routes.Mount(router); err != nil {
    return err
}
// Compose runtime.RiverJobs() with the host fleet, or start managed workers.
// Application middleware uses runtime.Verifier(); domain code uses client.
```

Use the same pattern with `authkitfiber.Routes(runtime).Mount(app)` or
`authkithttp.Routes(runtime).Mount(mux)` for a standard `http.ServeMux` or Chi
router. Handle the error returned by `Routes` before calling `Mount`.
The `adapters/http` package is included in the core module; Gin and Fiber are
separate modules.

`ConfigureHTTP` is one-shot. A failed build consumes the attempt and closes
partial HTTP resources; the operation client remains available. Calling
`HTTPRoutes` before configuration seals HTTP disabled and returns an error.
Configure before obtaining route bundles; configuration after Close is refused.
The runtime closes its HTTP resources before its engine resources.

The HTTP policy chooses groups, API prefix, exclusions, wrappers and refresh
cookies once through `authhttp.Config.Mount`. The runtime derives concrete
routes from that policy and enabled identity features. Native route inspection
shows the actual inventory. JWKS remains at `/.well-known/jwks.json`, browser
OIDC under `/oidc`, and published documents at their standard root path; mount
AuthKit on the host root router. No catch-all is installed.

`authhttp.New(runtime, config)` and `authhttp.NewMount` remain lower-level
constructors for hosts explicitly managing HTTP lifetime themselves. The
runtime-configured path owns that work automatically. Neither constructor
accepts a portable or remote operation Client as a server backend. This release
adds no remote AuthKit client or standalone service.

## Verification in a host

`runtime.Verifier()` is a `*verify.Verifier`; `verify` imports no Postgres or
Redis, so a pure resource server depends on it alone.
`verify.Required`/`Optional` and their `authkitgin` and `authkitfiber` equivalents
put `verify.Claims` in the request context. `Optional` permits a missing
credential but rejects a present invalid credential; it never downgrades an
invalid token to anonymous access. `Required` accepts any supported principal,
including machine principals, so user-only handlers must also check the result
of `UserClaims` (or `claims.IsUser()` with `net/http`).

`RequirePermission` resolves the group name once and
authorizes the immutable UUID: a user is checked live against `GroupID`, a
group-bound API key must match the scope, an unbound delegated token is
authorized from its own `permissions`. `AuthorityIssuer` is this deployment's
`Token.Issuer`; `verify.PermissionScopeFromContext` hands the handler the
authorized scope.

### Fiber v3

Install the separate adapter module:

```sh
go get github.com/open-rails/authkit/adapters/fiber
```

The middleware and typed accessors mirror the Gin adapter. Configure the local
runtime once as above, then register its inventory:

```go
routes, err := authkitfiber.Routes(runtime)
if err != nil {
    return err
}
app := fiber.New()
app.Get("/api/me", authkitfiber.Required(runtime.Verifier()), func(c fiber.Ctx) error {
    user, ok := authkitfiber.UserClaims(c)
    if !ok {
        return fiber.ErrUnauthorized
    }
    return c.JSON(fiber.Map{"user_id": user.UserID})
})
if err := routes.Mount(app); err != nil {
    return err
}
```

All installed endpoints appear in `app.GetRoutes(true)`, named with
`authkitfiber.RouteNamePrefix`. `Mount` takes the root `*fiber.App`; HTTP policy
was already supplied to `ConfigureHTTP`. Exact method/path conflicts, unsupported
patterns and disabled HTTP methods are rejected before registration. Put host
catch-alls after mounting. Unmatched requests follow Fiber's native routing.

`Claims(c)` returns all verified claims, `UserClaims(c)` returns only user
claims, and `Principal(c)` exposes the authenticated principal. They read the
standard context available through `c.Context()`, so downstream Go services can
also use `verify.ClaimsFromContext(c.Context())`. `RequiredLive` adds the same
live account checks as the Gin and `net/http` middleware; its constructor
returns an error when the verifier has no liveness source. `RequirePermission`
applies the same permission policy using a Fiber scope resolver.

Gin and Fiber's `UserClaimsData` names both alias `verify.UserClaimsData`, and
their accessors delegate to `verify.UserClaimsFromContext`. Only `UserID` is
guaranteed populated on a successful user result. Profile fields are normally
absent with `Required`/`Optional`; `RequiredLive` loads the current email,
verification flag, and username but does not refresh token entitlements or MFA
claims. See [user-claim presence and freshness](docs/verification.md#user-claims-presence-and-freshness).

## Surfaces

- `docs/api-endpoints.md` — generated route table plus wire notes; CI fails
  when stale.
- `docs/naming-policy.md` — user/group naming, renames and aliases.
- [docs/ownership.md](docs/ownership.md) — role replacement and final-owner protection.
- `SEMVER.md` — what the version contract covers.
- `SECURITY.md` — reporting and the CI gates.

## Refresh cookie

`MountOptions{RefreshCookie: true}` moves the rotating refresh token out of
every response body into an `HttpOnly`+`Secure`+`SameSite=Lax` cookie
(`authkit_rt`) path-scoped to the mount's `POST /token`, which requires the
cookie and rejects body refresh tokens. Native mounts require body tokens and
never consume refresh cookies. `DELETE /logout`
and a refresh failing with `user_banned` clear it; an unknown-token `401`
never does. The SPA and mount must share an origin. Cookie-mode JSON mutations
reject cross-origin, opaque-origin and cross-site requests before consuming
credentials. Omitted `Origin` remains valid for non-browser clients unless fetch
metadata indicates another site. Origin comparison uses the deployment scheme
and request host or configured frontend origin; forwarded origin headers are
never trusted. Browser OIDC callbacks retain their state-cookie binding.
Cookie mode is off by default.

Mounted JSON API bodies require `Content-Type: application/json` (parameters such
as `charset=utf-8` are allowed), including when cookie mode is off. Empty-body
routes retain their existing behavior. JSON clients using body tokens continue
to work across origins when the host allows them.

## Browser OIDC

`GET /oidc/{provider}/login[?return_to=/app/path][&ui=popup&popup_nonce=…]`
→ provider → `/oidc/{provider}/callback` (GET, or POST for form_post) → `302`
to `Frontend.BaseURL + OIDCReturnPath` (default `/login/callback`):

- success: `#access_token=…&refresh_token=…&expires_in=…&provider=…[&return_to=…]`
  (no `refresh_token` with the refresh cookie);
- error: `#error=<code>&flow=login|link&provider=…`; `2fa_enrollment_required`
  carries `enrollment_token`, `enrollment_expires_in`, `allowed_methods`
  instead of an access token;
- popup: `postMessage` of `{type: "AUTHKIT_OIDC_RESULT", access_token, …, nonce}`
  or `{type: "AUTHKIT_OIDC_ERROR", error, flow, provider, nonce}`.

`return_to` must be app-relative. Linking a provider to an existing account is
`POST /api/v1/oidc/{provider}/link/start`: it needs fresh authentication
(`403 step_up_required`) and an existing link for the same issuer must be
unlinked first (`409 provider_change_requires_unlink`). Completion requires that
same session to remain live and fresh. Successful linking returns an empty 204
for JSON, or redirects with `#flow=link&result=success&provider=…`; it retains the
existing session and issues no tokens or refresh cookie. See
[credential and recovery grants](docs/security/credential-grants.md).

## RBAC

`Config.RBAC` is `[]embedded.PersonaDef`. Each persona is a permission
namespace (`org:members:read`) with a role catalog; non-root personas name one
`Parent`; `root` is the parentless singleton with AuthKit's built-in owner
role. `Capabilities` opt a persona into the generated
API-key, remote-application and custom-role routes; `Creation.Enabled` mounts
`POST /<persona>`. Assignments are rows keyed by persona and role name: treat
both as durable identifiers and never rename in place; removed names fail
closed without deleting rows. One role per subject per group; who may create a
group is the host's decision.

## Signed documents and delegated tokens

`documents.NewService` signs, persists and re-verifies an immutable JSON
envelope (`type`, `iss`, `aud`, opaque `payload`) with the engine's live key.
Pass it in `authhttp.Config.Documents`; `MountHandler` then serves
`GET|HEAD /.well-known/authkit/documents/{digest}` to the remote applications
pinned in `Config.Documents.Readers` (by id, proven domain or root-registered
issuer — never slug). Receivers use `documents.NewResolver` and
`verify.Verifier.VerifyDocument`. The resolver guards nil/default transports
against private and reserved destinations, including current DNS answers.
`ResolverOptions.AllowHTTP` is the existing development opt-in for local HTTP
and private destinations. An explicit custom transport retains the host's network
policy; resolver timeouts, redirect bounds, response caps and verification still
apply.

`POST /api/v1/delegated/token` mounts when `Config.Delegated.Audiences` is set
and requires the one host seam:

```go
deps.DelegatedAuthorization = func(ctx context.Context, req authkit.DelegationRequest) (authkit.DelegationGrant, error) {
	if !mayDelegate(ctx, req.UserID, req.RequestedGrant) {
		return authkit.DelegationGrant{}, authkit.ErrDelegationRefused // 403 delegation_refused; any other error is 503
	}
	return authkit.DelegationGrant{Permissions: []string{"resource:read"}}, nil
}
```

The request `{audiences, ttl_seconds, delegate_certificate_der_b64url,
requested_grant}` is clamped to the configured audiences and TTL bounds;
AuthKit signs only the grant plus every published document digest, bound to
the delegate's leaf certificate as `cnf: {"x5t#S256": …}` (RFC 8705). A bound
token verifies only when `r.TLS.PeerCertificates[0]` hashes to that value —
terminate TLS on the resource server with
`tls.Config{ClientAuth: tls.RequestClientCert}` or stricter; anything else
fails `sender_proof_required`.

Browser clients can use the same route without client certificates when the
issuer enables `Config.Delegated.AllowDPoP`. A validated DPoP proof binds the
result to a browser key as `cnf.jkt`; direct resource calls use the `DPoP`
authorization scheme and a fresh proof for each request. The host authorizer
still decides every permission and must handle the JWK binding with a nil
`DelegateCertificate`. See [browser delegation](docs/browser-delegation.md) for
the exact wire profile, receiver configuration and browser key lifecycle.

## Application self-registration

`Config.Applications = ApplicationsConfig{SelfRegistration: true, OrgPersona: "org"}`
mounts `POST /api/v1/applications/register` `{"domain": "cozy.art"}`. The
server fetches `https://<domain>/.well-known/authkit/application.json`; that
fetch is the domain-control proof (https, no redirects, SSRF-guarded). The
document declares `issuer`, one of
`jwks_uri`/`public_keys`, and a requested `slug` (default: the hostname)
claimed like any org slug. The result is a `registered`-tier remote
application plus a service-owned `OrgPersona` group. Re-registering the same
domain re-proves the root and refreshes the keys — that is key rotation; a
keypair never rotates itself. `Deps.ApplicationAdmission` is the host's cost
gate.

## Device keys

`Config.DeviceKeys.Enabled` mounts `RouteDeviceKeys` for native clients.
`POST /api/v1/device-keys/enroll/begin` (email + public key → emailed code)
and `enroll/finish` (code + signature; an MFA-protected account must also
present its second factor) enrol a per-machine key. `login/begin` +
`login/finish` exchange a signed challenge for a short access token and
nothing else — no refresh session. `GET /api/v1/device-keys`,
`DELETE /api/v1/device-keys/{id}` and `POST /api/v1/device-keys/revoke-others`
manage keys; a revoked machine cannot revoke its replacement.

## Passkey primitives

`/api/v1/passkeys/*` covers browser login, registration and management. A host
that drives WebAuthn itself calls the same ceremonies on `*embedded.Runtime`;
every finish consumes its ceremony once and only for the purpose it was begun
with:

- `BeginDiscoverablePasskeyVerification` / `Finish…` → `VerifiedPasskey`, an
  identity proof only — no session, token or cookie;
- `BeginPasskeyAccount` / `Finish…` → a new passkey-only user (needs an open
  `Registration.NativeUserMode`);
- `BeginPasskeyRegistration(userID)`, then `FinishPasskeyRegistration` (add) or
  `FinishPasskeyReplacement` (atomic single-passkey rotate).

The host gates who may call these and never treats a `VerifiedPasskey` as a
session.

## Liveness

`verify.Required` is stateless: a banned or deleted user keeps a valid access
token until it expires (at most one access TTL). For a surface that cannot
accept that window:

```go
// authhttp.New(runtime, cfg) already wires its operation client as the liveness source.
requiredLive, err := authkitgin.RequiredLive(srv.Verifier()) // verify.RequiredLive for net/http
```

It denies banned, deleted, reserved and unknown accounts on the next request
and hands the handler fresh `Username`/`Email`/`EmailVerified`. Fail-closed:
one `UserLivenessByIDs` read per request, no cache, a lookup error denies.
A standalone `verify.NewVerifier()` still needs an explicit
`WithLiveness(client)`; without a source, live middleware construction returns
`verify.ErrLivenessUnconfigured`. Hosts can replace a service verifier's source
with the same setter. Attaching the source does not change stateless middleware.

Choose the scope where the check runs by mounting middleware, with no global
configuration switch or implicit admin-role policy:

- `verify.Required` and `verify.Optional` keep native-user token checks stateless.
- `verify.RequiredLive` requires credentials and checks native-user liveness.
- `verify.OptionalLive` admits anonymous requests without a lookup; presented
  credentials must verify, and native users must pass the liveness check.

The Gin and Fiber adapters expose matching `RequiredLive` and `OptionalLive`
constructors. Mount the returned native middleware on routes, groups, or the
whole application using the framework's usual registration methods.

```go
requiredLive, err := verify.RequiredLive(srv.Verifier())
if err != nil { return err }
optionalLive, err := verify.OptionalLive(srv.Verifier())
if err != nil { return err }
mux.Handle("/admin/", requiredLive(adminHandler)) // explicit sensitive-route policy
mux.Handle("/profile", optionalLive(profileHandler))
// Alternatively, wrap the unwrapped application handler instead of its routes:
handler := optionalLive(applicationHandler)
```

Mount on a route, a subtree/group, or the outer application handler according to
the host's policy; choose one scope to avoid redundant lookups. Anonymous
requests through `OptionalLive` remain anonymous. Invalid credentials, banned
accounts, and liveness-backend failures are refused instead of becoming
anonymous. These checks do not grant admin permissions; authorization remains a
separate route policy. Verified machine/external principals retain the existing
verifier behavior and do not acquire a native-user directory lookup.

AuthKit's built-in root-permission operations (such as the admin user directory,
ban, and account recovery routes) explicitly check native-user liveness after
permission authorization. A banned operator cannot use a still-valid token for
those operations. This policy follows the sensitive operation, not a role named
`admin`, and does not enable account lookups on ordinary application routes.

## Sessions across issuers

Deployments sharing one account schema under different issuers (separate site
logins, shared accounts) each set `Token.AccountIssuers` to the same issuer set.

| Operation | Refresh sessions revoked on |
| --- | --- |
| `DELETE /logout`, `DELETE /user/sessions[/{id}]`, `RevokeIssuerSessions`, session-cap eviction, refresh reuse | this issuer |
| `AdminRevokeAccountSessions[As]` (`POST /admin/users/{user_id}/sessions/revoke`), password change/reset/admin set, contact change, ban, deletion | every account issuer |

The emergency revoke also revokes device keys and returns
`authkit.AccountSessionRevocation`: covered issuers, per-issuer counts, and live
sessions left under unlisted issuers (nonzero means incomplete configuration).
Each revoked session is recorded under its own issuer, plus one
`account_sessions_revoked` event.

Revocation stops refresh and step-up re-authentication at once. It does not
recall issued access tokens: `verify.Required` accepts them until `exp`
(`AccessTokenDuration`), and `RequiredLive`/`AllowLive` check account liveness
and live permissions, not sessions. To cut privileged access immediately, also
ban the account or remove its roles.

## Account erasure across sites

Each site owns data keyed by the shared account, so deleting the account is a
handoff, not one host's job. Deleting a user (soft or hard) raises one erasure
obligation with one acknowledgement per `Token.AccountIssuers` entry — the
deleting deployment's own set, unioned with any already recorded.

```go
// Each site drains its own obligations, e.g. from a scheduled job.
res, err := authkit.AcceptErasureObligations(ctx, client, cfg.Token.Issuer, 500,
    func(ctx context.Context, o authkit.ErasureObligation) error {
        return myLedger.RecordErasure(ctx, o.UserID) // must COMMIT before returning nil
    })
```

Acknowledging means **"durably accepted into my own ledger"**, not "erased".
The hook must commit a row the site can replay later; returning nil without one
discards the only notice the site will get. A failed accept leaves the
obligation pending and never blocks the later pages.

| | |
| --- | --- |
| `ListErasureObligations(ctx, site, after, limit)` | keyset page (`created_at`, `user_id`), oldest first; `next == ""` on the last page. Progresses past any backlog. |
| `AcknowledgeErasure(ctx, site, userID)` | idempotent; a site the obligation does not require is a no-op. |
| `ListUsersDeletedBefore(ctx, cutoff, limit)` | the purge-ready set: accounts deleted before `cutoff` that **every** required site acknowledged — not every soft-deleted account. |
| `ErasureBacklog(ctx)` | per-site unacknowledged count and the oldest pending obligation (the age bound). |

A site added to `AccountIssuers` later is only required for obligations raised
after it is configured; back-fill its own ledger from the account store before
adding it. The purge job (`adapters/riverjobs`) is fleet-unique, so only the
executing host's `BeforeUserHardDelete` hook runs; the other sites are covered
by their own acceptance pass. `ListUsersDeletedBefore` never offers an
unacknowledged account, so an offline site retains the identity rather than
losing the notice, and the obligation — user id, email, username, phone —
outlives the hard delete until the last site acknowledges, then closes itself.
