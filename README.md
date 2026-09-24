# AuthKit

Embedded auth library for Go services: users, sessions, MFA, passkeys, device
keys, OAuth/OIDC and Solana login, RBAC permission groups, API keys, signed
documents and delegated tokens, running in your process against your Postgres
(18+) and Redis. Tests exercise the embedded HTTP handlers directly; AuthKit
owns its PostgreSQL migration source and runs it through migratekit.

One module, `github.com/open-rails/authkit`, includes the core and every adapter.
One root release tag versions them together; adapter import paths are unchanged.
Framework dependencies enter an application's build only when it imports the corresponding adapter. The embedded engine uses River
for PostgreSQL maintenance; the root and `verify` packages remain engine-free.

For local tests, run `scripts/check.sh`. Applications call
`embedded.ApplyMigrations` with migration credentials before constructing the
engine, then call `runtime.Start(ctx)` before serving and `runtime.Close()` at shutdown.

See [verification trust and key ownership](docs/verification.md) for local versus
external identity, application delegation boundaries, and key rotation.
See [authentication workflows](docs/security/authentication-workflows.md) for
first-factor continuations, atomic registration, and workflow test coverage.
See [contact ownership](docs/security/contact-ownership.md) for why unproven
accounts cannot add login methods and what the first address proof revokes.

Without `Deps.Redis`, AuthKit keeps rate limits, codes and login state in
process memory, which is correct for a single replica only; multi-replica
deployments must configure Redis or Garnet. See
[rate limits](docs/security/rate-limits.md) for the per-address and per-account
policy.

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
Redis and in-memory TTL state keep their local expiry behavior. AuthKit also
owns the fixed 30-day recoverable account deletion lifecycle and its durable
application callbacks. There is no separate purge adapter to register.

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

Set HTTP policy in the runtime constructor, then obtain and mount its routes:

```go
cfg.HTTP = authhttp.Config{
    TrustedProxies: []string{"10.0.0.0/8"}, // or DirectPeerIP when no proxy is present
    Mount: authhttp.MountOptions{APIPrefix: "/api/v1", RefreshCookie: true},
}
runtime, err := embedded.New(cfg, embedded.Deps{Postgres: pg, Redis: rdb, Email: mailer})
if err != nil {
    return err
}
defer runtime.Close()
client := runtime.Client() // application user/group/token operations

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
The net/http, Gin, and Fiber adapters all ship in the root module.

Prefer `Config.HTTP` for policy known at construction. `ConfigureHTTP` supports
provisioning dependencies that become available later and is one-shot. A failed build consumes the attempt and closes
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

`embedded.New` initializes explicitly declared group containment and the root
singleton in one transaction. Omitted or empty RBAC leaves shared topology intact. Apply migrations before constructing a database-backed
runtime. Construction never grants user roles or restores revoked permissions.
Use `client.OperatorAssignGroupRole` and `client.OperatorUnassignGroupRole` for explicit
trusted operator commands; request paths use the actor-checked `*As` methods.
`Operator` describes the host's authority; it is not a built-in persona or role.

The runtime wraps a private engine and exposes only lifecycle, route, verifier,
job and construction dependencies. It has no public business methods, Genesis,
database, configuration or signer accessors. The HTTP transport receives its
local engine capability only while the runtime constructs it. This release
adds no remote AuthKit client or standalone service.

Native user JWTs establish identity; group memberships, roles and permissions
are always resolved live when a route requires permission. Native tokens do not
carry permission authority. The experimental `RootPermissionSnapshot` API has
been removed. Machine and delegated credentials retain their separate verified
permission ceilings and scope bindings.

Bans prevent login and refresh. An existing native identity JWT remains valid
until expiry (15 minutes by default), including on a permission route if its
current grant remains assigned. Revoking a role takes effect immediately at the
next permission check. Account liveness can still be explicitly requested with
`RequiredLive`, `OptionalLive`, or `IsLive`; it is not automatically added to
admin routes. Ownership mutations retain their current valid-owner invariants.

Select optional coarse entitlement claims explicitly:

```go
embedded.TokenConfig{EntitlementAllowlist: []string{"premium"}}
```

Only names actually granted by the entitlement provider are included. Empty
configuration skips that provider lookup during minting and omits the claim;
directory/admin provider results remain unfiltered. The allowlist is limited to
32 distinct names, 128 UTF-8 bytes per name and 2048 encoded JSON bytes. Provider
failure also omits the claim while allowing login; omission is not a successful
empty-grant lookup. These are token-time billing snapshots until refresh, not
live permission checks. Per-product ownership belongs in the billing query API.

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

For a consumer's provider-neutral interface, the same verifier implements
`AuthenticateRequest(context.Context, *http.Request) (auth.Principal, error)`
using `github.com/open-rails/helpers/auth`. The result exposes immutable identity
metadata and optional `auth.PermissionChecker` access. `Can` checks a host-resolved
`auth.Scope{Authority: issuer, ID: immutableGroupID}` and permission against live
native assignments or the verified machine credential's exact scope and ceiling.
The runtime wires its native checker automatically. Verify-only hosts can use
`WithPermissionChecker(client, authorityIssuer)`. Neither identity nor scope
selects an application's billing account or grants permission by itself.

`AuthenticateRequestLive` explicitly applies immediate account liveness; the
ordinary method retains the stateless user-session policy. Hosts that already
verified the request with trusted middleware may explicitly call
`PrincipalFromVerifiedClaims` after their admission policy. Those claims must come
from complete verification of this same unchanged request under the host's
intended issuer, audience, assurance and sender-proof policy. This handoff avoids
consuming a single-use DPoP proof twice. Ordinary authentication never trusts
ambient context claims. Retain the resulting principal only for that request.

### Fiber v3

Install AuthKit at the chosen root version, then import
`github.com/open-rails/authkit/adapters/fiber`. See the
[single-module upgrade instructions](SEMVER.md#single-module-upgrade) if the
application previously required an adapter module.

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
- [`sdk/auth-ui`](sdk/auth-ui) — `@openrails/auth-ui` browser client, React hooks
  and UI; each release attaches `openrails-auth-ui-X.Y.Z.tgz`.
- `SEMVER.md` — what the version contract covers.
- `SECURITY.md` — reporting and the CI gates.

## Refresh cookie

`MountOptions{RefreshCookie: true}` moves the rotating refresh token out of
every response body into an `HttpOnly`+`Secure`+`SameSite=Lax` cookie,
`__Host-authkit_rt` with `Path=/` so a sibling subdomain can neither plant nor
shadow it (plain-HTTP development uses the unprefixed `authkit_rt`). Cookies
from earlier releases are migrated on the next refresh; any cookie change must
go through the [cookie registry](docs/security/cookies.md). Only
`POST /token` reads it; it requires the cookie and rejects body refresh tokens. Native mounts require body tokens and
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

An account invitation never rides in a URL. To sign up with one, the page
POSTs `{"account_invite_token", "return_to"?, "ui"?, "popup_nonce"?}` to
`/oidc/{provider}/login` from its own origin and navigates to the returned
`auth_url`; the invitation is bound to the flow's server-side state. A GET
carrying `account_invite_token` is refused. On HTTPS the flow's state cookie is
`__Host-` prefixed. Providers may not share an issuer or use this deployment's.

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

An enabled remote application can own its immutable controlling group. Its
signed app-self token can use that group's existing member add, role-change,
removal, member-list and role-list endpoints. Mutations recheck current grants
and the credential's permission ceiling in the same transaction as the write;
both the replaced and requested roles must fit. Delegated user tokens do not
inherit the application's ownership. Registration invitations still require a
native user. A remote owner assignment in another group is rejected and never
counts as a remaining owner; ordinary ancestor permission grants are unchanged.

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

A group registering an application through its own routes binds the issuer on
its members' authority alone (`trust_root: "user"`). A later domain proof for
that issuer takes it over, unless the application is its group's last owner.
No application may claim this deployment's account issuers or an identity
provider's issuer.

## Device keys

`Config.DeviceKeys.Enabled` mounts `RouteDeviceKeys` for native clients.
`POST /api/v1/device-keys/enroll/begin` (email + public key → emailed code)
and `enroll/finish` (code + signature; an MFA-protected account must also
present its second factor) enrol a per-machine key. `login/begin` +
`login/finish` exchange a signed challenge for a short access token and
nothing else — no refresh session. `GET /api/v1/device-keys`,
`DELETE /api/v1/device-keys/{id}` and `POST /api/v1/device-keys/revoke-others`
manage keys; a revoked machine cannot revoke its replacement.

## Two-factor enrollment

`POST /user/2fa` starts (`{method}`) and confirms (`{method, code}`) a TOTP,
email or SMS factor. The confirming code verifies the enrolling session, so its
next refresh returns tokens rather than `2fa_required`; other sessions must
complete 2FA. See [API endpoints](docs/api-endpoints.md#two-factor-authentication).

An email/SMS 2FA code survives a wrong guess (`invalid_code`). The fifth miss
burns it; that miss and any later submission until a resend return
`2fa_code_expired`, as does an expired or unsent code.

## Passkey ceremonies

`/api/v1/passkeys/*` covers browser login, registration and management. AuthKit's
HTTP transport drives the private engine ceremonies; Runtime does not expose
workflow primitives to embedding applications. Every finish consumes its
ceremony once and only for the purpose for which it was begun.

## Liveness

`verify.Required` is stateless: a banned or deleted user keeps a valid access
token until it expires (at most one access TTL). For a surface that cannot
accept that window:

```go
// Config.HTTP wires the local engine as the liveness source.
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

AuthKit's built-in root-permission operations resolve permissions live, without
an implicit account-ban lookup. Existing native access tokens authenticate until
expiry; bans prevent login and refresh. Hosts can explicitly select the live
middleware above when they need immediate account revocation. Deleted or
reserved users cannot perform authority mutations, and ownership transitions
retain their stricter valid-owner checks.

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
and live permissions, not sessions. Removing the account's roles cuts privileged
access immediately. Bans block login and refresh; existing native access tokens
retain their remaining lifetime unless explicit live-account verification is used.

## Recoverable account deletion

Every accepted account deletion is soft for exactly 30 days. Ownership must be
transferred, or the group deleted, before its last eligible owner can delete
their account. Repeating deletion does not restart the clock. AuthKit revokes
existing sessions immediately, retains the identity for recovery, and schedules
a River finalizer for that account's exact deadline.

Pass optional `OnSoftDelete`, `OnHardDelete` and `OnRestore` functions in
`embedded.Deps`. Each receives `(context.Context, authkit.UserDeletion)` and
returns an error. The payload contains a deletion generation `ID`, `UserID`,
`DeletedAt` and `PurgeAt`. Soft callbacks must preserve recoverable host data;
restore callbacks undo reversible soft work. Hard callbacks run after the
deadline and before physical identity purge, so they can remove host foreign
keys. Final purge waits for all required applications to finish successfully.

Callbacks run at least once, outside database transactions, in lifecycle order
for each user and application. They must be idempotent and honor cancellation;
River retries errors without losing the cleanup. Nil means no application work
for that stage. The host does not poll a backlog or acknowledge events.

`Token.AccountIssuers` identifies deployments sharing account lifecycle. Each
issuer must compose its River fleet once before deletion affects it (until
then deletion fails with a logged cause, and startup warns naming it); AuthKit
remembers that issuer's River schema and queues callbacks directly into it,
even while the application is offline. Separate River schemas are supported,
but AuthKit and every participating fleet must address the same physical
database for atomic insertion. Binding verifies that identity, including
schema-bound pool copies. An issuer may bind a different River schema once it
has no active deletion generations or pending callbacks. The transition is
atomic and fences old runtime producers; active work must finish first.

Terminal generation and delivery history uses AuthKit's internal 90-day
retention and bounded maintenance batches. Active generations and unfinished
callbacks are never expired; old completed River jobs safely no-op afterward.

Trusted operators can use `client.OperatorRestoreUsers`; authorized HTTP
administrators use `POST /admin/users/{user_id}/restore`. Recovery before the
deadline invalidates that generation's finalizer without reviving revoked
sessions. Once finalization starts after the deadline, restoration is refused.
There is no public immediate-purge operation or configurable retention period.

A deleted user can prove their identity through the existing password,
passwordless, passkey, external-login or Solana login flow. Existing MFA still
applies. Successful proof returns `409 account_recovery_required` with an opaque
`recovery` object instead of a session. Submit its `token` to
`POST /account/recovery/confirm` to restore explicitly, then sign in normally.
The one-use confirmation expires within ten minutes and before the deletion
deadline; it is bound to that issuer, credential version and deletion generation.
It cannot authenticate API requests, enroll new MFA factors, or refresh a session.
Required but missing MFA enrollment needs operator recovery; no enrollment
access token is issued for a deleted account. Login never restores implicitly.
