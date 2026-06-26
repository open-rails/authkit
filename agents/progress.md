<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 149

---

# #144: Rename frontend OIDC callback config to OIDCReturnPath

**Completed:** no

STATUS 2026-06-26 (Claude): authkit-side DONE. `FrontendConfig.CallbackPath` →
`OIDCReturnPath` renamed end-to-end (public field, internal `Options` chain,
default const, normalize fn, and the OIDC/OAuth full-page redirect in
`http/{oidc,oauth2}_browser.go`); default `/login/callback` preserved; backend
provider-callback path (`oidcCallbackPath`) deliberately untouched. README,
SEMVER, and `agents/api-endpoints.md` updated. `go build ./...` + `go vet` + the
DB-free suite are green. Consumer migration pending the #143 coordinated bump.

Proposed 2026-06-26 (Paul + Codex). `embedded.FrontendConfig.CallbackPath` is
too vague and reads like the OAuth/OIDC provider callback URL. In AuthKit it is
not that. AuthKit owns the backend provider callback; this field is the host SPA
landing route after AuthKit finishes the OIDC/social login flow.

BREAKING HARDCUT before v1.0: no compatibility alias, no deprecated field.

## Target shape

```go
Frontend: embedded.FrontendConfig{
    BaseURL:       "https://app.example.com",
    OIDCReturnPath: "/login/callback",
}
```

Meaning: after OIDC/social login completes, AuthKit redirects the browser to
`BaseURL + OIDCReturnPath` with the login result.

## Tasks

- [ ] Rename `FrontendConfig.CallbackPath` to `OIDCReturnPath`.
- [ ] Update config normalization/defaulting to keep the default path
      `/login/callback`.
- [ ] Update OIDC browser-flow code to use `OIDCReturnPath`.
- [ ] Update README/examples and first-party consumers.
- [ ] Search docs/comments/tests for `CallbackPath` and replace with the new
      name where it refers to this frontend landing route.
- [ ] Validate with `go test ./...`.

---

# #143: Client API cleanup — client-first construction + small capability interfaces

**Completed:** no

## Child issues (split 2026-06-26)

This issue had grown to five unrelated hardcuts; the independent ones were carved out into
their own issues (same v1.0 release train, ONE coordinated consumer bump tracked here in #143):
- #145 — RBAC single-source config (`Config.RBAC []PersonaDef`, root, composition, drift).
- #146 — HTTP route-group reshape + Gin/Chi adapter surface + `/auth/capabilities`.
- #147 — registration modes + first-class invites.
- #148 — 2FA policy + TOTP key material.
#143 now keeps only: client-first construction (done), small capability interfaces,
`authhttp.Server` paring, `embedded` option/package hygiene, the identity-provider + option
culls, and the shared consumer-migration + `go test ./...` tail.

**Build order & shared-file hotspots (2026-06-26).** Split for REVIEWABILITY, not file
independence — do NOT work these as parallel branches; they collide. Hotspots:
`internal/authcore/config.go` (#143/#144/#145/#147/#148 all edit a config struct here),
`service.go` (#143/#145/#147/#148), `verify/middleware.go` (#146/#148), and migration
`001_auth_schema.up.sql` (#145 single-parent, #143 drop `api_key_resources`, #149 drop
`allowed_origins`). One HARD dependency: **#146 before #148** — #148's forced-enrollment gate
reuses #146's `IsUser()`/`RequiredUser`. Suggested sequence: #144 → #143 → #145 → #146 →
#148 → #147 → #149 → consumer bump LAST (the single coordinated migration in #143's tail).

STATUS 2026-06-26 (Claude): small capability interfaces STARTED (additive,
non-breaking). Added `authkit.Authorizer` + `authkit.TokenIssuer` (the two with real
consumers — authz gate, platform token minting) in `interfaces.go`, with conformance
proofs in `embedded/conformance.go` (`var _ authkit.Authorizer = (*embedded.Client)(nil)`).
Grown from real consumption, NOT the 7-interface taxonomy — the rest land when a
signature actually narrows. Also dropped `ApplyBootstrapManifestFile` from the contract
(Paul's call; lands in #142's portability audit). build+vet+gofmt green; full suite green.
Client-first construction is folded into #142 (one migration, with remote).

STATUS 2026-06-26 (Claude): slice-A option culls landed (authkit-side, breaking).
Removed: `WithDBTXWrapper` (dead, no call sites); `WithErrorLogger` +
`InternalErrorEvent` + the `errorLogger` field (swallowed internal errors now go to
`slog.Default()` with structured attrs — default deployments newly emit those ERROR
logs); `WithSolanaDomain` (SIWS message domain now derived from `Frontend.BaseURL`/
issuer host with the existing Origin→Host request fallback); and public
`embedded.WithEphemeralStore` (internal `authcore.WithEphemeralStore` kept as the
mechanism; `embedded.New` still auto-injects an in-memory store and `WithRedis`
stays). Public-surface inventory in SEMVER §4.2/§5 updated. `go build` + `go vet` +
DB-free suite green (caught + fixed one regression: `register_response_test.go`
constructs via `authcore.NewService` directly, so it re-injects the memory store
through the internal option). Remaining slice-A culls: `WithRateLimiter`/
`WithoutRateLimiter` → automatic; `WithClientIPFunc` → `WithTrustedProxies`;
`WithPermissionGroupAuthorizer`; `WithSolanaSNSResolver` → AuthKit-owned default;
`WithAuthLogger`/`WithAuthLogReader` → `WithClickHouse`.

STATUS 2026-06-26 (Claude): three more slice-A culls landed (authkit-side, breaking).
(1) Rate limiter is now AUTO-OWNED — `NewServer` creates it after options: Redis-backed
when `authhttp.WithRedis` is supplied (shared cross-instance), in-memory otherwise. The
`WithRateLimiter`/`WithoutRateLimiter` seams are kept but advanced/test-only (set an
`rlExplicit` flag) and dropped from the SEMVER inventory. (2) `WithClientIPFunc` →
`WithTrustedProxies(cidrs ...string)` as the normal proxy knob (wraps
`ClientIPFromForwardedHeaders`; an invalid CIDR fails `NewServer`); RemoteAddr default
unchanged; raw `WithClientIPFunc` kept advanced/test-only. (3) Deleted public
`WithPermissionGroupAuthorizer` + `PermissionGroupAuthorizer` (the per-request authz
override footgun) — generated group routes authorize through `embedded.Client.Can`;
`groupCanFn` survives only as an UNEXPORTED package-internal test hook, so the
declared-perm wiring tests still run DB-free. openrails must move lazy merchant-group
materialization to provision time (accepted break). New tests: rate-limiter auto-wiring
(mem/redis/disabled) + trusted-proxy trust/ignore/bad-CIDR. build + vet + DB-free suite
green. Remaining slice-A are NET-NEW builds, not culls: `WithSolanaSNSResolver` → default
SNS resolver, and `WithAuthLogger`/`WithAuthLogReader` → `WithClickHouse` adapter.

REVIEW (Claude, 2026-06-26): strong core, trim the edges.
- KEEP (the real win): client-first construction — `authhttp.NewServer(client, httpOpts)`,
  drop `.Client()`, split embedded-vs-http options, pare `Server` to adapter methods.
  Honest layering (server = adapter over a client the host owns); kills the escape
  hatch the old `NewServer(cfg,pg)` needed. Do it.
- DON'T delete `authkit.Client`. The broad interface IS #142's swap seam — a host
  flipping embedded↔remote holds ONE `authkit.Client` field. Small capability
  interfaces COEXIST with it (hold broad at the swap point, pass narrow slices to
  functions). Deleting it loses the one-line swap #138/#142 are built on.
- GROW the small interfaces from REAL consumption points (`verify.PermissionChecker`
  is the model — 1 method, the gate uses it), NOT 7 speculative ones upfront. Define
  `Authorizer` + maybe `TokenIssuer` now; add the rest when a signature actually
  narrows. A 7-interface taxonomy is the opposite over-engineering from the kitchen sink.
- REJECT moving `Config` → root `authkit.Config`. #138 deliberately partitioned
  `Config`/`Options`/ports into `embedded` as ENGINE CONSTRUCTION, off the wire
  contract (remote uses its own `remote.Config{BaseURL,Token}`). Don't re-blur it —
  keep `embedded.Config`.
- `embedded.New` STAYS — `New` is the Go idiom (etcd `clientv3.New`), and `remote.New`
  already exists (`remote/remote.go:44`). The `NewClient` rename is REJECTED (Paul,
  2026-06-26): the `NewServer` symmetry isn't worth churning two constructors.
- SEQUENCING: this reshapes the SAME construction/interface surface as #142 (remote).
  Separate issues → consumers migrate TWICE. Batch the client-first changes WITH #142
  so consumers move once, to the final v1.0 shape.
- BASELINE: cozy-art + tensorhub are still on pre-#138 `core` (never migrated to
  v0.65/0.66). Bring them current via #138/#141 first — #143 shouldn't be their first move.

REFINE (Claude, 2026-06-26, after Paul review): seven design tightenings (not scope
changes). Most now live in the child issues — #1/#2 → #145, #3 → #147, #4 → #148,
#5/#6 → #146/#147, #7 → #148. SPLIT DONE 2026-06-26 (see Child issues above).
1. Permission catalog is earned ONLY by the `CustomRoles` capability; derive it from
   roles otherwise — don't make hosts hand-maintain a second declaration.
2. Single-parent personas: commit STORAGE to singular too (drop `group_persona_parents`,
   use a `parent_persona` column); first verify no consumer needs multi-parent.
3. Invites: an unknown-email group invite sends TWO independent tokens (registration +
   group), not one token that "carries" the other — no subsystem coupling.
4. 2FA `Required` gates the SESSION — existing un-enrolled users get a forced-enrollment
   challenge on next auth, not just new signups.
5. Drop `RouteVerification` — fold into Registration (signup) + Account (contact change);
   five route groups, not six.
6. Name the numbers: shareable TTL 7d / email-bound 72h; `/auth/capabilities` gets cache headers.
7. TOTP: v1 reserves a 1-byte key-id prefix, builds NO keyring (future rotation stays additive).

GROUND (Claude, 2026-06-26, durability trace): the RBAC schema is config-as-code held
in-memory (`GroupSchema`, re-derived each boot) — the permission catalog and role catalogs
are EPHEMERAL config like the passwordless flag, NOT durable state, so they don't drift.
The real durable surface is narrow and reference-by-string: containment (`group_persona_parents`,
seeded ADDITIVELY → drifts), and runtime rows (`group_custom_roles`, `group_user_roles`) that
name persona/role by text with no FK or reconcile. This grounds refinements #1/#2 and adds
a new DECISION: schema names are durable identifiers. Tasks updated below.

Proposed 2026-06-26 (Paul + Codex, after reviewing current AuthKit plus
doujins/hentai0/cozy-art/tensorhub consumers). The current public seam is too
wide and too vaguely named:
- `embedded.New(...)` constructs an in-process client, but reads less clearly than
  `authhttp.NewServer(...)`.
- future `remote.New(...)` would repeat the same vague constructor name.
- root `authkit.Client` is a 94-method kitchen-sink interface. Real consumers use
  small slices: route mounting + verification, DB-backed authorization, user/admin
  management, bootstrap/import tooling, permission-group/federation operations,
  and token issuing. The broad concrete client can exist, but hosts should not be
  pushed to depend on one giant interface.
- `embedded.Client` is the concrete in-process engine and may remain broad; the
  problem is the broad root interface (`authkit.Client`) that every backend is
  asked to satisfy forever.
- `authhttp.Server` should be an HTTP adapter over a client, not a programmatic
  auth facade. It should expose route handlers/specs, verifier, and maybe HTTP
  health/status helpers only.
- `embedded` also re-exports too many contract/config/helper types; it should be
  the in-process implementation package, not the namespace where every AuthKit
  concept lives.

BREAKING HARDCUT before v1.0: no backwards compatibility, no deprecated aliases,
no transition shims. Do this as a public-interface cleanup, then update all four
first-party consumers in the same release train.

## Target shape

Construction names:
```go
embeddedClient, err := embedded.New(cfg, pg, opts...)
remoteClient := remote.New(baseURL, token)
server := authhttp.NewServer(embeddedClient, httpOpts...)
```

Package roles:
| Package | Role |
|---|---|
| `authkit` | public contract types, DTOs, sentinel errors, validation helpers, and small capability interfaces |
| `authkit/embedded` | in-process client implementation + construction options only |
| `authkit/remote` | future remote client implementation over the management API |
| `authkit/http` | mountable HTTP server/routes over an AuthKit client + verifier aliases |
| `authkit/verify` | token verifier and middleware primitives |

Minimal embedded-host import surface:
| Package | Normal host use |
|---|---|
| `authkit` | config, DTOs, errors, validation, permission helpers, small interfaces |
| `authkit/embedded` | `New` + embedded runtime options |
| `authkit/http` | `NewServer` + route specs/handlers/options |
| `authkit/verify` | protect host-owned routes + read claims |
| `authkit/adapters/{gin,chi}` | router convenience when the host uses that router |
| `authkit/migrations/postgres` | host migration command |
| `authkit/migrations/clickhouse` | standard auth/event logging migration command when enabled |

Optional/advanced packages, not part of the normal embedding story:
`adapters/twilio/*`, `adapters/riverjobs`, `oidc`, `authprovider`, `lang`,
`password`, `jwt`, `ratelimit/*`, `storage/*`, `siws`, and `authtest`.

Rule: Postgres migrations are required standard setup because Postgres is the
system of record. ClickHouse migrations are standard optional setup: not
required to boot AuthKit, but the normal path when auth/event logging is enabled.

Host mental model:
- construct the programmatic client first (`embedded.New` now, `remote.New`
  later),
- pass that client to `authhttp.NewServer(...)` to expose the HTTP route surface,
- keep programmatic management/provisioning/RBAC/token work on the client instead of
  pulling a hidden client back out of the server.

## Tasks

- [x] CONSTRUCTION SHAPE (client-first: `authhttp.NewServer(client, httpOpts)`, drop
      `.Client()`, split embedded-vs-http options) FOLDED INTO #142 and DONE there
      (2026-06-26): `NewServer(client, opts)`, `.Client()` dropped, options split
      (engine→`embedded.New`, http→`authhttp`), 34 in-repo sites migrated. See #142
      "Construction shape". `embedded.New` stays (Go idiom); the `NewClient` rename is
      REJECTED (Paul, 2026-06-26). External consumer migration pending the next bump.
- [~] Design the first small root interfaces from real consumers, not speculation:
      (DONE: `Authorizer` + `TokenIssuer` in `interfaces.go`. The rest grow when a real
      signature narrows — not pre-built.)
      - `Authorizer`: `Can`, `ListEffectivePermissions`, `IsUserAllowed`,
        `ListRoleSlugsByUserErr`.
      - `UserAdmin`: admin list/get/session/ban/unban/soft-delete/session revoke.
      - `RoleManager`: root and permission-group role assignment/removal.
      - `PermissionGroups`: create/resolve groups, list memberships/members,
        invite links, API keys.
      - `Federation`: remote applications + delegated attribute definitions.
      - `TokenIssuer`: delegated token + service JWT minting.
      - `Bootstrapper`: bootstrap manifest + import/migration-only helpers.
- [x] DECISION: KEEP `authkit.Client` as the broad swap seam — #142 needs ONE interface
      both embedded+remote satisfy for the one-line embedded↔remote swap. The small
      capability interfaces COEXIST with it (hold the broad one at the swap point; pass
      narrow slices to functions). Not a compat shim — a deliberate contract.
- [ ] Keep `embedded.Client` broad as the concrete engine type if that is the
      simplest implementation. Do not confuse concrete method count with public
      interface size.
- [x] Pare `authhttp.Server` down to HTTP-adapter methods only (DONE 2026-06-26):
      dropped the `SetEntitlementsProvider` engine passthrough (host now calls it on
      its own client). Remaining exported methods are all HTTP adapters/status:
      `APIHandler`, `APIRoutes`, `OIDCHandler`, `OIDCBrowserRoutes`, `JWKSHandler`,
      `PermissionGroupRoutes`, `Routes`, `Verifier`, and the SMS-health status reads
      (`SMSAvailable`/`SMSHealthy`/`SMSHealthReason`/`CheckSMSHealth` — kept as useful
      status helpers). No programmatic auth facade remains.
- [x] DECISION: contract types already live in root `authkit` (#141 hardcut moved them;
      `embedded` re-exports ENGINE symbols only). `Config`/`Options`/ports STAY in
      `embedded` — engine construction, not wire contract (#138 partition; remote uses
      its own `remote.Config`). Examples read `embedded.New(embedded.Config{...}, pg)`.
- [ ] Keep `embedded.Option` only for in-process construction dependencies
      (`WithEmailSender`, `WithSMSSender`, `WithEntitlements`,
      `WithEphemeralStore`, etc.). Do not make `embedded` a dumping ground for
      validation constants and DTO aliases.
- [x] DECISION: simplify identity-provider config. Do not expose separate
      built-in vs custom-provider fields; a provider is a provider.
- [ ] Delete `IdentityConfig.ProviderDescriptors`.
- [ ] Replace `IdentityConfig.Providers map[string]oidc.RPConfig` with
      `IdentityConfig.Providers []authprovider.Provider`.
      ACCEPTED BREAK (2026-06-26): widest blast radius in the cull — doujins, hentai0, AND
      cozy-art all build the `map[string]oidckit.RPConfig` form. Clean breaking change, no
      migration helper; the three migrate their provider config to the slice at the bump.
- [ ] Keep provider name inside `authprovider.Provider.Name`, not as a map key.
- [ ] Add small helper constructors for built-ins only if they materially improve
      examples, e.g. `authprovider.Google(clientID, clientSecret)`.
- [ ] Update first README example to use either `Identity: embedded.IdentityConfig{}`
      or one built-in provider constructor, not custom-provider descriptor plumbing.
- [ ] Make examples and docs use root contract names:
      `authkit.Config`, `authkit.User`, `authkit.ValidateUsername`,
      `authkit.SubjectKindUser`, `authkit.RegistrationVerificationRequired`, etc.
      `embedded` should appear only for `embedded.New` and embedded-only
      options/types.
- [ ] Pare embedding docs down to the normal-host packages only:
      `authkit`, `embedded`, `authhttp`, `verify`, one router adapter, and
      `migrations/postgres` plus `migrations/clickhouse`. Put `jwt`, `oidc`, `authprovider`, `storage`,
      `ratelimit`, `siws`, `password`, Twilio adapters, River jobs, and
      `authtest` in an advanced/support section.
- [ ] Keep direct `jwt` use out of normal host examples. Token signing should go
      through `client.MintDelegatedAccessToken` / `client.MintServiceJWT`; hosts
      should not handle private keys for routine embedding.
- [ ] Move advanced engine hooks out of the first README constructor example:
      `WithEntitlements` (host billing/product entitlements projected into access
      tokens plus admin user detail/list enrichment and entitlement filtering),
      and `WithClickHouse` (auth/session history backed by ClickHouse). Keep them
      documented only in advanced/support sections.
- [x] DECISION: delete API-key resource scopes entirely. CANONICAL MODEL (Paul,
      2026-06-26): a credential is minted ON a specific persona INSTANCE — a repo's or an
      org's permission group — and that instance IS the resource; the permissions + one
      role on that instance ARE the key's scope. The `APIKeyResource`/`Resources` list was
      a redundant SECOND scoping axis bolted on top of that — delete it. Narrower scope =
      mint the key on a narrower group (`repo` under `org`), never a second opaque list.
      cozy-art's service-JWT `Resources` use (the only consumer) is therefore either
      over-scoped — drop it — or re-expressed as the minting group-instance + role; AuthKit
      does NOT preserve the parallel axis. Service JWTs follow the same rule: scope is the
      issuer's stored authority + audience, not a `Resources` list.
- [x] DECISION: API-key verification is built in, not a host constructor option.
      AuthKit verifies key ID/secret, revocation/expiry, permission group state,
      and role permissions through the verifier's client-backed enricher.
- [ ] Remove `WithAPIKeyResourceAuthorizer`, `APIKeyResourceAuthorizer(Func)`,
      `APIKeyResourceAuthorizationRequest`, `APIKeyResource`, and the `Resources` fields
      from public/core/http contracts. SCOPE (2026-06-26): `APIKeyResource`/`Resources` is
      NOT API-key-only — it is also on the SERVICE-JWT contract (`ServiceJWTClaims.Resources`
      `servicejwt.go:32`, `verify.ServiceJWTPrincipal.Resources` `verify/service_jwt.go:24`),
      so rip it out of the service-JWT path too (breaks cozy-art's production service-JWT
      minting `cozy-art/internal/servicejwt/servicejwt.go` — accepted). `ErrResourceScopeDenied`
      is TWO symbols: the Go sentinel (`errors.go:45`, also in the `errors.Is` list `:80`) AND
      the HTTP wire code (`http/error_codes.go:538`, mapped in
      `permission_group_operations.go:576-580`) — remove both. DO NOT touch SIWS's unrelated
      `Resources` (`siws/message.go`, EIP-4361 sign-in-message field).
- [ ] Remove the `resources` field from `POST /<persona>/<instance_slug>/api-keys`
      request/response/list payloads; API-key minting remains governed by
      `<persona>:credentials:manage` plus the existing no-step-up role-grant
      check.
- [ ] Preserve built-in credential-management permissions: root operators use
      intrinsic `root:credentials:manage`; host personas use generated
      `<persona>:credentials:manage`. Group owners may mint/revoke API keys for
      permission groups they own, but still cannot grant an API-key role above
      their own effective permissions.
- [ ] Drop `profiles.api_key_resources` from the hard-cut Postgres schema and
      delete resource-scope normalization/load/list/authorization code and tests.
- [x] DECISION: first-run embedded constructor options should be only normal
      runtime dependencies: `WithRedis`, `WithEmailSender`, and `WithSMSSender`.
      Everything else is either config, automatic default, advanced/support, or
      test/internal plumbing.
- [x] DECISION: `authhttp.LanguageConfig` should expose only `Supported` and
      `Default`. Do not make the query parameter or cookie name configurable;
      hardcode both to `lang`.
- [ ] Delete public `LanguageConfig.QueryParam` and `LanguageConfig.CookieName`.
      No language config should mean English-only: supported languages `["en"]`,
      default `"en"`.
- [x] DECISION: remove public SMS `DeliveryConfirmTimeout` configuration. The
      Twilio sender should use a fixed internal delivery-confirm timeout around
      10-15 seconds; hosts should not tune this in normal AuthKit setup.
- [ ] Delete `DeliveryConfirmTimeout` from public SMS sender config and docs; keep
      one package-private constant for the internal default.
- [x] DECISION: delete `WithDBTXWrapper` entirely. It was only a sqlc/pgx
      query-decorator seam for hypothetical counting/spy queriers, and current
      source has no test/user call sites. If a future test needs query spying,
      add that locally in the test instead of preserving a public option.
- [ ] Remove `WithDBTXWrapper` from `internal/authcore/options.go`,
      `embedded/aliases.go`, and any public surface inventory/docs.
- [x] DECISION: do not expose `WithSolanaSNSResolver` as a normal client option.
      AuthKit should provide the standard Solana Name Service resolver itself
      when Solana/SIWS is enabled; hosts should not wire a resolver.
- [ ] Replace host-provided SNS resolver wiring with an AuthKit-owned default
      resolver. Keep timeout/cache TTL as fixed internal defaults unless a real
      host need appears.
- [ ] Remove `WithSolanaSNSResolver` from first-run docs and public examples; if a
      custom resolver remains for tests, keep it out of the normal host API.
- [x] DECISION: do not expose generic auth-event logger/reader wiring in the
      normal host-facing API. AuthKit supports ClickHouse for auth/session event
      history; call the option `WithClickHouse(...)` (or `WithClickHouseAuthLog`
      if the name must be narrower) and wire both write and read sides there.
- [ ] Add a first-party ClickHouse auth-event adapter that implements both
      `AuthEventLogger` and `AuthEventLogReader` against the bundled ClickHouse
      migration schema. This is the standard implementation for admin sign-in
      history / user login history views.
- [ ] Replace `embedded.WithAuthLogger(...)` and `authhttp.WithAuthLogReader(...)`
      in public examples/API with one `embedded.WithClickHouse(ch)` option. The
      embedded client owns both auth-event writes and history reads; `authhttp.NewServer(client)`
      should derive the reader from the client, not require a separate server
      option. Passing no ClickHouse means no external auth-event history and admin
      sign-in history routes should report auth log unavailable.
      ACCEPTED BREAK: doujins routes auth logs through its OWN analytics service (not a raw
      ClickHouse handle), so `WithClickHouse(ch)` is not a drop-in for it — doujins either
      adopts the bundled ClickHouse adapter or keeps its own logger via the internal/
      advanced `AuthEventLogger` seam. Breaking change, accepted.
- [ ] Keep low-level `AuthEventLogger` / `AuthEventLogReader` interfaces internal
      or advanced-only only if needed for tests; do not document custom file/stdout
      loggers until there is a real host need.
- [x] DECISION: remove public `WithEphemeralStore` from the host-facing API. It is
      jargon and unnecessary: AuthKit should always create and use an in-memory
      auth-state store when Redis is not supplied.
- [ ] Keep `embedded.WithRedis(rdb)` as the only normal host knob for temporary
      auth state. Redis replaces the default in-memory store for multi-instance
      deployments and stores short-lived auth data such as challenges, OIDC state,
      passwordless/verification/reset tokens, and related counters.
- [x] DECISION: do not expose `authhttp.WithRateLimiter` as normal host setup.
      AuthKit owns the rate-limit policy and should create the limiter itself:
      Redis-backed when the embedded client has Redis, in-memory otherwise.
      Custom limiter injection, if kept, is internal/test/advanced only.
- [ ] Replace public examples of `authhttp.WithRateLimiter(...)` /
      `authhttp.WithoutRateLimiter()` with automatic rate limiting derived from
      the embedded client. Do not allow production hosts to accidentally disable
      brute-force/spam protections through a normal setup option.
- [x] DECISION: replace raw `authhttp.WithClientIPFunc(...)` in normal docs with
      `authhttp.WithTrustedProxies(trustedProxies)`. The server should keep a
      safe default using `RemoteAddr`; hosts behind proxies only provide trusted
      proxy CIDRs. Keep arbitrary `ClientIPFunc` injection internal/test/advanced.
      ACCEPTED BREAK: not a drop-in for hentai0, which passes a CUSTOM `ClientIPFunc`
      (not CIDRs) — it moves to `WithTrustedProxies` (CIDRs) or the advanced
      `ClientIPFunc` seam. doujins already passes CIDR-derived `ClientIPFromForwardedHeaders`
      and maps cleanly. Breaking change, accepted.
- [x] DECISION: delete public `authhttp.WithErrorLogger`. For swallowed internal
      handler failures, AuthKit should use Go's standard `slog.Default()` so the
      host controls output globally (`slog.SetDefault(...)`) and infrastructure
      captures stdout/stderr as usual.
- [x] DECISION: delete public `authhttp.WithPermissionGroupAuthorizer`. Generated
      permission-group routes should authorize through the embedded client/engine
      (`Can`) directly — a per-request authz OVERRIDE on security-critical routes is a
      footgun. CORRECTION (2026-06-26): this is NOT test-only — openrails uses it in
      PRODUCTION (`controlplane/service.go:183` → `AuthorizePermissionGroupRoute`) to
      lazily materialize a merchant group before the check. Deleting it is an accepted
      openrails break: openrails must move lazy group creation to seed/provision time
      (out of the per-request authz path). No internal/test seam needed — just delete it.
- [x] DECISION: delete public `authhttp.WithSolanaDomain`. SIWS challenge domain
      should be derived from AuthKit config (`Frontend.BaseURL` / issuer host) and
      request fallback, not a separate server constructor option.
- [ ] Remove `WithPermissionGroupAuthorizer` and `WithSolanaDomain` from first-run
      docs and public API inventory.
- [ ] Delete `PermissionGroupAuthorizer`, `WithPermissionGroupAuthorizer`, and the
      `groupCanFn` field from public HTTP server code. Update tests to exercise
      the real `Can` path or use package-internal helpers instead of a public
      option seam.
- [ ] Delete `WithErrorLogger`, `InternalErrorEvent` as a public callback contract,
      and the server `errorLogger` field. Route swallowed internal handler errors
      to `slog.Default()` with structured attributes instead.
- [x] Update current consumers to v0.69.0 client-first (DONE 2026-06-26, all
      committed+pushed; build+vet green per repo). The migration is mechanical: the
      host builds the engine with `embedded.New`/`core.New` (splitting engine vs HTTP
      options), passes it to `authhttp.NewServer(client, ...)`, and uses the held
      `*embedded.Client` everywhere `authhttp.Service.Client()` was called.
      - openrails → v0.67.0: `ControlPlane.authClient`; Core()/delegated verifier use it.
      - hentai0: `AuthKitService.Client`; threaded to the AuthKitProvider + OpenRails
        embed sessionIdentity + user writer + entitlements install.
      - doujins: `buildAuthKitService` returns the client too; `Infrastructure.AuthKitClient`
        + `ServerInterface.GetAuthKitClient`; threaded to admin writer / gate / entitlements.
      - cozy-art → openrails v0.67.0: `AuthKitProvider.Client()` + `API.authClient`;
        dropped the `.(*core.Client)` casts.
      - tensorhub → openrails v0.67.0: `identity.Service.authClient` (replaced all 19
        `authProvider.Client()` sites).
      (Narrowing broad `authkit.Client` injection to capability interfaces is a later,
      non-blocking polish — the broad seam stays per the #143 review.)
- [x] Add compile-time conformance checks for the small interfaces:
      `var _ authkit.Authorizer = (*embedded.Client)(nil)`, etc. (done in `embedded/conformance.go`).
- [ ] Update README/embedding docs to show:
      - `authhttp.NewServer` for mounted auth routes,
      - `embedded.New` for in-process library operations,
      - future `remote.New` for standalone AuthKit.
- [ ] Validation: `go test ./...` in authkit, then targeted builds/tests in
      doujins, hentai0, cozy-art, and tensorhub after the coordinated bump.

## Non-goals

- Do not split the concrete implementation into `client.Users().Roles().Tokens()`
  subclients yet. Small interfaces over the current methods are the lazy cleanup.
- Do not preserve old `core`, `providers/*`, `riverjobs`, or `identity` package
  aliases indefinitely. Migrate first-party consumers forward instead.
- Do not design the full remote management API here; #142 owns that. This issue
  only names the client constructors and shrinks the public dependency boundary.

## Depends on / coordinates with

- #142 standalone server + remote SDK: constructor naming and remote-client target.
- #138 package restructure: this is a follow-up correction to the too-broad
  `authkit.Client` seam created there.
- #141 cleanup: consumer package-name migration continues the same pre-v1 hardcut.

---

# #145: RBAC single-source config — Config.RBAC []PersonaDef

**Completed:** no

Split out of #143 (2026-06-26): personas, roles, and permissions configured in exactly ONE
place — `Config.RBAC []PersonaDef`, root an ordinary entry, config-time composition across
libraries, and a name-immutable / fail-closed drift policy. Part of the #143 release train;
the coordinated consumer bump + final `go test ./...` live in #143. Cross-cutting design
context (REVIEW / REFINE / GROUND) is in the #143 head.

- [x] DECISION: simplify RBAC persona containment. A group instance already has
      exactly one parent (`parent_id`/`parent_persona`); the public schema should
      also declare exactly one parent persona per persona type, not
      `AllowedParents []string`.
- [ ] Replace `PersonaDef.AllowedParents []string` with `PersonaDef.Parent string`
      hard-cut. Empty parent is valid only for the intrinsic `root` persona;
      every non-root persona names exactly one parent persona. Do not default
      missing parent to `root`; missing parent is a config error.
- [x] DECISION: host-defined top-level personas must explicitly write
      `Parent: authkit.RootPersona`. Do not treat empty `Parent` as root, and do
      not ask host apps to define the intrinsic root persona themselves.
- [x] RESEARCH (2026-06-26): the explicit catalog `RBAC.Permissions []PermissionDef` is
      currently DEAD — it flows to `Options.Permissions` (`service.go:408`) but is never
      read for authz and never persisted. The REAL permission universe is the union of
      `RoleDef.Permissions` across `Groups`, held in the in-memory `GroupSchema` (ephemeral
      config, no DB row, no drift). Custom-role grants (`group_custom_roles`) validate only
      STRUCTURALLY today (`ValidateGrantPattern`, namespace-pure), against no catalog.
- [x] DECISION (refined 2026-06-26): the catalog is earned by ONE thing — the `CustomRoles`
      capability, whose grants need a bounded universe wider than what default roles mention;
      the catalog IS that bound. So the catalog lives PER-PERSONA as `PersonaDef.Catalog`, read
      ONLY when that persona enables custom roles; when off, derive the universe from the union
      of that persona's role grants. DELETE the top-level `RBAC.Permissions`/`PermissionDef`
      entirely — a per-deployment flat list is the wrong shape (permissions are persona-namespaced)
      and it is non-authoritative today. One catalog home, inside the persona.
- [x] DECISION (2026-06-26): personas, roles, and permissions are configured in ONE place —
      `Config.RBAC []PersonaDef`. Drop the `RBACConfig` wrapper and the top-level catalog; each
      persona (root included) is one self-describing struct in that slice. Permissions are
      defined exactly once, as the grant strings inside `Roles`; `PersonaDef.Catalog` is not a
      second definition, it only widens the grantable universe for custom roles. Root is an
      ordinary entry — omit it ⇒ authkit injects the intrinsic root; include
      `PersonaDef{Name: authkit.RootPersona, ...}` to add operator roles / override capabilities
      using the identical fields as every other persona. No second declaration anywhere.
- [ ] Validate persona role permissions against the catalog — derived-from-roles when
      no custom roles, explicit when custom roles widen it. App-declared roles AND
      custom-role grants must reference catalog permissions; reserve wildcard grants
      such as `<persona>:*` for AuthKit's generated owner role and deliberate
      internal expansion.
- [ ] Update `BuildSchema`/`NewGroupSchema` validation and containment seeding for
      singular parent persona definitions. No configurable multi-parent hierarchy.
- [ ] FIRST: grep the four consumers for any persona that attaches under two different
      parent persona types (e.g. a `team` valid under either `org` or `enterprise`).
      Single-parent is a one-way schema door — if one exists, this hardcut is wrong.
      The plan asserts none; prove it before cutting.
- [ ] Commit STORAGE to singular too: replace `group_persona_parents` with a
      `parent_persona` column on the containment/persona definition and DROP the join
      table. A many-parent table behind a one-parent API is the dead flexibility this
      issue deletes from the public surface — pick singular end to end.
- [ ] Single-parent ALSO fixes the seed drift: `SeedContainment` is additive-only today
      (`INSERT ... ON CONFLICT DO NOTHING`, `permission_group_store.go:56`), so removing or
      renaming a parent in config leaves a stale row and the DB trigger keeps enforcing the
      OLD parent. With one parent per persona the seed becomes a real reconcile —
      `INSERT ... ON CONFLICT (persona) DO UPDATE SET parent_persona = $2`. Make the seed
      upsert, not accrete.
- [x] RESEARCH (2026-06-26): authz is LATE-BOUND by name. `ResolveGrants`
      (`permission_group_authorize.go:33`) resolves each stored assignment `(persona, role)` against
      the CURRENT schema: a catalog role → its current in-memory perms (so editing a role's perms is a
      LIVE update for every holder, no re-assignment); a custom role → its stored perms, but ONLY while
      the persona still has CustomRoles on; a name matching NEITHER contributes nothing. Unknown
      persona/role/permission and disabled CustomRoles all FAIL CLOSED — dead rows grant zero, never
      error, never fail open. So removing authority via config is always safe.
- [x] DECISION (2026-06-26): drift policy follows from the late-binding above — four rules, no
      migration system:
      (1) NAMES ARE IMMUTABLE IDENTIFIERS. No in-place rename; a rename = delete + add, which
          mass-orphans every assignment/api-key row naming the old role (they fail closed to zero).
      (2) NEVER REUSE A RETIRED NAME — OPERATOR discipline authkit CANNOT enforce. Resolution is by-name,
          so re-adding a name reactivates stale rows under the NEW meaning; but a role named role-B with
          new perms is the SAME operation as a legitimate in-place edit, and authkit keeps no cross-deploy
          memory of prior meaning, so it cannot tell repurpose from edit (intent isn't on the wire). The
          hazard only bites if orphans exist at reuse time → authkit's job is to make removal LOUD (the
          drift report below); the operator's job is to clear/reassign orphans on removal, after which
          reuse is safe. Hard enforcement would need a persisted tombstone ledger + seed-time check —
          YAGNI until someone is actually bitten.
      (3) REMOVE IS ALWAYS SAFE per the fail-closed contract — worst case is dead rows, never surprise
          access. This is the guarantee hosts get; state it in docs.
      (4) SURFACE orphans, do NOT auto-prune assignments. A drift report counts rows whose
          `(persona, role)` is absent from the schema so operators clean up DELIBERATELY. Auto-deleting
          assignments on seed is rejected: a config typo dropping a role would nuke everyone's grants.
          (Containment IS reconciled/pruned — it is pure config with no human intent; assignments carry
          human intent, so prune is destructive.)
- [ ] Document the durability boundary AND the drift rules in the RBAC config docs — this is the
      mitigation (authkit can't enforce; operators must be aware). Cover: catalog + role catalogs are
      ephemeral in-memory config (swap freely; editing a role's perms is a live update for all holders);
      containment + runtime role rows (`group_user_roles`/`group_custom_roles`/`api_keys`) are durable and
      name-referenced. Spell out the operator contract: (1) schema names are immutable identifiers — no
      in-place rename; (2) NEVER reuse a retired name for a different concept, and clear/reassign orphaned
      assignments on removal (authkit only surfaces them via the drift report); (3) removing authority is
      always safe — unresolved names fail closed to zero, never fail open. Put this where operators will
      see it (the RBAC config doc + a CHANGELOG/UPGRADE note), not buried.
- [ ] Update docs/examples to show `persona:resource:action` permissions inside
      persona roles, e.g. `root:users:ban`, `merchant:subscriptions:cancel`,
      `endpoint:deployments:restart`.
- [x] DECISION: each persona, including the intrinsic root persona, should expose
      only three optional management capabilities, all off by default: allow API
      keys, allow remote applications, and allow custom role definitions. Custom
      role definitions mean a specific permission-group instance may define
      additional local roles; when off, only the application-declared/hardcoded
      persona roles exist.
- [ ] Replace the current split public shape
      (`AllowCustomRoles` plus `Routes.CustomRoleCreation`, `Routes.APIKeyMinting`,
      `Routes.RemoteAppRegistration`) with one clearer persona capability block,
      e.g. `Capabilities: authkit.PersonaCapabilities{APIKeys: true,
      RemoteApplications: true, CustomRoles: true}`. Keep member assignment and
      invite acceptance as standard permission-group behavior, not part of this
      optional capability list.
- [ ] Allow host config to override root persona capabilities without requiring
      the host to redefine the whole intrinsic root persona. Root uses the same
      capability names and route-generation rules as every other persona.
- [ ] Route generation should derive API-key, remote-application, and custom-role
      management routes directly from those three capabilities. Disabled means
      no generated public route.
- [x] DECISION (2026-06-26): ROOT is configured exactly like any persona — same
      `Capabilities{APIKeys, RemoteApplications, CustomRoles}` block (all default OFF: operators
      aren't end users, root is a singleton, machine-cred/federation routes stay off until asked),
      same `Parent:""`, same `Roles`/`Catalog`. Host root config is ADDITIVE, never a replacement:
      the built-in `root:` perms (`IntrinsicRootPermissions`) and the `owner = root:*` role are
      ALWAYS present; host config only ADDS operator roles (and catalog perms if root enables custom
      roles). So `GrantableUniverse(root)` must seed from `IntrinsicRootPermissions()` ∪ app root
      grants ∪ root `Catalog` — else a bounded/custom operator role couldn't grant `root:users:ban`.
      Root `CustomRoles` off (default) just means no runtime-defined extra operator roles; kept
      configurable for symmetry.
- [x] DECISION (2026-06-26): persona sets are COMPOSABLE across libraries/apps — openrails
      contributes its personas, an app on it (doujins/cozy-art/tensorhub) adds its own. Realize this
      at CONFIG-time, not as a mutable runtime schema: a library exports `[]authkit.PersonaDef`, the
      final host concatenates into `Config.RBAC` before `embedded.New`, authkit validates the union,
      and `GroupSchema` stays immutable/validated-once. A layered framework (openrails owns
      construction) accepts app persona contributions in its OWN config and threads them through —
      one field of plumbing, zero new authkit surface. Merge rules: non-root persona names are
      GLOBALLY UNIQUE (collision = construction error, never a silent shadow — one library shadowing
      another's persona is an authz footgun); ROOT is the one mergeable persona (all contributors'
      root roles/catalog union, intrinsic always present); root `Capabilities` are set ONLY by the
      final host (library root contributions carry roles/catalog, never capability flips — fail
      closed so a library can't silently enable API keys on root); parent refs resolve across the union.
- [x] DECISION (2026-06-26, FINAL): composition is config-time. NO post-construction
      `client.RegisterPersonas` / mutable runtime schema — rejected: the layered case (openrails owns
      construction) is solved by openrails accepting persona contributions in its own config, which it
      needs anyway to expose routes/migrations, so a runtime API buys little and costs a mutable schema
      (atomic swap, re-validate, reconcile-seed, "register before serving" ordering). Not re-litigated.

**RBAC single-source config — ordered implementation checklist.** Canonical tick-list:
consolidates the single-parent / capabilities / catalog / durability decisions above into
the concrete steps to reach `Config.RBAC []PersonaDef`. Target persona shape:

    type PersonaDef struct {
        Name         string                      // = permission namespace; root = authkit.RootPersona
        Parent       string                      // exactly one; authkit.RootPersona for top-level; "" only for intrinsic root
        Roles        []RoleDef                   // Name + []"<persona>:resource:action" grants; owner (<persona>:*) auto-injected
        Capabilities authkit.PersonaCapabilities // {APIKeys, RemoteApplications, CustomRoles} — all off by default
        Catalog      []string                    // OPTIONAL grantable universe; read ONLY when Capabilities.CustomRoles
    }

Types & public surface:
- [ ] Add `authkit.PersonaCapabilities{APIKeys, RemoteApplications, CustomRoles bool}` to root `authkit`.
- [ ] Rewrite `PersonaDef` (`internal/authcore/permission_group.go:145`): `AllowedParents []string`→`Parent string`;
      `AllowCustomRoles bool` + `Routes ManagementProfile`→`Capabilities authkit.PersonaCapabilities`; add `Catalog []string`.
- [ ] Delete `ManagementProfile` (`permission_group.go:135`). Its non-capability route toggles (MemberAssignment,
      InviteLinks) move to config-aware route generation; root member-assignment defaults OFF (no auto-enable).
- [ ] Collapse `Config.RBAC RBACConfig`→`Config.RBAC []PersonaDef` (`config.go:15,197`); delete `RBACConfig`,
      `RBACConfig.Permissions`, and `PermissionDef` (`config.go:202,213`).
- [ ] Delete `Options.Permissions` (`service.go:103`) and its copy from cfg (`service.go:408`) — dead catalog field.

Validation & schema build:
- [ ] FIRST: grep the four consumers for any persona attaching under two different parent types (e.g. `team` under
      `org` OR `enterprise`). Single-parent is a one-way schema door — abort the hardcut if one exists.
- [ ] `normalizePersona` (`permission_group.go:202`): drop the `Routes.CustomRoleCreation requires AllowCustomRoles`
      check; when `Capabilities.CustomRoles` && `Catalog` non-empty, validate each catalog entry is a namespace-pure
      `<persona>:...` pattern and that declared role grants ⊆ the effective catalog.
- [ ] `validateRoot` (`permission_group.go:253`): root = the persona with empty `Parent` (single-root unchanged).
- [ ] `validateContainment` (`permission_group.go:276`): single `Parent` edge, not a `[]AllowedParents` loop; keep the
      acyclic-tree + declared-persona checks (now simpler).
- [ ] `ValidateParent` (`permission_group.go:370`): compare the proposed parent to the single `Parent`, not a slice.
- [ ] `BuildSchema`/`IntrinsicRootPersona` (`permission_group_root.go:48,63`): root uses `Parent:""`, `Capabilities{}`
      (NOT auto member-assignment); host overrides by passing `PersonaDef{Name: RootPersona, ...}`.
- [ ] `GroupSchema.GrantableUniverse(persona)` = `Catalog` when CustomRoles on, else union of role grants.
      For root, ALWAYS union in `IntrinsicRootPermissions()` so built-in `root:` perms stay grantable.

Composition & root merge:
- [ ] `BuildSchema` (`permission_group_root.go:63`) MERGES the intrinsic root INTO a host-supplied
      `PersonaDef{Name: RootPersona}` instead of using it as-is: owner=`root:*` + intrinsic perms always
      present; host root roles/catalog appended; host sets root `Capabilities` (default all-off).
- [ ] Persona-set merge in `BuildSchema`/`NewGroupSchema`: non-root names globally unique (collision = error);
      root mergeable (union roles/catalog); root `Capabilities` from the final host only (reject capability
      flips in library root contributions); parent refs resolved across the union.
- [ ] Composition is config-time: libraries export `[]authkit.PersonaDef`; host concatenates into `Config.RBAC`.
      No mutable runtime schema (decided).

Catalog's only consumer — custom roles:
- [ ] Custom-role define path (`http/permission_group_operations.go:617` `groupCustomRoleDefine` + core) validates grants
      against `GrantableUniverse(persona)`, not just `ValidateGrantPattern`; reject grants outside the catalog.

Durable storage — containment reconcile + migration:
- [ ] Migration: `group_persona_parents` PK `(persona, allowed_parent_persona)`→single-parent shape (`persona` PK +
      `parent_persona text NOT NULL`); update the containment trigger/CHECK at `001_auth_schema.up.sql:298`. No table for
      catalog/roles — they stay in-memory.
- [ ] `SeedContainment` (`permission_group_store.go:56`): reconciling upsert —
      `INSERT ... ON CONFLICT (persona) DO UPDATE SET parent_persona=$2`, and DELETE personas absent from the schema.

Drift handling (assignments are late-bound by name — fail-closed; see DECISION above):
- [ ] Add a drift report (startup log + on-demand method): count `group_user_roles`, `group_custom_roles`,
      `api_keys` rows whose `(persona, role)` is absent from the current schema. Report only — do NOT
      auto-delete assignments (a config typo dropping a role would nuke everyone's grants).
- [ ] Admin role listings mark a stored role absent from the schema as `unknown/removed` (resolve against the
      schema; never render an orphan as if it were live authority).
- [ ] Test the fail-closed contract: removed catalog role, renamed role, removed permission, and
      CustomRoles-disabled each resolve to ZERO grants (never error, never fail open); and a REUSED name
      reactivates stale rows — the documented hazard, proving rule (2) matters.

Consumers, docs, validation:
- [ ] Migrate the four consumers' RBAC config to the new shape (single `Parent`, `Capabilities`, optional `Catalog`).
- [ ] `cmd/authkit-devserver/main.go:245,344`: remove `toPermissionDefs`/`RBACConfig{Permissions:...}`; per-persona
      `Catalog` only where custom roles are used.
- [ ] README/examples: one `Config.RBAC []PersonaDef` slice; root as an ordinary entry; permissions only as role grants
      (+ per-persona `Catalog` when custom roles). Document the durability boundary (catalog/roles ephemeral; containment
      + runtime role rows durable & name-referenced — renames orphan).
- [ ] `go test ./...` green; then targeted consumer builds after the coordinated bump.


---

# #146: HTTP route-group reshape + router-adapter surface

**Completed:** no

Split out of #143 (2026-06-26): five host-mounted route groups (`RouteAuth` /
`RouteRegistration` / `RouteAccount` / `RouteAdmin` / `RoutePermissionGroups`), config-aware
mounting, the Gin/Chi adapter surface (`WithGroups`, `authkitgin.Use` /
claims accessors), `verify.RequiredUser` / `OptionalUser`, and `GET /auth/capabilities`. Part
of the #143 release train (shared consumer bump tracked in #143).

- [x] DECISION: route groups should be coarse host-mounted surfaces, not the main
      feature-toggle system. Hosts should turn features on/off in config
      (`Registration`, passkeys, passwordless, persona capabilities), and disabled
      features should not expose usable routes. Route-group mounting is for where
      a host places whole surfaces in its router.
- [ ] Rework/rename route groups around host decisions:
      `Auth` (login/token/logout/password reset/passwordless), `Registration`
      (account creation + signup email/phone confirmation), `Account` (current
      user/profile/MFA/passkeys + changing a verified email/phone), `Admin`, and
      `PermissionGroups`. Email/phone verification folds into Registration (signup)
      and Account (contact change) — NO separate `Verification` group unless a real
      standalone no-account verification flow actually exists. Keep OIDC browser
      redirects and JWKS as separately mounted special cases.
- [ ] Replace current route constants with the new public route groups (FIVE, no
      `RouteVerification`): `RouteAuth`, `RouteRegistration`, `RouteAccount`,
      `RouteAdmin`, and `RoutePermissionGroups`. Delete `RoutePublic`,
      `RouteSession`, `RouteUser`, and `RoutePasskeys` from the host-facing API.
- [ ] Add adapter-level route group selection for the normal host API:
      `authkitgin.RegisterAPI(v1, srv, authkitgin.WithGroups(...))` and the same
      for Chi. `WithGroups(g ...authhttp.RouteGroup)` is SUGAR over the existing
      `svc.Routes().Groups(g...)` (`http/routes.go:53`): `WithGroups(...)` ⇒
      `WithRoutes(svc.Routes().Groups(g...))`, not a third selection path. The
      default `RegisterAPI(v1, srv)` registers all enabled JSON API routes.
      NOTE: only `WithGroups`/`RegisterAPI` need a Chi twin — the Gin-native helpers
      below (`Use`, `RequirePermission`, and context accessors) are Gin-only by nature.
      Chi middleware already IS `func(http.Handler) http.Handler`, so Chi handlers use
      `verify` directly. Do not build `authkitchi.Use`.
- [ ] Add a tiny Gin-native adapter surface for host routes:
      - Middleware logic lives in `verify`, not duplicated in `authkitgin`. Add ONE
        general adapter:
        `authkitgin.Use(mw ...func(http.Handler) http.Handler) gin.HandlerFunc`.
        README examples should use:
        `authkitgin.Use(verify.RequiredUser(v))`,
        `authkitgin.Use(verify.OptionalUser(v))`,
        `authkitgin.Use(verify.Required(v))`,
        `authkitgin.Use(verify.Optional(v))`, and
        `authkitgin.Use(verify.Sensitive())`.
        Do NOT add wrapper aliases like `authkitgin.RequireUser` /
        `OptionalAuth` / `RequireAuth` / `OptionalUser`; they duplicate `verify`
        with no new value. Do NOT add mixed host-concept helpers like
        `RequireUserOrService`, `RequireTenant`, `RequireScope`, `RequireAPIKey`, or
        `RequireRemoteApplication` in this pass. Tensorhub shows those are app caller
        models, not AuthKit primitives: AuthKit authenticates and narrows; the host
        resolves tenant/resource/caller semantics from token facts plus live lookups.
        Add a narrower named gate only after multiple consumers need the same exact
        AuthKit-level predicate.
      - Add exactly one Gin-native authorization helper because permission scopes
        normally come from Gin route params, not Go's `http.Request.PathValue`:
        `authkitgin.RequirePermission(client, perm, func(*gin.Context) verify.PermissionScope)`.
        It adapts to `verify.RequirePermission` internally, preserving the same authz
        logic, but lets examples and hosts use `c.Param("repo")` / `c.Param("org")`
        directly instead of hardcoding fake slugs or relying on net/http path-value
        plumbing.
      - `authkitgin.Use` is the only adapter with real semantics: chain the mw around
        a TERMINAL handler that reassigns `c.Request = r`
        — so the context a gate set (e.g. `Required`'s `SetClaims`) propagates to later
        Gin handlers — then calls `c.Next()`. A gate that short-circuits (writes 401,
        never calls inner) means the terminal never runs, so `c.Next()` is never called
        and the chain stops with no double-write. The wrapped mw must write through
        `c.Writer` and read/write `c.Request`.
      - Remote-application allowed-origin / CORS / delegated-origin binding is deleted
        separately in #149. Do not move origin checks into `VerifyRequest`; token
        verification stays about signature, issuer, audience, expiry, and authority.
      - Do not expose the giant union `verify.Claims` as the normal host-facing
        generic-auth shape. Add a smaller `authkit.Principal` / `authkitgin.Principal(c)`
        for generic auth: only principal kind, issuer, and generic subject. It must
        not expose user-only fields like email/session/roles/entitlements, nor
        programmatic credential details like permissions/resources/remote-app DB ids.
        Handlers that need human-user details must use `UserClaims(c)` behind
        `OptionalUser`/`RequireUser`; handlers that need live roles/tenant membership/
        effective permissions call the client explicitly (`Can`, `EffectivePermissions`,
        `ListRoleSlugsByUser`, etc.). `verify.RequirePermission(...)` can consume the
        internal broad claims for API-key/delegated authority without putting those
        fields on the generic public principal. Planned shape: `Kind`, `Issuer`, `Subject`.
      - Delete the planned `authkitgin.DelegatedPrincipal(c)` accessor. Tensorhub-style
        resource APIs should translate AuthKit's low-level verified claims into their
        own caller model once (`invoker`, `payer`, tenant, quota tier), then handlers
        use that app-owned model. Keep delegated-token facts on `verify.Claims` /
        `Claims.Delegated()` for adapter middleware that truly needs them; do not
        promote delegated JWT internals as Gin happy-path API.
        Do not add `authkitgin.RequireDelegated`.
      - Keep `verify.Claims` as the internal verifier/session union if useful, but
        make the Gin happy path use only `value, ok` accessors: `Principal(c)`,
        and `UserClaims(c)`.
        `UserClaims` adds the same human-user predicate as `verify.RequiredUser`.
        Planned `UserClaims` shape is token-only and native-user-only:
        `UserID`, `Email`, `EmailVerified`, `Username`, `SessionID`, `Entitlements`,
        `AMR`, `ACR`, `AuthTime`, and `MFAEnrolled`. Do NOT include `Roles` here:
        Doujins, Hentai0, and Tensorhub all resolve role/global-role/tenant-role state
        live at authorization chokepoints instead of trusting stale token roles.
        Handlers already behind required middleware may ignore the `ok` return. Do NOT
        add `GetPrincipal`/`GetUserClaims`/`Must*` variants: they are wrapper API with
        no value over Go's normal `value, ok` pattern. Do NOT make context getters write
        HTTP responses, and do NOT reimplement token extraction in the adapter.
      - README examples should use normal Gin route shape:
        `router.GET(path, authkitgin.Use(verify.RequiredUser(v)), func(c *gin.Context) { ... })`.
        Show optional/required user routes separately from optional/required generic
        auth routes. Generic auth examples inspect only principal kind, issuer, and
        subject, and must not treat a generic principal as native-user claims or
        programmatic credential details.
      - Consumer audit (2026-06-26, all five consumers + OpenRails read): the spectrum
        confirms the thin-token rule. OpenRails' `/me`/user path copies token fields
        (`UserID`, `Email`, `EmailVerified`, `Username`, `SessionID`, `Roles`,
        `Entitlements`) into its own `UserContext` with ZERO DB lookup. cozy-art is the
        thinnest: it reads ONLY token `UserID`, then hits Postgres/engine for everything
        it actually needs (metadata, tier, roles). Doujins/Hentai0 read `UserID`
        (+ `Entitlements` for premium gating, straight off the token — never DB-fetched)
        then resolve roles / effective-permissions / liveness LIVE; Tensorhub treats
        native-user tokens as sub-only and re-resolves tenant + global/tenant roles live.
        Machine principals (API-key / remote-app / delegated) authorize off token
        `Permissions` / attributes with no per-handler lookup. Two load-bearing facts:
        (a) EVERY consumer hand-gates on `UserID != ""` to mean "human user", and
        Tensorhub proves that unsafe — a worker token's `UserID` is `"gen-orchestrator"`,
        not a UUID, and the uuid-cast broke Postgres — so AuthKit must expose a canonical
        kind test (`Claims.IsUser()`, below) and consumers should delete the hand-rolled
        check; (b) the ONE unavoidable per-request DB hit — API-key resolution, since keys
        are opaque / not self-describing — happens ONCE at the verifier/gate (the
        client-backed enricher, #143), so even API-key handlers read already-resolved
        claims and the accessors stay zero-DB. The public-accessor rule: token claims are
        cheap identity/authority facts available with NO lookup; live profile / role /
        tenant / membership state is fetched only by the handlers that need it, via
        explicit `Authorizer` calls (`Can`, `EffectivePermissions`, `ListRoleSlugsByUser`).
      - For a raw `net/http` handler, use gin's built-in `gin.WrapH` — do NOT add an
        `authkitgin.WrapH` passthrough (gin already ships it; the path-value rewrite in
        `registerRoutes` is only for AuthKit's own generated paths, not a host's). Do
        NOT mirror every `verify.*` middleware as `authkitgin.*`; the generic adapter is enough.
- [ ] Delete `verify.RequireFreshAuth` entirely. `Sensitive()` is the only public
      step-up gate: it includes freshness, returns `step_up_required` metadata,
      and requires MFA when the user has MFA enrolled. Remove the `authhttp`
      re-export, docs/examples, and tests for `RequireFreshAuth`; replace any
      remaining call sites with `Sensitive(...)` or delete them.
- [ ] Delete public `verify.RequireAMR` and `verify.RequireACR` middleware. Keep
      AMR/ACR claims and `Claims.HasAMR` internally because `Sensitive()` and token
      issuance need them, but exact-auth-method route gates are niche API surface.
      Hosts should use `Sensitive()` for normal step-up/MFA enforcement.
- [ ] Delete public `verify.RequiredServiceJWT`, `ServiceJWTPrincipalFromContext`,
      `ServiceJWTPrincipal`, and their `authhttp` aliases. First-party service JWTs
      are not a normal host route gate; use ordinary `Required` + `RequirePermission`
      for machine credentials.
- [ ] Do not add route-middleware/accessor variants for service/delegated/machine
      principal classes: no `authkitgin.RequireServiceJWT`, `authkitgin.RequireDelegated`,
      `authkitgin.GetDelegatedUser`, `authkitgin.GetRemoteApplication`,
      `authkitgin.GetAPIKey`, or matching `verify.Require*` wrappers. Host apps that
      need app concepts such as invoker/payer/tenant should run one host-owned caller
      resolver over `Principal(c)` plus low-level `verify.ClaimsFromContext`.
- [ ] Test `authkitgin.Use` short-circuit + context propagation: a 401 gate
      (`verify.Required` with no token)
      must NOT reach the Gin handler; a passing gate must, and
      `authkitgin.Principal(c)`/`UserClaims(c)` must then see the values the gate set.
      The only adapter code with real semantics.
- [ ] Add a canonical `verify.Claims.IsUser()` plus a `PrincipalKind()` enum
      (user / api_key / remote_application / delegated / service) so the "is this a
      human user" test lives in ONE place: `IsUser()` = `UserID != "" && !IsAPIKey() &&
      !IsRemoteApplication() && !IsDelegated()` (over the existing `Claims.Is*` helpers,
      `verify/claims.go:112-153`). All five consumers hand-roll `UserID != ""` today and
      Tensorhub showed that unsafe for non-user principals — this is the strict primitive
      that replaces it; the accessors and gates below build on it. This is the "be
      stricter on consumers" lever: a wrong/duplicated check becomes one library call.
      SURFACE COLLAPSE: with `PrincipalKind()` + `IsUser()` as the public kind surface, the
      standalone boolean methods `IsAPIKey()` / `IsRemoteApplication()` are redundant
      (`PrincipalKind()==api_key`, etc.) — make them internal/unexported helpers, NOT host
      API. Keep `IsDelegated()` internal too (`Delegated()` and the #78 issuer gate use it).
      Net host-facing claim surface: `ClaimsFromContext` (substrate) + `IsUser()`/
      `PrincipalKind()` (kind) + `Delegated()`/typed accessors (delegated-only routes). The
      consumers' hand-rolled `IsAPIKey()`/`IsRemoteApplication()` branches migrate to
      `PrincipalKind()`.
- [ ] Add `verify.RequiredUser(verifier)` and `verify.OptionalUser(verifier)`
      for host routes that require or optionally enrich with a native human user.
      They run the normal auth pipeline and then gate on `Claims.IsUser()` — rejecting
      API keys, remote apps, delegated tokens, and service principals. `RequiredUser`
      fails closed (401) otherwise; `OptionalUser` drops to anonymous.
      `verify.Required(...)`/`verify.Optional(...)` remain "any valid AuthKit
      principal", so user-profile/session handlers should not hand-read `claims.UserID`.
- [ ] Remove `srv.Routes().Groups(...)` from README/happy-path docs. Keep
      `srv.Routes()` / raw `RegisterRoutes(...)` only as the advanced escape hatch
      for custom routers, route wrappers, generated docs, or tests.
- [ ] Route mapping:
      `RouteAuth` gets `/auth/capabilities`, `/token`, `/sessions/current`,
      `/logout`, `/password/login`, password reset routes, passwordless routes,
      `/2fa/challenge`, `/2fa/verify`, Solana login/challenge, and passkey login
      begin/finish. `RouteRegistration` gets `/register`, `/register/availability`,
      `/register/resend-*`, and `/register/abandon` (signup-time verification resends
      ride here). `RouteAccount` gets `/email/verify/*`, `/phone/verify/*`, `/me`,
      `/user/*`, provider unlink/link/step-up routes, Solana link, 2FA enrollment
      and backup-code routes, and passkey register/list/update/delete routes.
      `RouteAdmin` remains admin user/operator routes. `RoutePermissionGroups`
      remains generated persona-group management plus group invite redemption.
- [x] INVESTIGATION: Doujins is the root-only case. It declares no non-root
      personas (`RBAC.Groups` is only `permission.RootGroupType()`), regular users
      belong to no group, and product admin role grants are app-owned
      (`POST /admin/roles/grant|revoke`) because Doujins needs entitlement side
      effects and product-specific response shapes. It still needs effective
      permission visibility for the SPA/admin nav and backend checks.
- [ ] Split permission visibility from permission-group management. Move
      `GET /me/permissions` to `RouteAccount` because apps without public group
      management still need it for UI gating. Keep the response rooted in the
      current principal and default to singleton `root`; if scoped permission
      checks are needed, prefer explicit scoped endpoints later over stuffing the
      full group-management surface into every app.
- [ ] Make `GET /me/groups` config-aware. It belongs in `RouteAccount` only when
      the deployment declares at least one non-root persona or otherwise enables
      user-visible memberships. Root-only apps like Doujins should not have to
      expose group discovery just to show admin permissions.
- [ ] Keep `POST /invites/redeem` under `RoutePermissionGroups` and mount it only
      when invite-link support is enabled for at least one persona. If invite-only
      account registration needs a public invite check/start route, that belongs
      to `RouteRegistration`, not the group-management route group.
- [ ] Make root management routes opt-in. `IntrinsicRootPersona(...)` should not
      automatically set `MemberAssignment: true`; hosts that want public root
      member/role management must explicitly enable it in root persona
      capabilities. The concrete client/core methods remain available for seed
      jobs, migrations, and app-owned admin routes.
- [ ] Stop generating role-catalog routes when every management capability is off.
      Today `GeneratedRoutes()` always emits `GET /<persona>/:instance_slug/roles`;
      that should be tied to custom role / member-management visibility rather
      than leaking a group-management endpoint into root-only deployments.
- [ ] Stop treating auth methods as primary route groups where config is better.
      Passkey login belongs to `RouteAuth`; passkey management belongs to
      `RouteAccount`; passkey availability should come from `PasskeyConfig`.
      Passwordless routes belong to `RouteAuth`, but are exposed/usable only when
      passwordless login is enabled. Registration routes belong to
      `RouteRegistration`, but are exposed/usable only when registration mode is
      not `Closed`; invite-only registration requires a valid invite token.
- [ ] Make route generation config-aware before mounting: disabled registration,
      passwordless, passkeys, 2FA methods, OIDC providers, Solana/SIWS, and persona
      capabilities should remove or fail-closed their routes by config. Hosts should
      not rely on omitting a route group as the security control.
- [x] DECISION: add one public, non-user auth capability/discovery endpoint instead
      of making frontends infer feature availability from mounted routes. Do not
      add a separate `/auth/availability`; service-level registration/login
      availability belongs in this one response.
- [ ] Replace `GET /identity-providers` with `GET /auth/capabilities`
      under `RouteAuth`. Keep provider summaries there and include only
      non-sensitive booleans/enums. Do not expose secrets, internal sender health,
      or admin-only config. It is static per-deploy config served unauthenticated on
      every frontend load — set `Cache-Control`/ETag, do not recompute per request.
- [ ] Define the `GET /auth/capabilities` response contract in root `authkit`
      types so embedded and remote/non-Go clients see the same shape. Include:
      registration mode plus invite-token requirement; enabled provider summaries;
      password login availability; passwordless enabled/channels/modes; passkey
      login availability; Solana/SIWS login availability; public verification
      requirements; and supported UI languages if language config remains mounted.
- [ ] Keep `GET /register/availability` separate and narrowly named for identifier
      checks (`username`, `email`, `phone_number`). It answers "is this value
      available?", not "which auth flows does this service support?".
- [ ] Delete `GET /identity-providers` in the hard-cut. Do not keep a compatibility
      alias during this breaking-change pass.
- [ ] Keep authenticated account-specific capability details on account endpoints:
      `/me` and `/user/2fa` should report user-specific MFA state, enrolled
      factors, allowed 2FA methods from config, backup-code status, linked
      providers, and available step-up methods.
- [ ] Move any custom auth-state store injection to internal tests or an unadvertised
      test seam. Do not expose it in README or normal package docs.

---

# #147: Registration modes + first-class invites

**Completed:** no

Split out of #143 (2026-06-26): the registration-mode cull (`Open` / `InviteOnly` / `Closed`)
plus first-class invites — account-registration invites SEPARATE from permission-group invites
(two independent tokens), email-bound redemption, shareable vs email-bound group links, and
rate limits. This is net-new feature surface, not API cleanup. Part of the #143 release train.

- [x] DECISION: registration policy enums belong in root `authkit`, not `embedded`,
      because they are shared public contract vocabulary for embedded + future remote.
- [x] DECISION: simplify `RegistrationMode` to public self-registration policy only:
      keep `Open`, `InviteOnly`, and `Closed`; delete `AdminOnly`,
      `AdminBootstrapOnly`, and `ManifestOnly`. Operators can always create users
      through privileged APIs/bootstrap/manual DB operations outside public native
      registration mode.
- [x] DECISION: `InviteOnly` means account onboarding by valid invite, not a generic
      permission-group consent flow. Owners/admins can directly add existing users
      to permission groups; invite links are only for onboarding someone who does
      not already have an account.
- [x] DECISION: do not send email/SMS notifications when an existing user is directly
      added to a permission group. It is spam-prone because owners can unilaterally
      add people to their own groups. Email/SMS belongs only to explicit invite
      onboarding for non-users.
- [x] DECISION: when an owner/admin tries to add an email that does not belong to
      an existing account, AuthKit should send an invite email asking that person
      to register or log in, then manually accept the invite link.
- [x] DECISION: email-bound invites may only be redeemed by an account with that
      same verified email. If an invite is sent to `fidika@gmail.com`, registering
      or logging in as `someoneelse@gmail.com` must not redeem it.
- [x] DECISION: support two group invite kinds: (1) general-purpose shareable link
      with no bound email, redeemable by whoever has the link within expiry/max-use
      limits; (2) email-bound invite, redeemable only by an account with the same
      verified email.
- [x] DECISION: invites are time-bound manual accepts. Do not auto-add users to
      permission groups after signup/login; the recipient must click/open the
      invite link and accept/redeem it. Default validity should be a few days for
      both shareable links and email-bound invite links.
- [x] DECISION: invite creation/email sending must be rate-limited. A user must
      not be able to spam a large number of invite emails quickly.
- [ ] Move `RegistrationVerificationPolicy` +
      `RegistrationVerificationNone|Optional|Required` to root `authkit`.
- [ ] Move simplified `RegistrationModeOpen|InviteOnly|Closed` to root `authkit`
      and delete `AdminOnly`, `AdminBootstrapOnly`, and `ManifestOnly`.
- [ ] Update `embedded.RegistrationConfig` to use the root registration enum types
      so future `remote` and host docs do not import shared vocabulary from
      `embedded`.
- [ ] Make `InviteOnly` real with first-class account-registration invites.
      A user can be invited to create an account without being invited to any
      permission group.
- [ ] Add a built-in root permission for standalone account-registration invites,
      `root:users:invite`. The root `owner` role gets it via `root:*`; hosts may
      add it to bounded operator roles when they want non-owner staff to invite
      new accounts.
- [ ] Keep account-registration invites and permission-group invites separate — and
      keep their TOKENS separate too. An unknown-email group invite under `InviteOnly`
      sends TWO independent tokens (a standalone account-registration invite plus the
      email-bound group invite), NOT one token that "carries" the other. Two clear steps
      (register, then accept the group invite), zero coupling between the subsystems; the
      email-bound rule already guards both. The only thing "carrying" would save is one
      email — not worth welding the two subsystems together.
- [ ] Authorize permission-group invites with that group's existing
      `<persona>:members:manage` no-escalation checks. A group owner/manager may
      attach a registration credential only for that group invite; this does not
      grant general `root:users:invite` authority.
- [ ] Registration invites must be high-entropy, time-bound URL tokens, not short
      OTP-style codes. Email-bound registration invites authorize account creation
      only for that email.
- [ ] Permission-group invite acceptance stays separate from account creation.
      If a group invite helped an unknown recipient register, the user still must
      manually accept/redeem the group invite before AuthKit adds the membership.
- [ ] Preserve the existing email-bound redemption rule in the onboarding flow:
      invite email must equal the redeemer account's verified email.
- [ ] Make the invite API/docs name invite kinds clearly: account-registration
      invite, permission-group shareable link, and permission-group email-bound
      invite.
- [x] RESEARCH: registration gating is SPLIT across two layers (NOT all in service.go):
      core `internal/authcore/service.go` (`normalizeRegistrationMode`,
      `PublicNativeUserRegistrationEnabled`, `CreatePendingRegistration*`,
      `ConfirmPendingRegistration*`, `CreatePendingPhoneRegistration*`), core passwordless
      (`passwordless.go`) and Solana (`service_solana.go`) — BUT the OIDC/OAuth auto-create
      gate is in the HTTP layer (`http/oidc_browser.go`, `http/oauth2_browser.go` via
      `publicRegistrationDisabled()`), not service.go. All need invite-aware checks.
- [x] RESEARCH: group invite storage already mostly fits the model:
      `migrations/postgres/001_auth_schema.up.sql` has `group_invite_links` with
      optional `email`, `max_uses`, `uses`, `expires_at`, and `revoked_at`.
- [x] RESEARCH: invite creation/redemption lives in
      `internal/authcore/group_invite_links.go`: `externalInvitesEnabled`,
      `CreateGroupInviteLink`, `inviteURL`, `sendGroupInviteEmail`,
      `RedeemGroupInviteLink`, plus default TTLs
      (`defaultEmailInviteTTL`, `defaultShareableInviteTTL`).
- [x] RESEARCH: permission-group HTTP member/invite routes live in
      `http/permission_group_operations.go` and `http/permission_group_routes.go`.
      `memberRequest` currently accepts only `user_id`, so "add by email, invite if
      unknown" requires an API/request-shape change.
- [x] RESEARCH: public route registry in `http/routes.go` already has registration,
      passwordless, verification, and `/invites/redeem`; invite landing/start may need
      either a new unauthenticated route or an invite token parameter accepted by
      existing registration/passwordless routes.
- [ ] Add ONE core helper `registrationAllowedForEmail(ctx, email) (bool, error)` and
      route ALL gates through it — do NOT thread invite-awareness through ~10 divergent
      call sites (`PublicNativeUserRegistrationEnabled()` takes no email, which is exactly
      why the single email-aware helper is needed). Under `InviteOnly` it returns true iff a
      valid, unexpired email-bound account-registration invite exists for that email; `Open`
      stays true; `Closed` false. Call it from the core sites AND the HTTP-layer OIDC/OAuth
      gates (`publicRegistrationDisabled()`), passwordless, and Solana.
- [ ] Spec the two cross-subsystem rules the two-token flow needs: (1) consuming an
      email-bound account-registration invite MUST set `email_verified=true` on the new
      account — else `RedeemGroupInviteLink` (which requires a verified email,
      `group_invite_links.go:342`) rejects the follow-on group redemption; (2) define the
      account-registration invite's TTL relative to the group invite plus a re-issue path,
      so a stranger can't consume the account token, register, then find the group invite
      already expired (account created, no membership).
- [ ] Update `internal/authcore/group_invite_links.go` defaults to CONCRETE TTLs —
      `defaultEmailInviteTTL` = 7 days, `defaultShareableInviteTTL` = 72h — the
      identity-proven (email-bound) invite outlives the anyone-with-the-link shareable
      one, never the reverse. (Email-bound 7d is already today's value; shareable goes
      24h → 72h.) A removed knob
      still needs a named default; "a few days" is not a spec. Keep explicit per-invite
      expiry overrides.
- [ ] Add the account-registration invite contract separately from group invites,
      including creation, email delivery, validation during registration, expiry,
      revocation, and consumption semantics.
- [ ] Update `CreateGroupInviteLink` / `CreateGroupInviteLinkRequest` /
      `GroupInviteLinkCreated` contract docs to name the two permission-group
      kinds: no-email shareable link vs email-bound invite.
- [ ] Update `http/permission_group_operations.go` add-member flow: existing
      `user_id` adds directly and silently; email with no account creates/sends an
      email-bound group invite instead of failing or auto-adding. If registration
      is not public, also send a SEPARATE email-bound account-registration invite —
      two independent tokens (per above), do not fold one into the other.
- [ ] Add invite-specific rate limits around invite creation/email sending,
      preferably keyed by actor user, target email, and group; return a stable
      rate-limit error instead of sending more mail.
- [ ] Add/adjust HTTP route support so an unauthenticated invite recipient can land
      on an account-registration invite or permission-group invite, register or
      log in, then manually redeem/accept any group invite. Do not auto-redeem a
      group invite after account creation.
- [ ] Add integration tests for: existing user direct add no notification; unknown
      email creates group invite; standalone account-registration invite works
      under `InviteOnly`; group invite for unknown email can authorize registration
      only through an attached account-registration invite; wrong verified email
      cannot register/redeem; manual group accept required; expired/revoked/
      exhausted invites rejected; shareable group link still obeys expiry/max-use
      but does not unlock invite-only registration by itself.

---

# #148: 2FA policy + TOTP key material

**Completed:** no

Split out of #143 (2026-06-26): `TwoFactor.Mode` / `Methods` replacing `RequireEnrollment`,
`Required` gating the SESSION (existing un-enrolled users get a forced-enrollment challenge —
human-user principals only, and the enroll/verify routes must be allowlisted or the gate
deadlocks; reuse #146 `RequiredUser`'s predicate), backup codes tied to availability, and the
TOTP key as first-class vault key material with a reserved 1-byte rotation prefix. Part of the
#143 release train.

- [x] DECISION: TOTP secret-encryption keys use the same security model as signing
      keys: AuthKit reads them from the vault-mounted key directory (`Keys.Path`,
      `/vault/auth` by default); host apps do not manually load/pass secrets during
      normal embedded setup.
- [x] DECISION: replace `TwoFactorConfig.RequireEnrollment bool` with explicit
      host policy: `Mode` (`authkit.TwoFactorDisabled|Optional|Required`) plus
      `Methods []authkit.TwoFactorMethod` (`Email|SMS|TOTP`). `Disabled` means no
      user 2FA enrollment/challenge routes are usable; `Optional` means users may
      enroll; `Required` means every user must enroll before normal session use.
      Role-level `RequiresMFA` stays available for narrower enforcement.
- [x] DECISION: backup codes are not host-configurable. When 2FA enrollment is
      available, backup-code generation/recovery is always available as the
      standard recovery path.
- [ ] Move 2FA policy vocabulary to root `authkit`: `TwoFactorMode`,
      `TwoFactorDisabled`, `TwoFactorOptional`, `TwoFactorRequired`,
      `TwoFactorMethod`, `TwoFactorEmail`, `TwoFactorSMS`, `TwoFactorTOTP`.
- [ ] Update `embedded.TwoFactorConfig` to use `Mode` and `Methods`; remove
      `RequireEnrollment` from the public config hard-cut.
- [ ] Gate 2FA routes and service operations from config: disabled means no
      enroll/challenge/verify flow; optional/required expose only configured
      methods, and fail closed when a method dependency is missing (for example,
      SMS sender absent).
- [ ] `Required` gates the SESSION, not just signup. When a host flips
      `Optional → Required`, existing un-enrolled users must hit a forced-enrollment
      challenge on their next authenticated request. Spec this transition explicitly —
      gating only new registrations leaves every pre-existing user unprotected.
      GROUNDING (2026-06-26, verified): today's gate is only HALF-built — these are
      NET-NEW items, not a re-spec:
      (a) The `2fa_enrollment` claim is minted only by `Issue2FAEnrollmentToken`; the
          middleware gate (`verify/middleware.go:46`) fires only when that claim is
          present, and `requireSessionMFAState` (`mandatory_2fa.go`) runs only at session
          ISSUE/REFRESH (`IssueRefreshSession`/`ExchangeRefreshToken`). So an existing
          un-enrolled user with a still-valid access token keeps full API access until it
          expires — the "next request" gate does not exist yet. Build it.
      (b) The refresh path returns 403 + `allowed_methods` but mints NO enrollment token
          (`auth_token_post.go` `send2FAEnrollmentRequiredError`), so a user gated at
          refresh CANNOT reach the enroll routes without re-logging-in — a lockout. Fix:
          refresh-time gating must hand back a usable enrollment token like the login path does.
      (c) The enroll allowlist `allowed2FAEnrollmentPath` (`verify/middleware.go:105`) is a
          hardcoded `/user/2fa` suffix match — it must DERIVE from the new `Mode`/`Methods`
          + route registration (so `Disabled`/partial-method configs stay consistent), and
          must NOT strand `/2fa/challenge`/`/2fa/verify`.
      (d) Principal-kind exclusion works only by accident today (API keys return before the
          gate; delegated/service never get the human-only claim). The per-request gate must
          gate EXPLICITLY on the `Claims.IsUser()` predicate (#146) — machine principals
          can't enroll TOTP and must bypass.
- [ ] Keep backup-code routes/operations tied to 2FA availability, not to a
      separate config flag.
- [ ] Treat the TOTP encryption key as first-class key material, not incidental
      config: define the file format, load path, validation, reload/rotation story,
      and error semantics at the same rigor level as JWT signing keys.
- [ ] Add vault/file loading for `TwoFactor.TOTPSecretKey` under `Keys.Path`.
      Use strict file permissions/parse validation, require 16/24/32 bytes after
      decoding, and fail closed for TOTP enrollment if the key is missing or invalid.
- [ ] Decide whether TOTP key config needs the same knobs as signing keys
      (`Source`/custom provider, path override, reloadable file source). Prefer a
      small shared key-loading abstraction over host apps reading secrets manually.
- [ ] TOTP rotation, lazy version: v1 stores a 1-byte key-id/version prefix on every
      encrypted TOTP secret and builds NO keyring. That reserves the calibration knob so
      a future keyring/rotation is purely additive (old secrets stay decryptable by their
      prefix) with zero rotation machinery now. Full keyring/rotation is a separate issue.
- [ ] Keep the explicit `TwoFactor.TOTPSecretKey []byte` override for tests and
      custom key management, but make it an override over the file source, not the
      normal path.
- [ ] Document the expected vault-mounted TOTP key filename/format next to the JWT
      `keys.json` docs.

---

# #149: Delete remote-application allowed origins + AuthKit CORS

**Completed:** no

Split out of #146 (2026-06-26): hard-cut the whole remote-application
`allowed_origins` / delegated-Origin / AuthKit-owned CORS system. It is browser
cooperation, not meaningful token security; delegated bearer-token security is
signature, issuer, audience, expiry, and permission/resource checks. Host apps own
ordinary CORS for their own browser APIs.

- [x] DECISION: delete AuthKit-owned allowed-origin enforcement entirely. Do not
      move it into `VerifyRequest`; do not keep it as optional public middleware.
- [x] DECISION: delegated tokens are not cookie credentials. A random origin cannot
      automatically attach a runtime bearer token, and any non-browser caller can spoof
      `Origin`, so AuthKit origin binding is marginal complexity, not core security.
- [ ] Delete public middleware/helpers:
      `verify.RemoteApplicationCORS`, `verify.RequireDelegatedOrigin`,
      `Verifier.RemoteApplicationAllowedOrigins`, `Verifier.OriginAllowedForIssuer`,
      and their `authhttp` aliases.
- [ ] Delete origin helper API from root/internal surface:
      `NormalizeAllowedOrigin(s)`, `OriginAllowed`, `ErrInvalidAllowedOrigins`, and
      related tests unless another non-CORS caller remains.
- [ ] Remove `AllowedOrigins` from `authkit.RemoteApplication`,
      `RemoteApplicationRegistration`, `CreateRemoteApplicationRequest`,
      `UpdateRemoteApplicationRequest`, HTTP request/response DTOs, bootstrap manifest
      structs, and generated/admin JSON responses.
- [ ] Remove `allowed_origins` from Postgres remote-application schema and sqlc
      queries/models; add the hard-cut migration to drop the column.
- [ ] Update remote-application create/update validation so issuer/JWKS/public keys
      remain validated, but no allowed-origin validation/error path exists.
- [ ] Delete tests whose only purpose is allowed-origin normalization, CORS preflight,
      or delegated-origin middleware. Replace with tests proving delegated token
      verification still gates on issuer/audience/expiry/permissions.
- [ ] Update README and adapter docs: no AuthKit CORS setup. Hosts use their normal
      Gin/Chi/global CORS middleware if they expose browser APIs.
- [ ] Migrate consumers off the deleted surface during the coordinated breaking bump.
      The four apps (`doujins`, `hentai0`, `cozy-art`, `tensorhub`) only set
      `allowed_origins` config/request fields — drop those. OpenRails is the heavy case
      (accepted breakage): it calls the deleted Go symbols directly
      (`OriginAllowedForIssuer`, `RemoteApplicationAllowedOrigins`, `authkit.OriginAllowed`)
      and has its own CORS subsystem (`ginmw/security.go`, `http_base.go` `CORSHTTP`) plus
      a merchant-manifest `allowed_origins` field, all built on AuthKit's union source. It
      must REBUILD CORS independently (host-owned origin list), not just delete config.

---

# #150: Dead / duplicate / unnecessary code removal

**Completed:** no

STATUS 2026-06-26 (Claude): Paul's v0.72 (`ea37bf4`, merged) already landed most of the #143–#149
train (origin/CORS deleted #149; RBACConfig/AllowedParents gone #145; RoutePublic→RouteAuth +
principal.go/capabilities.go #146; RegistrationModeAdminOnly gone + account_registration_invites
#147; RequireEnrollment→TwoFactorMode/Methods #148; WithAuthLogger→clickhouse_audit #143). Newly
STALE here: #157 (provider fields gone in his reshape); #185 PREMISE done (he removed
`Resources`/`APIKeyResource`/`ResolveAPIKeyWithResources`) — but he KEPT `ResolveAPIKey`+
`ResolveAPIKeyDetailed` and `MintAPIKey`+`MintAPIKeyWithOptions`, so the "collapse to one" rec is
dropped (match his keep-both style). Everything else in #150 is still live (incl. the flagship #174).

STATUS 2026-06-26 (Claude): TIER 1 DONE + green (build+vet, jwt + validation tests pass):
#151 `embedded.Wrap` deleted; #152 `ResolveRemoteApplicationGroup` deleted; #153
`RemoveRemoteApplicationMember` deleted; #154 `EnableTOTP2FA` no-op deleted AND
`EnableTOTP2FADefault`→`EnableTOTP2FA` renamed (clean name reclaimed now the wrapper is gone;
internal-only, 3 sites); #156 `http/validate.go`+`validate_test.go` deleted, the reserved-names-pass-
syntax guard relocated to `internal/authcore/identity_validation_test.go`; #158 `jwt.mergePublicKeys`
deleted, `NewKeyRing` uses `clonePublicKeyMap` + explicit nil→empty normalize (preserves non-nil pubs).

STATUS 2026-06-26 (Claude): TIER 2 (clean/safe subset) DONE + green (build+vet): #159 `normalizeEmail`
inlined to `NormalizeEmail` (2 callers) + deleted; #160 ephemeral `marshalJSON`/`unmarshalJSON`/
`jsonMarshal`/`jsonUnmarshal` deleted, `ephem*JSON` call `json.Marshal`/`json.Unmarshal` directly;
#161 `sanitizeStepUpReturnTo` deleted, 2 callers → `sanitizeReturnTo`; #163 inline obfuscation →
`obfuscateVerificationID`; #164 `email_verify.go` uses `parseIP` (dropped `net` import); #170 twilio
`g` alias inlined. DEFERRED: #162 (`clientIP`→`remoteIP`) needs a careful 12-site pass and is still
referenced by `AllowNamed` (#155, breaking) — own pass; #165/#166 subsumed by #186; #167/#172/#173
low-value (likely leave); #168/#169 advanced-adapter shared-pkg (bigger); #171 depends on #188.

STATUS 2026-06-26 (Claude): #174 (flagship) DONE + green (build+vet; jwt `SignWithType` unit test —
4 branches — + authcore token-minting tests pass). Added exported
`jwt.SignWithType(ctx, signer, claims, typ string, requireHeader bool)`; collapsed ALL 7 HeaderSigner
typ-stamp sites onto it — `service.go` (access, requireHeader=true), `service_jwt.go` (ServiceJWT,
requireHeader=false fallback), `delegated.go`, `remote_application_token.go`, `custom_jwt.go`
(`opts.Type`, empty→plain Sign), `authtest/issuer.go`, `cmd/authkit-devserver/main.go`. No
`.(jwtkit.HeaderSigner)` asserts remain outside `jwt/`.

Remove dead code, redundant no-op wrappers, pure-duplicate helpers, and same-logic /
different-name functions across the module. Every item is grounded in code (file:line) and
checked against its call sites + the public re-export layer (`embedded/aliases.go`,
`embedded/facade_methods.go`, root `*.go`, `http/*aliases`); per-item evidence (why, consumer
impact, confidence) is in `agents/audits/dead-duplicate-code.md`. Already-tracked culls
(#143–#149, #142) are excluded.

DECISION 2026-06-26 (end state = MORE IDIOMATIC Go, not merely smaller): each removal lands the code
on the idiomatic shape, called out per-issue below as an **Idiomatic target**. The recurring levers:
let the stdlib do its job (`encoding/json` Marshaler dispatch — #160); typed results over
`map[string]any` for known shapes (#180); small, *used* interfaces, not speculative tiers (#189);
one shared type/helper instead of duplicate-and-convert (#174, #175, #181, #188); the house helper
over a local re-implementation (#162, #163, #164); explicit intent over hidden-default wrappers
(#154); resolvers RETURN errors, handlers map them to HTTP (#176); and a minimal exported surface —
no no-op aliases, no test-only or write-only exports (#155, #157, #159, #161, #187, #191, #192).
`gofmt` + `go vet` clean at every gate; match surrounding conventions.

DECISION 2026-06-26: phase by blast radius. Tier 1 + the safe half of Tier 2 are internal-only
(unexported, or exported-but-not-re-exported, so no consumer can reach them) → land FIRST as
non-breaking deletions/inlines, build + vet green at each gate. Tier 3 are behaviour-preserving
consolidations. Tier 4 are public-surface breaks → ride the #143–#149 coordinated consumer bump,
never a separate break (the three biggest fold INTO #143). Rule: an exported symbol counts as dead
only if it is ALSO absent from the facade and the HTTP routes.

DECISION 2026-06-26 (do NOT touch without sign-off — two security traps):
- `cmd/authkit-server` local `isDevEnv` (`main.go:202`) looks like a dup of
  `embedded.IsDevEnvironment`, but it gates the UNAUTHENTICATED management API and uses an
  allow-list (`"test"`=dev) vs the canonical deny-list (everything-but-prod=dev). Merging WIDENS
  what counts as dev on a security boundary — leave unless security-reviewed.
- `siws.Verify` (combined one-shot, `siws/siws.go:67`) has zero in-repo callers (the live path uses
  split `ParseMessage`/`ValidateDomain`/`ValidateTimestamps`/`VerifySignature`) but is PUBLIC SIWS
  surface an external verifier could use — product decision before cutting.

DECISION 2026-06-26 (out-of-scope bugs found alongside — fix elsewhere, NOT this issue):
`storage/memory/siws_cache.go:33` spawns a cleanup goroutine with no `Close()` (its `StateCache`
sibling has one → goroutine leak); `ratelimit/redis/limiter.go:22` stores `context.Context` in the
struct and ignores per-call ctx; the http change-flow handlers match `err.Error()` substrings
("same as current"/"already in use") — fragile, belongs with the error-sentinel work in plans
008/009/011.

## Child issues (one per removal — track/work independently)

Each line below is its own issue section further down. Phase tag in parens.

Tier 1 — dead code, internal-only (non-breaking; land first):
#151 `embedded.Wrap` · #152 `Service.ResolveRemoteApplicationGroup` ·
#153 `Service.RemoveRemoteApplicationMember` · #154 no-op `Service.EnableTOTP2FA` ·
#156 `http.validateUsername`/`validate.go` ·
#157 write-only `Server.oidcProviders`/`providers` · #158 `jwt.mergePublicKeys`.
(#155 re-tiered to Tier 4 — `http.AllowNamed` is exported + SEMVER-covered.)

Tier 2 — redundant wrappers / duplicate helpers, internal-only (non-breaking):
#159 `authcore.normalizeEmail` · #160 ephemeral JSON-marshal indirection ·
#161 `http.sanitizeStepUpReturnTo` · #162 `http.clientIP`≡`remoteIP` (+IP-source fix) ·
#163 `obfuscateVerificationID` reuse · #164 `parseIP` reuse · #165 `mergeScopes`≡`mergeStringSets` ·
#166 `cloneStringMap` [opt] · #167 `passwordResetData` twins [opt] · #168 twilio shared helper ·
#169 gin/chi `routepath` · #170 twilio sms `g` [trivial] · #171 ratelimit `get`/`remaining` ·
#172 devserver bootstrap wrappers · #173 `writeJSON`/env helpers [opt].

Tier 3 — same-logic consolidations (behaviour-preserving, internal-only):
#174 `jwt.SignWithType` (HIGHEST-VALUE) · #175 shared `signWithHeaders` ·
#176 `resolveBrowserUser`/`finishBrowserLogin` · #177 step-up tail · #178 SIWS decode/error ·
#179 verify/confirm handler twins · #180 `writeAccessTokenJSON` · #181 `firstTrimmedNonEmpty` ·
#182 role-grants resolution · #183 http outbound client.

Tier 4 — public-surface dups / dead exports (BREAKING; ride the #143–#149 bump):
#155 dead exported `http.AllowNamed` (SEMVER §4.5) ·
#184 `SolanaConfig` (→#143) · #185 `ResolveAPIKey`/`MintAPIKey` collapse (→#143) ·
#186 `oidc/defaults.go` cluster (→#143) · #187 `PermissionTokenCovers`→`PermMatches` ·
#188 `ratelimit.Limit` hoist · #189 limiter 3-tier→2 · #190 `ApplyBootstrapManifestFile` ·
#191 dead exported helpers · #192 test-only exports.

## Depends on / coordinates with

- #143 — three breaking dedup angles + the provider-fields drop fold into its bump (note added in #143 head).
- #146 — Tier-3 email/phone handler consolidation overlaps the Account-group route rework; share bodies there.
- #149 — origin/CORS deletions already own the `origin.go` cluster; this work doesn't touch it.
- Plans 008/009/011 — the `err.Error()` substring fragility logged above belongs to the error-sentinel work, not here.
- SEMVER.md — every Tier-4 removal edits a SEMVER section (cross-walk in the audit doc); the doc's own drift (still on `core`/`authbase`/`identity`/`roles`) coordinates with #143 below.

## SEMVER reconciliation

- [x] Cross-walk every Tier-4 item → its SEMVER.md section (table in `agents/audits/dead-duplicate-code.md`).
- [ ] On each Tier-4 removal, edit the mapped SEMVER.md section and bump MAJOR — target the symbol's CURRENT package, not the stale one named in the doc.
- [ ] DRIFT (coordinate with #143): rebase SEMVER.md §4.1 table + the `core`/`authbase`/`identity`/`roles` sections onto the real tree (`embedded` + root `authkit`); #143 already updates §4.2/§5 — extend that, do NOT reopen archived #138/#141. A v1.0 contract can't be cut while the doc names absent packages.
- [ ] Specifics: `PermMatches`/`PermissionTokenCovers` are listed under `authbase` (gone) but live in root `permission.go` (SEMVER.md:274); `ApplyBootstrapManifestFile` is already absent from SEMVER (no edit, just delete the method); `jwt.NewStaticKeySourceFromRing`/`RSAPublicToJWK` are covered by the jwtkit set, not by name.

## Verified-clean (recorded so they aren't re-audited)

`errorsByCode`/`ErrorForCode` (intentional single source for cross-transport `errors.Is`); the
`httperror.go` message catalog (one humanizer); `embedded/aliases.go` ↔ root split (zero
overlap); `import_users.go` vs `users_batch.go` (insert vs read); `audit.go` vs
`audit_context.go`; `ephemeral.go` vs `ephemeral_data.go`; `register_availability.go` vs
`availability.go`; storage memory `KV` vs `SIWSCache`/`StateCache` (distinct interfaces);
`getClaims` vs `ClaimsFromContext` (different signatures); verify token-type const re-aliases
(deliberate core-free layering #110). Full list in the audit doc.

---

# #151: Delete dead `embedded.Wrap`

**Completed:** no

Parent #150 (Tier 1, internal-only, non-breaking).

RESEARCH (2026-06-26, verified): `embedded.Wrap` (`embedded/facade.go:59-62`) has ZERO references
module-wide incl. tests (`grep '\.Wrap('` is empty). Its doc comment "Used by the authkit/http
transport" is STALE: the transport is client-first — `NewServer(client *embedded.Client, ...)`
(`http/server.go:42`) extracts the engine via `embedded.Unwrap` (`server.go:46`), never `Wrap`.
`Wrap` was the adapter for the old `NewServer(cfg, pg)` engine-construction path, obsoleted by the
#142 client-first cut. Its `*authcore.Service` param is an `internal/` type, so it is also
uncallable by any external consumer — provably dead for every caller, not just in-repo.

- [ ] Delete `func Wrap` + its stale doc comment (`embedded/facade.go:59-62`).
- [ ] Keep `Unwrap` (the live engine-extraction seam `NewServer` uses).
- [ ] `go build ./... && go vet ./...` green.

---

# #152: Delete dead `Service.ResolveRemoteApplicationGroup`

**Completed:** no

Parent #150 (Tier 1, internal-only).

RESEARCH (2026-06-26, verified): `Service.ResolveRemoteApplicationGroup`
(`internal/authcore/service_remote_applications.go:328-337`) has ZERO references module-wide incl.
tests. It is a one-line convenience wrapper — `GetRemoteApplication(ctx, issuer)` then returns
`.PermissionGroupID`. Not on `authkit.Client`, not re-exported via `embedded`, no HTTP route, so no
consumer can reach it. The live group-id resolution is the unexported `remoteApplicationGroupID`
(used by the membership methods) plus `GetRemoteApplication` directly.

- [ ] Delete `func (s *Service) ResolveRemoteApplicationGroup` (`service_remote_applications.go:328-337`).
- [ ] `go build ./... && go vet ./...` green.

---

# #153: Delete dead `Service.RemoveRemoteApplicationMember`

**Completed:** no

Parent #150 (Tier 1, internal-only).

RESEARCH (2026-06-26, verified): `Service.RemoveRemoteApplicationMember`
(`internal/authcore/remote_application_memberships.go:67-88`) has ZERO references module-wide incl.
tests. Its `AddRemoteApplicationMember` sibling IS live (bootstrap seeds the owner role,
`bootstrap_manifest.go:365`, + tests), but the remove counterpart was never wired to any caller,
route, or facade — the only remote-app membership mutation with no caller. Not re-exported.

- [ ] Delete `func (s *Service) RemoveRemoteApplicationMember` (`remote_application_memberships.go:67-88`).
- [ ] Keep `AddRemoteApplicationMember` (used by bootstrap seeding).
- [ ] `go build ./... && go vet ./...` green.

---

# #154: Delete no-op `Service.EnableTOTP2FA` wrapper

**Completed:** no

Parent #150 (Tier 1, internal-only).

RESEARCH (2026-06-26, verified): `Service.EnableTOTP2FA` (`internal/authcore/totp.go:61-64`) is a
one-line delegate — `return s.EnableTOTP2FADefault(ctx, userID, code, false)`. Its only caller
module-wide is `totp_test.go:59`; the real enrollment path (HTTP `/user/2fa`) calls
`EnableTOTP2FADefault` directly. Not re-exported via `embedded`/facade/`client.go`, so it reaches no
consumer — the `makeDefault=false` default it encodes is the test's only use of it.

**Idiomatic target:** intent at the call site — the lone test passes the explicit `false` to `EnableTOTP2FADefault`, rather than a default-bearing convenience wrapper hiding it.

- [ ] Delete `func (s *Service) EnableTOTP2FA` (`totp.go:61-64`).
- [ ] Repoint `totp_test.go:59` → `EnableTOTP2FADefault(ctx, user.ID, code, false)`.
- [ ] `go build ./... && go vet ./...` + `go test ./internal/authcore/` green.

---

# #155: Delete dead exported `http.AllowNamed` (BREAKING)

**Completed:** no

Parent #150 — RE-TIERED to Tier 4 (BREAKING) on revalidation; the parent's Tier-1 placement was
wrong (this symbol is exported + SEMVER-covered, not internal-only).

RESEARCH (2026-06-26, verified): the package-level `func AllowNamed(r *http.Request, rl RateLimiter,
bucket string) bool` (`http/ratelimit.go:30-43`) has ZERO in-repo callers — all rate-limiting runs
through `Service.rateLimited`→`allowResult`, which call the 2-arg INTERFACE method
`RateLimiter.AllowNamed(bucket, key)` (`service.go:147,194`), a different signature that STAYS. BUT
`AllowNamed` is EXPORTED and a covered public symbol in SEMVER §4.5 (`SEMVER.md:334`), so removal is
BREAKING — an external consumer could call it. (`clientIP` at `ratelimit.go:45` is its only caller
besides handlers; that helper's own collapse is #162.)

**Idiomatic target:** minimal exported surface — a package-level exported helper with no caller is API debt; the `RateLimiter` interface + its method are the real contract.

- [ ] Delete the package-level `AllowNamed` helper (`http/ratelimit.go:30-43`); keep the `RateLimiter` interface + its 2-arg `AllowNamed` method.
- [ ] Remove `AllowNamed` from SEMVER §4.5 (`SEMVER.md:334`); MAJOR bump — ride the #143–#149 consumer bump.
- [ ] `go build ./... && go vet ./...` green.

---

# #156: Delete `http.validateUsername` + `validate.go`

**Completed:** no

Parent #150 (Tier 1, internal-only).

RESEARCH (2026-06-26, verified): `http/validate.go` is a 3-line file whose only content is the
unexported `validateUsername(u) → embedded.ValidateUsername(u)` passthrough. Its sole caller is
`http/validate_test.go:19` (`TestValidateUsername_DoesNotHardcodeReservedList`); no production http
code calls it (registration uses `s.svc.ValidateUsernameForRegistration`). The test is a worthwhile
regression guard — it asserts username SYNTAX validation does NOT reject reserved names
(`admin`/`root`/`sudo`/`superuser`), which is reserved-account policy, not syntax — but it belongs at
the layer that owns `ValidateUsername`, not in `authhttp`.

- [ ] Delete `http/validate.go` (the unexported passthrough).
- [ ] RELOCATE the reserved-names-pass-syntax guard to the `ValidateUsername` owner (authcore `identity_validation_test.go`/`username_test.go`), calling `authkit.ValidateUsername` directly — do NOT drop the coverage.
- [ ] Delete `http/validate_test.go` once the assertion has moved.
- [ ] `go build ./... && go test ./...` green.

---

# #157: Drop write-only `Server.oidcProviders`/`providers` fields

**Completed:** no

Parent #150 (Tier 1, internal-only).

RESEARCH (2026-06-26, verified): in `NewServer`, `server.go:95` builds the LIVE lookup map
`s.authProvidersByName` (read in production at `provider_descriptors.go:38-50`), then `server.go:96-97`
ALSO stash the raw config maps into `s.oidcProviders`/`s.providers` (`http/service.go:29-30`).
Production never reads those two — the only readers are tests (`handlers_test.go:206`,
`oauth2_browser_test.go:220`) that rebuild `authProvidersByName` from them via `buildAuthProvidersMap`.
`oidc_return_to_integration_test.go:59` already shows the better pattern: set `authProvidersByName`
directly. Both fields are unexported → internal-only, safe.

**Idiomatic target:** no write-only state — derive the lookup once and hold only that; don't also stash the raw config the live map was built from.

- [ ] Delete fields `oidcProviders`/`providers` (`http/service.go:29-30`) and their assignments (`server.go:96-97`).
- [ ] Repoint the rebuild-from-raw-maps tests (`handlers_test.go:184-206,245-249`, `oauth2_browser_test.go:216-220`) to build `authProvidersByName` directly (small helper over `buildAuthProvidersMap`, mirroring `oidc_return_to_integration_test.go:59`).
- [ ] COORDINATE #143: falls out of the provider-config reshape (`Identity.Providers` map→slice + drop `ProviderDescriptors`) that feeds these fields — but the field removal is independently non-breaking.
- [ ] `go build ./... && go test ./http/` green.

---

# #158: Simplify `jwt.mergePublicKeys` → `clonePublicKeyMap`

**Completed:** no

Parent #150 (Tier 1, internal-only).

RESEARCH (2026-06-26, verified): `mergePublicKeys` (`jwt/pem.go:122-134`) is called exactly once,
with `extra=nil` (`jwt/keyring.go:19`); the `range extra` loop is then a no-op, so the merge half is
dead. NUANCE (not a byte-for-byte swap): when `base==nil`, `mergePublicKeys` returns an EMPTY non-nil
map (its `if out == nil { out = make(...) }` branch), whereas `clonePublicKeyMap(nil)` returns nil
(`pem.go:112-114`). So `NewKeyRing.pubs` is currently always non-nil; a naive swap would make it nil
when `verificationKeys==nil` and the active signer isn't a `PublicKeySigner`. Functionally this only
surfaces as `PublicKeys()` returning nil vs `{}` (ranging/lookup are equivalent), but preserve it.

- [ ] In `NewKeyRing` (`keyring.go:19`) replace `mergePublicKeys(verificationKeys, nil)` with `clonePublicKeyMap(verificationKeys)`, then normalize `if pubs == nil { pubs = map[string]crypto.PublicKey{} }` to keep `pubs` always non-nil (the existing `if pubs == nil` guard at `:23` already covers the PublicKeySigner branch).
- [ ] Delete `mergePublicKeys` (`pem.go:122-134`).
- [ ] `go build ./... && go test ./jwt/` green.

---

# #159: Inline + delete `authcore.normalizeEmail`

**Completed:** no

Parent #150 (Tier 2, internal-only).

RESEARCH (2026-06-26, verified): `normalizeEmail` (`internal/authcore/ephemeral.go:52-54`) is a bare
passthrough to the canonical `NormalizeEmail`. Exactly 2 callers — `service.go:1812`,
`pending_change.go:62`; the rest of the package calls `NormalizeEmail` directly, and there is no
lowercase `normalizePhone` twin, so the wrapper is gratuitous + inconsistent. Unexported → safe.

**Idiomatic target:** one canonical normalizer — call `NormalizeEmail` everywhere, no shadow lowercase alias.

- [ ] Replace the 2 calls (`service.go:1812`, `pending_change.go:62`) with `NormalizeEmail`.
- [ ] Delete `normalizeEmail` (`ephemeral.go:52-54`).
- [ ] `go build ./... && go vet ./...` green.

---

# #160: Replace ephemeral JSON-marshal indirection with stdlib

**Completed:** no

Parent #150 (Tier 2, internal-only).

RESEARCH (2026-06-26, verified): `marshalJSON`/`unmarshalJSON` (`ephemeral.go:118-136`) type-assert
the value to a LOCAL `jsonMarshaler`/`jsonUnmarshaler` interface (identical signatures to
`json.Marshaler`/`json.Unmarshaler`) and otherwise fall through to `jsonMarshal`/`jsonUnmarshal` —
one-line aliases of `json.Marshal`/`json.Unmarshal` (`:138-139`). `encoding/json` ALREADY honors
those interfaces natively, so the assert path is functionally identical to the fallback; and grep
confirms NO `internal/authcore` type defines `MarshalJSON`/`UnmarshalJSON`, so it never even fires.
Pure redundant indirection. Callers are only the 3 ephem helpers (`:60,:75,:108`); `json` is already
imported.

**Idiomatic target:** let the stdlib do its job — `json.Marshal`/`json.Unmarshal` already honour `Marshaler`/`Unmarshaler`; call them directly instead of re-implementing the dispatch.

- [ ] In `ephemSetJSON` use `json.Marshal(value)` (`:60`); in `ephemGetJSON`/`ephemConsumeJSON` use `json.Unmarshal(b, out)` (`:75,:108`).
- [ ] Delete `marshalJSON`, `unmarshalJSON`, `jsonMarshal`, `jsonUnmarshal` + the two inline interface types (`ephemeral.go:118-139`).
- [ ] `go build ./... && go test ./internal/authcore/` green.

---

# #161: Delete `http.sanitizeStepUpReturnTo`

**Completed:** no

Parent #150 (Tier 2, internal-only).

RESEARCH (2026-06-26, verified): `sanitizeStepUpReturnTo` (`http/step_up.go:456-458`) is a verbatim
no-op alias — `return sanitizeReturnTo(value)`. Exactly 2 callers: `oauth2_browser.go:75`,
`step_up.go:191`. The underlying `sanitizeReturnTo` is used in 5+ live sites (`link_landing.go:34`,
`oidc_browser.go:64,314`, `oauth2_browser.go:43`, `step_up.go:461`) and stays. Both unexported → safe.

**Idiomatic target:** no no-op alias — call `sanitizeReturnTo` directly; a same-signature pass-through earns its keep only when it adds behaviour.

- [ ] Repoint `oauth2_browser.go:75` and `step_up.go:191` to `sanitizeReturnTo`.
- [ ] Delete `sanitizeStepUpReturnTo` (`step_up.go:456-458`).
- [ ] `go build ./... && go vet ./...` green.

---

# #162: Collapse `http.clientIP` → `remoteIP`

**Completed:** no

Parent #150 (Tier 2, internal-only).

RESEARCH (2026-06-26, verified): `clientIP` (`http/ratelimit.go:45-55`) and `remoteIP`
(`http/client_ip.go:111-124`) are functionally identical `SplitHostPort(RemoteAddr)` extractors
(`remoteIP` only adds an explicit empty-RemoteAddr early-return, same result). `remoteIP` is the
lower-level peer extractor the `ClientIPFromForwardedHeaders`/`DefaultClientIP` plumbing builds on
(`client_ip.go:23,33,52`); `clientIP` is a near-duplicate called directly by 11 handlers for
audit/log IP (`audit.go:10`, `email_verify.go:194,200`, `password_reset.go:40`, `passkeys.go:103`,
`oidc_browser.go:234`, `oauth2_browser.go:263`, `user_2fa_verify_post.go:82`,
`phone_password_reset.go:39`, `auth_token_post.go:25`, `password_login_post.go:354`) plus the dead
`AllowNamed` (`ratelimit.go:36`, removed by #155). Both unexported → safe; behavior-preserving.

**Idiomatic target:** one IP-extraction helper — `remoteIP` is the lower-level primitive the rest of the IP plumbing builds on; handlers should call it, not a byte-identical twin.

- [ ] Delete `clientIP` (`ratelimit.go:45-55`); repoint the 11 handler callers to `remoteIP`. (The `ratelimit.go:36` caller disappears with #155; sequence after/with it.)
- [ ] `go build ./... && go vet ./...` green.

SEPARATE (behaviour, NOT this dedup — flagged, do not bundle): audit/log IP uses the raw peer
(`remoteIP`), while rate-limit keys use the trusted-proxy-aware `s.clientIP` (`service.go:161`).
Behind a trusted proxy, audit logs the proxy's IP, not the real client. Unifying them changes logged
values, so it needs a deliberate decision — out of scope for this removal.

---

# #163: Reuse `obfuscateVerificationID` in password-login

**Completed:** no

Parent #150 (Tier 2, internal-only).

RESEARCH (2026-06-26, verified): `password_login_post.go:322-325` inlines verification-ID masking
that is BEHAVIOURALLY IDENTICAL to the existing helper `obfuscateVerificationID`
(`step_up.go:437-442`) — both mask all but the last 5 chars and both guard `len > 5` (CORRECTION to
the original finding: the inline does NOT miss the guard; it has it at `:323`). Same package
(`authhttp`), so a direct call works. Pure behaviour-preserving dedup.

**Idiomatic target:** reuse the existing `obfuscateVerificationID` helper instead of a copy-pasted inline of its logic.

- [ ] Replace the 4-line inline block (`password_login_post.go:322-325`) with `obfuscatedID := obfuscateVerificationID(verificationID)`.
- [ ] `go build ./... && go vet ./...` green.

---

# #164: Reuse `parseIP` in email-verify

**Completed:** no

Parent #150 (Tier 2, internal-only, minor).

RESEARCH (2026-06-26, verified): `email_verify.go:194` uses `net.ParseIP(clientIP(r))`; the house
helper `parseIP` (`util.go:42-51`) does `SplitHostPort`-then-`ParseIP`, and `auth_token_post.go:25`
uses the consistent `parseIP(clientIP(r))`. CORRECTION to the original framing: this is a CONSISTENCY
change, not a correctness fix — `clientIP` already returns a bare host (port stripped), so the current
call is already correct. The win is matching the house helper and dropping the import (`net.` is used
ONLY at line 194; imported at `:6`). Coordinate with #162 (inner `clientIP`→`remoteIP`).

**Idiomatic target:** use the house `parseIP` helper consistently (as `auth_token_post.go` does), keeping IP parsing in one place rather than scattering raw `net.ParseIP` calls.

- [ ] Replace `net.ParseIP(clientIP(r))` with `parseIP(clientIP(r))` (`email_verify.go:194`); after #162 this reads `parseIP(remoteIP(r))`.
- [ ] Drop the now-unused `net` import (`email_verify.go:6`).
- [ ] `go build ./... && go vet ./...` green.

---

# #165: Dedupe `oidc.mergeScopes` ≡ `http.mergeStringSets`

**Completed:** no

Parent #150 (Tier 2) — SUBSUMED BY #186 on revalidation; no independent work.

RESEARCH (2026-06-26, verified): the two are identical order-preserving string-set unions, but they
do NOT coexist after #186. `oidc.mergeScopes` (`oidc/defaults.go:141`) is called ONLY from
`applyMinimalConfig` (`oidc/defaults.go:99`) — inside the dead `oidc/defaults.go` builder cluster
that #186 deletes (+ one test). `http.mergeStringSets` (`provider_descriptors.go:142`) is called from
the LIVE `applyRPConfigToProvider` (`:138`) and stays. Deleting the cluster (#186) removes
`mergeScopes`, leaving `mergeStringSets` as the sole impl — no second copy left to merge. (They also
live in different packages — `oidckit` vs `authhttp` — so there is no shared unexported home anyway.)

- [ ] No separate change. When #186 lands, confirm `mergeScopes` is gone and `mergeStringSets` is the surviving impl, then close this.

---

# #166: Share `cloneStringMap` (oidc/authprovider)

**Completed:** no

Parent #150 (Tier 2) — SUBSUMED BY #186 on revalidation; no independent work.

RESEARCH (2026-06-26, verified): the two `cloneStringMap` bodies are byte-identical, but the oidc
copy (`oidc/defaults.go:121`) is called ONLY at `defaults.go:75` inside `RPClientFromProvider` — part
of the dead cluster #186 deletes. The `authprovider` copy (`provider.go:366`) is called from the LIVE
public `Clone` (`provider.go:128`) and stays. So #186 removes the duplicate; the survivor is
package-private to `authprovider`. Different packages → no shared home needed.

- [ ] No separate change. Closes when #186 lands (the oidc copy goes with the cluster).

---

# #167: Collapse `passwordResetData`/`passwordResetSessionData` [low value — likely leave]

**Completed:** no

Parent #150 (Tier 2, internal-only, low).

RESEARCH (2026-06-26, verified): `passwordResetData` and `passwordResetSessionData`
(`ephemeral_data.go:54-60`) are byte-identical `struct{ UserID string }`, distinguished by their KEY
PREFIX in the store/consume helpers (`keyPasswordReset` vs `keyPasswordResetSession`), not the struct.
Collapsing to one `userIDData` saves ~3 trivial lines but erases the intent the two names carry
(reset-token record vs reset-session record). Per the no-over-engineering rule this is borderline
padding.

- [ ] RECOMMEND leave as-is (distinct names document distinct ephemeral records). Collapse to one `userIDData` only if already editing this file for another reason — not worth a standalone change.

---

# #168: Extract shared twilio helper (contextLanguage/appLabel/httpClient)

**Completed:** no

Parent #150 (Tier 2, internal-only; advanced "Provided" adapter, low priority).

RESEARCH (2026-06-26, verified): `adapters/twilio/email` and `adapters/twilio/sms` are SEPARATE
packages (both named `twilio`, different import paths). `contextLanguage(ctx)` is byte-identical
(`email/twilio.go:162-180` ≡ `sms/twilio.go:136-154`). `appLabel()` is identical logic but a METHOD on
each package's own `*Sender` (`email:259-264`, `sms:129-134`). `httpClient()` is the same shape
(`email:~98`, `sms:94-99`) — VERIFY the default `Timeout` matches before sharing (sms defaults to 10s).
Sharing requires a new shared internal package; the methods become free functions over the field value.

- [ ] Add a shared internal pkg (e.g. `adapters/twilio/internal/common`): `ContextLanguage(ctx) string`, `AppLabel(name string) string`, default-`*http.Client` constructor.
- [ ] Repoint email + sms; keep `appLabel`/`httpClient` as 1-line methods delegating to it (preserve each Sender's field access + its default timeout).
- [ ] `go build ./... && go test ./adapters/twilio/...` green.

---

# #169: Extract `adapters/internal/routepath` (gin/chi)

**Completed:** no

Parent #150 (Tier 2, internal-only; advanced "Provided" adapter, low priority).

RESEARCH (2026-06-26, verified): `routeParamNames`, `cleanMountPath`, `joinRoutePath` are
byte-identical across `adapters/gin/gin.go:99-128` and `adapters/chi/chi.go:84-113`, pure string ops
with NO router dependency, and all three are LIVE in both (gin `:78,:54,:119,:57`; chi
`:74,:54,:65,:104,:75`). The router-specific glue (gin `SetPathValue`, chi `URLParam`) stays per
adapter; only these three move.

- [ ] Add `adapters/internal/routepath` exporting `ParamNames`/`Clean`/`Join`.
- [ ] Repoint gin + chi to it; delete the duplicated copies.
- [ ] `go build ./... && go test ./adapters/...` green.

---

# #170: Inline twilio sms alias `g` [trivial]

**Completed:** no

Parent #150 (Tier 2, internal-only, trivial).

RESEARCH (2026-06-26, verified): `sms/twilio.go:224` assigns `g := strings.TrimSpace(s.AccountSID)`
solely to feed `req.SetBasicAuth(g, …)` on the next line — a poorly-named single-use local
(`strings.TrimSpace(s.AccountSID)` is already computed inline at `:214`; the email adapter inlines its
equivalent). Pure readability.

- [ ] Inline to `req.SetBasicAuth(strings.TrimSpace(s.AccountSID), strings.TrimSpace(s.AuthToken))` (`sms/twilio.go:224-225`); delete `g`.

---

# #171: Move ratelimit `get`/`remaining` to shared pkg

**Completed:** no

Parent #150 (Tier 2, internal-only; advanced "Provided" pkg, low priority).

RESEARCH (2026-06-26, verified): both helpers are byte-identical across backends. `remaining(limit,
used int) int` (`memory/limiter.go:224-230` ≡ `redis/limiter.go:133-139`) is a pure int helper with NO
type dependency — movable now. `get(bucket) (Limit, bool)` (`memory:48-56` ≡ `redis:33-41`, incl. the
hardcoded `Limit{Limit:100, Window:time.Minute}` fallback) returns the PACKAGE-LOCAL `Limit` type, so
it can only move once `Limit` is hoisted to the shared `ratelimit` pkg — DEPENDS ON #188. The
sliding-window storage itself (in-mem slice vs Redis ZSET) genuinely differs and stays per-backend.

- [ ] Move `remaining` to the shared `ratelimit` pkg as `Remaining(limit, used int) int`; repoint both backends.
- [ ] AFTER #188 (shared `ratelimit.Limit`): move `get` as `LookupLimit(limits, bucket) (ratelimit.Limit, bool)`; repoint both; delete the per-backend copies.
- [ ] `go build ./... && go test ./ratelimit/...` green.

---

# #172: Collapse devserver bootstrap-manifest wrappers [low value]

**Completed:** no

Parent #150 (Tier 2, internal-only; devserver is OUT OF CONTRACT per SEMVER §9).

RESEARCH (2026-06-26, verified): `applyBootstrapManifest` (path-based — load file then apply,
`main.go:249-259`, sole caller runServe `:151`) and `applyBootstrapManifestData` (manifest-based —
apply with a different error wrap, `:261-267`, sole caller runBootstrapApply `:223`). Not true
duplicates — a path-variant and a data-variant of the same op, each used once, sharing only the
`svc.ApplyBootstrapManifest(...)` call. Low-value collapse. (The same builder also touches
`toPermissionDefs`/`RBACConfig{Permissions}` at `:245`, already tracked for removal by #145 — this
file churns there anyway.)

- [ ] Keep ONE manifest-based helper (the current `…Data`); have runServe (`:151`) call `embedded.LoadBootstrapManifestFile` then it. Delete the path-based wrapper.
- [ ] `go build ./...` green. Low priority — fold in when touching the devserver for #145.

---

# #173: Share `writeJSON` + env helpers across cmds/server [low value — likely leave]

**Completed:** no

Parent #150 (Tier 2, internal-only; cmd mains are OUT OF CONTRACT per SEMVER §9).

RESEARCH (2026-06-26, verified): `writeJSON` is byte-identical in three places — `server/management.go:112`
(3 uses), `cmd/authkit-server/main.go:170` (2 uses), `cmd/authkit-devserver/main.go:444` (10 uses) —
plus duplicated env helpers (`envOr`/`firstEnv`/CSV-split) between the two cmd `main` packages. But the
two cmds are SEPARATE `main` packages (no shared unexported helper possible), so deduping means either
exporting `server.WriteJSON` (a public symbol for a 4-line helper) and/or a new shared internal pkg for
the env helpers (a whole package for two binaries) — both cost more than the ~12 saved lines.

- [ ] RECOMMEND leave as-is (no-over-engineering rule). At most, if the `server` pkg independently wants it, export `server.WriteJSON` and have the two cmds reuse it — but do NOT add a shared internal pkg just for `envOr`.

---

# #174: Add `jwt.SignWithType`; collapse the HeaderSigner typ-stamp idiom (HIGHEST-VALUE)

**Completed:** no

Parent #150 (Tier 3, internal-only; adds one additive exported `jwtkit` symbol — MINOR, non-breaking).

RESEARCH (2026-06-26, verified): the `signer.(jwtkit.HeaderSigner)` + `SignWithHeaders(…, {"typ":…})`
idiom is hand-rolled at 5 authcore sites in THREE distinct shapes:
- REQUIRE header (error if not a `HeaderSigner`), always stamp typ: `service.go:735-739` (access,
  `AccessTokenType`), `remote_application_token.go:98-101` (`RemoteApplicationAccessTokenType`),
  `delegated.go:131-134` (`DelegatedAccessTokenType`).
- FALL BACK to plain `signer.Sign` if not a `HeaderSigner`, always stamp typ: `service_jwt.go:106-110`
  (`ServiceJWTType`).
- CONDITIONAL: stamp typ ONLY when `opts.Type != ""` (then require header), else plain `Sign`:
  `custom_jwt.go:176-182`.
Plus the same idiom in `authtest/issuer.go:90` and `cmd/authkit-devserver/main.go:426`.

DESIGN: one helper covers all three — `jwt.SignWithType(ctx, signer Signer, claims, typ string,
requireHeader bool) (string, error)`: `typ==""` → plain `Sign`; `typ!="" && requireHeader` → assert
`HeaderSigner`, error if not, `SignWithHeaders`; `typ!="" && !requireHeader` → `HeaderSigner` if
available else `Sign`. Mapping: A-sites `(typ=<const>, requireHeader=true)`; service_jwt
`(ServiceJWTType, false)`; custom_jwt `(opts.Type, true)` — its empty-typ branch reproduces today's
"plain Sign when no type" path.

**Idiomatic target:** the helper accepts the `Signer` interface and performs the `HeaderSigner` type-assertion in ONE place — replacing five hand-rolled assert-or-fail copies with a single tested seam.

- [ ] Add `SignWithType` to `jwt` (jwtkit) with the semantics above + a unit test per branch.
- [ ] Repoint `service.go:735` (keep its `(tok, expiresAt, err)` wrapping), `remote_application_token.go:98`, `delegated.go:131` with `requireHeader=true`.
- [ ] Repoint `service_jwt.go:106` with `requireHeader=false`.
- [ ] Repoint `custom_jwt.go:176` passing `opts.Type` + `requireHeader=true` (empty type → plain Sign, preserving current behaviour).
- [ ] Repoint `authtest/issuer.go:90` and `cmd/authkit-devserver/main.go:426`.
- [ ] `go build ./... && go test ./...` green.

---

# #175: Extract shared `signWithHeaders` across signer types

**Completed:** no

Parent #150 (Tier 3, internal-only to `jwtkit`; behaviour-preserving).

RESEARCH (2026-06-26, verified): `SignWithHeaders` is byte-identical across `RSASigner`
(`jwt/jwt.go:82-92`), `ECDSASigner` (`signers_ec.go:68-78`), `Ed25519Signer` (`signers_ed.go:38-48`) —
same `NewWithClaims` → header-merge loop (skip `kid`/`alg`) → set `kid` → `SignedString(key)` —
differing ONLY by signing method (RSA `SigningMethodRS256`, Ed25519 `SigningMethodEdDSA`, ECDSA
`s.signingMethod()`). The plain `Sign` (NewWithClaims + kid + SignedString) is triplicated the same
way. `SignedString` takes `any`, so one free function serves all three.

**Idiomatic target:** DRY across the signer method-set — one shared helper with the concrete signing method + key passed in, instead of the same body copied per key type.

- [ ] Add unexported `signWithHeaders(method jwt.SigningMethod, key any, kid string, claims jwt.MapClaims, headers map[string]any) (string, error)` in `jwt`.
- [ ] Rewrite each signer's `Sign`/`SignWithHeaders` as 1-liners over it (RSA/Ed25519 pass their const method; ECDSA passes `s.signingMethod()`; `Sign` passes `headers=nil`).
- [ ] `go build ./... && go test ./jwt/` green.

---

# #176: Extract `resolveBrowserUser` + `finishBrowserLogin` (OIDC/OAuth)

**Completed:** no

Parent #150 (Tier 3) — PARTLY behaviour-affecting on revalidation; NOT a blind extract.

RESEARCH (2026-06-26, verified): the OIDC callback (`oidc_browser.go:143-206`) and OAuth2's factored
`resolveOAuthUser` (`oauth2_browser.go:374-445`) share the SAME five-branch shape (explicit-link +
already-linked conflict; existing (issuer,sub) link; C-2 email-conflict refusal; public-registration
gate; create+link+verify+username). The token/redirect TAILS (`oidc_browser.go:208-282` ≈
`oauth2_browser.go:236-310`) are near-identical (IssueRefreshSessionWithAuthMethods + 2FA/banned
handling → IssueAccessToken → LogSessionCreated → popup HTML / JSON / fragment redirect).

BUT they have DIVERGED — merging is NOT purely behaviour-preserving:
- LINK-WRITE FAILURE: `resolveOAuthUser` treats `LinkProviderByIssuer` as load-bearing and FAILS the
  callback on error (`oauth2_browser.go:384-387,430-433`); the OIDC inline SWALLOWS it
  (`_ = s.svc.LinkProviderByIssuer(...)`, `oidc_browser.go:149,201`). OAuth2's is the safer/newer shape;
  unifying onto it CHANGES OIDC behaviour (link failures begin failing the callback).
- OIDC has a `provider != "discord"` carve-out on email_verified (`:198`) and back-fills `email` from
  the stored provider email (`:155-157`); OAuth2 has neither.
- ERROR STYLE: `resolveOAuthUser` RETURNS sentinels (caller maps to HTTP); OIDC WRITES responses inline.
- INPUT TYPE: OIDC `oidckit.Claims` (pointer fields) vs OAuth2 `oauth2UserInfo` (value fields).

**Idiomatic target:** the shared resolver RETURNS sentinel errors and the handler maps them to HTTP (the OAuth2 shape) — a resolver should not write HTTP responses; the handler owns the transport.

- [ ] Extract `finishBrowserLogin(...)` for the token/redirect tail FIRST — mechanical, behaviour-preserving; reconcile small diffs (OIDC passes `nil` IP to `IssueRefreshSession` at `:209` but `clientIP(r)` to `LogSessionCreated`).
- [ ] `resolveBrowserUser`: DECIDE the canonical behaviour (recommend OAuth2's fail-closed link handling) — a deliberate behaviour change for OIDC; coordinate with the error-handling-correctness track, not this dedup alone. Preserve OIDC-specific bits (discord email_verified carve-out, provider-email backfill); adapt `claims`-vs-`info` via a small normalizer.
- [ ] `go build ./... && go test ./http/` green; add a test pinning OIDC link-write-failure → callback fails.

---

# #177: Share the step-up completion TAIL (not the whole function)

**Completed:** no

Parent #150 (Tier 3, internal-only; behaviour-preserving).

RESEARCH (2026-06-26, verified): `completeOAuthStepUp` (`oauth2_browser.go:346-372`) and
`completeOIDCStepUp` (`step_up.go:213-243`) are NOT the same body — they share the empty-StepUpUserID
guard + `GetProviderLinkByIssuer` match, but DIFFER: OIDC adds a `validOIDCStepUpTime(...)` auth-time
freshness check (`:222-225`) and marks via `MarkSessionAuthenticated` (no methods); OAuth2 has no
auth-time check and marks via `MarkSessionAuthenticatedWithMethods(..., {"oauth"})`. The genuinely
VERBATIM duplicate is the POST-mark TAIL — `freshAccessTokenResponse` → `body["provider"]=…` → JSON
or `redirectStepUpResult(...,"success")` (OIDC `:230-242` ≡ OAuth2 `:359-371`, differing only in the
provider-string source).

- [ ] Extract the shared tail, e.g. `emitStepUpResult(w, r, sd, providerName string) bool` (the JSON/redirect success path).
- [ ] Keep both functions' distinct front halves (OIDC's auth-time check + plain Mark; OAuth2's Mark-with-methods); call the shared tail from each.
- [ ] `go build ./... && go test ./http/` green.

---

# #178: Extract `decodeSIWSOutput` (SIWS login/link share the decode block)

**Completed:** no

Parent #150 (Tier 3, internal-only; behaviour-preserving).

RESEARCH (2026-06-26, verified): `handleSolanaLoginPOST` (`solana_siws.go:95-191`) and
`handleSolanaLinkPOST` (`:193-276`) share a ~33-line VERBATIM block — the anonymous
`Output{Account{Address,PublicKey},Signature,SignedMessage}` request struct + `decodeJSON`, the
Std→RawURL base64 fallback decode of signature/signedMessage/publicKey, and building
`siws.SignInOutput` (login `:100-147` ≡ link `:204-251`). The "try Std, fall back to RawURL" decode is
itself repeated 3× inside each handler. The error switches DIFFER and stay per-handler: login
(`:159-172`) maps banned/registration-disabled/timestamp + default `unauthorized`; link (`:254-267`)
maps `ErrWalletAlreadyLinked` + default `serverErr` — only 4 arms in common (challenge-not-found/
expired, signature-invalid, address-mismatch, domain-invalid).

- [ ] Add a local `decodeB64(s string) ([]byte, error)` (Std then RawURL); use it for the 3 repeats.
- [ ] Extract `decodeSIWSOutput(r) (siws.SignInOutput, ErrorCode, bool)` (struct + decodeJSON + the 3 decodes); both handlers call it.
- [ ] Leave the two error switches per-handler (different cases + defaults). Optionally factor only the 4 shared arms — not required.
- [ ] `go build ./... && go test ./http/` green.

---

# #179: Parameterize verify/confirm/password-reset handler twins

**Completed:** no

Parent #150 (Tier 3, internal-only; mostly behaviour-preserving — one asymmetry fix flagged).
COORDINATE with #146 Account-group rework (this is the body-sharing angle, not the route reshape).

RESEARCH (2026-06-26, verified) — three email/phone handler pairs that are channel-parameterizable:

(a) CONFIRM-LINK twins (cleanest; both unexported): `confirmEmailVerificationToken` +
`handleEmailVerifyLinkFailure` (`email_verify_confirm_link_post.go`) ≡ the phone versions
(`phone_verify_confirm_link_post.go`) — identical control flow (3 confirm-by-token tries in order →
issue tokens / "changed" message; failure tree target→validate→normalize→GetUserBy→verified?409:410→
pending?400:410), differing only by validator/normalizer/engine-methods/error-codes/verified-field.
ASYMMETRY (latent bug the merge fixes): email maps `ErrUserBanned`→401 in both issue-token branches
(`:16-19,:27-30`); phone does NOT — a banned user confirming a PHONE token gets 500 (`serverErr`),
not 401. Unifying normalizes this (behaviour change for phone: 500→401, an improvement — flag it).

(b) VERIFY-REQUEST twins: `handleEmailVerifyRequestPOST` (`email_verify.go`) ≡
`handlePhoneVerifyRequestPOST` (`phone_verify.go`) — same skeleton incl. the change-flow error switch.
NOTE: those switches match `err.Error()` SUBSTRINGS ("same as current"/"already in use") — fragile;
that belongs with the error-sentinel work in plans 008/009/011, not this dedup.

(c) PASSWORD-RESET confirm: `handleEmailPasswordResetConfirmPOST` ≡ `handlePhonePasswordResetConfirmPOST`
both call the SAME `ConfirmPasswordReset` (`password_reset.go`/`phone_password_reset.go`), differing
only in success payload. Request halves differ (email anti-enumeration silent, phone explicit errors)
→ keep request halves separate.

- [ ] (a) Parameterize the confirm-link twins by a channel descriptor (validator, normalizer, the 3 confirm-by-token fns, GetUserBy*, verified-field, error codes); decide the unified `ErrUserBanned`→401 handling (fixes the phone 500).
- [ ] (b) Share the verify-request change-flow switch; do NOT fix the substring matching here (→ plans 008/009/011).
- [ ] (c) Share the password-reset CONFIRM handler (one body, success payload as a param); leave the request halves separate.
- [ ] `go build ./... && go test ./http/` green; add a test pinning banned-user phone-confirm → 401.

---

# #180: Add `writeAccessTokenJSON`; migrate inline token envelopes

**Completed:** no

Parent #150 (Tier 3, internal-only; ONE additive wire change flagged).

RESEARCH (2026-06-26, verified): the OAuth-style token-pair envelope (`access_token`, `token_type`,
`expires_in`, `refresh_token`) is rebuilt inline ~7×: `passwordless.go:125` (+`return_to`),
`passkeys.go:105`, `solana_siws.go:180` (+`created`,`user`), `user_2fa_verify_post.go:102`,
`password_login_post.go:377,386`, `auth_token_post.go:40` — despite the existing `authTokensResponse`
struct (`email_verify.go:14`) + `createTokensForUser` returning it. Each recomputes
`int64(time.Until(exp).Seconds())` and the `"Bearer"` literal. NUANCE — NOT uniform:
`auth_token_post.go:40` (the `/token` refresh response) OMITS `token_type` and uses `int` (not
`int64`) for `expires_in`. SEMVER §6.3 specifies all four fields incl. `token_type:"Bearer"`, so a
shared helper would ADD `token_type` there — an additive response field (MINOR per §6.8) that brings
`/token` into contract conformance. Confirm intended.

**Idiomatic target:** a typed result for a known shape — marshal the `authTokensResponse` struct (via the writer) instead of hand-built `map[string]any` literals scattered across handlers.

- [ ] Add `writeAccessTokenJSON(w, status int, access, refresh string, exp time.Time, extra map[string]any)` emitting the 4 core fields + merged extras.
- [ ] Migrate the 7 sites; extras carry `return_to` (passwordless), `created`+`user` (solana), etc.
- [ ] CONFIRM the `auth_token_post.go` change (gains `token_type`) is acceptable — additive + contract-conforming; note in SEMVER §6.3 if needed.
- [ ] `go build ./... && go test ./http/` green.

---

# #181: Add `firstTrimmedNonEmpty`; migrate identifier coalesces

**Completed:** no

Parent #150 (Tier 3, internal-only; behaviour-preserving).

RESEARCH (2026-06-26, verified): the "first non-empty after `TrimSpace`" coalesce is hand-written 4×,
each in its OWN field order — `email_verify.go:122` (Email→Identifier), `register.go:323`
(Identifier→Email), `passkeys.go:69` (Login→Email), `password_login_post.go:29` (Email→Login) — and
`passwordlessIdentifier(identifier, email, phone)` (`passwordless.go:137-145`) is the same logic over
3 args. A variadic `firstTrimmedNonEmpty(vals ...string) string` covers all (each caller passes its
fields in its own order); order preserved → behaviour-preserving.

**Idiomatic target:** one variadic `firstTrimmedNonEmpty(...string)` instead of repeated two-line `if x=="" { x = … }` ladders.

- [ ] Add `firstTrimmedNonEmpty(vals ...string) string` (first non-empty after `TrimSpace`).
- [ ] Migrate the 4 inline coalesces; reduce `passwordlessIdentifier` to `firstTrimmedNonEmpty(identifier, email, phone)` (or replace its callers).
- [ ] `go build ./... && go test ./http/` green.

---

# #182: Consolidate role-grants resolution

**Completed:** no

Parent #150 (Tier 3, internal-only; behaviour-preserving).

RESEARCH (2026-06-26, verified): `roleGrantsForAuthz(sch, persona, gid, role, resolver)`
(`permission_group_assign_authz.go:101-111`) and `effectiveGroupRolePermissions(ctx, groupID,
persona, role)` (`api_keys.go:165-180`) share the same core lookup — catalog role
(`sch.Role(persona, role)`) → its perms, else custom role via a `CustomRoleResolver`. They DIFFER in:
(1) resolver SOURCE — the former takes a pre-built resolver (sync, no DB); the latter builds its own
via `groupStore().CustomRolesFor(ctx, …)` (needs ctx/DB); (2) UNKNOWN role — the former ERRORS
("not assignable"), the latter returns `[]string{}` (fail-closed); (3) COPY — the latter defensively
copies (`append(nil, …)`), the former returns the slice directly.

- [ ] Extract a shared inner `resolveRolePerms(sch, gid, persona, role string, resolver CustomRoleResolver) ([]string, bool)` (catalog-or-custom; copy defensively → also removes the former's no-copy aliasing, read-only so no observable change).
- [ ] Keep each caller's wrapper: `roleGrantsForAuthz` errors on `!found`; `effectiveGroupRolePermissions` builds the resolver (ctx/DB) then returns `[]string{}` on `!found`.
- [ ] `go build ./... && go test ./internal/authcore/` green.

---

# #183: Collapse http outbound HTTP clients

**Completed:** no

Parent #150 (Tier 3, internal-only; behaviour-preserving).

RESEARCH (2026-06-26, verified): `oauth2_http_client.go` defines `oauth2OutboundTimeout = 30s` +
`oauth2OutboundHTTPClient` (both UNEXPORTED), functionally identical to `default_outbound_client.go`'s
`defaultOutboundHTTPClient` (`DefaultOutboundTimeout = 30s`). The oauth2 client is used at
`oauth2_browser.go:326` + `oauth2_provider.go:74`; the default at `remote_application_client.go`. Same
30s-bounded `*http.Client` → one suffices.

- [ ] Repoint `oauth2_browser.go:326` + `oauth2_provider.go:74` to `defaultOutboundHTTPClient`; delete `oauth2_http_client.go`.
- [ ] `go build ./... && go vet ./...` green.

NOTE (cross-pkg, NOT this issue): the same 30s-client/`DefaultOutboundTimeout` also exists in
`oidc/http_client.go` and `verify/helpers.go`; `verify` is core-free (#110) and can't share with
`http`, so that triplication is partly by-design — leave it. This issue collapses only the
within-`http` duplicate.

---

# #184: Drop orphaned `SolanaConfig` type (BREAKING)

**Completed:** no

Parent #150 (Tier 4, BREAKING → rides #143's Solana cull).

RESEARCH (2026-06-26, verified): `authcore.SolanaConfig` (`config.go:137-151`; fields Network /
SNSEnabled / SNSResolver / SNSLookupTimeout / SNSCacheTTL) is re-exported as `embedded.SolanaConfig`
(`aliases.go:60`) but is STRUCTURALLY DEAD — grep shows only the type def + the alias; no `Config`
(or any struct) has a `SolanaConfig` field and none of its fields are read anywhere. The live Solana
config is the flat `Config.SolanaNetwork string` (`config.go:55`, read at `service.go:400`).
SEMVER §4.2 lists `SolanaConfig` as a covered config type while §7.3 lists the live `SolanaNetwork` —
so the type is covered-but-orphaned. Removal is BREAKING (public `embedded.SolanaConfig`) but inert
(no consumer can wire it to anything).

- [ ] Delete `authcore.SolanaConfig` (`config.go:137-151`) + the `embedded.SolanaConfig` alias (`aliases.go:60`).
- [ ] Remove `SolanaConfig` from the SEMVER §4.2 config-types list; MAJOR bump — ride the #143 consumer bump.
- [ ] `go build ./... && go vet ./...` green.

---

# #185: Collapse `ResolveAPIKey`/`MintAPIKey` pairs post-Resources-cull (BREAKING)

**Completed:** no

Parent #150 (Tier 4, BREAKING → rides #143's API-key `Resources` cull; untracked angle of #143).

RESEARCH (2026-06-26, verified): both pairs differ from their twins ONLY by the `Resources` axis #143
removes:
- RESOLVE: `ResolveAPIKey` (`api_keys.go:414-420`) literally calls `ResolveAPIKeyWithResources`
  (`:424`) and discards `.Resources`, returning `(PermissionGroupID, Permissions)`. Once `ResolvedAPIKey`
  loses `Resources`, the `WithResources` variant returns the same `(group, perms)` → redundant.
- MINT: `MintAPIKey` (`:187`) delegates to `MintAPIKeyWithOptions(APIKeyMintOptions{Name,Role,
  CreatedBy,ExpiresAt})`. `APIKeyMintOptions` (`contract.go:22-28`) is exactly {Name, Role, Resources,
  CreatedBy, ExpiresAt} — so removing `Resources` leaves precisely `MintAPIKey`'s 4 positional params →
  the options-struct variant adds nothing.
#143 removes the `Resources` field but does NOT note this resolver/mint convergence — that is this issue.

- [ ] After #143's `Resources` removal: keep ONE resolver (`ResolveAPIKey`); delete `ResolveAPIKeyWithResources` + the `ResolvedAPIKey` struct.
- [ ] Keep ONE mint entry; delete the now-redundant `MintAPIKeyWithOptions`/`APIKeyMintOptions` (or keep the options form and drop the positional — pick one per #143's final API-key shape).
- [ ] Update SEMVER §4.2 (facade `ResolveAPIKey[WithResources]`, `MintAPIKey`) + §4.2 domain type `ResolvedAPIKey`; MAJOR on the #143 train.
- [ ] `go build ./... && go test ./...` green.

---

# #186: Delete dead `oidc/defaults.go` builder cluster (BREAKING)

**Completed:** no

Parent #150 (Tier 4, BREAKING; relates to #143 but mostly independent).

RESEARCH (2026-06-26, verified): these `oidc` builders have ZERO callers outside `oidc/` and outside
oidc's own tests — `DefaultsFor` (`defaults.go:24`), `NewManagerFromMinimal` (`:37`),
`RPClientFromProvider` (`:64`), `applyMinimalConfig` (`:94`, unexported), `AppleWithKey`
(`apple.go:68`) — plus the helpers only they use (`mergeScopes` `:141`, `cloneStringMap` `:121`,
`ensureOpenID`, …). The LIVE provider→RP mapping is `http.applyRPConfigToProvider`
(`provider_descriptors.go:133`) + `oidckit.NewManagerFromProviders` (`oidc_link_start_post.go:12`).
CORRECTION (do NOT over-delete): `oidckit.RPConfig` is NOT dead — it is the live provider-config type
used by `config.go:158` (`Identity.Providers`), `http/service.go:29`, and `applyRPConfigToProvider`.
Its eventual removal is #143's `Providers map→[]authprovider.Provider` migration, NOT this issue.

- [ ] Delete `DefaultsFor`, `NewManagerFromMinimal`, `RPClientFromProvider`, `AppleWithKey`, and the now-orphaned unexported helpers (`applyMinimalConfig`, `mergeScopes` [closes #165], `cloneStringMap` [closes #166], `ensureOpenID`, …) — confirm each has no remaining non-test caller after the others go.
- [ ] KEEP `RPConfig` and the live `http.applyRPConfigToProvider` mapping; do NOT touch the map→slice migration (that's #143).
- [ ] Update the SEMVER §4.4 oidckit list (drop the deleted builders + `AppleWithKey`); MAJOR bump.
- [ ] Move/delete the oidc tests that exercised the deleted builders; `go build ./... && go test ./...` green.

---

# #187: Collapse `PermissionTokenCovers` → `PermMatches` (BREAKING)

**Completed:** no

Parent #150 (Tier 4, BREAKING).

RESEARCH (2026-06-26, verified): `PermissionTokenCovers` (`permission.go:50-54`) is
`return PermMatches(strings.TrimSpace(grant), strings.TrimSpace(requested))` — and `PermMatches`
(`permission.go:18-20`) ALREADY trims both args on entry, so the wrapper's only added work is a
redundant double-trim. Both exported, same package. In-repo callers: `verify/claims.go:230`,
`verify/verifier.go:269` — both can call `PermMatches` directly. SEMVER §4.3 (`SEMVER.md:274`) lists
`PermMatches`/`PermissionTokenCovers` under `authbase` (STALE — they now live in root `authkit`
`permission.go`); removal is BREAKING (an external resource server could import `PermissionTokenCovers`).

**Idiomatic target:** no redundant wrapper — `PermMatches` already trims and is the one matcher; a second name that only re-trims is noise.

- [ ] Repoint `verify/claims.go:230` + `verify/verifier.go:269` to `PermMatches`; delete `PermissionTokenCovers` (`permission.go:50-54`).
- [ ] Drop `PermissionTokenCovers` from SEMVER §4.3 (fix the stale `authbase`→root location while there); MAJOR bump — ride the #143–#149 train.
- [ ] `go build ./... && go test ./...` green.

---

# #188: Hoist one `ratelimit.Limit`; delete dup structs + converters (BREAKING)

**Completed:** no

Parent #150 (Tier 4, BREAKING; "Provided"/advanced pkgs, small blast radius — pairs with #143's
auto-owned limiter). Unblocks #171's `get` move.

RESEARCH (2026-06-26, verified): `Limit{Limit int; Window, Cooldown time.Duration}` is byte-identical
in THREE places — `memorylimiter` (`ratelimit/memory/limiter.go:13`), `redislimiter`
(`ratelimit/redis/limiter.go:13`), `authhttp` (`http/ratelimit_defaults.go:11`). `ToMemoryLimits`/
`ToRedisLimits` (`ratelimit_defaults.go:99-113`) exist ONLY to field-copy `authhttp.Limit` →
`memorylimiter.Limit`/`redislimiter.Limit`. The shared `ratelimit` pkg (`ratelimit/result.go`) has no
`Limit` yet — natural home next to `ratelimit.Result`. All three types + both converters are exported
(SEMVER §4.4 lists the backend `Limit`s; §4.5 lists `authhttp.Limit`/`ToMemoryLimits`/`ToRedisLimits`).

**Idiomatic target:** define the type ONCE in the shared `ratelimit` pkg and accept it across backends — eliminating the duplicate-and-convert (`ToMemoryLimits`/`ToRedisLimits`) dance.

- [ ] Add `ratelimit.Limit`; change both backends' `New(rdb, map[string]ratelimit.Limit)`; have `http` consume `ratelimit.Limit`.
- [ ] Delete `memorylimiter.Limit`, `redislimiter.Limit`, `authhttp.Limit`, `ToMemoryLimits`, `ToRedisLimits`.
- [ ] Update SEMVER §4.4 + §4.5; MAJOR bump.
- [ ] `go build ./... && go test ./ratelimit/... ./http/` green. (Then #171's `get` can move.)

---

# #189: Collapse limiter interface 3-tier → 2; drop `AllowNamedWithRetryAfter` (BREAKING)

**Completed:** no

Parent #150 (Tier 4, BREAKING; pairs with #143's auto-owned limiter — custom injection becomes
advanced/internal-only).

RESEARCH (2026-06-26, verified): `allowResultForKey`/`allowResult` (`http/service.go:119-149`,
`:171-194`) type-switch in order: `RateLimiterWithResult` (`:123`) → `RateLimiterWithRetryAfter`
(`:131`) → bare `RateLimiter.AllowNamed` (`:147`). Both built-in backends implement `AllowNamedResult`
(`memory/limiter.go:77`, `redis/limiter.go:54`), so the Result branch ALWAYS wins for AuthKit's own
limiters and the RetryAfter branch (`:131-146`) is UNREACHABLE for them — it exists only for a
hypothetical host limiter that implements `AllowNamedWithRetryAfter` but NOT `AllowNamedResult`. Each
backend also carries a vestigial `AllowNamedWithRetryAfter` wrapper (`memory:72`, `redis:49`) that just
drops fields from `AllowNamedResult`. The 3 limiter interfaces are exported (SEMVER §4.5); collapsing
drops a public extension point — BREAKING, justified by #143 (hosts shouldn't inject custom limiters
on the normal path).

**Idiomatic target:** small, *used* interfaces — keep `RateLimiter` + `RateLimiterWithResult`; drop the speculative third tier no built-in satisfies.

- [ ] Delete the `RateLimiterWithRetryAfter` interface (`http/ratelimit.go:26-28`) + the middle type-switch branch in `allowResultForKey`/`allowResult`.
- [ ] Delete `AllowNamedWithRetryAfter` from both backends (`memory/limiter.go:72`, `redis/limiter.go:49`).
- [ ] Keep `RateLimiter` + `RateLimiterWithResult`.
- [ ] Update SEMVER §4.5 (drop `RateLimiterWithRetryAfter`); MAJOR bump.
- [ ] `go build ./... && go test ./ratelimit/... ./http/` green.

---

# #190: Delete orphaned `Service.ApplyBootstrapManifestFile`

**Completed:** no

Parent #150 (listed under Tier 4, but actually NON-BREAKING on revalidation — can land with Tier 1).

RESEARCH (2026-06-26, verified): `Service.ApplyBootstrapManifestFile` (`bootstrap_manifest.go:78`) has
only ONE caller — its own test (`bootstrap_manifest_test.go:493,511`). It is NOT on the contract:
`client.go:164-165` explicitly documents "There is deliberately no ApplyBootstrapManifestFile on the
contract" (the #142 decision — a file path is the server's filesystem, meaningless for a remote
client), and it is NOT on the `embedded` facade (only `ApplyBootstrapManifest` is, `facade_methods.go:337`).
So although exported on the internal `Service`, it is unreachable by any consumer → effectively
internal-only, NON-BREAKING, already absent from SEMVER (no SEMVER edit). The load-then-apply
composition lives in the devserver (`LoadBootstrapManifestFile` + `ApplyBootstrapManifest`).

- [ ] Delete `ApplyBootstrapManifestFile` (`bootstrap_manifest.go:78`).
- [ ] Rewrite `TestApplyBootstrapManifestFileLoadsAndAppliesYAML` (`bootstrap_manifest_test.go:493`) to call `LoadBootstrapManifestFile` + `ApplyBootstrapManifest` (preserve the YAML-load coverage).
- [ ] `go build ./... && go test ./internal/authcore/` green. No SEMVER change / no bump — may land with Tier 1.

---

# #191: Remove dead exported helpers

**Completed:** no

Parent #150 (Tier 4, BREAKING — unused/test-only exported helpers, removed on merits). Each verified
by a repo-wide caller sweep (2026-06-26):

**Idiomatic target:** minimal exported surface — every exported symbol is a promise; convenience wrappers no consumer calls are API debt. Keep the one entry point each (`PublicToJWK`, `BuiltIn`, `LoadBootstrapManifestFile`, `remoteAppOptions`).

- [ ] `verify.RemoteAppOptions` (`verify/helpers.go:17`) — ZERO callers anywhere (the stated authhttp reuse never happened); the unexported `remoteAppOptions` is the real one. Remove the exported alias; keep `remoteAppOptions`. SEMVER §4.3 drops the "(+RemoteAppOptions)" note.
- [ ] `jwt.NewStaticKeySourceFromRing` (`jwt/keyring.go:39`) — ZERO callers. Remove. KEEP `KeyRing`/`NewKeyRing` (legit Advanced rotation primitive; `NewKeyRing` is test-only in-repo but public). Not individually named in SEMVER §4.4.
- [ ] `jwt.RSAPublicToJWK` (`jwt/jwks.go:40`) — ZERO callers; narrowing wrapper of `PublicToJWK`. Remove. Covered by the SEMVER §4.4 jwtkit "conversion funcs" set, not by name.
- [ ] `authprovider.BuiltIns()` (`authprovider/provider.go:117`) — ZERO callers; singular `BuiltIn(name)` is what's used. Drop `BuiltIns` from the SEMVER §4.4 authprovider list.
- [ ] `http.MintDelegatedAccessToken` + `http.DelegatedAccessParams` (`http/delegation.go:35,25`) — thin re-exports of `embedded.MintDelegatedAccessToken` / `authkit.DelegatedAccessParams`; NO production caller, but ~15 http TEST sites use them (`delegation_verify_test.go`, `service_jwt_test.go`, `jwks_resilience_test.go`). Migrate those tests to `embedded.MintDelegatedAccessToken(ctx, signer, p)` + `authkit.DelegatedAccessParams` (as `admin_directory_test.go:364` already does), THEN delete the http re-export + alias. CORE symbols stay (SEMVER §4.2); the http re-exports are NOT in SEMVER §4.5 → no §4.5 edit.
- [ ] `embedded.ParseBootstrapManifestYAML` ALIAS only (`embedded/aliases.go:166`) — the alias has no in-repo consumer; KEEP the underlying `authcore.ParseBootstrapManifestYAML` (used by `LoadBootstrapManifestFile:75` + 9 authcore tests). Drop only the embedded re-export; SEMVER §4.2 drops `ParseBootstrapManifestYAML` from the bootstrap-types list (`LoadBootstrapManifestFile` stays as the seam).
- [ ] `go build ./... && go test ./...` green; MAJOR bump — ride the #143–#149 train.

---

# #192: Demote/remove test-only exported Service methods

**Completed:** no

Parent #150 (listed under Tier 4, but both are NON-BREAKING — neither is re-exported to consumers).

RESEARCH (2026-06-26, verified):
- `Service.RemoteApplicationRoles` (`remote_application_memberships.go:90`) — only 2 callers, both
  tests (`remote_application_owner_test.go:43`, `bootstrap_manifest_test.go:325`); NOT on `client.go`
  or the facade. The real authority path is `ResolveRemoteApplicationAuthority` (on the contract, used
  by `verify`). Effectively internal-only → safe to delete or unexport.
- `Service.RemoveGroupSubject` (non-`As`, `permission_group_service.go:199`) — only caller is
  `permission_group_service_integration_test.go:179`; the runtime path is `RemoveGroupSubjectAs`
  (contract `client.go:94`, facade `:73`, used at `http/permission_group_operations.go:70`). NOT
  re-exported (facade exposes only `…As`). BUT it is DOCUMENTED as a deliberately-retained genesis/
  migration primitive (`permission_group_assign_authz.go:157`; `facade_methods.go:72`: "the unchecked
  RemoveGroupSubject is genesis-only"), symmetric with the unchecked `AssignGroupRole`. So this is a
  JUDGMENT call, not a clean dead-delete.

**Idiomatic target:** don't export for tests — a method only tests call should be unexported (or the test should drive it through the real path); exported identifiers are for consumers.

- [ ] `RemoteApplicationRoles`: delete (or unexport); repoint the 2 tests (assert via `ResolveRemoteApplicationAuthority` or the group store). Non-breaking.
- [ ] `RemoveGroupSubject`: CONFIRM with the maintainer whether the documented genesis/migration use is real/planned. If no path will ever call it → remove + repoint the integration test to `RemoveGroupSubjectAs`. If kept for symmetry with the unchecked assign side → LEAVE (intentional, not dead). Do not auto-delete a documented-intentional primitive.
- [ ] `go build ./... && go test ./internal/authcore/` green. Neither needs a SEMVER edit or bump (not on the public surface).
