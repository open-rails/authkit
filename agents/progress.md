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

**Completed:** yes

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

STATUS 2026-06-26 (Claude): authkit-side DONE, green on a fresh-migrated DB. Renamed the
PUBLIC field only (`config.go` `FrontendConfig.OIDCReturnPath`); the internal engine option
`Options.FrontendCallbackPath` keeps its accurate name (renaming it is churn the issue doesn't
call for). Default `/login/callback` preserved. The unrelated `oidcCallbackPath` (provider-callback
derivation) was correctly left alone. First-party consumer migration rides the coordinated #143 bump.

## Tasks

- [x] Rename `FrontendConfig.CallbackPath` to `OIDCReturnPath` (public field; internal
      `Options.FrontendCallbackPath` intentionally kept — accurate internal name).
- [x] Update config normalization/defaulting to keep the default path `/login/callback`.
- [x] Update OIDC browser-flow code to use `OIDCReturnPath` (read site `service.go:309`).
- [x] Update README/examples (authkit). First-party consumers migrate at the coordinated bump.
- [x] Search docs/comments/tests for `CallbackPath` (README/SEMVER/api-endpoints).
- [x] Validate with `go test ./...` (green on fresh DB; only tree-wide failures are #148's
      in-flight 2FA tests, unrelated).

---

# #143: Client API cleanup — client-first construction + small capability interfaces

**Completed:** yes

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

IMPLEMENTED 2026-06-26 (Claude) — authkit-side, all green on a fresh-migrated test DB
(only tree-wide failures are #148's in-flight 2FA integration tests, unrelated to this work):
- API-KEY + SERVICE-JWT RESOURCE SCOPES — DELETED end to end: `APIKeyResource`, `Resources`
  fields (APIKey/APIKeyMintOptions/ResolvedAPIKey/ServiceJWTClaims/ServiceJWTMintOptions/
  verify.Claims/ServiceJWTPrincipal), `APIKeyResourceAuthorizer(Func)`/`Request`,
  `WithAPIKeyResourceAuthorizer`, `ErrResourceScopeDenied` (Go sentinel + HTTP wire code),
  `profiles.api_key_resources` table, the `resources` request/response field, and the service-JWT
  `resources` claim. `ResolveAPIKeyWithResources`→`ResolveAPIKeyDetailed` (regenerated remote SDK).
  SIWS `Resources` (EIP-4361) untouched.
- IDENTITY-PROVIDER CONFIG — `Providers map[string]oidc.RPConfig` + `ProviderDescriptors` → ONE
  `Providers []authprovider.Provider`; added `authprovider.Google/Apple/Discord/GitHub(id,secret)`;
  deleted dead `Service.oidcProviders`/`providers` fields.
- OPTION CULLS — `WithDBTXWrapper`; `WithErrorLogger`/`InternalErrorEvent`/`errorLogger` (→`slog`);
  public `WithPermissionGroupAuthorizer`/`PermissionGroupAuthorizer` (kept UNEXPORTED test-only
  `groupCanFn`); `WithSolanaDomain` (→ config-derived); `LanguageConfig.QueryParam`/`CookieName`
  (hardcoded `lang`; no-config ⇒ English-only); SMS `DeliveryConfirmTimeout` (→ fixed 12s const,
  always-on). `WithSolanaSNSResolver`/`WithEphemeralStore` demoted to advanced, not deleted (SNS has
  no owned-default resolver; WithEphemeralStore removal collided with #148/#146-owned test files).
- RATE-LIMIT/PROXY — added `WithTrustedProxies(cidrs)`; automatic Redis-aware rate limiting (memory
  default, redislimiter when `WithRedis`). `WithRateLimiter`/`WithoutRateLimiter`/`WithClientIPFunc`
  kept advanced.
- DEFERRED (net-new, NO regression — `WithAuthLogger`/`WithAuthLogReader` still work): first-party
  ClickHouse adapter + `embedded.WithClickHouse`; AuthKit-owned default SNS resolver (on-chain RPC).
NOTE: the shared compose DB is stale vs the evolving migration (#145 `group_id`→`permission_group_id`);
`task test` needs a DB re-migrate once #145 lands — validation above ran against a fresh DB.

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
- [x] Keep `embedded.Client` broad as the concrete engine type if that is the
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
- [x] Keep `embedded.Option` only for in-process construction dependencies
      (`WithEmailSender`, `WithSMSSender`, `WithEntitlements`,
      `WithEphemeralStore`, etc.). Do not make `embedded` a dumping ground for
      validation constants and DTO aliases.
- [x] DECISION: simplify identity-provider config. Do not expose separate
      built-in vs custom-provider fields; a provider is a provider.
- [x] Delete `IdentityConfig.ProviderDescriptors`.
- [x] Replace `IdentityConfig.Providers map[string]oidc.RPConfig` with
      `IdentityConfig.Providers []authprovider.Provider`.
      ACCEPTED BREAK (2026-06-26): widest blast radius in the cull — doujins, hentai0, AND
      cozy-art all build the `map[string]oidckit.RPConfig` form. Clean breaking change, no
      migration helper; the three migrate their provider config to the slice at the bump.
- [x] Keep provider name inside `authprovider.Provider.Name`, not as a map key.
- [x] Add small helper constructors for built-ins only if they materially improve
      examples, e.g. `authprovider.Google(clientID, clientSecret)`.
- [x] Update first README example to use either `Identity: embedded.IdentityConfig{}`
      or one built-in provider constructor, not custom-provider descriptor plumbing.
- [x] Make examples and docs use root contract names:
      `authkit.Config`, `authkit.User`, `authkit.ValidateUsername`,
      `authkit.SubjectKindUser`, `authkit.RegistrationVerificationRequired`, etc.
      `embedded` should appear only for `embedded.New` and embedded-only
      options/types.
- [x] Pare embedding docs down to the normal-host packages only:
      `authkit`, `embedded`, `authhttp`, `verify`, one router adapter, and
      `migrations/postgres` plus `migrations/clickhouse`. Put `jwt`, `oidc`, `authprovider`, `storage`,
      `ratelimit`, `siws`, `password`, Twilio adapters, River jobs, and
      `authtest` in an advanced/support section.
- [x] Keep direct `jwt` use out of normal host examples. Token signing should go
      through `client.MintDelegatedAccessToken` / `client.MintServiceJWT`; hosts
      should not handle private keys for routine embedding.
- [x] Move advanced engine hooks out of the first README constructor example:
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
- [x] Remove `WithAPIKeyResourceAuthorizer`, `APIKeyResourceAuthorizer(Func)`,
      `APIKeyResourceAuthorizationRequest`, `APIKeyResource`, and the `Resources` fields
      from public/core/http contracts. SCOPE (2026-06-26): `APIKeyResource`/`Resources` is
      NOT API-key-only — it is also on the SERVICE-JWT contract (`ServiceJWTClaims.Resources`
      `servicejwt.go:32`, `verify.ServiceJWTPrincipal.Resources` `verify/service_jwt.go:24`),
      so rip it out of the service-JWT path too (breaks cozy-art's production service-JWT
      minting `cozy-art/internal/servicejwt/servicejwt.go` — accepted). `ErrResourceScopeDenied`
      is TWO symbols: the Go sentinel (`errors.go:45`, also in the `errors.Is` list `:80`) AND
      the HTTP wire code (`http/error_codes.go:538`, mapped in
      `permission_group_operations.go:576-580`) — remove both. DO NOT touch SIWS's unrelated
      DONE 2026-06-26: code/tests/docs updated and `go test ./...` green.
      `Resources` (`siws/message.go`, EIP-4361 sign-in-message field).
- [x] Remove the `resources` field from `POST /<persona>/<instance_slug>/api-keys`
      request/response/list payloads; API-key minting remains governed by
      `<persona>:credentials:manage` plus the existing no-step-up role-grant
      check.
- [x] Preserve built-in credential-management permissions: root operators use
      intrinsic `root:credentials:manage`; host personas use generated
      `<persona>:credentials:manage`. Group owners may mint/revoke API keys for
      permission groups they own, but still cannot grant an API-key role above
      their own effective permissions.
- [x] Drop `profiles.api_key_resources` from the hard-cut Postgres schema and
      delete resource-scope normalization/load/list/authorization code and tests.
- [x] DECISION: first-run embedded constructor options should be only normal
      runtime dependencies: `WithRedis`, `WithEmailSender`, and `WithSMSSender`.
      Everything else is either config, automatic default, advanced/support, or
      test/internal plumbing.
- [x] DECISION: `authhttp.LanguageConfig` should expose only `Supported` and
      `Default`. Do not make the query parameter or cookie name configurable;
      hardcode both to `lang`.
- [x] Delete public `LanguageConfig.QueryParam` and `LanguageConfig.CookieName`.
      No language config should mean English-only: supported languages `["en"]`,
      default `"en"`.
- [x] DECISION: remove public SMS `DeliveryConfirmTimeout` configuration. The
      Twilio sender should use a fixed internal delivery-confirm timeout around
      10-15 seconds; hosts should not tune this in normal AuthKit setup.
- [x] Delete `DeliveryConfirmTimeout` from public SMS sender config and docs; keep
      one package-private constant for the internal default.
- [x] DECISION: delete `WithDBTXWrapper` entirely. It was only a sqlc/pgx
      query-decorator seam for hypothetical counting/spy queriers, and current
      source has no test/user call sites. If a future test needs query spying,
      add that locally in the test instead of preserving a public option.
- [x] Remove `WithDBTXWrapper` from `internal/authcore/options.go`,
      `embedded/aliases.go`, and any public surface inventory/docs.
- [x] DECISION: do not expose `WithSolanaSNSResolver` as a normal client option.
      AuthKit should provide the standard Solana Name Service resolver itself
      when Solana/SIWS is enabled; hosts should not wire a resolver.
- [x] Replace host-provided SNS resolver wiring with an AuthKit-owned default
      resolver. Keep timeout/cache TTL as fixed internal defaults unless a real
      host need appears.
- [x] Remove `WithSolanaSNSResolver` from first-run docs and public examples; if a
      custom resolver remains for tests, keep it out of the normal host API.
- [x] DECISION: do not expose generic auth-event logger/reader wiring in the
      normal host-facing API. AuthKit supports ClickHouse for auth/session event
      history; call the option `WithClickHouse(...)` (or `WithClickHouseAuthLog`
      if the name must be narrower) and wire both write and read sides there.
- [x] Add a first-party ClickHouse auth-event adapter that implements both
      `AuthEventLogger` and `AuthEventLogReader` against the bundled ClickHouse
      migration schema. This is the standard implementation for admin sign-in
      history / user login history views.
- [x] Replace `embedded.WithAuthLogger(...)` and `authhttp.WithAuthLogReader(...)`
      in public examples/API with one `embedded.WithClickHouse(ch)` option. The
      embedded client owns both auth-event writes and history reads; `authhttp.NewServer(client)`
      should derive the reader from the client, not require a separate server
      option. Passing no ClickHouse means no external auth-event history and admin
      sign-in history routes should report auth log unavailable.
      ACCEPTED BREAK: doujins routes auth logs through its OWN analytics service (not a raw
      ClickHouse handle), so `WithClickHouse(ch)` is not a drop-in for it — doujins either
      adopts the bundled ClickHouse adapter or keeps its own logger via the internal/
      advanced `AuthEventLogger` seam. Breaking change, accepted.
- [x] Keep low-level `AuthEventLogger` / `AuthEventLogReader` interfaces internal
      or advanced-only only if needed for tests; do not document custom file/stdout
      loggers until there is a real host need.
- [x] DECISION: remove public `WithEphemeralStore` from the host-facing API. It is
      jargon and unnecessary: AuthKit should always create and use an in-memory
      auth-state store when Redis is not supplied.
- [x] Keep `embedded.WithRedis(rdb)` as the only normal host knob for temporary
      auth state. Redis replaces the default in-memory store for multi-instance
      deployments and stores short-lived auth data such as challenges, OIDC state,
      passwordless/verification/reset tokens, and related counters.
- [x] DECISION: do not expose `authhttp.WithRateLimiter` as normal host setup.
      AuthKit owns the rate-limit policy and should create the limiter itself:
      Redis-backed when the embedded client has Redis, in-memory otherwise.
      Custom limiter injection, if kept, is internal/test/advanced only.
- [x] Replace public examples of `authhttp.WithRateLimiter(...)` /
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
- [x] Remove `WithPermissionGroupAuthorizer` and `WithSolanaDomain` from first-run
      docs and public API inventory.
- [x] Delete `PermissionGroupAuthorizer`, `WithPermissionGroupAuthorizer`, and the
      `groupCanFn` field from public HTTP server code. Update tests to exercise
      the real `Can` path or use package-internal helpers instead of a public
      option seam.
- [x] Delete `WithErrorLogger`, `InternalErrorEvent` as a public callback contract,
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
- [x] Update README/embedding docs to show:
      - `authhttp.NewServer` for mounted auth routes,
      - `embedded.New` for in-process library operations,
      - future `remote.New` for standalone AuthKit.
- [x] Validation: `go test ./...` in authkit plus real consumer integration/build
      checks against this AuthKit working tree.
      2026-06-26 proof: AuthKit `task SQLC_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_itest_codex_145146?sslmode=disable test`
      passed on a freshly migrated Postgres DB; OpenRails `go test ./... -count=1`
      passed with a local AuthKit replace; Doujins real integration tests passed
      (`go test -tags=integration ./tests -run TestAuthIntegration`, plus admin/users
      and embedded-billing packages); Hentai0 live compose integration passed for auth,
      billing identity, refresh/logout/OIDC, and delegated-token failures; Tensorhub
      real testcontainer integration passed for platform policy, pricing store,
      OpenRails admission, and usage outbox; Cozy Art passed API/app/servicejwt package
      tests plus the tagged embedded billing smoke against a migrated disposable Postgres.

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

**Completed:** yes

Split out of #143 (2026-06-26): personas, roles, and permissions configured in exactly ONE
place — `Config.RBAC []PersonaDef`, root an ordinary entry, config-time composition across
libraries, and a name-immutable / fail-closed drift policy. Part of the #143 release train;
the coordinated consumer bump + final `go test ./...` live in #143. Cross-cutting design
context (REVIEW / REFINE / GROUND) is in the #143 head.

- [x] DECISION: simplify RBAC persona containment. A group instance already has
      exactly one parent (`parent_id`/`parent_persona`); the public schema should
      also declare exactly one parent persona per persona type, not
      `AllowedParents []string`.
- [x] Replace `PersonaDef.AllowedParents []string` with `PersonaDef.Parent string`
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
- [x] Validate persona role permissions against the catalog — derived-from-roles when
      no custom roles, explicit when custom roles widen it. App-declared roles AND
      custom-role grants must reference catalog permissions; reserve wildcard grants
      such as `<persona>:*` for AuthKit's generated owner role and deliberate
      internal expansion.
- [x] Update `BuildSchema`/`NewGroupSchema` validation and containment seeding for
      singular parent persona definitions. No configurable multi-parent hierarchy.
- [x] FIRST: grep the four consumers for any persona that attaches under two different
      parent persona types (e.g. a `team` valid under either `org` or `enterprise`).
      Single-parent is a one-way schema door — if one exists, this hardcut is wrong.
      The plan asserts none; prove it before cutting.
- [x] Commit STORAGE to singular too: replace `group_persona_parents` with a
      `parent_persona` column on the containment/persona definition and DROP the join
      table. A many-parent table behind a one-parent API is the dead flexibility this
      issue deletes from the public surface — pick singular end to end.
- [x] Single-parent ALSO fixes the seed drift: `SeedContainment` is additive-only today
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
- [x] Document the durability boundary AND the drift rules in the RBAC config docs — this is the
      mitigation (authkit can't enforce; operators must be aware). Cover: catalog + role catalogs are
      ephemeral in-memory config (swap freely; editing a role's perms is a live update for all holders);
      containment + runtime role rows (`group_user_roles`/`group_custom_roles`/`api_keys`) are durable and
      name-referenced. Spell out the operator contract: (1) schema names are immutable identifiers — no
      in-place rename; (2) NEVER reuse a retired name for a different concept, and clear/reassign orphaned
      assignments on removal (authkit only surfaces them via the drift report); (3) removing authority is
      always safe — unresolved names fail closed to zero, never fail open. Put this where operators will
      see it (the RBAC config doc + a CHANGELOG/UPGRADE note), not buried.
- [x] Update docs/examples to show `persona:resource:action` permissions inside
      persona roles, e.g. `root:users:ban`, `merchant:subscriptions:cancel`,
      `endpoint:deployments:restart`.
- [x] DECISION: each persona, including the intrinsic root persona, should expose
      only three optional management capabilities, all off by default: allow API
      keys, allow remote applications, and allow custom role definitions. Custom
      role definitions mean a specific permission-group instance may define
      additional local roles; when off, only the application-declared/hardcoded
      persona roles exist.
- [x] Replace the current split public shape
      (`AllowCustomRoles` plus `Routes.CustomRoleCreation`, `Routes.APIKeyMinting`,
      `Routes.RemoteAppRegistration`) with one clearer persona capability block,
      e.g. `Capabilities: authkit.PersonaCapabilities{APIKeys: true,
      RemoteApplications: true, CustomRoles: true}`. Keep member assignment and
      invite acceptance as standard permission-group behavior, not part of this
      optional capability list.
- [x] Allow host config to override root persona capabilities without requiring
      the host to redefine the whole intrinsic root persona. Root uses the same
      capability names and route-generation rules as every other persona.
- [x] Route generation should derive API-key, remote-application, and custom-role
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
- [x] Add `authkit.PersonaCapabilities{APIKeys, RemoteApplications, CustomRoles bool}` to root `authkit`.
- [x] Rewrite `PersonaDef` (`internal/authcore/permission_group.go:145`): `AllowedParents []string`→`Parent string`;
      `AllowCustomRoles bool` + `Routes ManagementProfile`→`Capabilities authkit.PersonaCapabilities`; add `Catalog []string`.
- [x] Delete `ManagementProfile` (`permission_group.go:135`). Its non-capability route toggles (MemberAssignment,
      InviteLinks) move to config-aware route generation; root member-assignment defaults OFF (no auto-enable).
- [x] Collapse `Config.RBAC RBACConfig`→`Config.RBAC []PersonaDef` (`config.go:15,197`); delete `RBACConfig`,
      `RBACConfig.Permissions`, and `PermissionDef` (`config.go:202,213`).
- [x] Delete `Options.Permissions` (`service.go:103`) and its copy from cfg (`service.go:408`) — dead catalog field.

Validation & schema build:
- [x] FIRST: grep the four consumers for any persona attaching under two different parent types (e.g. `team` under
      `org` OR `enterprise`). Single-parent is a one-way schema door — abort the hardcut if one exists.
      DONE 2026-06-26: checked doujins, hentai0, cozy-art, tensorhub, and openrails; no multi-parent
      persona declarations found. Tensorhub uses `org -> {repo,endpoint,dataset}`; openrails uses
      separate root children `merchant` and `customer`; doujins/hentai0 are root-only.
- [x] `normalizePersona` (`permission_group.go:202`): drop the `Routes.CustomRoleCreation requires AllowCustomRoles`
      check; when `Capabilities.CustomRoles` && `Catalog` non-empty, validate each catalog entry is a namespace-pure
      `<persona>:...` pattern and that declared role grants ⊆ the effective catalog.
- [x] `validateRoot` (`permission_group.go:253`): root = the persona with empty `Parent` (single-root unchanged).
- [x] `validateContainment` (`permission_group.go:276`): single `Parent` edge, not a `[]AllowedParents` loop; keep the
      acyclic-tree + declared-persona checks (now simpler).
- [x] `ValidateParent` (`permission_group.go:370`): compare the proposed parent to the single `Parent`, not a slice.
- [x] `BuildSchema`/`IntrinsicRootPersona` (`permission_group_root.go:48,63`): root uses `Parent:""`, `Capabilities{}`
      (NOT auto member-assignment); host overrides by passing `PersonaDef{Name: RootPersona, ...}`.
- [x] `GroupSchema.GrantableUniverse(persona)` = `Catalog` when CustomRoles on, else union of role grants.
      For root, ALWAYS union in `IntrinsicRootPermissions()` so built-in `root:` perms stay grantable.

Composition & root merge:
- [x] `BuildSchema` (`permission_group_root.go:63`) MERGES the intrinsic root INTO a host-supplied
      `PersonaDef{Name: RootPersona}` instead of using it as-is: owner=`root:*` + intrinsic perms always
      present; host root roles/catalog appended; host sets root `Capabilities` (default all-off).
- [x] Persona-set merge in `BuildSchema`/`NewGroupSchema`: non-root names globally unique (collision = error);
      root mergeable (union roles/catalog); root `Capabilities` from the final host only (reject capability
      flips in library root contributions); parent refs resolved across the union.
- [x] Composition is config-time: libraries export `[]authkit.PersonaDef`; host concatenates into `Config.RBAC`.
      No mutable runtime schema (decided).

Catalog's only consumer — custom roles:
- [x] Custom-role define path (`http/permission_group_operations.go:617` `groupCustomRoleDefine` + core) validates grants
      against `GrantableUniverse(persona)`, not just `ValidateGrantPattern`; reject grants outside the catalog.

Durable storage — containment reconcile + migration:
- [x] Migration: `group_persona_parents` PK `(persona, allowed_parent_persona)`→single-parent shape (`persona` PK +
      `parent_persona text NOT NULL`); update the containment trigger/CHECK at `001_auth_schema.up.sql:298`. No table for
      catalog/roles — they stay in-memory.
- [x] `SeedContainment` (`permission_group_store.go:56`): reconciling upsert —
      `INSERT ... ON CONFLICT (persona) DO UPDATE SET parent_persona=$2`, and DELETE personas absent from the schema.

Drift handling (assignments are late-bound by name — fail-closed; see DECISION above):
- [x] Add a drift report (startup log + on-demand method): count `group_user_roles`, `group_custom_roles`,
      `api_keys` rows whose `(persona, role)` is absent from the current schema. Report only — do NOT
      auto-delete assignments (a config typo dropping a role would nuke everyone's grants).
- [x] Admin role listings mark a stored role absent from the schema as `unknown/removed` (resolve against the
      schema; never render an orphan as if it were live authority).
- [x] Test the fail-closed contract: removed catalog role, renamed role, removed permission, and
      CustomRoles-disabled each resolve to ZERO grants (never error, never fail open); and a REUSED name
      reactivates stale rows — the documented hazard, proving rule (2) matters.

Consumers, docs, validation:
- [x] Migrate the four consumers' RBAC config to the new shape (single `Parent`, `Capabilities`, optional `Catalog`).
      2026-06-26 proof: Doujins, Hentai0, Tensorhub, Cozy Art, and OpenRails are on
      `master` and build/test against this AuthKit working tree with local replaces.
- [x] `cmd/authkit-devserver/main.go:245,344`: remove `toPermissionDefs`/`RBACConfig{Permissions:...}`; per-persona
      `Catalog` only where custom roles are used.
- [x] README/examples: one `Config.RBAC []PersonaDef` slice; root as an ordinary entry; permissions only as role grants
      (+ per-persona `Catalog` when custom roles). Document the durability boundary (catalog/roles ephemeral; containment
      + runtime role rows durable & name-referenced — renames orphan).
- [x] `go test ./...` green (2026-06-26), plus targeted real consumer integration
      checks after the coordinated bump; see #143 validation proof above for commands.


---

# #146: HTTP route-group reshape + router-adapter surface

**Completed:** yes

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
- [x] Rework/rename route groups around host decisions:
      `Auth` (login/token/logout/password reset/passwordless), `Registration`
      (account creation + signup email/phone confirmation), `Account` (current
      user/profile/MFA/passkeys + changing a verified email/phone), `Admin`, and
      `PermissionGroups`. Email/phone verification folds into Registration (signup)
      and Account (contact change) — NO separate `Verification` group unless a real
      standalone no-account verification flow actually exists. Keep OIDC browser
      redirects and JWKS as separately mounted special cases.
- [x] Replace current route constants with the new public route groups (FIVE, no
      `RouteVerification`): `RouteAuth`, `RouteRegistration`, `RouteAccount`,
      `RouteAdmin`, and `RoutePermissionGroups`. Delete `RoutePublic`,
      `RouteSession`, `RouteUser`, and `RoutePasskeys` from the host-facing API.
- [x] Add adapter-level route group selection for the normal host API:
      `authkitgin.RegisterAPI(v1, srv, authkitgin.WithGroups(...))` and the same
      for Chi. `WithGroups(g ...authhttp.RouteGroup)` is SUGAR over the existing
      `svc.Routes().Groups(g...)` (`http/routes.go:53`): `WithGroups(...)` ⇒
      `WithRoutes(svc.Routes().Groups(g...))`, not a third selection path. The
      default `RegisterAPI(v1, srv)` registers all enabled JSON API routes.
      NOTE: only `WithGroups`/`RegisterAPI` need a Chi twin — the Gin-native helpers
      below (`Use`, `RequirePermission`, and context accessors) are Gin-only by nature.
      Chi middleware already IS `func(http.Handler) http.Handler`, so Chi handlers use
      `verify` directly. Do not build `authkitchi.Use`.
- [x] Add a tiny Gin-native adapter surface for host routes:
      DONE 2026-06-26: added `authkitgin.Use`, `authkitgin.RequirePermission`,
      `authkitgin.Principal(c)`, and `authkitgin.UserClaims(c)` with focused adapter
      tests and README examples.
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
- [x] Delete `verify.RequireFreshAuth` entirely. `Sensitive()` is the only public
      step-up gate: it includes freshness, returns `step_up_required` metadata,
      and requires MFA when the user has MFA enrolled. Remove the `authhttp`
      re-export, docs/examples, and tests for `RequireFreshAuth`; replace any
      remaining call sites with `Sensitive(...)` or delete them.
- [x] Delete public `verify.RequireAMR` and `verify.RequireACR` middleware. Keep
      AMR/ACR claims and `Claims.HasAMR` internally because `Sensitive()` and token
      issuance need them, but exact-auth-method route gates are niche API surface.
      Hosts should use `Sensitive()` for normal step-up/MFA enforcement.
- [x] Delete public `verify.RequiredServiceJWT`, `ServiceJWTPrincipalFromContext`,
      `ServiceJWTPrincipal`, and their `authhttp` aliases. First-party service JWTs
      are not a normal host route gate; use ordinary `Required` + `RequirePermission`
      for machine credentials.
- [x] Do not add route-middleware/accessor variants for service/delegated/machine
      principal classes: no `authkitgin.RequireServiceJWT`, `authkitgin.RequireDelegated`,
      `authkitgin.GetDelegatedUser`, `authkitgin.GetRemoteApplication`,
      `authkitgin.GetAPIKey`, or matching `verify.Require*` wrappers. Host apps that
      need app concepts such as invoker/payer/tenant should run one host-owned caller
      resolver over `Principal(c)` plus low-level `verify.ClaimsFromContext`.
- [x] Test `authkitgin.Use` short-circuit + context propagation: a 401 gate
      (`verify.Required` with no token)
      must NOT reach the Gin handler; a passing gate must, and
      `authkitgin.Principal(c)`/`UserClaims(c)` must then see the values the gate set.
      The only adapter code with real semantics.
- [x] Add a canonical `verify.Claims.IsUser()` plus a `PrincipalKind()` enum
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
      DONE 2026-06-26: added root `authkit.PrincipalKind`, `authkit.Principal`,
      `Claims.PrincipalKind()`, `Claims.Principal()`, and `Claims.IsUser()` with claim-kind
      coverage. Removed public `Claims.IsAPIKey()` / `Claims.IsRemoteApplication()` /
      `Claims.IsDelegated()` helpers and moved internal call sites to private helpers,
      `PrincipalKind()`, or `Delegated()`.
- [x] Add `verify.RequiredUser(verifier)` and `verify.OptionalUser(verifier)`
      for host routes that require or optionally enrich with a native human user.
      They run the normal auth pipeline and then gate on `Claims.IsUser()` — rejecting
      API keys, remote apps, delegated tokens, and service principals. `RequiredUser`
      fails closed (401) otherwise; `OptionalUser` drops to anonymous.
      `verify.Required(...)`/`verify.Optional(...)` remain "any valid AuthKit
      principal", so user-profile/session handlers should not hand-read `claims.UserID`.
- [x] Remove `srv.Routes().Groups(...)` from README/happy-path docs. Keep
      `srv.Routes()` / raw `RegisterRoutes(...)` only as the advanced escape hatch
      for custom routers, route wrappers, generated docs, or tests.
- [x] Route mapping:
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
- [x] Split permission visibility from permission-group management. Move
      `GET /me/permissions` to `RouteAccount` because apps without public group
      management still need it for UI gating. Keep the response rooted in the
      current principal and default to singleton `root`; if scoped permission
      checks are needed, prefer explicit scoped endpoints later over stuffing the
      full group-management surface into every app.
- [x] Make `GET /me/groups` config-aware. It belongs in `RouteAccount` only when
      the deployment declares at least one non-root persona or otherwise enables
      user-visible memberships. Root-only apps like Doujins should not have to
      expose group discovery just to show admin permissions.
- [x] Keep `POST /invites/redeem` under `RoutePermissionGroups` and mount it only
      when invite-link support is enabled for at least one persona. If invite-only
      account registration needs a public invite check/start route, that belongs
      to `RouteRegistration`, not the group-management route group.
- [x] Make root management routes opt-in. `IntrinsicRootPersona(...)` should not
      automatically set `MemberAssignment: true`; hosts that want public root
      member/role management must explicitly enable it in root persona
      capabilities. The concrete client/core methods remain available for seed
      jobs, migrations, and app-owned admin routes.
- [x] Stop generating role-catalog routes when every management capability is off.
      Today `GeneratedRoutes()` always emits `GET /<persona>/:instance_slug/roles`;
      that should be tied to custom role / member-management visibility rather
      than leaking a group-management endpoint into root-only deployments.
- [x] Stop treating auth methods as primary route groups where config is better.
      Passkey login belongs to `RouteAuth`; passkey management belongs to
      `RouteAccount`; passkey availability should come from `PasskeyConfig`.
      Passwordless routes belong to `RouteAuth`, but are exposed/usable only when
      passwordless login is enabled. Registration routes belong to
      `RouteRegistration`, but are exposed/usable only when registration mode is
      not `Closed`; invite-only registration requires a valid invite token.
- [x] Make route generation config-aware before mounting: disabled registration,
      passwordless, passkeys, 2FA methods, OIDC providers, Solana/SIWS, and persona
      capabilities should remove or fail-closed their routes by config. Hosts should
      not rely on omitting a route group as the security control.
- [x] DECISION: add one public, non-user auth capability/discovery endpoint instead
      of making frontends infer feature availability from mounted routes. Do not
      add a separate `/auth/availability`; service-level registration/login
      availability belongs in this one response.
- [x] Replace `GET /identity-providers` with `GET /auth/capabilities`
      under `RouteAuth`. Keep provider summaries there and include only
      non-sensitive booleans/enums. Do not expose secrets, internal sender health,
      or admin-only config. It is static per-deploy config served unauthenticated on
      every frontend load — set `Cache-Control`/ETag, do not recompute per request.
- [x] Define the `GET /auth/capabilities` response contract in root `authkit`
      types so embedded and remote/non-Go clients see the same shape. Include:
      registration mode plus invite-token requirement; enabled provider summaries;
      password login availability; passwordless enabled/channels/modes; passkey
      login availability; Solana/SIWS login availability; public verification
      requirements; and supported UI languages if language config remains mounted.
- [x] Keep `GET /register/availability` separate and narrowly named for identifier
      checks (`username`, `email`, `phone_number`). It answers "is this value
      available?", not "which auth flows does this service support?".
- [x] Delete `GET /identity-providers` in the hard-cut. Do not keep a compatibility
      alias during this breaking-change pass.
- [x] Keep authenticated account-specific capability details on account endpoints:
      `/me` and `/user/2fa` should report user-specific MFA state, enrolled
      factors, allowed 2FA methods from config, backup-code status, linked
      providers, and available step-up methods.
- [x] Move any custom auth-state store injection to internal tests or an unadvertised
      test seam. Do not expose it in README or normal package docs.

---

# #147: Registration modes + first-class invites

**Completed:** no — design FINALIZED 2026-06-26 (NO TOKENS; invites keyed to identity).
Codex's tokened account-registration subsystem AND every URL/link token (shareable or
email-bound) are superseded; rework to identity-keyed DB rows.

DECISION 2026-06-26 (Paul, FINAL — supersedes the earlier token / no-token / single-use-link
iterations): invites carry NO URL token at all. Each invite is keyed to the identity it targets;
authenticating-as / verifying that identity IS the credential.
  - Permission-group invite -> keyed to a UserID. You invite an EXISTING user. Pending-membership
    row (user_id, persona, instance_slug, role, invited_by, expires_at, accepted_at, revoked_at).
    The invitee sees it when logged in and manually accepts — being authenticated AS that UserID is
    the credential. No token, no email match.
  - Account-registration invite -> keyed to an email OR phone. You invite a not-yet-user by contact.
    Allowlist row (contact, kind=email|phone, invited_by, expires_at, consumed_at, revoked_at). They
    register with that contact; the normal signup contact-verification proves ownership;
    `registrationAllowedForContact(contact)` = contact ∈ allowlist. Consuming marks it used + sets
    the contact verified. No token.
  - NO shareable/unbound link and NO URL token in either case — drops the single-use-link idea and
    the `group_invite_links` code/max_uses machinery entirely. Simplest design: an invite always
    targets a known identity (UserID for a member, contact for a registrant).
  HARD DEPENDENCY (registration only): the invited signup MUST verify the contact — the
  contact-ownership proof is the credential.
  ORDERING: a non-user can be invited only to REGISTER (by contact); once they exist they are
  invited to a GROUP (by UserID).

OPEN (needs Paul) — combined "invite stranger@email straight into group X": group invites need a
UserID but a stranger has none yet. (i) two steps — registration invite now (contact), then a
UserID-keyed group invite after they register (simplest); or (ii) the registration invite carries a
deferred "then add to group X as role Y" intent that materializes as a UserID-keyed pending group
invite on registration (better UX). Recommend (ii); defaulting to (i) until confirmed.

REWORK 2026-06-26 (Claude): converge the shipped tokened subsystem to the decision above:
  (a) account_registration_invites.go — drop the high-entropy URL token + `randB64` code +
      `WithAccountRegistrationInviteToken`/`ConsumeAccountRegistrationInvite` ctx-token plumbing.
      Table becomes a CONTACT allowlist (contact, kind, invited_by, expires_at, consumed_at,
      revoked_at). `hasValidAccountRegistrationInvite` -> pure contact lookup (no token). FORCE
      contact verification on the invited signup; consuming marks used + verifies the contact.
  (b) permission-group invite — replace the `group_invite_links` code/email/max_uses link with a
      UserID-keyed pending-membership table; accept = authenticated UserID matches the row. Delete
      the shareable-link + email-bound-link code paths.
  (c) `groupMemberAdd` — existing user_id -> direct add (unchanged); unknown email/phone ->
      registration invite (contact allowlist) [+ deferred group intent per the OPEN decision]. No
      token responses anywhere.
  Update Codex's integration tests to assert identity-keyed (no-token) redemption.

AUDIT 2026-06-26 (Codex): revised integration coverage for the changed invite and
registration flows. Added DB-backed HTTP/core checks for invite-only `/register`,
invite-only passwordless auto-registration, unknown-email permission-group member
add minting separate group/account invites, rerunnable account-invite core
registration, and RBAC drift reporting. Also fixed the bugs those tests exposed:
passwordless invite-only now returns `registration_disabled` instead of a generic
500, unknown-email member add no longer treats `pgx.ErrNoRows` as a DB failure,
and RBAC drift SQL qualifies `r.deleted_at`. Validation green against a freshly
migrated throwaway Postgres DB:
`task SQLC_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_itest_codex?sslmode=disable' test`.

STATUS 2026-06-26: account-registration invites are implemented and DB-backed
integration coverage is green; consumer breaking-bump work remains tracked in
#143/#145/#149, not here.

DONE (validated, `go build ./...` clean, unit tests pass):
- Registration vocabulary moved to root `authkit` (`registration.go`): `RegistrationMode`
  (Open/InviteOnly/Closed only — `AdminOnly`/`AdminBootstrapOnly`/`ManifestOnly` HARD-DELETED) +
  `RegistrationVerificationPolicy`. `authcore` re-exports via alias, `embedded` re-exports the
  surviving consts. `normalizeRegistrationMode` switch + error message trimmed;
  `externalInvitesEnabled` comment updated; all readers + the 3 tests
  (policy_switches/register_availability/oauth2_browser) migrated off the deleted modes;
  `TestPolicySwitches_RejectsLegacyBootstrapOnlyMode` still proves legacy modes are rejected.
- `embedded.RegistrationConfig` already uses the (now root-backed) enum types.
- Added intrinsic root permission `root:users:invite` (`PermRootUsersInvite`); in
  `IntrinsicRootPermissions`, owner holds it via `root:*`, re-exported through `embedded`.
- Concrete invite TTL defaults: `defaultEmailInviteTTL`=7d, `defaultShareableInviteTTL` 24h->72h
  (identity-proven email-bound outlives the anyone-with-the-link shareable one, never reverse).
- Central email-aware gate `registrationAllowedForEmail(ctx, email)` (`registration_gate.go`):
  the SINGLE chokepoint — Open->true, Closed->false, InviteOnly->`hasValidAccountRegistrationInvite`.
  Core email front-door (`CreatePendingRegistrationWithLanguage`) routes through it (Open/Closed
  unchanged); `TestRegistrationAllowedForEmail` covers the matrix.

IMPLEMENTED (SUPERSEDED token design — see DECISION/REWORK above) — first-class
account-registration-invite subsystem, separate from permission-group invites
(own table + high-entropy time-bound URL token, NOT `group_invite_links`).
`InviteOnly` now admits email-bound account creation with a valid account invite;
standalone account invites require `root:users:invite`; unknown-email
permission-group adds mint separate group and account invite tokens when
registration is invite-only; registration, passwordless, OIDC/OAuth, and verified
pending-registration finalizers route through the invite-aware gate. NOTE: the
high-entropy TOKEN for the email-bound + account-registration cases is being
replaced with DB rows (verified-email match) per the 2026-06-26 decision; only the
shareable group link keeps a token.

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
- [x] ~~DECISION: support two group invite kinds: (1) general-purpose shareable link
      with no bound email, redeemable by whoever has the link within expiry/max-use
      limits; (2) email-bound invite, redeemable only by an account with the same
      verified email.~~ SUPERSEDED 2026-06-26 (FINAL decision above): NO group invite
      links at all. A permission-group invite is keyed to a UserID (existing user
      accepts while logged in). Inviting a not-yet-user is a REGISTRATION invite
      (keyed to email/phone), not a group invite. No shareable link, no max_uses.
- [x] DECISION: invites are time-bound manual accepts. Do not auto-add users to
      permission groups after signup/login; the recipient must click/open the
      invite link and accept/redeem it. Default validity should be a few days for
      both shareable links and email-bound invite links.
- [x] DECISION: invite creation/email sending must be rate-limited. A user must
      not be able to spam a large number of invite emails quickly.
- [x] Move `RegistrationVerificationPolicy` +
      `RegistrationVerificationNone|Optional|Required` to root `authkit`.
- [x] Move simplified `RegistrationModeOpen|InviteOnly|Closed` to root `authkit`
      and delete `AdminOnly`, `AdminBootstrapOnly`, and `ManifestOnly`.
- [x] Update `embedded.RegistrationConfig` to use the root registration enum types
      so future `remote` and host docs do not import shared vocabulary from
      `embedded`.
- [x] Make `InviteOnly` real with first-class account-registration invites.
      A user can be invited to create an account without being invited to any
      permission group.
- [x] Add a built-in root permission for standalone account-registration invites,
      `root:users:invite`. The root `owner` role gets it via `root:*`; hosts may
      add it to bounded operator roles when they want non-owner staff to invite
      new accounts.
- [x] Keep account-registration invites and permission-group invites separate — and
      keep their TOKENS separate too. An unknown-email group invite under `InviteOnly`
      sends TWO independent tokens (a standalone account-registration invite plus the
      email-bound group invite), NOT one token that "carries" the other. Two clear steps
      (register, then accept the group invite), zero coupling between the subsystems; the
      email-bound rule already guards both. The only thing "carrying" would save is one
      email — not worth welding the two subsystems together.
- [x] Authorize permission-group invites with that group's existing
      `<persona>:members:manage` no-escalation checks. A group owner/manager may
      attach a registration credential only for that group invite; this does not
      grant general `root:users:invite` authority.
- [x] ~~Registration invites must be high-entropy, time-bound URL tokens, not short
      OTP-style codes.~~ SUPERSEDED 2026-06-26: email-bound account-registration invites
      carry NO token — they are an email-keyed allowlist row; the invited signup's own
      email-verification is the inbox proof. Email-bound invites still authorize account
      creation only for that email. (High-entropy tokens remain only for the unbound
      shareable group link.)
- [x] Permission-group invite acceptance stays separate from account creation.
      If a group invite helped an unknown recipient register, the user still must
      manually accept/redeem the group invite before AuthKit adds the membership.
- [x] Preserve the existing email-bound redemption rule in the onboarding flow:
      invite email must equal the redeemer account's verified email.
- [x] Make the invite API/docs name invite kinds clearly: account-registration
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
- [x] Add ONE core helper `registrationAllowedForEmail(ctx, email) (bool, error)` and
      route ALL gates through it — do NOT thread invite-awareness through ~10 divergent
      call sites (`PublicNativeUserRegistrationEnabled()` takes no email, which is exactly
      why the single email-aware helper is needed). Under `InviteOnly` it returns true iff a
      valid, unexpired email-bound account-registration invite exists for that email; `Open`
      stays true; `Closed` false. Call it from the core sites AND the HTTP-layer OIDC/OAuth
      gates (`publicRegistrationDisabled()`), passwordless, and Solana. Solana has no email
      binding and stays fail-closed for new account auto-create under `InviteOnly`.
- [x] Spec the two cross-subsystem rules the two-token flow needs: (1) consuming an
      email-bound account-registration invite MUST set `email_verified=true` on the new
      account — else `RedeemGroupInviteLink` (which requires a verified email,
      `group_invite_links.go:342`) rejects the follow-on group redemption; (2) define the
      account-registration invite's TTL relative to the group invite plus a re-issue path,
      so a stranger can't consume the account token, register, then find the group invite
      already expired (account created, no membership).
- [x] Update `internal/authcore/group_invite_links.go` defaults to CONCRETE TTLs —
      `defaultEmailInviteTTL` = 7 days, `defaultShareableInviteTTL` = 72h — the
      identity-proven (email-bound) invite outlives the anyone-with-the-link shareable
      one, never the reverse. (Email-bound 7d is already today's value; shareable goes
      24h → 72h.) A removed knob
      still needs a named default; "a few days" is not a spec. Keep explicit per-invite
      expiry overrides.
- [x] Add the account-registration invite contract separately from group invites,
      including creation, email delivery, validation during registration, expiry,
      revocation, and consumption semantics.
- [x] Update `CreateGroupInviteLink` / `CreateGroupInviteLinkRequest` /
      `GroupInviteLinkCreated` contract docs to name the two permission-group
      kinds: no-email shareable link vs email-bound invite.
- [x] Update `http/permission_group_operations.go` add-member flow: existing
      `user_id` adds directly and silently; email with no account creates/sends an
      email-bound group invite instead of failing or auto-adding. If registration
      is not public, also send a SEPARATE email-bound account-registration invite —
      two independent tokens (per above), do not fold one into the other.
- [x] Add invite-specific rate limits around invite creation/email sending,
      preferably keyed by actor user, target email, and group; return a stable
      rate-limit error instead of sending more mail.
- [x] Add/adjust HTTP route support so an unauthenticated invite recipient can land
      on an account-registration invite or permission-group invite, register or
      log in, then manually redeem/accept any group invite. Do not auto-redeem a
      group invite after account creation.
- [x] Add integration tests for: existing user direct add no notification; unknown
      email creates group invite; standalone account-registration invite works
      under `InviteOnly`; group invite for unknown email can authorize registration
      only through an attached account-registration invite; wrong verified email
      cannot register/redeem; manual group accept required; expired/revoked/
      exhausted invites rejected; shareable group link still obeys expiry/max-use
      but does not unlock invite-only registration by itself. AuthKit suite is
      green with DB-backed integration enabled (2026-06-26 command above).

---

# #148: 2FA policy + TOTP key material

**Completed:** yes

STATUS 2026-06-26 (Claude): DONE. Vocab moved to root `authkit` (`twofactor.go`:
`TwoFactorMode` Disabled/Optional/Required, `TwoFactorMethod` Email/SMS/TOTP), re-exported
through `authcore` + `embedded`. `embedded.TwoFactorConfig` now carries `Mode` + `Methods`
(RequireEnrollment removed hardcut); `core.Options` gains `TwoFactorMode`/`TwoFactorMethods`,
`RequireMFAEnrollment` derived from `Mode==Required`. POLICY gate `twoFactorMethodConfigured`
chokes `enable2FA` (all enroll paths); user-facing DEPENDENCY fail-closed
(`TwoFactorMethodAvailable`: sender/key present) gates the HTTP enroll handler,
StartTOTPEnrollment, status `AllowedMethods`, and the enrollment-required responses. Disabled
short-circuits `requireSessionMFAState` + the login challenge (no lockout of users enrolled
while Optional). Per-request SESSION gate (note a) built in `verify.VerifyRequest`:
`WithRequireMFAEnrollment` (set from `o.RequireMFAEnrollment` in `http.NewServer`) +
claims-only `IsUser() && !MFAEnrolled` check (note d), allowlist broadened to all
2FA enroll/challenge/verify routes (note c). Refresh-path lockout (note b) fixed:
`ExchangeRefreshToken` returns `*TwoFAEnrollmentRequiredError{UserID}` so the refresh handler
mints a usable enrollment token like login. TOTP key is first-class vault material
(`totp_key.go`): loads `<Keys.Path>/totp.key` (base64/hex/raw → 16/24/32 bytes, perms checked,
fail-closed on missing), explicit `[]byte` kept as override; encrypted secrets carry a 1-byte
version prefix authenticated as AAD (reserves lazy rotation, no keyring). Backup codes stay
tied to availability (unchanged — generated by `enable2FA`, not a separate flag). Tests:
`totp_key_test.go` (decode/load/round-trip+tamper/method-gating) + `verify/mfa_enrollment_gate_test.go`
(allowlist + gate) PASS; existing TOTP/2FA suites green. README + config docs updated.
`go build ./...` clean for my surface (transient errors in the tree are the concurrent
#143/#145/#146 work). Validated with `go test ./internal/authcore/ -run TOTP|2FA|MFA|TwoFactor`
and `./verify/` (DB tests needing the #145 `parent_persona` schema fail on stale test DB — not
#148). Docs note (`totp.key` filename/format) added next to keys.json.

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
- [x] Move 2FA policy vocabulary to root `authkit`: `TwoFactorMode`,
      `TwoFactorDisabled`, `TwoFactorOptional`, `TwoFactorRequired`,
      `TwoFactorMethod`, `TwoFactorEmail`, `TwoFactorSMS`, `TwoFactorTOTP`.
- [x] Update `embedded.TwoFactorConfig` to use `Mode` and `Methods`; remove
      `RequireEnrollment` from the public config hard-cut.
- [x] Gate 2FA routes and service operations from config: disabled means no
      enroll/challenge/verify flow; optional/required expose only configured
      methods, and fail closed when a method dependency is missing (for example,
      SMS sender absent).
- [x] `Required` gates the SESSION, not just signup. When a host flips
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
- [x] Keep backup-code routes/operations tied to 2FA availability, not to a
      separate config flag.
- [x] Treat the TOTP encryption key as first-class key material, not incidental
      config: define the file format, load path, validation, reload/rotation story,
      and error semantics at the same rigor level as JWT signing keys.
- [x] Add vault/file loading for `TwoFactor.TOTPSecretKey` under `Keys.Path`.
      Use strict file permissions/parse validation, require 16/24/32 bytes after
      decoding, and fail closed for TOTP enrollment if the key is missing or invalid.
- [x] Decide whether TOTP key config needs the same knobs as signing keys
      (`Source`/custom provider, path override, reloadable file source). Prefer a
      small shared key-loading abstraction over host apps reading secrets manually.
- [x] TOTP rotation, lazy version: v1 stores a 1-byte key-id/version prefix on every
      encrypted TOTP secret and builds NO keyring. That reserves the calibration knob so
      a future keyring/rotation is purely additive (old secrets stay decryptable by their
      prefix) with zero rotation machinery now. Full keyring/rotation is a separate issue.
- [x] Keep the explicit `TwoFactor.TOTPSecretKey []byte` override for tests and
      custom key management, but make it an override over the file source, not the
      normal path.
- [x] Document the expected vault-mounted TOTP key filename/format next to the JWT
      `keys.json` docs.

---

# #149: Delete remote-application allowed origins + AuthKit CORS

**Completed:** yes

STATUS 2026-06-26 (Claude): AuthKit side DONE. Deleted `origin.go` and
`verify/remote_application_origins.go` (RemoteApplicationCORS, RequireDelegatedOrigin,
RemoteApplicationAllowedOrigins, OriginAllowedForIssuer, NormalizeAllowedOrigin(s),
OriginAllowed, addVary, errNoRemoteApplicationSource) + `authhttp` aliases + the
`invalid_allowed_origins` wire code. Removed `AllowedOrigins` from `authkit.RemoteApplication`,
`BootstrapManifestRemoteApplication`, the issuer-client registration DTOs, the group
remote-app register request/response JSON, and all core construction sites. Dropped the
`allowed_origins` column from `001_auth_schema.up.sql`, the sqlc queries, and regenerated
`internal/db`. Deleted the two origin-only tests (CORS preflight + delegated-origin middleware)
and `TestNormalizeAllowedOrigins`; issuer/audience/permission gating stays proven by
`TestVerifierRejectsUnregisteredIssuer` + `TestDelegatedPermissionCeilingEnforced`. README has
no CORS section; SEMVER.md surface list trimmed. `grep` for the deleted surface is CLEAN; no
#149-related build errors.
Consumer migration (the four apps + OpenRails CORS rebuild) is done in the coordinated
#143 breaking bump and validated against this AuthKit working tree on 2026-06-26.

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
- [x] Delete public middleware/helpers:
      `verify.RemoteApplicationCORS`, `verify.RequireDelegatedOrigin`,
      `Verifier.RemoteApplicationAllowedOrigins`, `Verifier.OriginAllowedForIssuer`,
      and their `authhttp` aliases.
- [x] Delete origin helper API from root/internal surface:
      `NormalizeAllowedOrigin(s)`, `OriginAllowed`, `ErrInvalidAllowedOrigins`, and
      related tests unless another non-CORS caller remains.
- [x] Remove `AllowedOrigins` from `authkit.RemoteApplication`,
      `RemoteApplicationRegistration`, `CreateRemoteApplicationRequest`,
      `UpdateRemoteApplicationRequest`, HTTP request/response DTOs, bootstrap manifest
      structs, and generated/admin JSON responses.
- [x] Remove `allowed_origins` from Postgres remote-application schema and sqlc
      queries/models; add the hard-cut migration to drop the column.
- [x] Update remote-application create/update validation so issuer/JWKS/public keys
      remain validated, but no allowed-origin validation/error path exists.
- [x] Delete tests whose only purpose is allowed-origin normalization, CORS preflight,
      or delegated-origin middleware. Replace with tests proving delegated token
      verification still gates on issuer/audience/expiry/permissions.
- [x] Update README and adapter docs: no AuthKit CORS setup. Hosts use their normal
      Gin/Chi/global CORS middleware if they expose browser APIs.
- [x] Migrate consumers off the deleted surface during the coordinated breaking bump.
      2026-06-26 proof: Doujins, Hentai0, Cozy Art, Tensorhub, and OpenRails build/test
      against this AuthKit working tree with local replaces. OpenRails now owns CORS
      origin matching locally and no longer calls AuthKit remote-application origin APIs;
      the four apps no longer depend on deleted AuthKit allowed-origin request/config
      fields.
