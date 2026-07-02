<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 231

<!-- AUDIT IMPL STATUS (2026-07-02, Claude) — resume here
Branch: audit-impl (LOCAL only, not pushed). Merged + `go build ./... && go vet ./...` green:
  #200 closed (non-goal); #223 (invite-email sender); #224 (ClaimsBuilder deleted); #225 (credentialScanner
  inlined); #226 (allowResult delegates); #196 (SIWS mem cache memoized + test); #197 (CodeForError walks the
  chain + test); #198 (memory limiter Limit<=0 guard + test); #217 (redis limiter atomic Lua, TOCTOU fixed);
  #215 (authenticated request path now STATELESS — removed per-request ban gate + discord/role/email enrichment,
  0 DB lookups, realigns with #90); #216 (single JWT parse); #208 (surface trims: AuthCapabilities→authhttp,
  drop RBACDriftReport facade, unexport unused jwtkit sources); #218 (SIWS regexp hoist + touchAccessToken
  in-query throttle); #227 (thread loaded user + MFAStatus through the token-issue path — refresh/login/2fa-verify
  now read profiles.users ONCE, compute MFA ONCE; was 3× / 2-3×); #228 (GET /me: Get2FASettings 3×→1,
  UserPreferredLanguage read dropped via preferred_language on UserByID, provider slugs/HasPassword once —
  ~15→~5-6 round-trips + count test); #229 (register/availability: one combined CheckPendingRegistrationConflict
  instead of two + test); #230-safe (dropped unused last_authenticated_at/revoked_at from SessionsListByUser).
  FULL `task test` GREEN (exit 0). Pre-existing flake to watch: internal/db/querytest TestQueryPerformance
  `users_purge_candidates shared read blocks >64` — fails on clean master too (68>64 there, 76>64 here; varies);
  untouched query, not ours. Candidate: loosen threshold or ANALYZE before measuring.
SURFACE NOTE (#228): added optional `PreferredLanguage *string` to public authkit.User + authkit.AdminUser
  (json omitempty, backward-compatible) to read language off the loaded row — small ADDITIVE surface growth,
  justified by removing a /me round-trip; preferred_language is legit profile data. #230 projection-narrowing
  was DESCOPED (#227 already removed the read repetition; narrowing a once-read row risks caller breakage).
#215+#227 SECURITY DESIGN (verified coherent): every token/session MINT point gates banned/deleted via
  ensureUserAccess — password/2fa (IssueAuthenticatedSession), email-verify/OIDC/SIWS/passkey
  (IssueRefreshSessionWithAuthMethods L63), refresh (ExchangeRefreshToken top gate). The ungated
  insertRefreshSession is only reached THROUGH those gated wrappers. No per-request live check; banned user keeps
  only their existing ≤15min access token, cannot login or refresh. #215 enrichment-removal safe because nothing
  reads the enriched Claims fields (doujins resolves roles via its own RoleSlugsForUser(UserID); token never
  carried email/roles anyway — token_issue.go:64/67).
ALSO MERGED (2026-07-02, breaking phase): #199 (security backlog — password-reset revoke-err propagation F8 +
  atomic MFA/step-up consume F2; F1 already fixed in #176); #201 (relocate Passwordless+ExchangeRefreshToken off
  the Client interface → HTTP-only; regenerated mirrors 95→89; membership rule in SEMVER); #203 (riverjobs takes
  authkit.Client + Authorizer godoc); #204 (SEMVER error coverage); #207 (deleted authprovider Transforms DSL →
  IdentityMapper); #210 (NewServer reuses engine Redis); #212 (construction error, no panic). Build+vet green.
PLAN (Paul, 2026-07-02): finish ALL authkit breaking changes, then COMMIT+PUSH+TAG a new version (push now
  authorized). Then migrate consumers one at a time starting with ~/openrails.
NEXT (remaining, serial — shared files client.go/interfaces.go/SEMVER/generated, do in-tree not via worktree
  agents which branch from master): #206 (strip aliasing: delete http/verify_aliases.go, collapse Service/Server,
  dedupe MintDelegatedAccessToken, drop dead email param, legacy code-as-token), #202 (move storage/ratelimit/siws
  under internal/), #205 (dir renames http→authhttp/oidc→oidckit/jwt→jwtkit), #209 (gin-native Optional/Required),
  #211 (one construction entrypoint + RegisterAll), #213 (consolidate error registries + HTTPStatus), #214 (Mint*
  verbs + Principal classifier), #219–#222 (batch-native reads/entitlements/mutations). Then push+tag.
RULES: reduce API/SEMVER surface + total LOC; keep build+vet green after each change; integration-test new
  behavior; push+tag ONLY after all authkit breaking changes land. Tick each issue's tasks as done.
-->


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
- CLICKHOUSE (DONE 2026-06-26, simplified per Paul): DELETED the whole `AuthEventLogger`/
  `AuthEventLogReader` abstraction + `WithAuthLogger`/`WithAuthLogReader` seams + aliases. Now a
  single concrete `WithClickHouse(conn)` — AuthKit uses ClickHouse DIRECTLY to log session events
  (INSERT) and answer admin sign-in history (SELECT) against `user_auth_session_events`. Engine
  exposes `ListSessionEvents` + `SessionEventHistoryEnabled`; `http/admin_signins` calls the engine
  directly (no separate reader option). clickhouse-go promoted indirect→direct. Round-trip
  INTEGRATION-TESTED against real ClickHouse (`clickhouse_audit_test.go`, env-gated on
  `AUTHKIT_TEST_CLICKHOUSE_ADDR`; passed against the local CH on :9002).
- SNS (DONE 2026-06-26): the AuthKit-owned default resolver ALREADY EXISTED (keyless SNS SDK proxy
  `sdk-proxy.sns.id/favorite-domain/{address}`, auto-installed in `NewService`) — earlier "deferred"
  was wrong. Helius is forward-only (name→address), so the proxy is correct. DELETED the
  `WithSolanaSNSResolver` override seam + `embedded.SolanaSNSResolver` alias + `SolanaConfig.SNSResolver`
  field + all doc mentions (AuthKit owns the resolver; no host override). FIXED a real bug: the proxy
  `stale` flag (wallet set a primary domain then transferred/sold it) was ignored → AuthKit could show
  a `.sol` name the user no longer owns; now returns empty. Unit-tested (`...IgnoresStaleFavorite`).
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

**Completed:** yes — IMPLEMENTED 2026-06-27 (Claude). Resolved the contradiction in favor of Paul's FINAL unified token (the shipped code had deliberately gone two-separate-tokens; user ruled for unification). Both halves now done: (b) known-user own-auth invites shipped earlier (`group_membership_invites.go` + `/me/group-invites/{id}/accept|decline`); (a) the register+join unified STRANGER token is now implemented — see "REGISTER+JOIN" note below. Build+vet green; DB-backed tests skip locally (no Postgres).

REGISTER+JOIN (a), done 2026-06-27: `account_registration_invites` gained nullable `permission_group_id`+`role` (migration 001). `CreateAccountRegistrationInviteRequest`/`…Created`/`AccountRegistrationInvite` (root `authkit/contract.go`) gained optional `Persona`/`InstanceSlug`/`Role`. `createAccountRegistrationInvite` branches: role-carrying → authorized by the group's `members:manage` no-escalation (reusing `validRoleForPersona`+`resolveGroupID`+`authorizeRoleChange`, NOT root:users:invite) + `externalInvitesEnabled`; plain → root:users:invite as before. `consumeAccountRegistrationInvite` now claims the code + grants any carried role in ONE tx (FOR UPDATE + `requireMFAForRoleAssignment` + `AssignRole`, mirroring RedeemGroupInviteLink); it no longer early-returns under non-InviteOnly so a role-carrying code grants under Open too. `groupMemberAdd` unknown-email path mints ONE role-carrying account invite (response key `group_invite`→`invite`) instead of two separate tokens. Test: `TestAccountRegistrationInvite_RegisterPlusJoin`. NOTE: `group_invite_links` stays for the existing redeem flow (not folded away — out of (a)'s scope).

DESIGN CONTEXT (FINALIZED 2026-06-26): the discriminator is STRANGER (no account yet)
vs KNOWN USER (has an account): a stranger gets a single-use token LINK; a known user accepts via
their OWN auth (no token). Codex's tokened account-reg subsystem is the right shape for the
stranger half; the known-user half + the unification below are the rework.

DECISION 2026-06-26 (Paul, FINAL — supersedes ALL earlier token/no-token/contact-keyed iterations):

  STRANGER (unknown / not yet a user) -> SINGLE-USE TOKEN code in a URL query param, UNBOUND.
    - AuthKit mints one single-use, unguessable code. It can email/text the link as a CONVENIENCE,
      but it is the SAME link the inviter may instead paste into Discord / hand over any channel. The
      code is NOT bound to the address it was sent to — possession of the link is the credential
      (single-use limits blast radius). Email/SMS delivery is convenience, not a binding.
    - ONE code covers the whole journey: under InviteOnly a valid code AUTHORIZES registration, and
      (when it carries an optional persona/instance/role) ALSO grants that group role on consume.
      Register + join = one token. A standalone registration invite is the same code with no role.
    - Redemption: recipient opens BaseURL+InvitePath?code=… -> SPA. Signed in -> SPA POSTs the code
      -> consumed -> granted. Not signed in -> SPA has them register / sign in first, THEN POSTs the
      code. "Visiting the link is acceptance"; the SPA MAY add a yes/no screen (its call whether to
      POST the code).

  KNOWN USER (already has an account) -> NO token. A pending invite keyed to the UserID.
    - AuthKit notifies them (email/text) with a link to the SPA accept/deny page; the accept/deny
      route authorizes with the recipient's OWN auth token (they are logged in as themselves), NOT a
      consumable code. "Visiting the link is acceptance", or the SPA shows an allow/deny screen then
      calls accept/deny with their auth.
    - Pending-membership row (user_id, persona, instance_slug, role, invited_by, expires_at,
      accepted_at, declined_at, revoked_at). Credential = authenticated as that UserID.
    - Distinct from the existing owner DIRECT-ADD (silently grants an existing user a role, no
      consent); the known-user INVITE is the consent-based variant.

  Net: strangers => one unbound single-use token link (any channel; combines register + join);
  known users => identity-keyed pending invite accepted with their own auth. No email-binding, no
  max_uses / multi-use shareable links. The combined "stranger straight into my group" case is
  handled by the single stranger code carrying the role — no separate deferred-intent table.

REWORK 2026-06-26 (Claude): converge the shipped subsystem to the decision above:
  (a) Stranger token — KEEP a single-use high-entropy code (Codex's account_registration_invites.go
      token is the right shape), but make it UNBOUND (drop email-as-redemption-binding) and unify it
      with the group invite: ONE code row optionally carries (persona, instance_slug, role); consuming
      it authorizes registration AND, if a role is set, grants it. registrationAllowedFor… becomes
      "a valid unconsumed code is presented" (the code is the credential), not a contact allowlist.
      PARTIALLY DONE (Claude): account-registration code is now UNBOUND — `hasValidAccountRegistration-
      Invite` + `consume…` key on the code alone (email ignored, single-use enforced);
      `TestAccountRegistrationInvite_UnboundByEmail` proves a different email registers with the same
      code. DONE 2026-06-27: optional (persona,instance,role) on the code now ALSO grants a group role
      on consume (the register+join unification) — see the REGISTER+JOIN note at the top of this issue.
  (b) Known-user group invite — ADD a UserID-keyed pending-membership table + accept/deny routes that
      authorize via the caller's OWN auth token (no code). Notify by email/text with an SPA link.
  (c) `groupMemberAdd` — target is an existing user -> known-user pending invite (consent) or direct
      add; unknown email/phone -> mint a stranger single-use code, email/text it, AND return the link
      so the inviter can share it any channel.
  (d) Simplify `group_invite_links` — single-use, unbound; the email column is delivery-only
      (optional), never a redemption constraint; drop `max_uses`/`uses`.
  Update Codex's integration tests to assert: stranger-code redemption (register + join in one),
  unbound any-holder single-use, and known-user own-auth accept/deny.

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

DONE (validated 2026-06-26; DB-backed tests added/updated):
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
- Concrete invite TTL default: group invite codes default to 72h and account-registration invite
  codes default to 7d.
- Central email-aware gate `registrationAllowedForEmail(ctx, email)` (`registration_gate.go`):
  the SINGLE chokepoint — Open->true, Closed->false, InviteOnly->valid unbound invite code.
  Core email front-door (`CreatePendingRegistrationWithLanguage`) routes through it (Open/Closed
  unchanged); `TestRegistrationAllowedForEmail` covers the matrix.
- Account-registration invites are high-entropy, time-bound, unbound, single-use URL-token invites
  in their own table. Under InviteOnly, possession of a valid code authorizes registration; the
  address the invite was delivered to is delivery metadata, not a redemption constraint.
- Permission-group invite links are high-entropy, time-bound, unbound, single-use URL-token links.
  Removed the public `Email` / `MaxUses` request/result fields, the email-bound mismatch/exhausted
  sentinel errors, the optional `GroupInviteEmailSender` / `GroupInviteMessage` alias surface, and
  the Twilio group-invite sender hook. A spent code succeeds only for the original redeemer's
  idempotent retry; a different holder gets not-found.
- Unknown-email permission-group add mints an unbound group invite link; when registration is
  invite-only it also mints a separate account-registration invite so the recipient can create an
  account before manually redeeming the group code. Existing users are still direct-add only.

Split out of #143 (2026-06-26): the registration-mode cull (`Open` / `InviteOnly` / `Closed`)
plus first-class invites — account-registration invites SEPARATE from permission-group invites
(two independent unbound single-use tokens for unknown-email InviteOnly onboarding) and rate
limits. This is net-new feature surface, not API cleanup. Part of the #143 release train.

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
- [x] ~~DECISION: email-bound invites may only be redeemed by an account with that
      same verified email.~~ SUPERSEDED 2026-06-26 (FINAL): stranger invites are NOT
      email-bound. The single-use code is UNBOUND — whoever holds the link redeems it
      once. The email/text is only a delivery convenience; the inviter may share the
      same link any channel (Discord etc.).
- [x] ~~DECISION: support two group invite kinds: (1) general-purpose shareable link
      ...; (2) email-bound invite ...~~ SUPERSEDED 2026-06-26 (FINAL): the two kinds are
      STRANGER vs KNOWN-USER, not shareable vs email-bound. Stranger -> single-use UNBOUND
      token link (any channel; consuming it registers-if-needed + grants the optional
      role). Known user -> NO token; accept/deny via their OWN auth token, keyed to UserID.
      No multi-use/max_uses shareable link.
- [x] DECISION: invites are time-bound manual accepts. Do not auto-add users to
      permission groups after signup/login; the recipient must click/open the
      invite link and accept/redeem it. Default validity should be a few days.
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
      returns TWO independent unbound single-use tokens (a standalone account-registration
      invite plus the group invite). Two clear steps: register, then manually redeem the
      group invite.
- [x] Authorize permission-group invites with that group's existing
      `<persona>:members:manage` no-escalation checks. A group owner/manager may
      attach a registration credential only for that group invite; this does not
      grant general `root:users:invite` authority.
- [x] Registration invites (the STRANGER path) must be high-entropy, time-bound,
      SINGLE-USE URL tokens, not short OTP-style codes. The token is UNBOUND (not tied
      to the address it was delivered to); possession of the link is the credential.
      (Known-user invites use no token — own-auth accept; see the FINAL decision above.)
- [x] Permission-group invite acceptance stays separate from account creation.
      If a group invite helped an unknown recipient register, the user still must
      manually accept/redeem the group invite before AuthKit adds the membership.
- [x] Make the invite API/docs name invite kinds clearly: account-registration
      invite and permission-group invite link.
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
      valid, unexpired unbound account-registration invite code is present; `Open`
      stays true; `Closed` false. Call it from the core sites AND the HTTP-layer OIDC/OAuth
      gates (`publicRegistrationDisabled()`), passwordless, and Solana. Solana has no email
      binding and stays fail-closed for new account auto-create under `InviteOnly`.
- [x] Update `internal/authcore/group_invite_links.go` default to a concrete 72h
      `defaultGroupInviteTTL`. Keep explicit per-invite expiry overrides.
- [x] Add the account-registration invite contract separately from group invites,
      including creation, email delivery, validation during registration, expiry,
      revocation, and consumption semantics.
- [x] Update `CreateGroupInviteLink` / `CreateGroupInviteLinkRequest` /
      `GroupInviteLinkCreated` contract docs to name the unbound single-use group-link shape.
- [x] Update `http/permission_group_operations.go` add-member flow: existing
      `user_id` adds directly and silently; email with no account creates/sends an
      unbound group invite instead of failing or auto-adding. If registration is
      invite-only, also create a SEPARATE unbound account-registration invite.
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
      only through a separate account-registration invite; manual group accept required;
      expired/revoked/spent invites rejected; group link still obeys expiry
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

---

# #150: Dead / duplicate / unnecessary code removal

**Completed:** yes — ALL children landed (2026-06-26/27): #155,#162,#168,#169,#171,#176,#179,#180,#184,
#186,#187,#188,#189,#190,#191,#192 are each `Completed: yes` below. The umbrella is closed. Two
non-blocking carryovers flagged for CI/follow-up: the #176 Part B forced-link-failure pinning test
needs a DB-backed run (no fault-injection seam locally), and the #176 targeted fail-closed was taken
over the full resolver-merge (recorded in #176). Ready to archive the done children to completed.md.

Reviewed + pruned 2026-06-26 (Claude): the done / wrong / low-value children were DELETED; only the
actionable ones remained. CAVEAT (historical): child research file:lines DRIFTED — they were re-grepped before each cut.

Remaining dead code / duplicate helpers / same-logic-different-name functions to remove, each its own
child section below. Per-item evidence is in `agents/audits/dead-duplicate-code.md`. Already-tracked
culls (#143–#149, #142) and everything Paul's v0.72 merge already landed are excluded.

## Remaining children (verdicts from the 6-agent review)

Safe internal-only (non-breaking — land first, build+vet green at each gate):
- #162 `clientIP`→`remoteIP`.

Behaviour-preserving consolidations (internal-only):
- #179 verify/confirm/reset handler twins (also FIXES a latent bug: phone confirm-link returns 500 for
  a banned user where email returns 401) · #180 `writeAccessTokenJSON` (adds `token_type` to the
  /token refresh envelope — additive wire change, wants sign-off).

Adapter / shared-pkg extractions (bigger, optional):
- #168 twilio shared helper (new internal pkg for ~28 lines) · #169 `adapters/internal/routepath`
  (gin+chi; a 3rd near-copy lives in `http/oidc_handler.go`) · #171 ratelimit `get`/`remaining`
  (depends on #188).

Public-surface / BREAKING — Paul APPROVED breaking unused exported symbols (no separate per-symbol
sign-off needed); still ride the #143 consumer bump + edit the mapped SEMVER.md section + MAJOR:
- #155 dead exported `http.AllowNamed` (SEMVER §4.5, ~line 323) · #184 orphaned `SolanaConfig` ·
  #187 `PermissionTokenCovers`→`PermMatches` · #188 hoist one `ratelimit.Limit` + drop dup structs ·
  #189 limiter 3-tier→2 + drop `AllowNamedWithRetryAfter` (checklist now includes the
  `ratelimit/memory/limiter_test.go` caller migration) · #191 dead exported helpers.

Internal dead deletes:
- #186 oidc dead SUBSET only — rewritten (most of the original cluster is LIVE) · #190
  `Service.ApplyBootstrapManifestFile` (non-breaking) · #192 `RemoteApplicationRoles` test-only delete
  (rewritten — `RemoveGroupSubject` is intentional and was dropped from scope).

Behaviour change — GREENLIT (no open maintainer calls remain):
- #176 — Paul greenlit BOTH parts: (A) the mechanical `finishBrowserLogin` tail extract, and (B) the
  resolver unification FAIL-CLOSED — OIDC stops silently swallowing `LinkProviderByIssuer` failures and
  now fails the callback like OAuth2 (the "no swallowing authz errors" fix, #136). Land B behind a
  pinning test; preserve OIDC's discord email_verified carve-out + provider-email backfill.

DECISION (do NOT touch without sign-off — two security traps):
- `cmd/authkit-server` local `isDevEnv` looks like a dup of `embedded.IsDevEnvironment` but gates the
  UNAUTHENTICATED management API with an allow-list (`"test"`=dev) vs the canonical deny-list; merging
  WIDENS what counts as dev on a security boundary.
- `siws.Verify` (one-shot, `siws/siws.go`) has zero in-repo callers but is PUBLIC SIWS surface an
  external verifier could use — product decision before cutting.

DECISION (out-of-scope bugs found alongside — fix elsewhere, NOT here): `storage/memory/siws_cache.go`
spawns a cleanup goroutine with no `Close()` (leak); `ratelimit/redis/limiter.go` stores a
`context.Context` in the struct; the http change-flow handlers match `err.Error()` substrings (fragile
— belongs with the error-sentinel work).

## SEMVER reconciliation (for the BREAKING children)
- [x] On each BREAKING removal, edit the mapped SEMVER.md section + MAJOR bump — target the symbol's
      CURRENT package, not the stale one named in the doc.
- [x] DRIFT (coordinate with #143): SEMVER.md §4.1 + the `core`/`authbase`/`identity`/`roles` sections
      still name absent packages; rebase onto the real tree (`embedded` + root `authkit`).
- [x] Specifics: `PermMatches`/`PermissionTokenCovers` live in root `permission.go` (listed under the
      gone `authbase`); `ApplyBootstrapManifestFile` is already absent from SEMVER (just delete).

---

# #155: Delete dead exported `http.AllowNamed` (BREAKING)

**Completed:** yes — done (Paul-approved): deleted the dead pkg-level `AllowNamed` from `http/ratelimit.go`; the 2-arg `RateLimiter.AllowNamed` interface method stays. SEMVER §4.5 drop APPLIED.

Parent #150 (BREAKING, but signed off — breaking an unused exported symbol is acceptable).

RESEARCH (verified): the package-level `func AllowNamed(r *http.Request, rl RateLimiter, bucket string) bool`
(`http/ratelimit.go`) has ZERO in-repo callers — all rate-limiting runs through
`Service.rateLimited`→`allowResult`, which call the 2-arg INTERFACE method `RateLimiter.AllowNamed(bucket, key)`
(a different signature that STAYS). It is exported + in SEMVER §4.5 (~line 323), so removal is BREAKING —
fine per sign-off. (Re-grep before cutting; the original's "clientIP is its only other caller" aside is
wrong — `clientIP` has 16+ callers, so removal won't orphan #162.)

- [x] Delete the package-level `AllowNamed` helper (`http/ratelimit.go`); keep the `RateLimiter` interface + its 2-arg `AllowNamed` method.
- [x] Remove `AllowNamed` from SEMVER §4.5; MAJOR bump (ride the #143 consumer bump).
- [x] `go build ./... && go vet ./...` green.

---

# #162: Collapse `http.clientIP` → `remoteIP`

**Completed:** yes — done: deleted `clientIP`; the 11 handler callers (audit/email_verify/password_reset/passkeys/oidc_browser/oauth2_browser/user_2fa_verify_post/phone_password_reset/auth_token_post/password_login_post) now call `remoteIP`. Internal-only → no SEMVER change. The trusted-proxy audit-vs-ratelimit behaviour split below stays out of scope.

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

- [x] Delete `clientIP` (`ratelimit.go:45-55`); repoint the 11 handler callers to `remoteIP`. (The `ratelimit.go:36` caller disappears with #155; sequence after/with it.)
- [x] `go build ./... && go vet ./...` green.

SEPARATE (behaviour, NOT this dedup — flagged, do not bundle): audit/log IP uses the raw peer
(`remoteIP`), while rate-limit keys use the trusted-proxy-aware `s.clientIP` (`service.go:161`).
Behind a trusted proxy, audit logs the proxy's IP, not the real client. Unifying them changes logged
values, so it needs a deliberate decision — out of scope for this removal.

---

# #168: Extract shared twilio helper (contextLanguage/appLabel/httpClient)

**Completed:** yes — done: added `adapters/twilio/internal/twiliocommon` (`ContextLanguage`/`AppLabel`/`DefaultHTTPClient`); email + sms repoint, keeping `appLabel`/`httpClient` as 1-line delegating methods (each Sender's field + its 10s default preserved). Internal-only → no SEMVER change.

Parent #150 (Tier 2, internal-only; advanced "Provided" adapter, low priority).

RESEARCH (2026-06-26, verified): `adapters/twilio/email` and `adapters/twilio/sms` are SEPARATE
packages (both named `twilio`, different import paths). `contextLanguage(ctx)` is byte-identical
(`email/twilio.go:162-180` ≡ `sms/twilio.go:136-154`). `appLabel()` is identical logic but a METHOD on
each package's own `*Sender` (`email:259-264`, `sms:129-134`). `httpClient()` is the same shape
(`email:~98`, `sms:94-99`) — VERIFY the default `Timeout` matches before sharing (sms defaults to 10s).
Sharing requires a new shared internal package; the methods become free functions over the field value.

- [x] Add a shared internal pkg (e.g. `adapters/twilio/internal/common`): `ContextLanguage(ctx) string`, `AppLabel(name string) string`, default-`*http.Client` constructor.
- [x] Repoint email + sms; keep `appLabel`/`httpClient` as 1-line methods delegating to it (preserve each Sender's field access + its default timeout).
- [x] `go build ./... && go test ./adapters/twilio/...` green.

---

# #169: Extract `adapters/internal/routepath` (gin/chi)

**Completed:** yes — done: added `adapters/internal/routepath` (`ParamNames`/`Clean`/`Join`); gin + chi repointed, duplicated local helpers deleted.

Parent #150 (Tier 2, internal-only; advanced "Provided" adapter, low priority).

RESEARCH (2026-06-26, verified): `routeParamNames`, `cleanMountPath`, `joinRoutePath` are
byte-identical across `adapters/gin/gin.go:99-128` and `adapters/chi/chi.go:84-113`, pure string ops
with NO router dependency, and all three are LIVE in both (gin `:78,:54,:119,:57`; chi
`:74,:54,:65,:104,:75`). The router-specific glue (gin `SetPathValue`, chi `URLParam`) stays per
adapter; only these three move.

- [x] Add `adapters/internal/routepath` exporting `ParamNames`/`Clean`/`Join`.
- [x] Repoint gin + chi to it; delete the duplicated copies.
- [x] `go build ./... && go test ./adapters/...` green.

---

# #171: Move ratelimit `get`/`remaining` to shared pkg

**Completed:** yes — done: moved to `ratelimit.LookupLimit`/`ratelimit.Remaining`; both backends repointed, local copies deleted.

Parent #150 (Tier 2, internal-only; advanced "Provided" pkg, low priority).

RESEARCH (2026-06-26, verified): both helpers are byte-identical across backends. `remaining(limit,
used int) int` (`memory/limiter.go:224-230` ≡ `redis/limiter.go:133-139`) is a pure int helper with NO
type dependency — movable now. `get(bucket) (Limit, bool)` (`memory:48-56` ≡ `redis:33-41`, incl. the
hardcoded `Limit{Limit:100, Window:time.Minute}` fallback) returns the PACKAGE-LOCAL `Limit` type, so
it can only move once `Limit` is hoisted to the shared `ratelimit` pkg — DEPENDS ON #188. The
sliding-window storage itself (in-mem slice vs Redis ZSET) genuinely differs and stays per-backend.

- [x] Move `remaining` to the shared `ratelimit` pkg as `Remaining(limit, used int) int`; repoint both backends.
- [x] AFTER #188 (shared `ratelimit.Limit`): move `get` as `LookupLimit(limits, bucket) (ratelimit.Limit, bool)`; repoint both; delete the per-backend copies.
- [x] `go build ./... && go test ./ratelimit/...` green.

---

# #176: Extract `resolveBrowserUser` + `finishBrowserLogin` (OIDC/OAuth)

**Completed:** yes. PART A done: extracted `finishBrowserLogin(w, r, userID, email, providerName, sessionEvent, created, sd)` (oidc_browser.go) covering the shared post-resolve tail; both callbacks delegate; behaviour-preserving (JSON branch now routes through #180's `writeAccessTokenJSON`). PART B done via the TARGETED fail-closed fix rather than the full resolver-merge: the two OIDC `_ = LinkProviderByIssuer(...)` swallow sites now fail the callback with `ErrProviderLinkFailed` (matching OAuth2's code + logging). Chose this over rewiring OIDC onto `resolveOAuthUser` because the merge's ONLY behavioural payload is the fail-closed handling, and the targeted fix preserves the OIDC-only quirks the issue said to keep (the `provider != "discord"` carve-out + provider-email backfill) at far lower risk. Build + existing OIDC happy-path tests green (regression for "successful login still completes"). NOTE: the forced-link-failure pinning test isn't constructible in this env (no DB, `s.svc` is concrete `*authcore.Service` with no fault-injection seam) — needs a DB-level fault or a service seam; flag for CI/follow-up.

Parent #150 (Tier 3). The post-resolve TAIL extract is a safe, behaviour-preserving dedup; the
resolver merge is NOT — keep it out of scope (or do it as a separate, deliberate behaviour-change step).

RESEARCH (2026-06-26, re-verified against current code):

SAFE — the post-resolve TAIL is shape-identical and parameterizable. OIDC `handleOIDCCallbackGET` tail
(`http/oidc_browser.go:229-303`) and OAuth2 `handleOAuthCallbackGET` tail (`http/oauth2_browser.go:239-312`)
are the same sequence: `IssueRefreshSessionWithAuthMethods(ctx, userID, UA, nil, {"oauth"})` (both pass
`nil` IP) with identical 2FA-enrollment / banned / `ErrSessionIssueFailed` handling → `extra["sid"]` →
`IssueAccessToken(ctx, userID, email, extra)` with identical banned / `ErrTokenIssueFailed` handling →
`LogSessionCreated` → `if created { SendWelcome }` → popup-HTML / JSON / fragment-redirect envelope (all
three branches byte-identical: same CSP header, `buildPopupHTML`, `buildAuthResultFragment`). ONLY
differences are parameterizable: provider string (`provider` vs `cfg.Name`), session-event label
(`"oidc_login"` vs `"oauth_login:"+cfg.Name`), and a local-var name.

NOT SAFE — the "resolve the user" section PRECEDING the tail has DIVERGED; merging it is a behaviour
change, not a dedup. OIDC resolves inline (`oidc_browser.go:135-227`); OAuth2 uses `resolveOAuthUser`
(`oauth2_browser.go:376-461`). Divergences:
- LINK-WRITE FAILURE (security boundary): OAuth2 FAILS the callback on `LinkProviderByIssuer` error
  (`oauth2_browser.go:386-389,443-446`); OIDC SWALLOWS it (`_ = s.svc.LinkProviderByIssuer(...)` at
  `oidc_browser.go:151,222`).
- DISCORD carve-out: OIDC gates email_verified on `provider != "discord"` (`oidc_browser.go:215`); OAuth2
  has none (`oauth2_browser.go:447`).
- PROVIDER-EMAIL BACKFILL: OIDC back-fills `email` from the stored provider email (`oidc_browser.go:157-159`);
  OAuth2 discards it.
- CREATE-BRANCH WRITE ORDER: OIDC SetEmailVerified→ConsumeInvite→Link (`:213-222`); OAuth2
  Link→SetEmailVerified→ConsumeInvite (`oauth2_browser.go:443-452`).
- ERROR STYLE: OIDC writes HTTP inline; OAuth2 returns sentinels the caller maps (`oauth2_browser.go:217-237`).
- INPUT TYPE: OIDC `oidckit.Claims` (pointer fields) vs OAuth2 `oauth2UserInfo` (value fields).

SCOPE — TWO parts, BOTH greenlit (Paul 2026-06-26). Land Part A first (mechanical, green at the gate),
then Part B (the deliberate behaviour change) behind its pinning test.

PART A — mechanical tail extract (behaviour-preserving):
- [x] Extract `finishBrowserLogin(w, r, userID, email, providerName, sessionEvent string, created bool, sd oidckit.StateData)` covering `oidc_browser.go:229-303` + `oauth2_browser.go:239-312`. Parameterize providerName + sessionEvent; pass `email` in; re-derive `state` inside via `r.URL.Query().Get("state")`. Call from each handler right after the user is resolved.
- [x] `go build ./... && go test ./http/` green (no behaviour change → existing tests pass unmodified).

PART B — resolver unification, GREENLIT, FAIL-CLOSED (this is a deliberate, correct behaviour change):
- [x] FAIL-CLOSED link handling: a `LinkProviderByIssuer` error now FAILS the callback (the two
      `oidc_browser.go:151,222` swallow sites now `serverErr(ErrProviderLinkFailed)`). DONE via a
      TARGETED fix at those two sites, NOT the full "unify onto `resolveOAuthUser`" rewrite — the
      merge's only behavioural payload was this fail-closed flip, so the targeted change achieves it
      at lower risk (see the Completed note above).
- [x] PRESERVE the OIDC-only behaviours: the `provider != "discord"` email_verified carve-out and the
      already-linked provider-email backfill stay intact (untouched by the targeted fix).
- [ ] Normalize `oidckit.Claims` → `resolveOAuthUser`'s value shape — NOT DONE / moot: the targeted
      fix kept OIDC's own resolver, so no Claims→oauth2UserInfo adapter was needed.
- [ ] PINNING TEST (forced link failure) — NOT DONE: not constructible in-repo without a DB-level
      fault or a service seam (`s.svc` is concrete `*authcore.Service`). Deferred to CI/follow-up; the
      SUCCESS-path regression is covered by the existing OIDC happy-path tests.
- [x] `go build ./... && go vet ./...` + existing `./http/` tests green.

---

# #179: Parameterize verify/confirm/password-reset handler twins

**Completed:** yes. (a) Extracted a `verifyChannel` descriptor + shared `confirmVerificationToken`/`handleVerifyLinkFailure`/`issueVerifiedTokens` (new `http/verify_confirm_link.go`); the email/phone confirm-link files are now thin wrappers. ASYMMETRY FIXED: a banned user confirming a PHONE link now gets 401 (was 500), matching email — pinned by `TestPhoneVerifyConfirm_BannedUserGets401` (verified by code path: `ConfirmPhoneVerificationByTokenUserID` has no ban check → `issueVerifiedTokens` → `ensureUserAccess` → `ErrUserBanned` → 401; test skips here, no DB). (b) Extracted `mapContactChangeError` (shared change-flow substring switch; matching kept fragile per plans 008/009/011). (c) Extracted `confirmPasswordReset` (shared confirm+error-mapping; request halves kept separate). Build + http tests green.

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

- [x] (a) Parameterize the confirm-link twins by a channel descriptor (validator, normalizer, the 3 confirm-by-token fns, GetUserBy*, verified-field, error codes); decide the unified `ErrUserBanned`→401 handling (fixes the phone 500).
- [x] (b) Share the verify-request change-flow switch; do NOT fix the substring matching here (→ plans 008/009/011).
- [x] (c) Share the password-reset CONFIRM handler (one body, success payload as a param); leave the request halves separate.
- [x] `go build ./... && go test ./http/` green; add a test pinning banned-user phone-confirm → 401.

---

# #180: Add `writeAccessTokenJSON`; migrate inline token envelopes

**Completed:** yes — added `newAuthTokens(access, refresh, exp)` (kills the `time.Until`/`"Bearer"` dup, incl. inside `createTokensForUser`) + `writeAccessTokenJSON(w, status, authTokensResponse, extra)` (marshals the struct + merged extras). Migrated the full-envelope sites: passwordless (+return_to), solana (+created/user), passkeys, user_2fa_verify, password_login (the 4-field branch only), auth_token_post (`/token` refresh). CONFIRMED change: `/token` now emits `token_type` (was absent) — additive + §6.3-conforming. Left untouched the distinct shapes: password_login's 3-field no-refresh re-issue, the 2FA-enrollment token, and step-up (no refresh_token). All http tests green.

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

- [x] Add `writeAccessTokenJSON(w, status int, access, refresh string, exp time.Time, extra map[string]any)` emitting the 4 core fields + merged extras.
- [x] Migrate the 7 sites; extras carry `return_to` (passwordless), `created`+`user` (solana), etc.
- [x] CONFIRM the `auth_token_post.go` change (gains `token_type`) is acceptable — additive + contract-conforming; note in SEMVER §6.3 if needed.
- [x] `go build ./... && go test ./http/` green.

---

# #184: Drop orphaned `SolanaConfig` type (BREAKING)

**Completed:** yes — UNBLOCKED + done (Paul 2026-06-27: "for solana config just network is sufficient, rest can be hardcoded; SNS can be always-on"). Two parts, both done:
- Deleted `authcore.SolanaConfig` (`config.go`) + the `embedded.SolanaConfig` alias; SEMVER §4.2 drops it. Live Solana config stays the flat `Config.SolanaNetwork string`.
- Removed the SNS knobs per Paul: dropped `Options.SolanaSNSEnabled/SolanaSNSLookupTimeout/SolanaSNSCacheTTL`; SNS is now unconditionally on (prerequisite is only a Postgres store) with the fixed 3s timeout / 24h cache constants. Removed the now-unreachable `SolanaSNSStatusDisabled` status (const + emit branches + `embedded` alias) and `TestSolanaSNSDisabledMetadata`. Stale-refresh coverage preserved via an unexported `snsCacheTTLOverride` test seam.

MAJOR — rides #143. All green incl. SNS suite.

Parent #150 (Tier 4, BREAKING → rides #143's Solana cull).

RESEARCH (2026-06-26, verified): `authcore.SolanaConfig` (`config.go:137-151`; fields Network /
SNSEnabled / SNSResolver / SNSLookupTimeout / SNSCacheTTL) is re-exported as `embedded.SolanaConfig`
(`aliases.go:60`) but is STRUCTURALLY DEAD — grep shows only the type def + the alias; no `Config`
(or any struct) has a `SolanaConfig` field and none of its fields are read anywhere. The live Solana
config is the flat `Config.SolanaNetwork string` (`config.go:55`, read at `service.go:400`).
SEMVER §4.2 lists `SolanaConfig` as a covered config type while §7.3 lists the live `SolanaNetwork` —
so the type is covered-but-orphaned. Removal is BREAKING (public `embedded.SolanaConfig`) but inert
(no consumer can wire it to anything).

- [x] Delete `authcore.SolanaConfig` (`config.go:137-151`) + the `embedded.SolanaConfig` alias (`aliases.go:60`).
- [x] Remove `SolanaConfig` from the SEMVER §4.2 config-types list; MAJOR bump — ride the #143 consumer bump.
- [x] `go build ./... && go vet ./...` green.

---

# #186: Delete dead `oidc/defaults.go` builder cluster (BREAKING)

**Completed:** yes — done: deleted `DefaultsFor`, `NewManagerFromMinimal`, `applyMinimalConfig`, `mergeScopes` (`oidc/defaults.go`) + `AppleWithKey` (`oidc/apple.go`); kept the live chain (`NewManagerFromProviders`/`RPClientFromProvider`/`cloneStringMap`/`ensureOpenID`/`RPConfig`). The 3 dead tests removed (their openid-gating coverage is preserved by the `FromProviders` descriptor tests). SEMVER §4.4 drops `AppleWithKey`. MAJOR — rides #143.

Parent #150 (BREAKING — `AppleWithKey` is in SEMVER §4.4).

RESEARCH (rewritten 2026-06-26 after sub-agent verification): most of the original "dead cluster" is
LIVE — `NewManagerFromProviders` (`http/oidc_link_start_post.go`) reaches `RPClientFromProvider` →
`cloneStringMap` + `ensureOpenID`, so those STAY. Genuinely dead (zero non-test callers, grep-verified):
`DefaultsFor`, `NewManagerFromMinimal` (test-only), `applyMinimalConfig` (only via
`NewManagerFromMinimal`), `mergeScopes` (only via `applyMinimalConfig` — this also closes the old #165),
and `AppleWithKey`. `RPConfig` and the live mapping are out of scope here (their removal is #143's
`Providers map→[]authprovider.Provider`). #166 is moot — `cloneStringMap` stays live.

- [x] Delete ONLY: `DefaultsFor`, `NewManagerFromMinimal`, `applyMinimalConfig`, `mergeScopes`, `AppleWithKey`. Re-grep each immediately before cutting; confirm zero non-test callers (delete inner-most first).
- [x] KEEP the live chain: `NewManagerFromProviders`, `RPClientFromProvider`, `cloneStringMap`, `ensureOpenID`, `RPConfig`.
- [x] Drop `AppleWithKey` (and any other deleted SEMVER-listed symbol) from SEMVER §4.4; MAJOR bump (ride #143).
- [x] Move/delete the oidc tests exercising the deleted builders; `go build ./... && go test ./...` green.

---

# #187: Collapse `PermissionTokenCovers` → `PermMatches` (BREAKING)

**Completed:** yes — done: deleted `PermissionTokenCovers` (`permission.go`); repointed `verify/claims.go` + `verify/verifier.go` to `PermMatches` (which already trims, so behaviour-identical). SEMVER §4.3 drops `PermissionTokenCovers` (and the stale `authbase`→root `authkit` location is fixed in the same pass). MAJOR — rides #143.

Parent #150 (Tier 4, BREAKING).

RESEARCH (2026-06-26, verified): `PermissionTokenCovers` (`permission.go:50-54`) is
`return PermMatches(strings.TrimSpace(grant), strings.TrimSpace(requested))` — and `PermMatches`
(`permission.go:18-20`) ALREADY trims both args on entry, so the wrapper's only added work is a
redundant double-trim. Both exported, same package. In-repo callers: `verify/claims.go:230`,
`verify/verifier.go:269` — both can call `PermMatches` directly. SEMVER §4.3 (`SEMVER.md:274`) lists
`PermMatches`/`PermissionTokenCovers` under `authbase` (STALE — they now live in root `authkit`
`permission.go`); removal is BREAKING (an external resource server could import `PermissionTokenCovers`).

**Idiomatic target:** no redundant wrapper — `PermMatches` already trims and is the one matcher; a second name that only re-trims is noise.

- [x] Repoint `verify/claims.go:230` + `verify/verifier.go:269` to `PermMatches`; delete `PermissionTokenCovers` (`permission.go:50-54`).
- [x] Drop `PermissionTokenCovers` from SEMVER §4.3 (fix the stale `authbase`→root location while there); MAJOR bump — ride the #143–#149 train.
- [x] `go build ./... && go test ./...` green.

---

# #188: Hoist one `ratelimit.Limit`; delete dup structs + converters (BREAKING)

**Completed:** yes — done: one `ratelimit.Limit`; deleted the 3 dup structs + `ToMemoryLimits`/`ToRedisLimits`; `DefaultRateLimits` returns `map[string]ratelimit.Limit` and `server.go` passes it straight to `New`. SEMVER §4.4/§4.5 APPLIED.

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

- [x] Add `ratelimit.Limit`; change both backends' `New(rdb, map[string]ratelimit.Limit)`; have `http` consume `ratelimit.Limit`.
- [x] Delete `memorylimiter.Limit`, `redislimiter.Limit`, `authhttp.Limit`, `ToMemoryLimits`, `ToRedisLimits`.
- [x] Update SEMVER §4.4 + §4.5; MAJOR bump.
- [x] `go build ./... && go test ./ratelimit/... ./http/` green. (Then #171's `get` can move.)

---

# #189: Collapse limiter interface 3-tier → 2; drop `AllowNamedWithRetryAfter` (BREAKING)

**Completed:** yes — done: dropped `RateLimiterWithRetryAfter` + the unreachable type-switch branches + both backend `AllowNamedWithRetryAfter` methods; the memory cooldown/window tests preserved via an `allowRetry` helper over `AllowNamedResult`. SEMVER §4.5 drop APPLIED.

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

- [x] Delete the `RateLimiterWithRetryAfter` interface (`http/ratelimit.go:26-28`) + the middle type-switch branch in `allowResultForKey`/`allowResult`.
- [x] Delete `AllowNamedWithRetryAfter` from both backends (`memory/limiter.go:72`, `redis/limiter.go:49`).
- [x] MIGRATE its only direct callers — `ratelimit/memory/limiter_test.go:89,97,114,122` (call
      `AllowNamedResult` and read the result instead) — else the test package won't compile.
- [x] Keep `RateLimiter` + `RateLimiterWithResult`.
- [x] Update SEMVER §4.5 (drop `RateLimiterWithRetryAfter`); MAJOR bump.
- [x] `go build ./... && go test ./ratelimit/... ./http/` green.

---

# #190: Delete orphaned `Service.ApplyBootstrapManifestFile`

**Completed:** yes — done: deleted the method; its test now uses `LoadBootstrapManifestFile`+`ApplyBootstrapManifest`. Off-contract → no SEMVER change.

Parent #150 (listed under Tier 4, but actually NON-BREAKING on revalidation — can land with Tier 1).

RESEARCH (2026-06-26, verified): `Service.ApplyBootstrapManifestFile` (`bootstrap_manifest.go:78`) has
only ONE caller — its own test (`bootstrap_manifest_test.go:493,511`). It is NOT on the contract:
`client.go:164-165` explicitly documents "There is deliberately no ApplyBootstrapManifestFile on the
contract" (the #142 decision — a file path is the server's filesystem, meaningless for a remote
client), and it is NOT on the `embedded` facade (only `ApplyBootstrapManifest` is, `facade_methods.go:337`).
So although exported on the internal `Service`, it is unreachable by any consumer → effectively
internal-only, NON-BREAKING, already absent from SEMVER (no SEMVER edit). The load-then-apply
composition lives in the devserver (`LoadBootstrapManifestFile` + `ApplyBootstrapManifest`).

- [x] Delete `ApplyBootstrapManifestFile` (`bootstrap_manifest.go:78`).
- [x] Rewrite `TestApplyBootstrapManifestFileLoadsAndAppliesYAML` (`bootstrap_manifest_test.go:493`) to call `LoadBootstrapManifestFile` + `ApplyBootstrapManifest` (preserve the YAML-load coverage).
- [x] `go build ./... && go test ./internal/authcore/` green. No SEMVER change / no bump — may land with Tier 1.

---

# #191: Remove dead exported helpers

**Completed:** yes — done: removed `verify.RemoteAppOptions` (kept unexported `remoteAppOptions`), `jwt.NewStaticKeySourceFromRing`, `jwt.RSAPublicToJWK`, `authprovider.BuiltIns`, `http.MintDelegatedAccessToken`+`http.DelegatedAccessParams` (the ~12 http test sites migrated to `embedded.MintDelegatedAccessToken`+`authkit.DelegatedAccessParams`), and the `embedded.ParseBootstrapManifestYAML` alias (underlying `authcore.ParseBootstrapManifestYAML` + `LoadBootstrapManifestFile` stay). SEMVER §4.3 drops the `(+RemoteAppOptions)` note; §4.4 drops `BuiltIns`; §4.2 drops `ParseBootstrapManifestYAML` (and §6.6 ref). MAJOR — rides #143.

Parent #150 (Tier 4, BREAKING — unused/test-only exported helpers, removed on merits). Each verified
by a repo-wide caller sweep (2026-06-26):

**Idiomatic target:** minimal exported surface — every exported symbol is a promise; convenience wrappers no consumer calls are API debt. Keep the one entry point each (`PublicToJWK`, `BuiltIn`, `LoadBootstrapManifestFile`, `remoteAppOptions`).

- [x] `verify.RemoteAppOptions` (`verify/helpers.go:17`) — ZERO callers anywhere (the stated authhttp reuse never happened); the unexported `remoteAppOptions` is the real one. Remove the exported alias; keep `remoteAppOptions`. SEMVER §4.3 drops the "(+RemoteAppOptions)" note.
- [x] `jwt.NewStaticKeySourceFromRing` (`jwt/keyring.go:39`) — ZERO callers. Remove. KEEP `KeyRing`/`NewKeyRing` (legit Advanced rotation primitive; `NewKeyRing` is test-only in-repo but public). Not individually named in SEMVER §4.4.
- [x] `jwt.RSAPublicToJWK` (`jwt/jwks.go:40`) — ZERO callers; narrowing wrapper of `PublicToJWK`. Remove. Covered by the SEMVER §4.4 jwtkit "conversion funcs" set, not by name.
- [x] `authprovider.BuiltIns()` (`authprovider/provider.go:117`) — ZERO callers; singular `BuiltIn(name)` is what's used. Drop `BuiltIns` from the SEMVER §4.4 authprovider list.
- [x] `http.MintDelegatedAccessToken` + `http.DelegatedAccessParams` (`http/delegation.go:35,25`) — thin re-exports of `embedded.MintDelegatedAccessToken` / `authkit.DelegatedAccessParams`; NO production caller, but ~15 http TEST sites use them (`delegation_verify_test.go`, `service_jwt_test.go`, `jwks_resilience_test.go`). Migrate those tests to `embedded.MintDelegatedAccessToken(ctx, signer, p)` + `authkit.DelegatedAccessParams` (as `admin_directory_test.go:364` already does), THEN delete the http re-export + alias. CORE symbols stay (SEMVER §4.2); the http re-exports are NOT in SEMVER §4.5 → no §4.5 edit.
- [x] `embedded.ParseBootstrapManifestYAML` ALIAS only (`embedded/aliases.go:166`) — the alias has no in-repo consumer; KEEP the underlying `authcore.ParseBootstrapManifestYAML` (used by `LoadBootstrapManifestFile:75` + 9 authcore tests). Drop only the embedded re-export; SEMVER §4.2 drops `ParseBootstrapManifestYAML` from the bootstrap-types list (`LoadBootstrapManifestFile` stays as the seam).
- [x] `go build ./... && go test ./...` green; MAJOR bump — ride the #143–#149 train.

---

# #192: Demote/remove test-only exported Service methods

**Completed:** yes — done: unexported `RemoteApplicationRoles` → `remoteApplicationRoles` (preserves the two authcore tests, which call it same-package); off-contract, so no SEMVER change. `RemoveGroupSubject` stays (out of scope below — it's the intentional genesis twin).

Parent #150 (listed under Tier 4, but NON-BREAKING — not re-exported to consumers).

RESEARCH (2026-06-26, re-verified): `Service.RemoteApplicationRoles`
(`internal/authcore/remote_application_memberships.go:69`) is test-only — sole callers
`remote_application_owner_test.go:43` and `bootstrap_manifest_test.go:324`. NOT on the contract
(`client.go`) or the embedded facade. The real authority path is `ResolveRemoteApplicationAuthority`
(contract `client.go:151`; consumed by `verify/verifier.go:321`). Clean dead-delete — no public
surface, no SEMVER impact.

OUT OF SCOPE (was previously bundled here): `Service.RemoveGroupSubject` (non-`As`,
`permission_group_service.go:210`) is NOT dead — it is the documented unchecked genesis/migration twin
of unchecked `AssignGroupRole`, intentionally retained (`permission_group_assign_authz.go:157`;
`facade_methods.go:72`). The runtime member-removal path is the actor-aware `RemoveGroupSubjectAs`
(contract `client.go:96`, used at `http/permission_group_operations.go:153`). Leave it.

**Idiomatic target:** a method only tests call should not be exported.

- [x] Delete (or unexport) `Service.RemoteApplicationRoles` (`remote_application_memberships.go:69`).
- [x] Repoint/remove its two tests (`remote_application_owner_test.go:43`, `bootstrap_manifest_test.go:324`) — assert via `ResolveRemoteApplicationAuthority` or the group store directly.
- [x] `go build ./... && go test ./internal/authcore/` green. No SEMVER edit (not on the public surface).

---

# #193: Self-leave permission groups + per-persona `RequireConsent` join policy

**Completed:** yes

IMPLEMENTED 2026-06-26 (Claude), all green (full suite 20/20 vs real Postgres + ClickHouse):
- A `RequireConsent bool` on `PersonaDef` (default false); `GroupSchema.RequireConsent(persona)`
  accessor; root stays instant (zero value). `groupMemberAdd` upgrades a known-user direct-add to a
  consent invite when the persona requires it (`if body.Invite || RequireConsent(persona)`). Tests:
  `TestPersonaRequireConsent`, `TestRequireConsent_HTTP_ForcesInvite`.
- B `LeaveGroup(ctx,userID,persona,instance)` removes the caller's own direct roles (no
  members:manage) via `UnassignSubject`; route `DELETE /me/groups/{persona}/{instance_slug}`
  (`handleMeGroupLeave`); on `authkit.Client` + facade + regenerated remote SDK. Tests:
  `TestLeaveGroupAndLastOwnerGuard_DB`, `TestMeGroupLeave_HTTP`.
- C shared last-owner guard: `PermissionGroupStore.OwnerCount` + `Service.refuseIfLastOwner`, wired
  into BOTH `RemoveGroupSubjectAs` and `LeaveGroup`; HTTP maps it to 409 `cannot_remove_last_owner`
  (reuses the `ErrCannotRemoveLastAdminRole` sentinel — no new sentinel/count-test churn).
- D docs: `agents/api-endpoints.md` (self-service membership table + RequireConsent note).
DECISION made: direct-add under RequireConsent is silently CONVERTED to an invite (202 invited), not
rejected — the caller's "add this person" intent is satisfied as "invite this person".

Proposed 2026-06-26 (Paul). Two membership gaps surfaced reviewing #147's invite model:
1. A member CANNOT voluntarily leave a permission group. The only removal path is the
   admin route `DELETE /<persona>/<instance_slug>/members/{user_id}` gated on
   `<persona>:members:manage` — a regular member is 403'd at the route gate, so they're
   stuck in any group they were added to. Self-removal is a basic feature that's missing.
2. The consent-vs-instant-add decision is a per-REQUEST whim (the `invite:true/false` flag
   on the member-add body). It should be an APPLICATION POLICY set per persona type in
   `Config.RBAC`, not chosen per call. Root should default to instant (no consent).

## Decisions

- CONSENT IS A PER-PERSONA POLICY. Add `RequireConsent bool` to `PersonaDef` (default
  `false`). The app declares it once per persona type in `Config.RBAC`. This is a membership
  POLICY, not a `PersonaCapabilities` flag.
  - `false` (default; what `root` uses) — an owner/manager may DIRECT-ADD an existing user
    instantly, no acceptance. They MAY still send a consent invite if they choose.
  - `true` — admitting a NEW member ALWAYS routes through a consent invite
    (`CreateGroupMembershipInvite`); a silent direct-add cannot drop someone into the group
    without their accept.
- ROOT DEFAULTS TO INSTANT. `IntrinsicRootPersona` leaves `RequireConsent` at its zero value
  (`false`) so operators managing the platform have no acceptance friction; force-add is the
  root default, not invite.
- POLICY IS A FLOOR, NOT A CEILING. The per-request `invite:true` may ask for MORE consent
  (send an invite even where not required); it can never ask for LESS — `invite:false` is
  ignored/overridden when the persona has `RequireConsent: true`.
- CONSENT GATES THE JOIN ONLY. Changing an existing member's role (`groupMemberRole`) and
  removing a member (`groupMemberRemove`) are ADMIN authority — immediate, NO acceptance,
  UNCHANGED. Acceptance is about opting INTO a group, not about an admin managing a member
  already in it. (No-escalation still applies to those admin actions; that's authority, not
  consent.)
- USERS CAN LEAVE. Any member may self-remove from a group instance with their OWN auth (no
  `members:manage`): new route `DELETE /me/groups/{persona}/{instance_slug}` + new core
  `LeaveGroup` that removes only the CALLER's own DIRECT roles in that group.
- LAST-OWNER GUARD (shared). A sole owner cannot leave (or be admin-removed) and orphan a
  group — generalize `ErrCannotRemoveLastAdminRole` (today root-group only) to any persona
  instance's last owner. They must add/transfer another owner first.
- UNKNOWN-EMAIL PATH UNAFFECTED. A non-existent user is always a shareable single-use LINK
  (redeeming IS the consent), regardless of `RequireConsent`.
- NO NEW DB TABLE / MIGRATION. `RequireConsent` is in-memory schema config; `LeaveGroup`
  reuses `UnassignSubject`. No notifications on direct-add / role-change / removal / leave.

## Tasks

### A. Per-persona `RequireConsent` join policy
- [x] Add `RequireConsent bool` to `PersonaDef` (`internal/authcore/permission_group.go:135`);
      surface it on the public `authkit.PersonaDef` shape too.
- [x] `IntrinsicRootPersona` (`permission_group_root.go:55`) leaves `RequireConsent=false`
      (zero value) — add a test asserting root is instant-add.
- [x] Expose the persona's policy via `GroupSchema` (e.g. `RequireConsent(persona) bool` or a
      `Persona(name)` lookup) so the member-add path can read it from the immutable schema.
- [x] Enforce in `groupMemberAdd` (`http/permission_group_operations.go:33`): for a KNOWN
      target user, if the persona's `RequireConsent` is true, ALWAYS create a
      `CreateGroupMembershipInvite` (override `invite:false`); if false, honor the request flag
      (direct-add default, consent invite when `invite:true`). The unknown-email branch is
      unchanged (always a link).
- [x] DECISION: direct-add under `RequireConsent:true` — RECOMMEND silently CONVERT to an
      invite (return `202 invited`), since the caller's intent ("add this person") is satisfied
      as "invite this person"; alternative is an explicit error. Pick one and document it.
- [x] No new schema-validation rule needed (it's a bool); document `RequireConsent` in the
      `PersonaDef` doc comment + the RBAC config docs (default instant; root instant).

### B. Self-leave (`LeaveGroup`)
- [x] Add core `LeaveGroup(ctx, userID, persona, instanceSlug)`
      (`internal/authcore/permission_group_assign_authz.go`): remove the caller's OWN direct
      roles at that group via `UnassignSubject`; NO `members:manage` check (subject == actor).
      Apply the last-owner guard (see C). Leaving a group you're not in is a no-op.
- [x] Add route `DELETE /me/groups/{persona}/{instance_slug}` under `RouteAccount`
      (`http/routes.go`, by the `/me/group-invites` routes), handler `handleMeGroupLeave`
      (`http/group_membership_invites.go` or a new `http/me_groups.go`): read the caller from
      claims, call `s.svc.LeaveGroup`, map the last-owner error to 409.
- [x] Add `LeaveGroup` to the broad `authkit.Client` interface (`client.go`) + `embedded.Client`
      facade (mirroring `RemoveGroupSubjectAs`); regenerate the remote SDK
      (`go run ./internal/genremote`).
- [x] Per-role leave variant (`DELETE /me/groups/{persona}/{instance_slug}/roles/{role}`) only
      if a real need appears; default is full leave (drop all the caller's direct roles there).

### C. Last-owner guard (shared by admin-remove + self-leave)
- [x] Generalize the sole-owner protection so BOTH `RemoveGroupSubjectAs` AND `LeaveGroup`
      refuse to remove the FINAL owner of a group instance. Today `ErrCannotRemoveLastAdminRole`
      guards only the root group's last admin — add a per-group "last owner" check (count owners
      of the gid; refuse if removing the last one), reusing that sentinel or a new
      `ErrCannotLeaveAsLastOwner` with a clear HTTP code.

### D. Tests + docs
- [x] DB-backed: `RequireConsent:true` forces an invite (direct-add converted/rejected);
      `RequireConsent:false`/root direct-adds instantly; `invite:true` still sends a consent
      invite under a non-consent persona.
- [x] DB-backed: a member self-leaves (role gone after); a non-last owner can leave; the sole
      owner is refused; leaving a non-membership is a no-op/404.
- [x] DB-backed: role-change and admin-remove of an EXISTING member stay immediate with no
      acceptance regardless of `RequireConsent` (the join-only boundary).
- [x] README / RBAC docs: document `RequireConsent` (per-persona, default instant, root instant)
      and the `DELETE /me/groups/...` self-leave route.
- [x] `go test ./...` green.

## Non-goals

- Do NOT add acceptance to role-change or removal of EXISTING members — admin-only, immediate.
- Do NOT notify (email/SMS) on direct-add, role-change, removal, or self-leave.
- No new persona CAPABILITY — `RequireConsent` is a membership policy on `PersonaDef`, not part
  of `PersonaCapabilities{APIKeys, RemoteApplications, CustomRoles}`.

## Depends on / coordinates with

- #145 (RBAC single-source): `RequireConsent` is a new `PersonaDef` field — coordinate with the
  schema build/validation there.
- #147 (invites): the consent-invite mechanism (`CreateGroupMembershipInvite` +
  `/me/group-invites` accept/decline) is what the `RequireConsent` join policy routes into.

---

# #194: Consolidate authkit-devserver into authkit-server (one binary; migrate integration tests)

**Completed:** yes

IMPLEMENTED 2026-06-28 (Claude). One binary now. Decision on the OPEN fork: PORTED
`/dev/mint` as-is (smallest migration — downstream suite unchanged; the `MintCustomJWT`
retirement stays a future follow-up). Folded into `cmd/authkit-server` behind the
existing `isDevEnv()` gate: `GET {prefix}/dev/whoami` (dev env) and `POST {prefix}/dev/mint`
(dev env + `AUTHKIT_DEV_MINT_SECRET`, double-gated/fail-closed). `/dev/mint` builds an
explicit `NewAutoKeySourceWithPath` so JWKS and the mint signer share one active key; the
prod path keeps `Keys.Path` auto-discovery untouched. Also ported `AUTHKIT_STATIC_ENTITLEMENTS`
(dev-gated `WithEntitlements`) and `AUTHKIT_API_KEY_PREFIX` (normal config). Added a `migrate`
subcommand + `AUTHKIT_MIGRATE_ON_START` (default false; compose sets true) — the README/CI no
longer depend on the devserver's migrate runner. DROPPED (deliberate): the `bootstrap apply`
CLI + `ApplyBootstrapOnStart` (nothing in the integration path scripts them; the
`LoadBootstrapManifestFile`+`ApplyBootstrapManifest` composition stays in `embedded`) and the
already-DEAD `DEVSERVER_PERMISSION_CATALOG`. Repointed `docker-compose.yaml` `issuer` at a new
`cmd/authkit-server/Dockerfile` with `AUTHKIT_*` env; updated CI step names, README, SEMVER §1.2/§9,
Taskfile desc, `.gitignore`. Deleted `cmd/authkit-devserver/`.

VALIDATION: `go build ./...` + `go vet ./...` + `gofmt` green. Live end-to-end against a fresh
compose Postgres: migrate-on-start applied the schema (healthz green), JWKS served, `/dev/mint`
rejected a wrong secret (401) and minted a valid `access+jwt`, `/dev/whoami` ran the REAL verifier
(401 for unknown user; 200 reflecting `user_id` after provisioning a real user via the dev mgmt
API + minting for its ID), and the host `migrate` command created `permission_group_id` on a clean
DB. NOTE: two register+join tests (`TestAccountRegistrationInvite_RegisterPlusJoin`,
`TestGroupMemberAddUnknownEmailMintsOnlyGroupInvite_HTTP`) fail on `task test`, but they ALSO fail
at parent `f96a489` (before this work) — pre-existing on master, unrelated to this consolidation
(both packages are `internal/authcore`/`http`, neither imports `cmd/`). The `internal/authcore`
one is `CreatePendingRegistration` hitting "ephemeral store not configured" — likely #143 fallout
where the in-memory store moved to `embedded.New` and a direct-`authcore.NewService` test harness
must re-inject it. Flagged separately; out of scope here. UPDATE 2026-06-28: both fixed (they were
stale test slop, not code bugs) — `task test` is now FULLY GREEN. (1) `setupInviteLinkTest` omitted
`RegistrationVerification`, getting the secure Required default → no store/sender in the DB-only
harness; pinned `RegistrationVerificationNone` (matches the passing sibling test). (2)
`...MintsOnlyGroupInvite_HTTP` asserted the SUPERSEDED two-token design (response key `group_invite`,
"no account-registration invite") — the shipped #147 register+join mints ONE role-carrying account
invite under key `invite`; rewrote+renamed it to `...MintsRoleCarryingAccountInvite_HTTP` asserting
current behavior. Both unrelated to the #194 consolidation.

Proposed 2026-06-28 (Paul). `cmd/authkit-devserver` (525 LOC) and `cmd/authkit-server`
(208 LOC, #142) now overlap ~80%: both wire the identical core surface — `/healthz`,
`/.well-known/jwks.json`, and the auth-flow mux (register/login/OIDC/JWKS) under
`/api/v1`. That mux block is a near-copy (`cmd/authkit-server/main.go:137-145` ≈
`cmd/authkit-devserver/main.go:168-188`) and WILL drift. The devserver predates #142,
when authkit was embedded-only and needed a throwaway issuer to test against; now that
`authkit-server` IS the real standalone product, the devserver should fold into it and
become the integration-test target.

The devserver is a TEST harness, not a product — some of what it carries must NOT ship
reachable in a production server. Consolidation must keep those affordances dev-gated,
fail-closed, exactly as `authkit-server` already does for the unauthenticated management
API (`main.go:154`, `isDevEnv()`).

## Current-state research (2026-06-28, verified)

What only `authkit-server` has: management API `/v1/call/` (`server.NewHandler`, the
remote-SDK target), Redis wiring, fail-closed mgmt-auth posture. Env prefix `AUTHKIT_`.

What only `authkit-devserver` has (all test-only):
1. `/dev/mint` (`main.go:362`) — mints ARBITRARY JWTs (any sub/aud/roles/entitlements) of
   authkit's real first-party `access` class, shared-secret gated (`DEVSERVER_DEV_MINT_SECRET`).
   Used by downstream-service E2E (billing-app) to test their verifier.
2. `/dev/whoami` (`main.go:346`) — reflects the principal as resolved by the REAL verifier
   (JWT user OR branded API key). Used by RBAC / API-key E2E.
3. `bootstrap apply` CLI subcommand (`main.go:203`) — `LoadBootstrapManifestFile` +
   `ApplyBootstrapManifest`; plus `ApplyBootstrapOnStart`.
4. Test seeding knobs: `staticDevEntitlements` via `embedded.WithEntitlements`
   (`main.go:137`), `DEVSERVER_PERMISSION_CATALOG`, `DEVSERVER_STATIC_ENTITLEMENTS`.

KEY FINDING — most of `/dev/mint` is already covered: the management API exposes
`MintCustomJWT` (`server/methods_gen.go:587`, `contract.go:107`) with arbitrary
`Claims`/`Subject`/`Audiences`/`Issuer`. So `/v1/call/MintCustomJWT` replaces `/dev/mint`
for downstream tokens — EXCEPT it refuses authkit's own `access` type
(`ErrCustomJWTReservedType`). `/dev/whoami` has NO mgmt-API equivalent (the mgmt API
provisions/mints; it does not reflect how a given bearer resolved).

CI shape: docker-compose `issuer` (the devserver) is used by `.github/workflows/test.yml`
as a migration-runner + DB + `/healthz` only; `task test` runs `go test ./...` against
Postgres DIRECTLY and never touches the HTTP dev endpoints. Those endpoints are consumed
by the EXTERNAL downstream e2e via `docker-compose.yaml`. So the contract to preserve is
the HTTP surface + env vars that docker-compose and the downstream suite drive.

Refs to update on delete: `docker-compose.yaml` (builds `cmd/authkit-devserver/Dockerfile`,
`DEVSERVER_*` env), `.github/workflows/test.yml`, `Taskfile.yml` (desc only),
`cmd/authkit-server/README.md`, `SEMVER.md`, `.gitignore`, `agents/*.md`.
`internal/authcore/bootstrap_manifest_test.go` uses the `LoadBootstrapManifestFile`
composition (not the binary) — unaffected.

## Design — fold dev affordances into authkit-server behind the existing dev gate

APPROACH A (recommended): one binary. Port `/dev/mint` + `/dev/whoami` (and, if kept,
`bootstrap` + the seeding knobs) into `cmd/authkit-server`, mounted ONLY when
`isDevEnv(cfg.env)` AND an explicit `AUTHKIT_DEV_MINT_SECRET` is set (mint stays
double-gated: dev env + secret, fail-closed — unreachable in prod even if the code ships).
Mirrors how the unauthenticated mgmt API is already dev-gated. Then delete
`cmd/authkit-devserver`. Least drift; one binary to explain.

APPROACH B (rejected unless zero dev code in the shipped artifact is required): keep dev
endpoints out of `authkit-server` entirely; put them in a thin test-only harness that
imports `server` and adds the routes. Purer prod binary, but reintroduces the second
binary this issue exists to delete.

OPEN DECISION (resolve before porting `/dev/mint`): does downstream E2E need real
`access`-class tokens, or can it move to `/v1/call/MintCustomJWT`?
- If access-class is required → port `/dev/mint` as-is behind the dev gate (it stays).
- If not → DROP `/dev/mint`; migrate downstream tests to `MintCustomJWT` over the mgmt API
  (fewer dev-only endpoints in the shipped binary — preferred if it holds).
Recommendation: port `/dev/mint` for now (smallest migration: downstream suite unchanged),
file a follow-up to retire it onto `MintCustomJWT` once we confirm no test asserts on the
`access` `typ`. `/dev/whoami` has no replacement → port it (dev-gated) regardless.

## Tasks

- [x] DECIDED: port `/dev/mint` as-is (access-class mint preserved; smallest migration — downstream suite unchanged). `MintCustomJWT` retirement is a future follow-up.
- [x] Added the dev-routes block to `cmd/authkit-server/main.go`, mounted only when `isDevEnv(cfg.env)`; `/dev/whoami` + `/dev/mint` (`devMintHandler`/`devWhoamiHandler`/`mintRequest`/`mintResponse`/`staticDevEntitlements`/`devSecretOK`) ported intercepting inside the `{prefix}/` handler.
- [x] `/dev/mint` double-gated: dev env AND non-empty `AUTHKIT_DEV_MINT_SECRET` (renamed from `DEVSERVER_DEV_MINT_SECRET`); fail-closed (prod or no secret ⇒ route absent). Live-verified: wrong secret → 401, no token → 401.
- [x] DROPPED `bootstrap apply` CLI + `ApplyBootstrapOnStart` — nothing in the integration path scripts them; the `LoadBootstrapManifestFile`+`ApplyBootstrapManifest` composition stays in `embedded`. Avoids adding subcommand surface for an unused entrypoint.
- [x] Test-seeding knobs: PORTED `AUTHKIT_STATIC_ENTITLEMENTS` (dev-gated `WithEntitlements`) + `AUTHKIT_API_KEY_PREFIX` (normal config). DROPPED `DEVSERVER_PERMISSION_CATALOG` — it was already DEAD in the devserver (loaded from env, never wired).
- [x] Pointed `docker-compose.yaml` `issuer` at the new `cmd/authkit-server/Dockerfile`; renamed env `DEVSERVER_*` → `AUTHKIT_*`. RESOLVED the migration note: `authkit-server` did NOT migrate on boot, so added `AUTHKIT_MIGRATE_ON_START` (compose sets `true`) + a `migrate` subcommand.
- [x] Updated `.github/workflows/test.yml` step names (devserver → authkit-server); `task test` unchanged.
- [~] INTEGRATION TESTS: the in-repo contract is preserved and live-verified — same HTTP surface (`/api/v1`, `/.well-known/jwks.json`, `/dev/mint`, `/dev/whoami`) under `AUTHKIT_*` env, exercised end-to-end against the compose server. Repointing the EXTERNAL downstream (billing-app) repo's env-var names is the downstream's one-line step (separate repo, not in this tree).
- [x] Deleted `cmd/authkit-devserver/` (incl Dockerfile + README).
- [x] Updated `SEMVER.md` (§1.2/§9), `cmd/authkit-server/README.md` (config table + dev section + `migrate`), `Taskfile.yml` desc, `.gitignore` (`/authkit-devserver` → `/authkit-server`).
- [x] Validated: `go build ./... && go vet ./... && gofmt` green; live `docker compose up issuer` → migrate-on-start + `/healthz` green, JWKS + `/dev/mint` + `/dev/whoami` round-trip (incl real provisioned user → 200). `task test` FULLY GREEN (the two pre-existing register+join failures turned out to be stale test slop, now fixed — see status head).

## Non-goals

- Do NOT move the management API or Redis into a separate binary — they stay on `authkit-server`.
- Do NOT expose any `/dev/*` route outside dev env — dev affordances are double-gated and fail-closed, never reachable in production.
- Do NOT rewrite the downstream E2E logic — this is a target swap + env rename, not a test rewrite (the `MintCustomJWT` migration, if chosen, is a separate follow-up).

## Depends on / coordinates with

- #142 (standalone server + remote SDK): `authkit-server` and `MintCustomJWT` are the consolidation target.
- #190 (delete `ApplyBootstrapManifestFile`): the devserver holds the `LoadBootstrapManifestFile` + `ApplyBootstrapManifest` composition #190 references; keep that composition reachable (server subcommand or test helper) when deleting the devserver.

---

# #195: query-contract-and-performance-harness

**Completed:** yes
**Status:** DONE 2026-06-29 (Codex). Added the shared compose-backed
`internal/testdb` scratch Postgres harness, semantic query-contract tests,
100k-row query perf/plan tests, budget/report docs, raw SQL inventory, and
Taskfile entrypoints. `task sqlc-check` now starts/migrates the shared Postgres
before sqlc generate/vet, so the prepare gate is self-contained. Validation:
`task sqlc-check`; `task test-query-contracts`; `QUERY_PERF_REPORT=/tmp/authkit-query-perf.json task test-query-perf`;
`AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable go test -count=1 ./internal/authcore ./http ./adapters/riverjobs ./remote`.

**Status:** PLANNED 2026-06-29. Build the shared AuthKit/OpenRails query testing
system: migrated Postgres, deterministic seed data, semantic query-contract tests,
large-scale query-performance checks, and raw-SQL pruning.

## Goal

`task sqlc-check` already proves sqlc queries PREPARE against the migrated schema.
This issue adds the next layer: execute important queries against real seeded data,
assert the results/mutations, and run heavyweight plan/performance tests against
large tables so missing indexes and bad query shapes are caught before production.

The command surface must match OpenRails exactly:

- `task test-query-contracts`
- `task test-query-perf`

## Metadata

- Category: test-infra
- Status: planned
- Passes: false
- Paired OpenRails issue: OpenRails #628

## Design

### A. Shared command contract

- Add `task test-query-contracts`: starts/uses a real Postgres, runs migrations,
  seeds small deterministic fixtures, and runs query-contract Go tests.
- Add `task test-query-perf`: starts/uses a real Postgres, runs migrations, bulk
  seeds large deterministic fixtures, runs `ANALYZE`, then executes hot queries
  through `EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)` with explicit budgets.
- Use identical env names in both repos:
  - `QUERY_TEST_DATABASE_URL` — optional existing DB override.
  - `QUERY_TEST_KEEP_DB` — keep the scratch DB for debugging.
  - `QUERY_PERF_SCALE` — default row scale for perf seeds.
  - `QUERY_PERF_REPORT` — optional JSON report path.
- Keep `task sqlc-check` as the cheap universal schema/query drift gate; do not
  fold perf tests into it.

### B. Query-contract tests

- Add a small harness under `internal/db/querytest` (or nearest existing test
  helper package) for:
  - scratch DB creation
  - migration application
  - deterministic fixture helpers
  - sqlc query wrapper access
  - transaction cleanup helpers where useful
- Add contract tests by query domain, not one giant generated-method runner.
- Cover the important sqlc groups first:
  - users / identity / owner namespace
  - sessions / refresh-session rotation
  - MFA / twofactor
  - provider links
  - remote applications
  - permission groups, roles, memberships, invites
  - API keys and reserved-account cleanup
- Each contract test should prove:
  - query executes
  - returned rows match seeded data
  - mutations change only intended rows
  - missing-row / duplicate / constraint edge cases return the expected behavior

### C. Query-performance tests

- Seed large datasets with `pgx.CopyFrom` / `COPY`, never row-by-row loops.
- Start with representative scales, then allow override:
  - default `QUERY_PERF_SCALE=100000`
  - manual/nightly target `QUERY_PERF_SCALE=1000000`
- Build reusable `Explain` helpers that parse JSON plans and fail on:
  - sequential scan over large identity/session/RBAC tables unless allowlisted
  - unexpected sort/hash spill or temp blocks
  - excessive shared read blocks
  - bad row-estimate skew for hot queries
  - execution time over query-specific budget
- Store query budgets in a small checked-in manifest, e.g.
  `internal/db/querytest/perf_budgets.yaml`.
- Keep wall-clock thresholds loose; prefer plan shape and buffer budgets because CI
  machines vary.

### D. Raw SQL inventory and pruning

- Add an inventory step for handwritten SQL outside `internal/db/queries`.
- Classify each raw query:
  - convert to sqlc
  - keep raw because it is dynamic SQL / DDL / advisory lock / session setup
  - delete because unused or duplicated
- Require every kept raw SQL path to have either:
  - a query-contract test, or
  - an explicit allowlist reason in the inventory.
- Prefer moving static raw queries into sqlc as domains are covered.

### E. CI policy

- PR/default CI:
  - `task sqlc-check`
  - `task test-query-contracts`
- Nightly/manual CI:
  - `task test-query-perf`
- Add docs explaining that `PREPARE` validates schema compatibility, while
  query-contract/perf tests validate behavior and scaling.

## Acceptance

- `task test-query-contracts` exists and runs against a migrated scratch Postgres.
- `task test-query-perf` exists with the same name/env contract as OpenRails.
- At least the first high-value AuthKit query domains have semantic contract
  coverage: users/identity, sessions, MFA, remote applications, permission groups.
- Perf harness can seed at least 100k users/sessions/memberships and emit JSON
  plan/budget reports.
- Raw SQL inventory exists; obvious duplicated/static raw queries are converted or
  deleted.
- `task sqlc-check`, `task test-query-contracts`, and focused normal Go tests pass.

## Non-goals

- Do not blindly auto-execute every generated sqlc method with fake arguments.
  Query args and seed state must be meaningful.
- Do not make million-row perf tests part of every local `task test` run.
- Do not add an ORM or a new query abstraction.

## Notes

- Pair implementation with OpenRails #628 so helpers, command names, env vars, and
  report shape stay identical.

---

# #196: [BUG] SIWS in-memory challenge cache re-created per request (Solana login broken without Redis)

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `http/siws_cache.go:11-16` returns a **fresh**
`memorystore.NewSIWSCache(...)` on every call in the no-Redis branch. `GenerateSIWSChallenge`
does `Put` on instance A; the follow-up login/link does `Consume` on a **new empty** instance B
→ always `ErrSIWSChallengeNotFound` → 401. Its sibling `stateCache()` (`http/service.go:195`)
memoizes into `s.memStateCache`; `siwsCache()` has no equivalent field. Secondary defect: each
`NewSIWSCache` starts an unstoppable `cleanupLoop` goroutine (`storage/memory/siws_cache.go:33`),
so every Solana request permanently leaks one goroutine + map.

Blast radius: no-Redis / single-instance deploys (prod requires Redis; no current consumer uses
SIWS) — but it's a shipped feature that is 100% broken in a supported config. Root-cause fix, not
per-caller.

## Tasks
- [ ] Add a `memSIWSCache siws.ChallengeCache` field to `authhttp.Service`; create once in `NewServer` (mirror `memStateCache` at `http/server.go:90`).
- [ ] Return `s.memSIWSCache` from `siwsCache()` in the `s.rd == nil` branch.
- [ ] Regression test: Put via challenge handler, then Consume via login handler on the same `Service`, no Redis → succeeds.
- [ ] (Optional) Give `memorystore.SIWSCache` a `Close()`/`closed` channel so the cleanup loop can stop, matching `StateCache`.

---

# #197: [BUG] Remote wire-error round-trip breaks `errors.Is` for WRAPPED sentinels

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `server/management.go:56` emits `err.Error()` verbatim
as the wire code and `statusFor` (`:80`) keys off `authkit.ErrorForCode(err.Error())`. The registry
(`errors.go:72` `ErrorForCode` / `errorsByCode`) + its test only guarantee the round-trip for **bare**
sentinels (`err.Error() == code`). Exposed `Client` methods return **wrapped** sentinels — e.g.
`StartPasswordless` → `emailDeliveryError(err)` = `fmt.Errorf("%w: %w", ErrEmailDeliveryFailed, err)`
(`internal/authcore/senders.go`). Result on the wire: `err.Error()` = `"email_delivery_failed: <detail>"`
→ not a registry key → **500 instead of 422**, and the remote client's
`errors.Is(err, authkit.ErrEmailDeliveryFailed)` returns **false**, silently breaking the documented
cross-transport error identity (#138/#142). Same for `ErrSMSDeliveryFailed` and any wrapped SIWS errors.

## Tasks
- [ ] Add `authkit.CodeForError(err) string` to `errors.go`: iterate the registry with `errors.Is(err, sentinel)` (chain-aware), return the matching sentinel's `.Error()` (else "").
- [ ] Use `CodeForError` in both `server/management.go` `writeErr` and `statusFor`.
- [ ] Extend `errors_test.go`: a wrapped sentinel round-trips (`errors.Is` survives) and maps to 422.

---

# #198: [BUG] In-memory rate limiter panics (index out of range) on bucket `Limit <= 0`

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `ratelimit/memory/limiter.go:98` — `len(ts) >= lim.Limit`
is true for an empty slice when `Limit == 0`, then `ts[0]` (`:99`) panics on the empty slice. Not
reachable via `DefaultRateLimits()` (all ≥ 1), but a host passing a custom `WithRateLimiter` limit of
`0` (incl. a `"default": {Limit: 0}`) crashes the request goroutine.

## Tasks
- [ ] Guard: `if lim.Limit > 0 && len(ts) >= lim.Limit {`, or clamp `Limit` to a minimum of 1 in `LookupLimit`/`New`.
- [ ] Test: a bucket with `Limit: 0`, first request → no panic (defined allow/deny, not a crash).

---

# #199: [SECURITY][v1 GATE] Ship the already-tracked pre-v1 security backlog before v1.0.0

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Two independent security passes found NO new high/medium
vuln — the core is well-hardened. The residual real risk is a set of items **already analyzed** in
`agents/audits/auth-login.md` but **not yet shipped**. This issue is the v1 gate so they don't slip:

- **F1 / plan 014** — OIDC browser callback swallows load-bearing writes with `_ =` (OAuth2 sibling
  fails closed). `http/oidc_browser.go:149,201`.
- **F8 / plan 020** — `finishPasswordReset` discards the `RevokeAllSessions` error
  (`internal/authcore/password_reset.go:84`) and rotates non-atomically; reset can "succeed" while an
  attacker's sessions survive. `ChangePassword`/`SetPasswordAfterFreshAuth` already `return err`.
  NOTE: the one-line error-propagation is a strict improvement shippable NOW, independent of the
  atomic-rotation half.
- **F2 / plan 015** — email/SMS 2FA + step-up codes use non-atomic get-then-del
  (`internal/authcore/ephemeral_data.go`), so the same code can authenticate two concurrent requests
  within the TTL. Every sibling uses the atomic `ephemConsumeJSON`.

## Tasks
- [ ] Ship plan 020: propagate `RevokeAllSessions` error in `finishPasswordReset` (do the one-liner now); complete the atomic-rotation half.
- [ ] Ship plan 014 (OIDC swallowed writes) and plan 015 (atomic code consume).
- [ ] Confirm all three are green + covered before tagging v1.0.0.

---

# #200: [SECURITY] CLOSED — audience-required + timing-oracle both rejected as non-goals

**Completed:** yes (WONTFIX — no code; decision record only)

Closed 2026-07-02 (Paul). Both items originally proposed here are deliberate NON-GOALS. Do not re-audit.

**1. Audience-required posture — REJECTED as over-engineering (Paul).** The conditional check at
`verify/verifier.go:754` (`if len(match.audiences) > 0 && ...`) stays as-is — it's harmless and active
when an issuer is configured with audiences. We will NOT add a `WithRequireAudience()` / fail-closed-at-
registration hardening: the openrails ecosystem's cross-service trust is deliberately broad, the local
issuer already binds `aud` at construction, and forcing an audience posture on federated issuers is
complexity we don't want.

**2. Login timing-oracle / account enumeration — REJECTED (Paul).** `PasswordLogin` timing differs
(fast not-found ~1ms vs ~50ms Argon2id for a real user, `internal/authcore/passwords.go:18-21`), but
account existence is INTENTIONALLY discoverable: the product surfaces "email/username already taken" and
a public `/register/availability` endpoint for login/registration ergonomics. Enumeration resistance is
explicitly not a goal, so equalizing timing defends nothing the front door already exposes, while a
dummy-hash equalizer would add ~50ms of memory-hard Argon2id to EVERY failed login.

(Archive to completed.md at next sweep.)

---

# #201: [v1 SURFACE] Define the "Client interface membership" rule; relocate browser-flow methods to HTTP-only

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). The `authkit.Client` interface has 95 methods; 43 have zero
downstream calls. IMPORTANT CORRECTION (Paul): unused ≠ useless — a general-purpose auth library's API
is defined by what a coherent embeddable toolkit should offer, not by what three in-house apps call.
Do NOT bulk-delete by adoption count. Instead adopt a written membership rule and apply it:

- **Layer test** — the Go `Client` is the *backend embedder's* capability surface. Keep a method if a
  server calls it in-process; a browser/end-user request-flow belongs on the HTTP layer only (Passkeys
  precedent, SEMVER §4.2).
- **Completeness/symmetry** — keep lifecycle-completing methods even if unused (`MintAPIKey` needs
  `RevokeAPIKey`; `SoftDeleteUser` implies `Restore`/`HardDelete`). Removing one arm is a footgun.
- **Commitment** — only WHOLE speculative features are YAGNI cuts. Verified: invite-links / api-key /
  remote-app management are all route-wired committed features → NOT cut candidates.

Defensible relocations to HTTP-only under the layer test: **Passwordless** (`StartPasswordless`/`Confirm*`;
the user completes it in a browser via `/passwordless/*`) and **`ExchangeRefreshToken`** (the `/token`
endpoint's job). KEEP APIKeys mint/list/revoke, `RevokeAllSessions`/`ListUserSessions`, RemoteApps CRUD,
user hard-delete/restore, `IsUserAllowed`, invite-links, `MintCustomJWT`.

## Tasks
- [ ] Write the 3-test membership rule into SEMVER.md (it governs future additions too, not just this trim).
- [ ] Relocate `Passwordless` (5) + `ExchangeRefreshToken` off `Client` to HTTP-only; keep the routes + the impl on `internal/authcore.Service`.
- [ ] Re-audit each remaining "unused" method against the rule; keep backend-capability + lifecycle methods.
- [ ] Regenerate remote/server; confirm authkit's own routes unaffected (`http` holds `embedded.Unwrap → *authcore.Service`, not the interface).

---

# #202: [v1 SURFACE] Move zero-external packages behind `internal/`

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Seven §4.1 "stable" packages are imported by zero consumers
(verified). Criterion here IS semantic (consumers only reach them *through* an option, never by naming
the type), so internalizing is non-breaking for real consumers:

- **`storage/memory`, `storage/redis`, `ratelimit/memory`, `ratelimit/redis`, `siws`** → `internal/`.
  Reached only via `embedded.WithRedis`/`authhttp.WithRedis` / internal wiring.
- **`remote`, `server`** → `internal/` OR mark Experimental. Generated Phase-2 transport, zero consumers
  — the real point is DON'T freeze them into the v1 contract while unproven.
- Guardrail: core **`ratelimit`** package (`Limit`/`Result`/`Reason*`) stays public — `DefaultRateLimits()`
  returns `map[string]ratelimit.Limit`.
- **`adapters/chi`** — keep as a Provided adapter but note it's speculative (all 3 apps use gin).
- **`authtest`** — different case: it exists to be a *consumer* test helper, so internalizing defeats it.
  It's unused even inside authkit's own tests → confirm the consumer-test story is real, else DELETE.

## Tasks
- [ ] Move storage/{memory,redis}, ratelimit/{memory,redis}, siws under `internal/`.
- [ ] Internalize or mark Experimental: remote, server. Keep core `ratelimit` public.
- [ ] Decide authtest: keep (with a real consumer-test example) or delete.
- [ ] Update SEMVER §4.1 package table.

---

# #203: [v1 SURFACE] #143 topic interfaces — fix godoc, riverjobs takes the interface, make it the held type (do NOT delete)

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Only the composite `authkit.Client` is referenced as a type,
and only by doujins; cozy-art/tensorhub hold the concrete `*embedded.Client`; no consumer types against a
narrow slice. CORRECTION: this is NOT evidence the split is useless — the split shipped in v0.72, all three
consumers integrated long before that and don't refactor working code to adopt a new seam. The seam's real
audience (new integrations + test fakes) isn't in this sample. So keep the interfaces; fix the real bugs:

- `authkit.Authorizer` godoc (`interfaces.go:9`) claims "doujins's request gate depends on it" — **false**:
  doujins' `RequirePermission` takes the fat `authkit.Client` and calls `verify.Allow(...)`. Doc bug.
- `adapters/riverjobs` forces a downcast to `*embedded.Client` (doujins `registry.go:50`) — authkit's own
  adapter defeating its own seam. Make it accept `authkit.Client`.

## Tasks
- [ ] Fix / delete the fictional `Authorizer` godoc claim.
- [ ] Change `adapters/riverjobs` (`RegisterPurgeDeletedUsersWorker`) to accept `authkit.Client`.
- [ ] Document `authkit.Client` (interface) as the recommended held type (SEMVER §4.2 example).

---

# #204: [v1 SURFACE] Cover `ErrInsufficientRoleAuthority` + `ErrRoleAssignmentEscalation` in the contract

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Both sentinels exist at HEAD (`errors.go:25,47`) and doujins
does `errors.Is` against both, but SEMVER.md references them **zero** times — a consumer depends on
uncovered surface, so a "non-breaking" change to them would silently break doujins.

## Tasks
- [ ] Add both sentinels to SEMVER §4's covered error list (or unexport them if they're not meant for consumers).

---

# #205: [v1 SURFACE][BREAKING] Package/path rename: `http`→`authhttp`, `oidc`→`oidckit`, `jwt`→`jwtkit`

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Folder name ≠ package name for three packages, so consumers
carry the path in the import and a different identifier in code (doujins imports `embedded` three ways).
It's a MAJOR/breaking rename → the pre-1.0 window is now-or-never. Paul: prefer doing all such breaking
renames while still on v0.x.

## Tasks
- [ ] Rename directories to match packages (or vice-versa): `http`↔`authhttp`, `oidc`↔`oidckit`, `jwt`↔`jwtkit`.
- [ ] Update SEMVER §4.1, README, api-endpoints, examples.
- [ ] Coordinate the consumer import migration with the #143 bump.

---

# #206: [v1 SURFACE][BREAKING] Strip legacy backcompat aliasing pre-1.0

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Paul: remove old aliasing / legacy names / backcompat while on
v0.x. KEY DISTINCTION — two kinds of "alias," only one is cruft:

- **Backcompat re-exports that duplicate a canonical PUBLIC home → DELETE:**
  - `http/verify_aliases.go` — re-exports the public `verify.*` (Verifier/Claims/Required/Optional, ~40
    symbols) under `authhttp` "so existing embedders keep compiling" after the #110 split. A second public
    path for symbols that already live in `verify`. Delete; consumers import `verify.X`.
  - `Service` ≡ `Server` type alias (`http/server.go:22`, #109 collision) — pick one name.
  - Duplicate mint entry point: `MintDelegatedAccessToken` as a `Client` method AND free func
    `authhttp.MintDelegatedAccessToken` — collapse to one.
  - Dead-param-for-compat: `internal/authcore/token_issue.go:64` `_ = email // kept for API compatibility` — drop the param.
  - Legacy `code`-carries-token acceptance in reset/verify confirm (#10) — require `token`, drop legacy field.
- **Facade re-exports that only LOOK like aliases → KEEP:** `embedded/aliases.go` (~50 `type X = authcore.X`)
  is the mechanism keeping `internal/authcore` internal while its types stay public. No canonical public
  alternative (alternative = export `internal/` — worse). Architecture, not debt.

Tell for the difference: if dropping the alias leaves the symbol reachable at a canonical public path, it's
droppable duplication; if it forces exporting `internal/` or a mass type-move, it's load-bearing facade.

## Tasks
- [ ] Delete `http/verify_aliases.go`; migrate the three consumers `authhttp.X` → `verify.X`.
- [ ] Collapse `Service`/`Server` to one name.
- [ ] Dedupe `MintDelegatedAccessToken` (one public entry point).
- [ ] Drop the dead `email` param in `token_issue.go`; remove the legacy `code`-as-token field.
- [ ] Explicitly KEEP `embedded/aliases.go`.

---

# #207: [v1 SURFACE][BREAKING] Delete the `authprovider` Transforms DSL; use `IdentityMapper` + standard OIDC claims

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit) — actions audit.md #3. The declarative field-mapping mini-language
(`UserMapping`, `FieldMapping` with `Transforms []string`, `FallbackLookup`, `MapIdentity`, `MapFallbackEmail`,
`ErrProviderInvalidTransform`) has zero downstream use, and its replacement ALREADY exists and is ALREADY
preferred: `Provider.IdentityMapper func(any)(Identity,error)` (`authprovider/provider.go:52`), used at
`http/oauth2_provider.go:43` when set. Refactor so OIDC providers (Google/Apple) read standard ID-token
claims via `oidckit` and OAuth2-only providers (Discord/GitHub) use an `IdentityMapper`; delete the DSL.

## Tasks
- [ ] Migrate built-ins (`authprovider/builtins.go`) off the DSL to standard-claims / `IdentityMapper`.
- [ ] Delete the DSL types + `MapIdentity`/`MapFallbackEmail` + `ErrProviderInvalidTransform`.
- [ ] Keep `Provider`, `ClientSecret`, `Identity`, `BuiltIn`, `Clone`, `AppleJWTSecret`.

---

# #208: [v1 SURFACE] Leaf surface cleanups

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Small, mostly non-breaking public-surface trims:

- Move `AuthCapabilities` + 6 sub-types (`capabilities.go:4-48`) into `authhttp` — built only by
  `http/providers_get.go`, a JSON response shape living in the root package.
- Drop the `RBACDriftReport` facade method (`embedded/facade_methods.go:353`, 0 callers); keep the engine
  impl, move the struct to `internal/authcore`.
- `jwtkit` export-only trims (SEMVER §11 #7): unexport advanced key sources with zero external use
  (`KeyRing`, `EnvKeySource`, `FileKeySource`, `ReloadableKeySource`, `NewAutoKeySource`,
  `NewGeneratedKeySource`, `ECDSASigner`, `Ed25519Signer`) — most are internally load-bearing, so unexport
  rather than delete; expose only the `KeySource`/`Signer` facade. Verify `KeyRing`.
- Delete the stale `var _ = time.Second // keep import` fragment in `contract.go` (`time` is genuinely used).

## Tasks
- [ ] Relocate `AuthCapabilities` types to `authhttp`.
- [ ] Drop `embedded.Client.RBACDriftReport`; move struct internal.
- [ ] Unexport the jwtkit advanced key sources; keep the facade.
- [ ] Delete the `contract.go` dead-comment fragment.

---

# #209: [DX] Ship gin-native `Optional`/`Required`; fix the discoverability gap

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). All three apps hand-write the identical `net/http`→`gin.HandlerFunc`
shim around `authhttp.Optional/Required` (doujins `authkit_http.go:15`, cozy-art `provider_authkit.go:56`,
tensorhub `service.go:750`). The shipped `authkitgin.Use/RequirePermission/UserClaims/Principal` helpers are
used **0 times** — they're documented but unreachable from the packages consumers actually import. Highest-
value ergonomic gap.

## Tasks
- [ ] Expose gin-native `Optional(v)`/`Required(v)` from where people import (e.g. methods on the returned server, or a clearly-surfaced `authkitgin`).
- [ ] Add a one-line godoc pointer from `verify.Optional/Required` to the gin adapter.

---

# #210: [DX] Take Redis once — fix the dual `WithRedis` split-brain footgun

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `embedded.WithRedis` and `authhttp.WithRedis` are separate; all
three apps wire both and each left a warning comment. The prod validation (`http/server.go:106`) only checks
the HTTP side, so a missing engine Redis passes and yields silent split-brain state across replicas.

## Tasks
- [ ] Have `NewServer` reuse the engine's configured Redis by default (single source); make a second `WithRedis` an override, not a requirement.

---

# #211: [DX] One construction entrypoint + a `RegisterAll` route helper

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Every app copy-pastes ~150 lines of `Config`→`embedded.New`→
`authhttp.NewServer` glue (doujins `di/authkit.go:66-195`, cozy-art `api.go:199-249`, tensorhub
`service.go:365-432`) plus the same `/oidc`→`/oidc/` redirect trio. The `Client`/`Service`/`Server` naming
triad is confusing (see #206 for the alias half).

## Tasks
- [ ] Offer `authhttp.New(cfg, pg, ...opts)` that builds both layers and routes options internally (keep the two-step path for advanced users).
- [ ] Ship a `RegisterAll(engine, svc, opts)` that mounts JWKS/OIDC/API (+ the /oidc redirect) in one call.

---

# #212: [DX] Return an error instead of panicking on `Registration.Verification=Required` without a sender

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). authkit panics at handler-mount when verification is Required but
no email/SMS sender is wired. cozy-art works around it by silently downgrading to Optional (`api.go:191-197`);
doujins pre-validates (`di/authkit.go:216-225`) — two workarounds for one footgun.

## Tasks
- [ ] Return a construction error from `NewServer`/`New` instead of panicking; document the requirement.

---

# #213: [DX] Consolidate the two error-code registries + one `HTTPStatus(err)` mapper

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Two parallel registries carry the same string values in different
types: `authkit.ErrX` sentinels (`errors.go`, ~60) and `authhttp.ErrorCode` (`http/error_codes.go`, ~210
consts), mapped to HTTP status by hand-written `errors.Is` chains in ~20 handlers. A consumer calling a
`Client` method directly must re-implement the mapping authkit already encodes. (Related: #197's `CodeForError`.)

## Tasks
- [ ] Expose one `authkit.HTTPStatus(err) (int, code)` mapper the handlers and consumers both use.
- [ ] Generate `authhttp.ErrorCode` from the sentinel set instead of a hand-maintained parallel list.

---

# #214: [DX] Consistent token verbs (`Mint*`) + a first-class `Principal`/`Source` classifier

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). The token surface uses arbitrary verbs for the same act of signing
a JWT (`IssueAccessToken` vs `MintCustomJWT`/`MintDelegated…`/`MintService…`), and tensorhub maintains a large
hand-written principal-disambiguation layer (`internal/api/principal.go`, ~20 fields; `auth_any.go:78-118`)
to tell delegated / remote-app / service-JWT / api-key apart at verify time.

## Tasks
- [ ] Standardize on `Mint{Access,Service,Delegated,RemoteApp,Custom}Token`.
- [ ] Ship a `verify.Principal`/`Source` classifier so consumers don't hand-roll the disambiguation.

---

# #215: [PERF][BREAKING] Make the authenticated-request path stateless (0 DB lookups) — realign with the #90 TTL-bound design

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit); redesigned 2026-07-02 (Paul). `verify/middleware.go:69-88` does up
to FOUR DB round-trips on every authenticated native-user request in stateful mode: hardcoded
`GetProviderUsername(…, "discord")`, `ListRoleSlugsByUser` (when the token has no roles), `UsersByIDs` (when
email absent), and the `IsUserAllowed` ban gate (which itself reads `profiles.users` TWICE — `UserByID` +
`UserIsReserved`). Target: 0 DB lookups on the common path.

**KEY FINDING — the per-request ban gate contradicts authkit's own design (#90).** `service.go:348-352`: the
15-min default access TTL "bounds revocation lag to one TTL window ... we deliberately rely on this bound
INSTEAD OF a per-request jti/liveness lookup." The middleware `IsUserAllowed` IS that per-request liveness
lookup #90 says to avoid. Ban/deleted is already enforced where new tokens are minted: login
(`ensureUserAccess`) and refresh (`ExchangeRefreshToken` → `ensureUserAccessByID` + `IsUserAllowed`, and
`RevokeAllSessions` on disable — verified `service_sessions.go:140`). So a banned/deleted user CANNOT get a
new access token; the existing one expires in ≤15min. Paul: that residual window is acceptable — drop the
live per-request check; never fetch more than the request needs.

## Tasks
- [ ] Remove the per-request `IsUserAllowed` ban gate from `verify/middleware.go` (ban enforced at login + refresh; ≤15min residual per #90).
- [ ] Remove the hardcoded `GetProviderUsername(…, "discord")` lookup.
- [ ] Drop per-request role/email enrichment: roles resolve lazily via `Can()` on permission-gated routes only (already DB-live there); email rides in the token. Common authenticated request → ZERO DB lookups.
- [ ] Keep a live ban/deleted check available ONLY for admin/sensitive routes where instant lockout matters (opt-in, not the global path).
- [ ] Integration tests: banned user keeps access until token expiry (≤15min), is rejected at refresh + can't mint a new token; assert the normal authenticated request path issues no DB query.

## Rejected (2026-07-02, Paul): a short-TTL ban-gate cache — over-engineering + security cost
A per-user cache on the ban/deleted gate would let a banned/deleted user keep authenticating for up to
the TTL — a soft fail-OPEN on a security gate (cuts against fail-closed-on-authz). It adds invalidation +
memory-growth + staleness concerns to buy an UNPROFILED speedup. Instant, uncached ban enforcement is the
correct default. Revisit ONLY if profiling later proves the ban gate is a real bottleneck. The two tasks
above (drop the hardcoded Discord lookup; merge the double users-row read) remove work AND code with zero
downside — those are the whole of #215 now.

---

# #216: [PERF] Kill the double JWT parse on every non-API-key request

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `verify/verifier.go:977` (`verifyClaimsWithHeader`) fully parses
via `VerifyClaims`, then re-parses with `ParseUnverified` (`:986`) solely to read the `typ` header — a second
base64-decode + JSON-unmarshal per request.

## Tasks
- [ ] Return `typ` from `VerifyClaims`'s single parse (internal variant), drop the `ParseUnverified` re-parse.

---

# #217: [PERF] Redis limiter: single Lua script (pipeline writes + fix TOCTOU over-admit)

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `ratelimit/redis/limiter.go:99-102`: the allowed path adds two
extra round-trips after the pipelined read (`ZAdd` + a redundant `Expire` that duplicates line 50). Login
endpoints call this twice (IP + identifier) → up to 6 round-trips/attempt. The count-check and `ZAdd` are also
non-atomic → concurrent requests over-admit.

## Tasks
- [ ] Replace the read-then-write sequence with one atomic Lua script (fixes round-trips AND the TOCTOU).
- [ ] Drop the redundant line-102 `Expire`.

---

# #218: [PERF] Minor hot-path allocation/write cleanups

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit).

## Tasks
- [ ] Hoist `headerRegex` (`siws/parse.go:21`) to a package-level `var` (compiled per call today; every other regex in the tree is already package-level).
- [ ] Throttle `touchAccessTokenAsync` (`internal/authcore/api_keys.go:388`) — only update `last_used_at` if older than N minutes, to cut the goroutine + write per API-key request.

---

# #219: [v1 SURFACE][DESIGN] Batch-native operation contract — collapse single↔batch duplication

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). Make batch the DEFAULT and ONLY shape for collection-oriented
operations: a single-item call is just the batch with a one-element slice. Removes batch+single handler
duplication, lets consumers act on many records in one round-trip (kills the N+1 flagged in #215 and
doujins #738), and shrinks the surface. The codebase already leans this way (`UsersByIDs`,
`RootRolesForUsers`, `ListEntitlementsBatch`) — this regularizes it and deletes the single-variants.

**Read contract:** `(ctx, []ID) (map[ID]T, error)` — missing IDs are simply absent; single-item is
`m[id]`. Trivial partial-result semantics.

**Write/mutation contract:** return PER-ITEM results — `[]OpResult{ID string; Err error}` (or
`map[ID]error`) — so partial failure is expressible; OR be explicitly all-or-nothing transactional where
that's the right semantic. Chosen + documented per op. A bare `([]T) error` single-error is the
ANTI-PATTERN to avoid (caller can't tell which item failed).

**EXCLUSIONS — do NOT batch (Rule 1).** Request-scoped single-subject auth primitives stay single:
`VerifyRequest`/`Verify`, `PasswordLogin`, `MintAccessToken`, `Can(subject,…)`, `ResolveAPIKey`, refresh
exchange. They're inherently one-principal / one-request; batching breaks their semantics and puts
partial-failure ambiguity on the auth path. Batch-native = collection ops, NOT per-request primitives.

## Tasks
- [ ] Write the read + write contract + the exclusion list into SEMVER.md as the operation-shape rule (governs future methods too).
- [ ] Apply via #220 (reads), #221 (entitlements), #222 (mutations).

---

# #220: [v1 SURFACE][BREAKING] Collapse single-item reads into batch reads

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit) — applies #219 to reads. Today `UsersByIDs` (batch, `client.go:48`)
coexists with single `GetUserByEmail/Phone/Username/SolanaAddress`; `ListRoleSlugsByUser`/`…Err`
(`client.go:78-79`) are single (doujins #738 runs one role query per user, `user_service.go:117`);
`GetProviderUsername` (`client.go:141`) is single AND is the unconditional per-request Discord lookup
called out in #215.

## Tasks
- [ ] Keep `UsersByIDs`; return `map[id]UserRef` for O(1) single-item access.
- [ ] Collapse `ListRoleSlugsByUser`/`ListRoleSlugsByUserErr` → `RoleSlugsByUsers(ctx, []userID) (map[string][]string, error)` (fixes doujins #738).
- [ ] Collapse `GetProviderUsername` → `ProviderUsernames(ctx, []userID, provider) (map[string]string, error)` (lets #215 enrichment batch instead of one lookup/request).
- [ ] Add `UsersByEmails`/`UsersByUsernames` batch lookups where admin/import paths resolve many by unique key; drop the single variants not needed by an auth primitive.

---

# #221: [v1 SURFACE][BREAKING] Collapse the entitlements provider trio to batch-only

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit) — applies #219; supersedes the audit's earlier "trio is justified"
note. Today three interfaces (`internal/authcore/service.go:114-137`): `EntitlementsProvider` (single),
`BatchEntitlementsProvider` (optional upgrade detected by type assertion), `EntitlementFilterProvider`
(reverse: entitlement → subjects). doujins already implements the batch one
(`openrailsembed/entitlements.go:53`). The single+batch optionality existed ONLY to avoid forcing batch on
providers — batch-native removes that reason.

## Tasks
- [ ] Merge single+batch into ONE `EntitlementsProvider{ ListEntitlements(ctx, []userID) (map[string][]string, error) }`; delete `BatchEntitlementsProvider` and the type-assertion upgrade dance in `service.go:2499`.
- [ ] Keep `EntitlementFilterProvider` (distinct reverse operation). Trio → 2.
- [ ] Update `WithEntitlements` + the doujins provider to the batch-only signature.

---

# #222: [v1 SURFACE][BREAKING] Batch-native bulk mutations with per-item results

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit) — applies #219 to writes. Today single-row mutations:
`SetEmailVerified`, `SoftDeleteUser`, `RestoreUser`, `HardDeleteUser`, `UpdateEmail`/`UpdateUsername`,
`AssignRoleBySlug`/`RemoveRoleBySlug` (+ `…As` actor-checked variants). Admin flows that touch many rows
(ban-many, purge, bulk role grant) currently loop one call per row.

## Tasks
- [ ] Convert bulk-capable mutations to batch-native returning per-item results (`[]OpResult{ID, Err}`); single-item = one-element slice.
- [ ] Preserve the per-item `…As` actor-authority check (no-escalation) inside the batch.
- [ ] Keep single-subject auth primitives OUT of batching per #219 (login/verify/mint/Can/ResolveAPIKey).
- [ ] Decide per op: per-item best-effort vs all-or-nothing transactional; document each.

---

# #223: [BUG] Group-invite email sender is dead code — FIX it to actually send (align with `SendPasswordResetLink`)

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit); refined 2026-07-02 (Paul: confirm group-invite-by-email still works).

**SCOPE GUARDRAIL — the invite FEATURE is fine and stays.** `CreateAccountRegistrationInvite` (`client.go:90`)
creates the invite, assigns the carried persona+role, and returns `AccountRegistrationInviteCreated{Code, URL,
Persona, Role, ...}` with the invite URL/token. Inviting an unknown email to a permission group with a role is
a live, tested flow (`TestGroupMemberAddUnknownEmailMintsRoleCarryingAccountInvite_HTTP`). This issue is ONLY
about the email-SEND helper, NOT invite creation.

**THE BUG.** `sendAccountRegistrationInviteEmail` (`internal/authcore/account_registration_invites.go:169-181`,
called at `:165`) type-asserts the host sender to `AccountRegistrationInviteEmailSender` (`:63`), whose method
takes `AccountRegistrationInviteMessage` — an `internal/authcore` struct NOT re-exported (verified). No consumer
can name that type, so the assertion ALWAYS fails and authkit NEVER sends the invite email. Today the invite is
delivered only if the host emails `created.URL` itself.

**ROOT CAUSE + FIX.** The sibling optional sender `SendPasswordResetLink(ctx, email, username, resetURL string)`
(`senders.go:38`) works precisely because it uses PLAIN STRING args, not an internal struct. Align the invite
sender the same way so authkit actually sends the invite email through the host's `EmailSender` — consistent
with how it already sends verification + password-reset-link emails.

## Tasks
- [ ] RECOMMENDED: change `SendAccountRegistrationInvite` to plain-string args (e.g. `(ctx, email, inviteURL, persona, role string)`) matching `SendPasswordResetLink`; delete the internal `AccountRegistrationInviteMessage` struct. Now a host sender CAN implement it and authkit sends the invite email.
- [ ] Test: a host `EmailSender` implementing the optional interface receives the invite send (assertion now succeeds).
- [ ] ALTERNATIVE (only if host-delivers-URL is explicitly preferred): delete the sender interface + method + call at `:165`; document that emailing `created.URL` is the host's job. Do NOT touch `CreateAccountRegistrationInvite`.

---

# #224: [OVER-ENG] Delete the unused `ClaimsBuilder` interface

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `jwt/jwt.go:26` — exported interface with **zero** references
(verified: only the 2 definition lines across authkit + all three consumers; no implementer, no
`WithClaimsBuilder`, no field, no caller). Speculative extension point nobody wired up.

## Tasks
- [ ] Delete the `ClaimsBuilder` interface (one-line reintroduction if custom-claim layering is ever actually needed).

---

# #225: [OVER-ENG] Inline the single-use `credentialScanner` interface

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `internal/authcore/passkeys.go:402-404` — the
`{ Scan(dest ...any) error }` "accept both pgx.Row and pgx.Rows" abstraction has exactly one consumer,
`scanWebAuthnCredential` (`:406`), whose only caller (`passkeyCredentialsByUser`, `:384`) always passes a
`pgx.Rows` from a `rows.Next()` loop. Only `pgx.Rows` is ever passed.

## Tasks
- [ ] Change `scanWebAuthnCredential` to take `pgx.Rows` (or `pgx.CollectableRow`) directly; delete the interface.

---

# #226: [OVER-ENG] Collapse `allowResult` into `allowResultForKey` (dedup limiter dispatch)

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `http/service.go:133` (`allowResult`) derives
`key := "auth:"+bucket+":ip:"+ip` then runs the IDENTICAL `RateLimiterWithResult` type-assert-else-`AllowNamed`
block (`:149-161`) that `allowResultForKey` already contains (`:118-130`).

## Tasks
- [ ] Have `allowResult` do its nil/IP checks, compute `key`, then `return s.allowResultForKey(bucket, key)` (~10 duplicated lines gone).

---

# #227: [PERF] Thread the user row + MFAStatus through the token-issue path (root fix — 3× user-read / 2-3× MFA per request)

**Completed:** no

Proposed 2026-07-02 (handler over-fetch audit). The token-issue helpers each RE-READ the full 15-col
`profiles.users` row and RE-COMPUTE `Get2FASettings` (2 queries) internally, so every caller pays the same
reads 2-3×. Verified on the two hottest write paths:
- **Refresh** (`internal/authcore/service_sessions.go:140-218`): `UserByID` runs 3× (`ensureUserAccessByID`
  L160, a full-row read at L174 used only for `email`, and again inside `IssueAccessToken`→`token_issue.go:88`),
  `IsUserReserved` 2×, `MFAStatus`/`Get2FASettings` 2× (`requireSessionMFAState` + `issueAccessToken`).
- **Password login** (`http/password_login_post.go`) and **2FA verify** (`http/user_2fa_verify_post.go:69-91`):
  same shape — the account row is read 3-5× and `MFAStatus` computed ~3× across `IssueRefreshSession*` +
  `AdminGetUser`-for-email + `IssueAccessToken`.

Root cause: `IssueAccessToken`/`IssueRefreshSession*`/`ensureUserAccessByID` take only a userID and re-fetch.
(The per-request MIDDLEWARE half of this waste is #215.)

## Tasks
- [ ] Add internal variants that accept an already-loaded `*User` + a precomputed `MFAStatus` (or a small `issueContext` struct) so the issue path adds ZERO extra user-row reads / MFA computations.
- [ ] Refresh: load the user row + MFAStatus ONCE at the top of `ExchangeRefreshToken`; thread through ensureUserAccess / email / IsUserAllowed / issueAccessToken. Target ~9-10 → ~3-4 round-trips.
- [ ] Login + 2FA-verify: carry the row/MFA already resolved into the issue path; drop the `AdminGetUser`-for-email calls (email is already on the row).
- [ ] Integration tests asserting the refresh / login / 2fa-verify paths read `profiles.users` at most once and compute 2FA settings once (query-counting stub or pg statement counter).

---

# #228: [PERF] GET /me — collapse ~15 round-trips (Get2FASettings 3×, HasPassword 2×, AdminGetUser 2×, provider slugs 2×)

**Completed:** no

Proposed 2026-07-02 (handler over-fetch audit). `http/user_me_get.go:40-173` (very hot — app boot / page loads)
issues ~15 queries with heavy duplication: `Get2FASettings` (2 queries) runs **3×** (`MFAStatus` L139 +
`stepUpMethods` L167 + `stepUpTwoFactorOptions` L168), `HasPassword` **2×** (L75 + L167), provider slugs
fetched twice (`UserProviderSlugs` L92 + `UserProviderSlugsDistinct` L167), `AdminGetUser`'s full
user+roles+entitlements pipeline runs **2×** (L50 + `step_up.go:380`), and a separate `UserPreferredLanguage`
read (L68) for one column the user row already loaded twice could carry.

## Tasks
- [ ] Compute `Get2FASettings` once; pass it into `MFAStatus`/`stepUpMethods`/`stepUpTwoFactorOptions`.
- [ ] Reuse the single `AdminGetUser` result (has email/roles/entitlements) instead of re-running it; fetch provider slugs once; `HasPassword` once.
- [ ] Add `preferred_language` to the `UserByID` projection so `GetPreferredLanguage` disappears. Target ~15 → ~5.
- [ ] Integration test asserting the `/me` handler's query count dropped to the target.

---

# #229: [PERF] GET /register/availability — one combined taken-check query, not one per field

**Completed:** no

Proposed 2026-07-02 (handler over-fetch audit). `http/register_availability.go:52-78` calls
`registrationUsernameAvailability` and `registrationEmailAvailability` separately, each invoking
`CheckPendingRegistrationConflict` → `UserEmailOrUsernameTaken`, a SINGLE query that already returns BOTH
`email_taken` and `username_taken`. Checking username+email together runs that two-`EXISTS` query TWICE
(email+"", then ""+username) instead of once. Warm path (typeahead can be hot).

## Tasks
- [ ] One `CheckPendingRegistrationConflict(email, username)` covering all provided fields; the query already supports both args.

---

# #230: [PERF] Narrow the `UserBy*` projections + drop unused over-fetched columns

**Completed:** no

Proposed 2026-07-02 (handler over-fetch audit). `UserByEmail/ByID/ByPhone/ByUsername` (`internal/db/users.sql.go`)
always SELECT the full 15-col row; hot callers use a slice (refresh needs only `email`; the liveness gate needs
only `deleted_at`/`banned_*`). Compounds with the repeated reads (#227). Also `SessionsListByUser`
(`sessions.sql.go:346`) selects `last_authenticated_at` + `revoked_at` that the handler never maps
(`revoked_at` is guaranteed NULL by the WHERE clause). Never fetch more than the request needs.

## Tasks
- [ ] Add narrow projections (or a merged single-row read per #227) for the hot liveness/email uses; keep the full row only where genuinely needed.
- [ ] Drop the unused `last_authenticated_at`/`revoked_at` columns from `SessionsListByUser`.
