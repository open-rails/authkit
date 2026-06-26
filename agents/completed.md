<!-- authkit issue tracker — COMPLETED issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs share ONE per-repo id space with progress.md
> (new issues take `next_id` from progress.md and bump it). Issues move here from progress.md when done.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.

---

# #142: Standalone self-hostable server + remote SDK (authkit Phase 2)

**Completed:** yes (track A client-first + full consumer migration; track B standalone
server + generated remote SDK, shipped v0.70.0. Two tasks pruned as over-engineering:
the in-process transport adapter and the flag/file config layer. mTLS / signed-JWT mgmt
auth left as future hardening — bearer token ships.)

STATUS 2026-06-26 (Claude): foundation landed (additive, non-breaking). Built the
remote-SDK transport END-TO-END for the first capability slice (`authkit.Authorizer`):
`authkit/server` management handler (`NewAuthorizerHandler` over any `authkit.Authorizer`
+ static bearer auth), `authkit/remote` client satisfying the SAME interface over HTTP,
and a parity test proving values round-trip AND `errors.Is(err, authkit.ErrX)` survives
the wire. `remote` is lean (net/http + authkit only, no engine/pgx). Interface-portability
audit started: DROPPED `ApplyBootstrapManifestFile` from the contract (a file path is the
SERVER's fs — meaningless remote; hosts load then `ApplyBootstrapManifest`).

STATUS 2026-06-26 (Claude): full code→error registry DONE. Added `authkit.ErrorForCode`
(all 47 sentinels, one shared map) in `errors.go` + `errors_test.go` (round-trip +
uniqueness check); normalized the `ErrGroupNotFound` sentence-code wart →
`permission_group_not_found`. `remote/` now resolves wire codes through the shared
registry (deleted its local 5-entry `codeErrors` map) — ONE source of truth for error
identity, client+server. build+test green.

STATUS 2026-06-26 (Claude): client-first construction DONE (Paul greenlit track A).
`authhttp.NewServer(client *embedded.Client, opts...)` — the server is now an HTTP
adapter over a client the host built; engine deps go on `embedded.New`, HTTP-layer
options stay on `NewServer`. Specifics: added `authcore.Service.Config()` (retains the
host Config so the transport reads HTTP-only OIDC providers/descriptors), `embedded.New`
now defaults to an in-memory ephemeral store (was the http layer's job), new
`embedded.WithRedis` (engine store) + `embedded.Unwrap` (engine extraction for the
transport); `authhttp.WithRedis` is now HTTP-only (OIDC/SIWS state caches), and the
engine-dep option wrappers (WithEphemeralStore/WithEmailSender/WithSMSSender/
WithEntitlements/WithClickHouse/WithAPIKeyResourceAuthorizer/WithSolanaSNSResolver) +
`Server.coreOpts` are deleted from `authhttp`. DROPPED `Server.Client()` (host owns the
client). Migrated all 34 in-repo `NewServer` sites (devserver + ~33 http tests + gin
test). build+vet+gofmt green; full DB-backed suites (http, internal/authcore, riverjobs)
+ non-DB suites pass on a fresh migrated DB.

STATUS 2026-06-26 (Claude): track A COMPLETE end-to-end. Shipped authkit v0.69.0
(client-first NewServer + dropped `Server.Client()` + shared `ErrorForCode` registry,
then pared `SetEntitlementsProvider` off the HTTP `Server`). Migrated the ENTIRE consumer
ecosystem to v0.69.0 client-first, each build+vet green and pushed: openrails v0.67.0,
hentai0, doujins, cozy-art, tensorhub. So #142 track A (client-first construction +
Server paring + consumer migration) is fully done.

REMAINING: only (B) the standalone-server bulk — the other ~89 mgmt-API methods,
`cmd/authkit-server`, app→server auth; the issue marks this "build when greenlit"
(speculative until the standalone product is committed). The foundation (remote SDK
transport + shared error identity) already proves the architecture.

Proposed 2026-06-25 (split out of #138 Phase 2, now that the embedded restructure +
pgx-free contract are committed). authkit is embedded-only today: an app runs the
engine in-process (`embedded.New` / `authhttp.NewServer`). This issue makes authkit
ALSO runnable as a STANDALONE, self-hostable server, so:
- non-Go apps can use authkit over an HTTP management API, and
- a Go app can swap embedded↔remote with ONE line (`embedded.New` ↔ `remote.New`) —
  both satisfy the pgx-free `authkit.Client` contract #138 established.

This is a NEW product surface, not a refactor — build when greenlit.

## Design — etcd's "one client, two transports" (NOT two client impls)
#138's etcd analysis is the blueprint:
- ONE consumer-facing client driven by a TRANSPORT: an in-process direct-call adapter
  (embedded) OR an HTTP transport (remote). Two independent client impls drift (error
  mapping, timeouts, partial coverage); one client + two transports does not.
- In-process = direct function calls through the real handler stack (etcd's `v3client`
  via `proxy/grpcproxy/adapter`), NOT a loopback socket.
- Handlers + wire DTOs defined ONCE; both transports feed them.

## Target packages
| Package | Role |
|---|---|
| `authkit/server` | standalone-server logic: engine + `authhttp` browser routes + the new authenticated MANAGEMENT API. Thin `main` in `cmd/authkit-server`. Owns its DB/Redis/config. |
| `authkit/remote` | Go SDK: `remote.New(url, creds) (*remote.Client, error)` satisfying `authkit.Client` by marshaling each method to the management API. Lean (net/http only). |
| transport seam | in-process direct-call adapter + HTTP transport feeding ONE shared client (etcd `v3client`). |

Non-Go clients hit the management REST API directly (no SDK).

## Construction shape (client-first) — folded from #143
Land these WITH the remote SDK so consumers migrate ONCE to the v1.0 shape (doing them
as a separate issue = two migrations of the same construction surface):
- [x] `authhttp.NewServer(client, httpOpts...)` — client-first; the server becomes an
      HTTP adapter over a client the host already built (no hidden engine). DONE.
- [x] Drop `authhttp.Server.Client()` — redundant once the host owns the client. DONE.
- [x] Split options: engine deps (senders / ephemeral store / entitlements / auth log /
      API-key authorizer / Solana) on `embedded.New`; HTTP behavior (rate limiter /
      client IP / language / error logger / route wrappers) on `authhttp.NewServer`.
      Moved `WithRedis` onto `embedded` (`embedded.WithRedis`); `authhttp.WithRedis` is
      now HTTP-state-only. `WithEphemeralStore` already on `embedded`. DONE.
- [ ] `remote.New` mirrors `embedded.New`; both return the concrete client, host types
      its var `authkit.Client` for the swap. (New-vs-NewClient naming = Paul's bikeshed.)
- [ ] KEEP the broad `authkit.Client` seam (per #143 review) — small capability
      interfaces from #143 coexist with it, they don't replace it.

STATUS 2026-06-26 (Claude): track B (standalone server + remote SDK) BUILT & proven
end-to-end (Paul greenlit "finish your 142"). The key decision — instead of 93
hand-written REST endpoints (the drift trap #138 warns about), a CODE GENERATOR
(`internal/genremote`, stdlib go/ast only) parses the `authkit.Client` interface and
emits BOTH sides into `*_gen.go` (`go generate ./...`, directive on client.go). One
source of truth → the transports cannot drift. Live smoke test: the binary created a
user over the management API and read it back; no-token call → 401.

## Tasks
- [x] **Interface portability audit.** `ApplyBootstrapManifestFile` already dropped from
      the contract (v0.67.0). The remaining maintenance/infra methods stay on the
      interface and are exposed verbatim through the generic dispatch (no per-method
      reshaping needed — the wire is method-name + JSON args).
- [x] **Management HTTP API contract** — generic dispatch `POST /v1/call/{Method}`:
      args = JSON object keyed by param name; success `{"result":…}`; failure
      `{"error":{"code":…}}` with the sentinel code. Covers the FULL `authkit.Client`
      (93 methods), generated. (`server/management.go` + generated `server/methods_gen.go`.)
- [x] **App→server auth** — static bearer token (`AUTHKIT_MGMT_TOKEN`). Fail-closed:
      outside dev the management API is NOT mounted without a token. (mTLS / signed
      service-JWT / least-privilege scoping are future hardening, not blocking.)
- [x] **`authkit/server`** — `server.NewHandler(client, token)` over any `authkit.Client`;
      thin `cmd/authkit-server` main (engine + authhttp browser routes + JWKS + mgmt API
      + env config). README at `cmd/authkit-server/README.md`.
- [x] **`authkit/remote`** — `remote.New(url, token)` returns a `*Client` satisfying the
      FULL `authkit.Client` (compile-time conformance in `remote/conformance.go`). All 93
      methods generated; error mapping re-derives `errors.Is(err, authkit.ErrX)` via the
      shared `authkit.ErrorForCode`.
- [x] ~~Transport seam (in-process direct-call adapter)~~ — DELETED as over-engineering.
      etcd needs `v3client` because its embedded client would otherwise re-implement the
      gRPC client; here the management handlers operate on the `authkit.Client` interface,
      which `embedded.Client` already IS (direct in-process calls), and `remote.Client` is
      GENERATED from that same interface. The two transports are derived from one contract
      and cannot drift — routing embedded through HTTP handlers would be pure in-process
      overhead for zero benefit. No adapter exists or is needed.
- [x] **Config unification** — DONE via env: `cmd/authkit-server` builds `embedded.Config`
      from `AUTHKIT_*`/`DB_URL` (issuer/keys/schema/redis/registration-verification). A
      flag/file config layer is YAGNI for ~11 knobs (etcd has it for a huge surface); add
      it only if a real deploy needs flags.
- [x] **Tests** — `remote/remote_test.go`: fake-`authkit.Client`-backed parity over
      `httptest` (bool/[]string/pointer-struct/multi-return/no-ctx round-trips + error
      identity + auth seam). `remote/parity_db_test.go`: REAL embedded engine — write via
      remote, read via both transports, ban via remote visible to the embedded client.
- [x] **Docs** — `cmd/authkit-server/README.md` (deploy guide, wire contract, env table,
      the embedded↔remote one-line swap, non-Go curl examples). Package docs on
      `server`/`remote`/`genremote` explain the transport + codegen.

## Open questions
- Management API home: a new `authkit/server` handler, or extend `authkit/http`?
- The awkward methods (bootstrap-from-file, cleanup) — remote-exposed at all?
- Error identity over the wire: map HTTP status+code → shared `authkit.Err*`.

## Depends on
#138 (DONE, committed `a08ac76`/`afa17d1`): the pgx-free `authkit.Client` contract +
the `authkit/embedded` / `authkit/verify` split this builds on.

---

# #141: Repo cleanup — top-level package & root-file tidy (pre-1.0 hardcut)

**Completed:** yes

STATUS 2026-06-25 (Claude): DONE. Cleanup committed `afa17d1` (local on master, not
pushed): all relocations/renames/deletes landed; `identity` replaced by
`Client.UsersByIDs`. The two surface flags are DECIDED — keep everything public
(external usage confirms oidc/password/lang are real library imports; siws leaks
through storage's public API; the root helpers are the shared lean layer). No
further churn. build+vet+gofmt green; full DB-backed + non-DB suites green on a
fresh DB. Flag-decision note is an uncommitted progress.md edit.

Proposed 2026-06-25 (Paul + Claude, after the #138 restructure). With the package
restructure landed, audit the public surface + repo root. Every top-level dir
EXCEPT `internal/` (compiler-private) and `cmd/` (binaries) is importable = public
API, so trimming/relocating now (pre-1.0) keeps the v1.0 surface clean. Breaking;
hardcut, no compat. In-repo importer counts noted; external consumers
(openrails/doujins) may differ — VERIFY before deleting.

## Tasks

### Relocate — group opt-in integrations under adapters/
- [x] `providers/{email,sms}/twilio` → `adapters/twilio/{email,sms}` (pkg `twilio`);
      `providers/` deleted. build+vet green.
- [x] `riverjobs/` → `adapters/riverjobs` (kept dir=package; cleaner than `adapters/river`
      with pkg `riverjobs`). `adapters/` now: chi, gin, twilio, riverjobs.

### Relocate — devserver support kit follows the binary into cmd/
- [x] `Dockerfile.devserver` → `cmd/authkit-devserver/Dockerfile`.
- [x] `DEVSERVER.md` → `cmd/authkit-devserver/README.md`.
- [~] `docker-compose.yaml` — KEPT at root (decision): it's the `task test` harness
      (Postgres + devserver), and moving it forces an awkward `context: ../..`. Just
      repointed its `dockerfile:` → `cmd/authkit-devserver/Dockerfile` (context stays root).
- [x] `config/bootstrap.example.yaml` → `cmd/authkit-devserver/bootstrap.example.yaml`;
      `config/` dir DELETED.
- [x] Doc links updated (README bootstrap-example path, SEMVER devserver list +
      `testing`→`authtest`). Taskfile needs no change (compose stayed at root; only a
      comment mentions it). `go build ./...` + `./cmd/authkit-devserver` green.

### Rename — kill the stdlib shadow
- [x] `testing/` → `authtest` (dir + `package testing`→`authtest`, killing the stdlib
      shadow). One in-repo importer (`http/verifier_multialg_test.go`, aliased
      `authkittesting`) repointed. build+vet green.

### Delete — verified against all 4 consumers (doujins/hentai0/cozy-art/tensorhub)
- [x] `roles/` (`roles.IDFromSlug`) — confirmed UNUSED in-repo AND in all 4
      consumers. DELETED. build+vet green.
- [x] `identity/` — DELETED ENTIRELY, with the replacement shipped in the same change:
        - authkit: added `UsersByIDs(ctx, []string) ([]UserRef, error)` to `authkit.Client`
          (new `UserRef` contract type + engine method `Service.UsersByIDs` over the
          existing `IdentityUsersByIDs` sqlc query + facade delegate). One method subsumes
          identity's three batch reads (usernames/emails/users-by-ids).
        - deleted `authkit/identity`; conformance holds (94-method Client); fixed the
          bootstrap-example test path (was `config/`, now `cmd/authkit-devserver/`).
          build+vet+gofmt green; full DB suite green on a fresh DB.
      CROSS-REPO (doujins, on next bump): writes → `embedded.Client.UpdateUsername`/
      `UpdateEmail` (gains the cooldown+validation its raw `identity` writes skipped);
      reads → `Client.UsersByIDs`. Stale sqlc `Identity*` write/single-lookup queries in
      `internal/db` are now unused (harmless generated code; prune on next sqlc regen).

### Read-access design (DECISION — so `identity` never gets re-added)
authkit must NOT ship pre-made query wrappers (`identity.Store` model: maintenance
treadmill, leaks internal sqlc, duplicates the engine, lets hosts bypass invariants).
Host read access is exposed TWO ways, by need:
1. curated read METHODS on `authkit.Client` — single lookups + `AdminListUsers` exist
   today; add batch ones (`UsernamesByIDs`/`UsersByIDs`) as real need appears. Portable
   (works embedded AND remote), keeps tables private, enforces invariants.
2. for an embedded host needing SQL JOINs against its own tables: a documented stable
   read VIEW (e.g. `profiles.users_public`) queried with the host's OWN tooling —
   authkit owns the view contract, the host owns the query. Add only when needed (YAGNI).
Writes ALWAYS go through the engine. Tables stay an implementation detail.

### Flags — DECIDED (keep everything; the public surface is correct)
- [x] Public-surface reduction → KEEP `siws`/`oidc`/`password`/`lang` public. External
      usage (across doujins/hentai0/cozy-art/tensorhub): oidc=4, password=2, lang=5 —
      all legitimately imported as library primitives. `siws`=0 direct, BUT its
      `ChallengeData` leaks through `storage/redis.SIWSCache`'s public signatures, so
      internalizing would break that public API or force deeper surgery — not worth it.
- [x] Root contract-pkg purity → KEEP `origin.go`/`httperror.go`/`permission.go` in
      root. The root package IS the lean shared layer (it absorbed authbase's role);
      these are legitimately-shared lean contract helpers (permission matching + key
      format have external users; the error envelope is the wire error shape). Moving
      them out just recreates the authbase split we deliberately folded. No churn.

## Keep (core / legit public)
`authprovider` (OAuth model, 6 importers), `embedded`, `http`, `verify`, `jwt`,
`oidc`, `migrations`, `ratelimit`, `storage`, `password`, `lang`,
`adapters/{chi,gin}`. Standard root files: `go.mod`/`go.sum`, `README.md`,
`LICENSE`, `SECURITY.md`, `.gitignore`, `.gosec.json`, `Taskfile.yml`, `sqlc.yaml`,
`BREAKING.md`, `SEMVER.md`.

## Coordinate
Lands with the #138 hardcut (same breaking pre-1.0 release); run after the #138
commit so restructure + cleanup ship together.

---

# #140: ship a Can-backed permission gate (RequirePermission middleware)

**Completed:** yes

STATUS 2026-06-26 (Claude): DONE both sides, DB-proven. authkit: shipped
`verify.RequirePermission` and factored its authority decision into exported
`verify.Allow(ctx, checker, claims, perm, scope)` (token-carried OR Can; v0.71.0) so
non-HTTP gates share it. doujins ADOPTED it — deleted its local
`principalHasPermissionDB`/`PrincipalHasPermissionDB`; the gin `RequirePermission` is now
a thin adapter over `verify.Allow`, and the OpenRails delegated billing-admin check calls
`verify.Allow` directly. The role→permission expansion was already gone (it delegated to
Can); this removed the last local gate copy. Behavior is identical by construction (same
token glob-match via `PermMatches` OR `Can` in the root scope); proven by the DB-backed
`TestIdentityContinuity` (real Postgres: non-admin → 403 on /v1/merchant/*) + authkit's
new `verify.Allow` unit test.

Proposed 2026-06-25 (doujins boundary review). authkit owns the permission-group
schema and has `Can(subjectID, subjectKind, persona, instanceSlug, perm)`, but
ships NO request-level gate — so embedding hosts hand-roll one AND reimplement the
role→permission expansion against a local copy of the catalog. doujins's
`principalHasPermissionDB` maps perm→roles from its own `roleBundles` and borrows
authkit only for role membership, duplicating what `Can` already does end-to-end.
Hard cut: ship the gate, hosts delete their copies.

STATUS 2026-06-25 (Claude): implementation DONE in the working tree —
`verify/require_permission.go` + `require_permission_test.go` (6 cases),
`go build/vet/test ./verify/` green. Held with #139 pending a pinnable release.

## Tasks
- [x] `net/http` `RequirePermission(checker, perm, resolve)` middleware in
      `verify/require_permission.go`: `resolve` → (persona, instanceSlug) so ONE
      gate serves singleton `root` AND resource-scoped `merchant`/`customer`; reads
      verified Claims; token-carried perms short-circuit, else `Can` → 403/next;
      fail-closed.
- [x] tests (`require_permission_test.go`, 6): singleton allow/deny, resource-scoped
      instance pass-through, token short-circuit, no-claims + nil-checker forbidden.
- [~] `Can` on the `authkit.Client` interface — #138's (93-method Client exists).
      The gate deliberately depends on a NARROW `verify.PermissionChecker` port
      (`embedded.Client`/`authkit.Client` satisfy it directly), so `verify` stays
      jwt-only and never imports the engine.
- [ ] document the net/http→gin wrap (composes with the standard gin wrapper, e.g.
      doujins's `wrapHTTPMiddleware`) — doc nicety, non-blocking.

CROSS-REPO CONSUMER (doujins #422/#423): once shipped, doujins deletes
`principalHasPermissionDB` + `catalogRolesGranting` + the local `permission.ForRoles`
expansion and gates purely via authkit. Pairs with #138's `authkit.Client`.

---

# #139: verify.Verifier.VerifyRequest — request→claims extractor (un-hack out-of-band auth gates)

**Completed:** yes

STATUS 2026-06-26 (Claude): DONE both sides. `verify.VerifyRequest` shipped (≤ v0.69.0);
doujins ADOPTED it — `internal/billing/openrailsembed/auth.go` now calls `v.VerifyRequest(r)`
(the discard-ResponseWriter hack is gone). No remaining cross-repo work.

STATUS 2026-06-25 (Claude): code + a direct `VerifyRequest` test are in the working tree; `verify` pkg green (Required now delegates to it). Held pending a pinnable authkit release; doujins re-applies then (doujins #422).

Proposed 2026-06-25. `verify.Required`/`Optional` are the only way to run the
full auth pipeline (bearer parse, API-key branch, JWT verify, 2FA + delegated
issuer gates, DB enrichment, ban/deleted gate). An embedder that must
authenticate a request OUTSIDE the http-middleware chain (openrails' billingauth
seam, consumed by doujins) currently drives `Required` against a throwaway
ResponseWriter and scrapes claims back out of the request context — a hack.

Change (additive, non-breaking; stays inside `verify/`, which #138 leaves
unchanged): extract the pipeline body of `Required` into

    func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error)

returning the enriched claims, or an error carrying the would-be HTTP status
(401/403) via an unexported `authError`. `Required` becomes a thin wrapper that
calls `VerifyRequest` and writes the response — single source of truth, behavior
preserved (verify tests green). Patch: scratchpad/authkit-verifyrequest.patch.

Coordinate with #138 (same repo, active): no package overlap (verify/ untouched
there), so this can land independently or fold into the #138 release.

CROSS-REPO CONSUMER (doujins): `internal/billing/openrailsembed/auth.go` replaces
its discard-writer `verifyRequest` with `v.VerifyRequest(r)` once authkit ships
this (needs a version doujins can pin).

---

# #138: Package restructure for embedded-now / standalone-later (etcd-style dual mode)

**Completed:** yes (Phase 1/1.5/1.6 done + committed; Phase 2 split to #142)

STATUS 2026-06-25 (Claude): Phase 1 landed in the working tree. Done: devserver →
`cmd/authkit-devserver/`; `core` package → `embedded` (`core.Service` →
`embedded.Client`, `NewFromConfig` → `New`, 69 importers updated); root `authkit`
package with the 93-method `Client` interface + data-contract re-exports +
compile-time conformance proof; `svc.Core()` → `svc.Client() authkit.Client`
(http + devserver are the root's first importers, seam exercised end-to-end);
#109 disambiguation (collision resolved by the rename). Cut public `NewService`
(Options+Keyset escape hatch, no real consumer) after rewriting its lone test
caller onto `embedded.New`. Deferred:
making root literally pgx-free (relocating ~115 type defs; only Phase-2 `remote`
needs it). Verified: `go build ./...` + `go vet ./...` green; non-DB tests pass;
DB-backed riverjobs purge + http server tests pass against the compose Postgres.
COMMITTED — Phase 1 `a08ac76`, with the 1.5/1.6 inversion+fold landed in the same
tree, then #141 cleanup `afa17d1` (local on master, not pushed). Phase 2 (standalone
server + `authkit/remote` SDK + transport seam) is SPLIT OUT to issue #142 — build
when greenlit.

Proposed 2026-06-25 (Paul + Claude design session). authkit is an **embedded Go
library today**. We want it to *later* be offered as a **self-hostable standalone
server** (so non-Go apps can use it over HTTP), and a consumer should swap
embedded ↔ standalone with **minimal effort** — the way openrails does. This issue
restructures the embedded library now so the swap seam exists, then stops.
Standalone is Phase 2, deferred until we decide to build that product. Breaking;
lands with the #108 hardcut, pre-1.0.

Reference design is **etcd** (runs both ways: `embed` package + `clientv3` +
standalone binary). An agent analyzed it; the load-bearing lessons:

1. **Lean client/contract module, heavy server module.** etcd's `client/v3` (gRPC
   only) + `api/v3` (shared DTOs) carry no raft/storage. → our lean root + heavy
   `embedded` split is right.
2. **Write the client ONCE; vary the transport.** etcd does NOT have two client
   impls. One `clientv3.Client` is fed by either a real gRPC socket OR a
   zero-serialization **in-process adapter** (`v3client.New(server)` via
   `proxy/grpcproxy/adapter`, presenting server handlers as the client interface).
   → **This corrects the earlier sketch of two independent impls (`embedded` +
   `remote`) each satisfying the interface — two impls drift (error mapping,
   timeouts, partial coverage). One client + two transports does not.**
3. **In-process = direct calls, NOT a loopback socket.** etcd's embedded fast path
   makes direct function calls through the real handler stack. → when we build
   standalone, embedded must not route through HTTP/loopback.
4. **One config struct, two front doors.** `embed.Config` is mutated by embedders
   and filled-from-flags/file by the binary (`etcdmain` wraps the same struct);
   `main` is ~10 lines.
5. **Frozen wire-contract package** (`api/v3`) versioned independently. → our root
   DTOs are the start of this.

## Target layout

| Package | Deps | Phase | Role |
|---|---|---|---|
| `authkit` (root) | lean (stdlib) | 1 | contract: `Client` interface, shared DTOs (`User`/`Session`/`APIKey`/`Config`…), sentinel errors. No pgx/redis/http. Swap seam + frozen wire-contract. |
| `authkit/embedded` | + pgx | 1 | in-process engine; `New(cfg, pg) (*Client, error)`; satisfies `authkit.Client` via direct Go calls. (today's `core` + `internal/authcore`) |
| `authkit/http` | + oidc/redis/ratelimit | 1 (rename) | browser-facing auth-flow routes an embedding app mounts. Stays; becomes a component of the Phase-2 standalone server. |
| `authkit/verify` | jwt only | 1 (unchanged) | local JWT validation, both modes. Must never import `embedded`. |
| `authkit/server` | + http + mgmt API | 2 | standalone self-hostable binary: engine + `http` routes + authenticated management API for non-Go clients. Thin `main` in `cmd/`. |
| transport/adapter layer | lean | 2 | in-process direct-call adapter (embedded) + HTTP transport (remote), both feeding one shared client (etcd `v3client`/`adapter`). |
| `authkit/remote` | + net/http | 2 | Go SDK over the mgmt API. Satisfies `authkit.Client`. |

Consumer code, unchanged across the swap:
```go
var c authkit.Client
c, _ = embedded.New(cfg, pg)                       // Phase 1 — in-process
c, _ = remote.New("https://auth.acme.com", creds)  // Phase 2 — standalone
c.CreateUser(ctx, "a@b.com", "alice")              // identical either way
```

## Phase 1 — embedded restructure + seam (this issue)

- [x] Create root `authkit`: `authkit.Client` interface = the portable 93-method
      subset (infra accessors `Postgres()`/`Keyfunc()`/`JWKS()`/`Options()`/`Schema()`
      kept OFF it), `client.go`; data types/enums/sentinel errors re-exported in
      `types.go`; compile-time `var _ Client = (*embedded.Client)(nil)` conformance
      proof holds. **DEFERRED:** literal "ZERO pgx imports" — root re-exports from
      `embedded`, so it transitively imports pgx today. Making root pgx-free means
      relocating ~115 type DEFINITIONS out of the pgx-importing engine files into a
      lean package (the structs themselves are plain — `User`/`Session`/`Config` use
      only stdlib — but their files hold the engine). That's a large separable
      surgery whose only consumer is Phase-2 `remote`; carved out as its own task.
- [x] Rename `core` → `embedded`; `core.NewFromConfig` → `embedded.New`;
      `core.Service` → `embedded.Client`; all 69 importers updated; build green.
- [x] DELETE public `core.NewService`/`embedded.NewService` (the Options+Keyset
      escape hatch — no real consumer; real construction is `embedded.New(Config, pg)`).
      Its one caller, the river purge-worker DB test, was rewritten onto
      `embedded.New(Config{Keys.VerifyOnly}, pg)` (no signer needed). Internal
      `authcore.NewService` kept (used by `New` + in-package tests). DB test green.
- [x] `svc.Core()` → `svc.Client()` returning `authkit.Client` (the interface seam;
      devserver bootstrap helpers now take `authkit.Client`). http + devserver are
      the root package's first real importers — seam exercised end-to-end.
- [x] Move devserver (`package main` at repo root, test-only) → `cmd/authkit-devserver/`;
      thin `main`. Frees root to be the library package. (Dockerfile.devserver build path updated.)
- [x] `authkit/http` #109 disambiguation: the collision is RESOLVED by the
      core→embedded rename (no second public `Service` type exists; facade is
      `embedded.Client`). `Server` kept as the recommended exported alias
      (`type Server = Service`); stale `core.Service` doc fixed. Full receiver
      rename `Service`→`Server` skipped — pure churn, no behavior change, nothing
      left to disambiguate.

**NOT in Phase 1 (YAGNI until standalone greenlit):** no `authkit/server` binary,
no management HTTP API, no `authkit/remote` SDK, no transport/adapter layer (with
one transport the engine *is* the client). The root interface is the one piece of
deliberate forward-investment — it makes the Phase-2 swap construction-only instead
of a type change in every consumer.

## Phase 2 — standalone server → SPLIT OUT to issue #142

The standalone self-hostable server, management HTTP API, `authkit/remote` SDK, and
the etcd "one client, two transports" seam are now planned in their own issue, #142.

## Phase 1.5 — contract inversion to the ideal greenfield shape (DONE — root pgx-free)

STATUS 2026-06-25 (Claude): COMPLETE. Root `authkit` is now pgx-free — it depends
on `authbase` + stdlib only (`go list -deps` verified). The wire contract (47+6
sentinel errors, `User`/`Session`, 34 DTOs/enums + 11 enum consts) lives in the
lean `authbase` package; `internal/authcore` aliases every symbol back so engine
code is unchanged; root re-exports the contract from `authbase`; the
`embedded.Client`→`authkit.Client` conformance assertion moved into `embedded`.
Dependency direction is now correct (infra → contract, never the reverse). build
+ vet green; full DB-backed suites pass on a fresh migrated DB. Only the optional
naming polish (fold `authbase` into root) remains. NOT committed (dirty worktree).

Decision (Paul, 2026-06-25): a pgx-free root is the IDEAL design, not just nicer —
it's the correct dependency direction. Infra (pgx persistence, http transport) are
ADAPTERS that depend INWARD on the contract; the contract depends on nothing heavy
(etcd `api/v3` / hexagonal ports). Today's shape is INVERTED — root re-exports
*outward* from the engine, so the contract depends on the implementation. Fix it.

**Contract home = `authbase`** (already lean/stdlib-only, already imported by
`authcore`; its own doc says it exists for verify "and, later, a remote SDK" — it
IS the designed contract package). Already holds RemoteApplication, APIKey types,
ResolvedAPIKey, ServiceJWTClaims, key-format helpers, 3 sentinel errors.

**Mechanic (incremental, build-green — no big-bang cycle-break):** for each
contract symbol DEFINED in `internal/authcore`:
1. move its DEFINITION into `authbase` (stdlib-only; topological order, leaves first);
2. in `authcore` replace the def with `type X = authbase.X` (authcore already imports authbase);
3. `embedded/aliases.go` + root `types.go` re-exports keep working via the alias chain → green.

**FINAL FLIP** (once every root-exposed symbol resolves through `authbase`):
point root `types.go` re-exports at `authbase` instead of `embedded`; move the
`var _ authkit.Client = (*embedded.Client)(nil)` conformance into `embedded`; drop
root's `embedded` import → **root is pgx-free**.

**Partition (contract vs engine):**
- CONTRACT → `authbase`: DTOs (`User`, `Session`, `AdminUser`, `GroupMember`, …),
  enums (`RegistrationMode`, `SessionRevokeReason`, …), the `*Request`/`*Result`/
  `*Options` in the `Client` interface, sentinel errors, key-format helpers.
- ENGINE → stays in `authcore`/`embedded`, OFF root's surface: `Config`, `Options`,
  `Keyset`, ports (`EmailSender`/`SMSSender`/`EntitlementsProvider`/`AuthEventLogger`),
  `WithX` construction options. Trim these from root `types.go` — they aren't contract.

**Cycle-break note:** the conformance assertion must leave root (else root→embedded→
pgx). Defining straight into root would force authcore→root while root still imports
embedded — a cycle; staging through `authbase` (which authcore already imports)
avoids it and keeps every step green.

**Stages** (each build-green) — ALL DONE except the optional fold-in:
- [x] sentinel errors → `authbase`: all 47 authcore-defined sentinels MOVED to
      `authbase/errors.go`; authcore aliases them (`var ErrX = authbase.ErrX`).
      Shared `errors.Is` identity now lives in the contract pkg.
- [x] leaf DTOs → `authbase`: `User` + `Session` (authbase/user.go).
- [x] composite DTOs + enums → `authbase`: 34 types + 11 enum consts moved to
      `authbase/contract.go` (Admin*, APIKey*, Bootstrap*, Group invite*, Group
      membership, mint params, Import*, Passwordless*, MFAStatus, PreferredLanguage),
      authcore aliases them all. One method (`AdminUserListOptions.normalize`)
      converted to a free function (can't define methods on an alias).
- [x] trim engine types off root `types.go`: root now re-exports ONLY the contract
      from `authbase` (102 symbols: DTOs + enums + 53 sentinel errors). `Config`/
      `Options`/`Keyset`/ports/`WithX` dropped from root (reach them via `embedded`).
- [x] FINAL FLIP → **root is pgx-free**: `types.go` re-exports from `authbase`,
      conformance assertion `var _ authkit.Client = (*embedded.Client)(nil)` moved
      to `embedded/conformance.go`, root's `embedded` import dropped. `go list -deps`
      on root = `{authbase}` only — no pgx/redis/authcore/embedded/http. `verify`
      still pgx-free. Full DB-backed suites (internal/authcore, http, riverjobs)
      green on a freshly-migrated DB.
- [ ] fold `authbase` into root `authkit` (one contract package) — see Phase 1.6.

## Phase 1.6 — fold authbase into root + delete legacy (HARDCUT, no compat) — DONE

STATUS 2026-06-25 (Claude): `authbase` package FOLDED into root `authkit` and
deleted; its 9 files now define the contract in the root package, root `types.go`
re-export shell deleted, all 34 importers repointed to root, stale comments
cleaned. Root `authkit` is the ONE contract package — pgx-free (`go list -deps` =
root only), holds DTOs + enums + 53 sentinel errors + the `Client` interface.
`verify` still pgx-free. build + vet + gofmt green; full DB-backed + non-DB suites
pass on a fresh DB. Only the cosmetic `embedded` alias trim declined (see below).
NOT committed (dirty worktree).

Make root `authkit` the ONE contract package consumers import (`authkit.User`,
`authkit.ErrUserNotFound`, `authkit.Client`). No `authbase` package, no redundant
re-export shells. Breaking; hardcut, no compatibility aliases.

- [x] Move `authbase/*.go` (9 files + `httperror_test.go`) into root `authkit`
      package; `package authbase` → `package authkit`. Defs now LIVE in root.
- [x] Delete root `types.go` (the re-export shell — redundant once defs are in root).
- [x] Rewrite all 34 `authbase` importers: import path → root, `authbase.` →
      `authkit.` (authcore engine aliases now `type X = authkit.X`; verify/http/embedded
      repointed). Stale `authbase` comment mentions cleaned up too.
- [x] Delete the now-empty `authbase/` directory.
- [x] Verify: no import cycle; root pgx-free + lean (`go list -deps` root = {root} only);
      `verify` still pgx-free; build + vet + gofmt green.
- [x] Full DB-backed suites (internal/authcore, http, riverjobs) + non-DB (root
      `authkit`, verify, jwt, adapters) pass on a fresh migrated DB; gofmt clean.
- [x] Trim `embedded/aliases.go` contract re-exports (HARDCUT, per Paul). Dropped
      all 117 redundant contract re-exports (types + 53 errors + enum consts +
      helpers); `embedded/aliases.go` now re-exports ENGINE symbols only
      (Config/Options/ports/WithX/engine enums). The 93-method `embedded` facade and
      every consumer (http/cmd/adapters/riverjobs) now spell the contract `authkit.X`;
      unused `embedded`/`authkit` imports pruned. One subtlety handled: a substring
      repoint had corrupted engine types sharing a contract prefix
      (`APIKeyResource*`) — reverted those to `embedded.X`. build + vet + gofmt green;
      full DB-backed + non-DB suites pass on a fresh DB; root still pgx-free.

## Open decisions

- Naming collision `authkit.Client` (interface) vs `embedded.Client` (struct) —
  fine in Go (`http.Client`); alternatives `authkit.API` / `embedded.Engine`.
- Root = contract (chosen — so `remote` imports it without pgx; no `authkit.New`,
  construction is `embedded.New`) vs root = embedded entrypoint (`authkit.New`,
  pulls pgx) with contract in `authkit/api`.
- Exact interface surface: which of the ~95 methods are portable contract vs
  embedded-only infra — needs a method-by-method pass.

---

# #136: Root RBAC redesign — owner/admin tiers, core-enforced no-escalation, bootstrap seed-if-absent

**Completed:** yes

Proposed 2026-06-23 (Paul + Claude design session). Rework the `root` persona's
operator model into a clean two-tier scheme with escalation safety enforced in
CORE, not left to callers. Land this BEFORE consumers adopt (doujins #420) so they
migrate to the final shape once. doujins + hentai0 share ONE root group.

STATUS 2026-06-23 (Codex): API-key resource-scope escalation path fixed in
core. `MintAPIKeyWithOptions` now fails closed for non-empty `resources` unless a
host-supplied `WithAPIKeyResourceAuthorizer` allows the exact scope request; the
HTTP mint path no longer has any bypass because it calls the same core method.
DB-backed HTTP integration tests cover ordinary API-key mint/list/revoke, denied
resource scopes when no authorizer is configured, allowed scoped keys resolving
with resources, and a rejected cross-resource escalation attempt. Also updated
stale root-owner HTTP test setup to use the genesis group-assignment path under
the new owner/admin model. Validation:
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./http -run 'TestGroupAPIKey' -count=1 -v`
and
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./... -count=1`
passed against the running compose Postgres.

STATUS 2026-06-23 (Codex): Remaining #136 implementation is now DONE in the
working tree. Runtime assignment gates now use `<persona>:roles:manage` in both
generated HTTP member-mutation routes and core no-escalation checks; API-key role
grants now run the same core no-step-up check before insert; the legacy
owner-reserved root helper was removed so the unchecked genesis path can seed
`owner`; bootstrap owner seeding is covered as seed-if-absent and zero-owner
recovery. `ListRoleSlugsByUserErr` already exists on the public facade. Focused
DB-backed validation passed:
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./internal/authcore -run 'TestAssignRoleBySlugAs_NoEscalation_DB|TestAssignRoleBySlug_AllowsOwnerGenesis|TestApplyBootstrapManifest|TestGeneratedRoutes_GatesAreCorrect' -count=1 -v`
and full DB-backed validation passed:
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./... -count=1`.
Release/tag remains a separate finalization step because this is still an
uncommitted dirty worktree and the repo is already tagged beyond the old
`v0.60.0` target (`v0.61.0`).

## Motivation
1. The root persona ships TWO equivalent `root:*` roles — `owner`
   (reserved/unassignable) and `super-admin` (assignable) — redundant and
   confusing ("why two god-mode roles?").
2. Role ASSIGNMENT is actor-less and does NOT enforce no-privilege-escalation:
   `assignRoleBySlug`/`AssignGroupRole` take (target, role) with no actor; the only
   guard is the blunt "owner slug is reserved". Before the 2026-06-23 API-key
   fix above, API-key resource scopes had the same caller-enforced shape. So a
   weak role able to call a grant path could mint a STRONGER role (e.g.
   super-admin), and API-key minters could previously attach host-defined
   resource scopes unless each caller remembered to close it.

## Target model
- **owner** = the apex. Holds `root:*`. Seeded via the bootstrap manifest
  (deploy-time). Manages root roles INCLUDING other owners (holds
  `root:roles:manage` via `root:*`).
- **admin** = an APP-declared operational role: a bundle of `root:` perms (e.g.
  `root:users:ban`, `root:content:moderate`) MINUS `root:roles:manage`, so admins
  do the work but cannot promote anyone. ("admin can't make admins" = just
  withhold one perm.) Declared by consumers (doujins #420), not authkit.
- Drop **super-admin** (folded into owner): remove `SuperAdminRoleName` from the
  intrinsic root persona. The `super-admin`→`admin` normalize shim in consumers
  goes away.

## Core-enforced invariants (the heart of this issue)
Every RUNTIME grant (root roles, org roles, AND api-key role grants) must pass,
enforced in authcore — NOT the caller:
1. **Capability:** actor holds the persona's role-manage perm (`root:roles:manage`
   for root). The "can assign at all" gate → admins lacking it can't promote.
2. **No step-up:** `perms(targetRole) ⊆ perms(actor in that persona-instance)`,
   subset-OR-equal, using existing wildcard coverage
   (`permission_group_authorize.Can` semantics: `root:*` ⊇ `root:users:ban`, but
   `{root:users:ban}` ⊉ `root:*`). Scoped to the same persona-instance. So owner
   (`root:*`) may grant owner+admin; a holder of `{root:users:ban}` may grant at
   most `{root:users:ban}`, never owner/admin.

This SUBSUMES the owner-reserved hack: only an actor holding `root:*` can grant
`root:*` → "only owners mint owners" falls out of the general rule. DELETE the
special-case reserved check. Generalizes to org personas + api-key role grants;
API-key resource-scope authorization is already core-enforced by the
`WithAPIKeyResourceAuthorizer` fix above. Requires making the assignment path
ACTOR-AWARE (add actor subjectID / an actor-aware variant) across
assign/unassign + the admin grant/revoke HTTP adapters + api-key role grant.

## Bootstrap = genesis + recovery
- The OPERATOR (bootstrap.yaml + deploy access) is the true root of trust; DB
  owners are runtime delegates. Bootstrap seeding BYPASSES the runtime rules
  (capability/no-escalation) — it is the genesis path. The manifest already seeds
  users + root roles; today "admin" mints super-admin — repoint to `owner`.
- **No "last owner" guard.** Removing all owners is allowed: worst case runtime
  role administration is soft-frozen (nobody holds `root:roles:manage`), NOT a
  lockout — the operator re-seeds an owner via bootstrap. One fewer edge case /
  source of bugs.
- Policy: owner seeding is **seed-if-absent** (break-glass — acts only when there
  are zero owners, never fights runtime owner edits), NOT idempotent
  desired-state. Day-to-day owner management stays in the runtime API.

## Open decision
`root:roles:manage` currently means "define/inspect operator roles" (role
DEFINITIONS). There is NO separate `root:roles:assign` / `root:members:assign` for
granting a role to a USER (membership). For this model one perm gating both
("owners assign, admins don't") suffices; split later only if we want an "assigns
other admins but can't edit role defs" tier.

## Tasks
- [x] Make role assignment ACTOR-AWARE (root + org + api-key paths).
- [x] Enforce capability + no-escalation (subset, wildcard-correct) in authcore.
- [x] Enforce API-key resource-scope no-escalation in core: non-empty
      `resources` require `WithAPIKeyResourceAuthorizer`; absent authorizer
      rejects by default with `resource_scope_denied`.
- [x] Route HTTP API-key minting through the core resource-scope authorizer path
      and return the specific `resource_scope_denied` error for denied scopes.
- [x] Enforce API-key role-grant no-step-up in core before insert; the creator
      must hold `<persona>:roles:manage` and cover the requested API-key role's
      effective permissions.
- [x] Drop `super-admin` from intrinsic root; keep `owner` as apex; delete the
      owner-reserved special case (subsumed by no-escalation).
- [x] Bootstrap: seed `owner` (not super-admin), seed-if-absent; NO last-owner guard.
- [x] Add an ERROR-RETURNING role/permission read (e.g. `ListRoleSlugsByUserErr`)
      so consumers can surface role-resolution failures instead of swallowing
      (today `ListRoleSlugsByUser` returns `[]string`, no error). Needed by doujins #420.
- [x] Tests: escalation attempts rejected (weak role can't grant stronger/owner);
      owner grants owner+admin; admin (no roles:manage) can't grant; bootstrap
      genesis bypasses; zero-owner recoverable via bootstrap.
- [x] Tests: DB-backed API-key integration covers normal key mint/list/revoke,
      fail-closed resource scopes, allowed scoped-key resolution, and rejected
      cross-resource and cross-role escalation.
- [ ] Release/tag finalization from a clean commit + update release target. SEMVER
      docs are updated; old `v0.60.0` target is stale because the repo is already
      tagged at `v0.61.0`.

## Cross-repo
Consumers adopt via doujins #420 (doujins + hentai0 share ONE root group).

---

# #49: Passwordless contact login and wallet account creation

**Completed:** yes

Add an optional passwordless contact flow for AuthKit users. A host can ask for phone or email, send an OTP and/or magic link, then mint a normal AuthKit session after confirmation. This remains separate from verification/password-reset links (#10) and additive to existing password, passkey, OIDC, and 2FA flows.

The OpenRails wallet use case needs one extra behavior beyond the old future plan: create-or-login. If the verified contact belongs to an existing user, confirm logs that user in. If no user exists and the host enables passwordless auto-registration, confirm creates a user with a generated username, verified email/phone, and no password. The user can add a password or passkey later, but first checkout should not require either.

## Goals

- Allow passwordless login by email OTP, email magic link, SMS OTP, and SMS magic link where senders support it.
- Allow create-if-missing for products like OpenRails customer wallets that need quick account creation at checkout.
- Keep existing `/register`, `/password/login`, passkey, OIDC, verification, password reset, and 2FA behavior intact.
- Record session assurance accurately: `amr=email` for email-confirmed login, `amr=sms` for phone-confirmed login, and no fake `pwd`.
- Keep the feature host-enabled; private deployments can leave it unmounted or disabled.

## Non-goals

- Do not replace password login or passkeys.
- Do not make verification links double as login links. Passwordless login gets its own purpose, token kind, TTL, rate limits, and audit events.
- Do not leak whether an identifier exists. Start always returns the same accepted response.
- Do not require username/password before first passwordless account creation.
- Do not make SMS magic links depend on Twilio Verify. Use the host SMS sender/Messaging API path already used for SMS links.

## API shape

- `POST /passwordless/start`
  - Body: `{ "identifier": "email-or-phone", "mode": "code|link|both", "return_to": optional }`
  - Behavior: normalize identifier, rate-limit by IP and identifier, create a pending passwordless challenge, send code/link if the host permits this channel, and always return an anti-enumeration `202`.
- `POST /passwordless/confirm`
  - Body for OTP: `{ "identifier": "email-or-phone", "code": "123456" }`
  - Body for magic link: `{ "token": "high-entropy-token" }`
  - Behavior: consume the challenge once, find or create the user as configured, mint access/refresh tokens, and return the same token response shape as existing login.

Use prefix-neutral AuthKit route names; host apps may mount them under `/auth/*`.

## Data model / token storage

- Store passwordless challenges in the existing ephemeral store pattern, keyed by hashed code/link token.
- Bind short OTP codes to the normalized identifier so a guessed code cannot verify another account.
- Store high-entropy magic-link tokens as hashes and consume them globally by token.
- Track purpose separately from verify/reset: `passwordless_login`.
- For create-if-missing challenges, store normalized identifier, channel, generated username candidate, preferred language if known, return target if allowed, TTL, and attempt counters.
- Do not insert a `profiles.user_passwords` row for passwordless-created users until they set a password.

## User creation behavior

- Existing verified contact: confirm logs in that user.
- Existing unverified contact: confirm marks that contact verified and logs in the user only if the challenge was sent to that contact.
- Missing contact with auto-registration disabled: consume or reject per policy but return a non-enumerating error shape.
- Missing contact with auto-registration enabled: create a user with generated username, set the verified email or phone, no password, and issue a session.
- Generated usernames must use the existing AuthKit username validation/reservation rules and retry on collision.

## Security notes

- Short OTPs need identifier binding, attempt caps, short TTL, and per-identifier rate limits.
- Magic-link tokens need high entropy, single-use consumption, short TTL, and safe return-target handling.
- Confirm success/failure uses the existing session lifecycle audit stream; request/rate-limit/account-created audit events need a broader audit-contract expansion if required later.
- Session minting should call the existing `IssueRefreshSessionWithAuthMethods` path with the right auth method.
- Sensitive operations can still require step-up or MFA later; this flow only establishes wallet/login identity.

## Tasks

- [x] Add feature/options wiring for passwordless login and passwordless auto-registration; default disabled unless a host enables it.
- [x] Add route specs for `POST /passwordless/start` and `POST /passwordless/confirm`.
- [x] Add core methods to create, store, consume, and expire passwordless challenges using the existing ephemeral-store pattern.
- [x] Add email and SMS delivery support for passwordless OTP/link messages, reusing the existing sender style where practical.
- [x] Add create-if-missing user path with generated username, verified email/phone, and no password row.
- [x] Add existing-user login path that verifies the contacted identifier and mints access/refresh tokens with `amr=email` or `amr=sms`.
- [x] Add anti-enumeration behavior and rate limits for start and confirm.
- [x] VERIFIED 2026-06-26: OTP/passwordless start is rate-limited by IP and
      identifier (`RLPasswordlessStart`: 6/hour + 1m cooldown). Confirm is
      rate-limited by IP and identifier (`RLPasswordlessConfirm`: 10/10m).
      Challenges expire after 10 minutes. Five bad typed-code attempts for the
      same identifier delete the challenge, so the original code no longer works.
- [x] Add safe `return_to` handling or explicitly return tokens only to the caller and let the host own navigation.
- [x] Add DB-backed tests for email OTP login, email magic-link login, SMS OTP login, SMS magic-link login, create-if-missing, existing-user resume, generated username collision, no password row, disabled feature, duplicate/expired token, invalid code attempt caps, and anti-enumeration responses.
- [x] Update README, `agents/api-endpoints.md`, and SEMVER notes with the new flow and host integration guidance.

## Validation

- [x] Real-server passwordless integration pass against a fresh migrated Postgres: `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_issue49_1782336194?sslmode=disable' go test ./http -run 'TestPasswordless' -count=1 -v`. This includes `TestPasswordlessRealHTTPServerEmailOTP`, which uses `httptest.NewServer(srv.APIHandler())` over actual HTTP plus the real DB.
- [ ] Full DB-backed `go test ./... -count=1` is blocked by unrelated existing permission-group/admin failures in `http` and `internal/authcore`; issue-49 focused DB-backed tests pass.

## Cross-repo

- OpenRails SaaS #19 will use this for customer wallet login/account creation at checkout while keeping merchant-app authentication separate.

---

# #129: Hard-cut remaining org terminology to persona / permission groups

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Remaining AuthKit-owned org terminology was hard-cut to permission groups, personas, and resource slugs. The public/API naming now uses `Persona`, `PermissionGroupID`, and `ResourceSlug`; stale org errors/types/routes/docs were removed or converted, and a terminology guard prevents reintroducing the old live surface.

## Validation

- `rg 'OrgID|OrgSlug|OrgMembership|GroupType|ResourceRef|resource_ref|/orgs|profiles\\.org|org_' ...` shows only negative-contract docs/tests and the terminology guard.
- `go test ./...`
- `task test` passed against `authkit_sqlc_tmp`.

---

# #128: Add admin-directory indexes and rename API-key storage tables

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). The compact Postgres baseline defines admin-directory btree indexes plus `profiles.api_keys` / `profiles.api_key_resources`; runtime API-key SQL, generated sqlc models, cleanup tests, and docs use the API-key storage names. Bearer token format stayed unchanged.

## Validation

- `task sqlc`
- Focused API-key/admin-directory integration tests passed against a migrated scratch Postgres database.
- `task test` passed against `authkit_sqlc_tmp`.

---

# #127: Rename 2FA storage to MFA and enforce MFA-required roles at assignment time

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Storage now uses `profiles.mfa_settings` and `profiles.mfa_factors`; sqlc query/model names use MFA storage names. `RoleDef.RequiresMFA` is the policy source, role assignment and invite acceptance reject MFA-required roles until the user has enabled MFA with at least one factor, and disabling/removing the last factor removes only human-user MFA-required role assignments in the same transaction.

## Validation

- `task sqlc`
- `TestMFARequiredRoleAssignmentAndDisableLifecycle`
- `TestMFARequiredInviteAcceptLifecycle`
- `TestMFARequiredRoleHTTPIntegration`
- `task test` passed against `authkit_sqlc_tmp`.

---

# #124: Clarify DB-backed test setup and prune low-value test coverage

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). The DB-backed test path is documented, CI uses the compose/migrated Postgres path for `task test`, and low-value route/source/private-helper tests were pruned while retaining behavior/security coverage.

## Validation

- `go test ./...`
- `task test` passed against `authkit_sqlc_tmp`.

---

# #122: Make sensitive-action reauth support 2FA refresh without full password login

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Sensitive-action checks require recent `auth_time`; MFA no longer bypasses freshness, `/reauth/2fa` supports default and method-selected factors without exposing factor IDs, and `/user/me` / `reauth_required` expose display-safe 2FA reauth options.

## Validation

- Reauth/freshness regression coverage is present in the HTTP and verify suites.
- `go test ./...`
- `task test` passed against `authkit_sqlc_tmp`.

---

# #125: 2FA factor hard-delete + Postgres schema cleanup

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). The 2FA/MFA storage cleanup is implemented in the compact Postgres baseline and current service/query code: per-factor soft-disable is gone, factors are hard-deleted, account settings hold only the login gate plus backup codes, dead schema objects were removed, sqlc was regenerated against a scratch current-schema Postgres, and role/data cleanup regressions are covered.

## Validation

- `SQLC_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_sqlc_tmp?sslmode=disable' task sqlc`
- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_sqlc_tmp?sslmode=disable' go test ./authprovider ./http ./internal/authcore ./migrations/postgres -run 'Test.*(EmailVerify|Security|MFARequiredRole|TwoFactorFactorHardDelete|TwoFactorSettingsDeriveFromDefaultFactor|AdminDeleteUserClearsGroupData|ClientIP|DecodeJSON|GitHub)' -count=1 -v`

---

# #123: Harden against security-audit findings

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). The audit fixes are implemented: email verification codes are email-scoped with identifier rate limits and failed-attempt invalidation, OAuth/OIDC redirect URIs no longer trust forwarded host headers, OAuth/OIDC state is browser-bound, GitHub email verification mapping is no longer hardcoded true, SIWS link nonce consumption is atomic, forwarded IP parsing uses the right-most untrusted hop, and JSON bodies are capped.

## Validation

- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_sqlc_tmp?sslmode=disable' go test ./authprovider ./http ./internal/authcore ./migrations/postgres -run 'Test.*(EmailVerify|Security|MFARequiredRole|TwoFactorFactorHardDelete|TwoFactorSettingsDeriveFromDefaultFactor|AdminDeleteUserClearsGroupData|ClientIP|DecodeJSON|GitHub)' -count=1 -v`

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Passkeys are implemented as a first-class AuthKit login method with WebAuthn registration/login ceremonies, discoverable credentials, management routes, RP config, storage in the consolidated Postgres baseline migration, MFA assurance claims, and focused integration coverage.

## What changed

- Added passkey RP config on `core.Config.Passkeys` with BaseURL-derived defaults and origin/RPID validation.
- Added passkey storage in `profiles.user_passkey_handles` and `profiles.user_passkeys` inside the consolidated `migrations/postgres/001_auth_schema.up.sql` baseline.
- Added `RoutePasskeys` routes: `POST /passkeys/register/begin`, `POST /passkeys/register/finish`, `POST /passkeys/login/begin`, `POST /passkeys/login/finish`, `GET /passkeys`, `PATCH /passkeys/{id}`, and `DELETE /passkeys/{id}`.
- Registration requires a recent authenticated session, uses resident/discoverable credentials, returns duplicate credential exclusions, and stores verified credentials.
- Login supports username-scoped and discoverable/usernameless ceremonies, requires user verification, rejects meaningful sign-count clone warnings, updates last-used/sign-count metadata, and mints normal AuthKit access/refresh sessions with `amr=["swk","mfa"]` and MFA `acr`.
- README, endpoint docs, and SEMVER public-contract notes describe the host RP config, route group, browser WebAuthn ceremony, and covered public symbols/routes.

## Validation

- `docker compose up -d --build issuer`
- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./http ./internal/authcore -run 'TestPasskey|TestMandatory2FARootRolePolicyHTTPIntegration' -count=1 -v`
- `task test`

## Notes

- No tag was cut from this dirty shared worktree. This is a minor public addition for the next AuthKit release/tag.
- The repo is intentionally using the compacted single baseline migration; no `013_user_passkeys.up.sql` was restored.

---

# #121: Close real auth bypass and destructive-action gaps

**Completed:** yes
**Status:** IMPLEMENTED 2026-06-23 (Codex). Closed the concrete bypass paths from the security audit with shared guards rather than per-route one-offs.

## What changed

- Removed the legacy OIDC browser `?link=1` bearer-token parsing path; browser linking must use authenticated `POST /oidc/{provider}/link/start`.
- `IssueRefreshSessionWithAuthMethods` now enforces mandatory-2FA satisfaction before minting any refresh session, closing OIDC/OAuth and sibling session-issuance bypasses.
- API-key minting now calls `AuthorizeAPIKeyResources` before storing resource scopes; non-empty resources fail when no host `ResourceScopeAuthorizer` is configured.
- `DELETE /user` and `DELETE /user/providers/{provider}` now require fresh auth or an inline current password, matching other sensitive account operations.

## Validation

- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./core -run 'TestResourceScopeAuthorizer|TestMintAPIKeyWithOptionsDeniesUnauthorizedResourcesBeforeInsert' -count=1 -v`
- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./http -run 'TestOIDCLegacyBrowserLinkRejects2FAEnrollmentToken|TestMandatory2FARootRolePolicyHTTPIntegration|TestDestructiveUserRoutesRequireFreshAuthOrPassword|TestProviderUnlinkRequiresFreshAuthOrPassword' -count=1 -v`
- `go test ./... -count=1`

## Acceptance

- Legacy browser OIDC linking cannot bypass authenticated link-start middleware or 2FA-enrollment token restrictions.
- OIDC/OAuth session issuance fails closed for mandatory-2FA users until enrollment is complete.
- API-key resource scopes are host-authorized before persistence.
- Account deletion and provider unlink require a recent session or current password.

---

# #120: simplify host-selective AuthKit route groups

**Completed:** yes
**Status:** IMPLEMENTED 2026-06-23 (Codex). The current public `RouteGroup` surface is too implementation-shaped (`password`, `two_factor`, `solana`, `email_verification`, `phone_verification`, `account_oidc_linking`, etc.). Hosts should be able to mount product surfaces, not AuthKit internals. Hard-cut to a small route-group model that lets apps include/exclude registration, login/session, user self-service, admin, permission-group management, and browser OIDC independently. Validation passed below.

## Target model

Route groups:

- `public`
  - Public JSON discovery/introspection routes.
  - Safe to mount in every deployment.
- `register`
  - Public native-user registration routes.
  - Mounting this group is not the security control by itself; `NativeUserRegistrationMode` still decides whether user creation is allowed.
- `session`
  - Login, refresh, logout, current-session lookup, password reset, login-time 2FA, and wallet login.
  - Allows "users can log in" without enabling registration.
- `user`
  - Authenticated self-service account routes: `/me`, `/user/*`, 2FA management, reauth, provider linking/reauth start, wallet linking.
- `admin`
  - Intrinsic `/admin/*` root-permission routes.
- `permission_groups`
  - `GET /me/groups` plus generated per-persona management routes.
- `browser_oidc`
  - Browser redirect OIDC routes, usually mounted separately from JSON API routes at `/oidc/*`.
- JWKS remains a separate public mount through `svc.JWKSHandler()` because it does not belong under the JSON API prefix.

## Route placement

- `public`
  - `GET /identity-providers`
- `register`
  - `POST /register`
  - `GET /register/availability`
  - `POST /register/resend-email`
  - `POST /register/resend-phone`
  - `POST /register/abandon`
  - `POST /email/verify/request`
  - `POST /email/verify/confirm`
  - `POST /phone/verify/request`
  - `POST /phone/verify/confirm`
- `session`
  - `POST /password/login`
  - `POST /token`
  - `DELETE /logout`
  - `POST /sessions/current`
  - `POST /email/password/reset/request`
  - `POST /email/password/reset/confirm`
  - `POST /phone/password/reset/request`
  - `POST /phone/password/reset/confirm`
  - `POST /2fa/challenge`
  - `POST /2fa/verify`
  - `POST /solana/challenge`
  - `POST /solana/login`
- `user`
  - `GET /me`
  - all authenticated `/user/*`
  - `POST /reauth/password`
  - `POST /reauth/2fa`
  - `POST /oidc/:provider/link/start`
  - `POST /oidc/:provider/reauth/start`
  - `POST /solana/link`
- `admin`
  - all `/admin/*`
- `permission_groups`
  - `GET /me/groups`
  - all generated `/:persona/:resource_id/*`
- `browser_oidc`
  - `GET /oidc/:provider/login`
  - `GET /oidc/:provider/callback`
  - `GET /oidc/:provider/reauth/callback`

## Decisions

- Do not keep implementation-specific groups as host-facing choices:
  - `RoutePassword`,
  - `RouteTwoFactor`,
  - `RouteSolana`,
  - `RouteEmailVerification`,
  - `RoutePhoneVerification`,
  - `RouteAccountOIDCLinking`.
- `browser_oidc` stays separate because it is redirect-based and commonly mounted outside the JSON API prefix.
- OIDC login with public registration disabled remains supported by policy:
  - keep `browser_oidc` mounted,
  - set `NativeUserRegistrationMode != open`,
  - existing linked provider identities can log in,
  - unknown provider identities cannot auto-register.
- `register` route mounting is ergonomics; registration mode is still the enforcement layer.
- Default API should still include all normal JSON groups unless a host requests a subset.

## Tasks

- [x] Add/rename route-group constants to the target model.
- [x] Reassign every static JSON `RouteSpec` to one of `public`, `register`, `session`, `user`, `admin`.
- [x] Keep generated permission-group routes under `permission_groups`.
- [x] Keep OIDC browser routes under `browser_oidc` and document that they mount separately from JSON API routes.
- [x] Remove old implementation-shaped group constants with a hard cut.
- [x] Add route-table tests proving each target group includes its intended routes.
- [x] Add route-table tests proving a host can mount session login without register routes.
- [x] Add route-table tests proving `browser_oidc` is not included when selecting only JSON groups unless explicitly requested through browser route accessors.
- [x] Update README and `agents/api-endpoints.md` with host mounting examples.
- [x] Update any consumers in this repo that reference the old group constants.

## Validation

- [x] `go test ./http -run 'TestAPIRoutes|TestOIDCBrowser|TestPermissionGroupRoutes' -count=1`
- [x] `go test ./http -count=1`
- [x] `go test ./adapters/... -count=1`
- [x] `go test ./... -count=1`

## Acceptance

- Host apps can choose product-level surfaces with a small stable API:
  `public`, `register`, `session`, `user`, `admin`, `permission_groups`, `browser_oidc`.
- A private-mode host can expose login/session/OIDC without exposing public registration.
- Existing registration policy checks still block all public user-creation paths, including OIDC/Solana auto-registration.
- Route grouping is documented from the host application's perspective, not AuthKit implementation internals.

---

# #119: support multiple enrolled 2FA factors with one default

**Completed:** yes
**Status:** IMPLEMENTED 2026-06-23 (Codex). AuthKit now stores enrolled 2FA factors separately from user-scoped backup codes, keeps one default factor, and lets login/reauth flows start a selected non-default factor without re-entering the password.

## What changed

- Added `profiles.two_factor_factors` in `migrations/postgres/012_two_factor_factors.up.sql`; existing enabled `two_factor_settings` rows migrate into one default factor.
- Added factor-aware core APIs for list/default/enroll/delete/set-default, selected login challenges, selected reauth, selected verification, and TOTP replay tracking on factor rows.
- Kept backup codes user-scoped and recovery-only; they are never listed as primary factors.
- Updated `GET/POST/DELETE /user/2fa`, `POST /2fa/verify`, and `POST /reauth/2fa` for multiple factors.
- Added `POST /2fa/challenge` so a frontend can switch from the default factor to another enrolled factor after password verification.
- Updated password-login responses to include `default_factor` and `available_factors`.
- Updated mandatory-2FA satisfaction to require at least one enabled AuthKit 2FA factor.
- Updated README and `agents/api-endpoints.md`.

## Validation

- `SQLC_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 vet`
- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./core ./http -run 'TestTOTPEnrollmentVerifyAndReplay|TestLegacyTwoFactorSettingsExposeDefaultFactor|TestMultiple2FAFactorsDefaultAndSelectedLoginHTTPIntegration|TestTOTPEnrollmentAndLoginHTTPIntegration|TestMandatory2FARootRolePolicyHTTPIntegration|TestTOTPReauthReturnsFreshMFAAccessToken' -count=1 -v`
- `go test ./...`

## Acceptance

- Existing single-factor users keep working after migration.
- New users can enroll multiple primary 2FA factors and choose among them during login/reauth.
- Frontends can keep the simple default flow and only show factor selection as an escape hatch.
- Backup codes remain recovery-only and are not modeled as primary factors.
- OIDC is not counted as AuthKit 2FA by default.
- Access-token `amr`/`acr` assurance semantics remain stable.

---

# #118: replace admin direct credential setters with compromised-account recovery

**Completed:** yes
**Status:** IMPLEMENTED 2026-06-23 (Codex). Admins can no longer directly set user email, username, or password over HTTP. AuthKit now exposes one compromised-account recovery action that invalidates current access paths, replaces the primary recovery identifier, and sends a password-reset request.

## Target model

- Remove admin HTTP routes that directly set email, username, or password:
  - `POST /admin/users/set-email`
  - `POST /admin/users/set-username`
  - `POST /admin/users/set-password`
- Add one recovery route:
  - `POST /admin/users/{user_id}/recover`
- Recovery accepts exactly one new primary identifier:
  - `{ "email": "new@example.com" }`, or
  - `{ "phone_number": "+15551234567" }`
- Recovery performs one DB-atomic credential cleanup, then sends reset instructions:
  - revoke all current refresh/login sessions,
  - delete the password hash,
  - delete linked provider/OAuth auth factors,
  - delete 2FA settings,
  - clear old email and phone,
  - set the new email or phone as the primary identifier,
  - send the matching password-reset request.
- Do not keep an `active` user concept. Existing state remains concrete: banned, deleted, or neither.
- Remove `POST /admin/users/toggle-active` and any explicit 404 sentinel/docs for it.
- Orgs are gone (#111), so there is no `recover org` admin flow. Remove stale `/admin/orgs/*` recovery/admin docs and any leftover org-recovery code constants if still present.

## Tasks

- [x] Add core recovery method that does the credential cleanup and identifier replacement.
- [x] Add minimal DB query for setting recovered email as verified; reuse existing password/provider/session/phone cleanup queries.
- [x] Add `POST /admin/users/{user_id}/recover` handler and route.
- [x] Remove admin set-email/set-username/set-password handlers and routes.
- [x] Remove `/admin/users/toggle-active` sentinel route and active-user docs/booleans that imply an active toggle.
- [x] Remove stale admin org recovery/admin org route docs and leftover org-recovery error code.
- [x] Update `README.md` and `agents/api-endpoints.md` route lists.
- [x] Tests: removed direct setter routes are absent.
- [x] Tests: recovery route is registered and rejects invalid bodies.
- [x] Tests: recovery deletes old auth factors, replaces identifier, revokes sessions, and sends reset.

## Validation

- `go test ./http -run 'TestAPIRoutesAdminUserRecoverySurface|TestAdminUserRecoverPOSTRejectsInvalidBody|TestAPIHandler_AdminUsersToggleActiveRoute_Removed|TestAPIHandler_AllRoutes|TestAPIRoutesIncludePreferredLanguageUserRoute' -count=1`
- `go test ./... -count=1`
- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:<temp>/authkit_db?sslmode=disable' go test ./core -run TestAdminRecoverUserEmailReplacesLoginFactors -count=1 -v` against a fresh migrated Postgres
- `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:<temp>/authkit_db?sslmode=disable' go test ./... -count=1` against the same fresh migrated Postgres

## Acceptance

- Admins cannot directly set arbitrary user credentials through HTTP.
- Recovery is a single auditable action for compromised accounts.
- Users have no separate active/inactive toggle; banning/deleting remain the supported account-state controls.
- User recovery is the only admin recovery flow; no org recovery route remains in docs or code.

---


# #117: require 2FA for configured permission-group roles

**Completed:** yes
**Status:** IMPLEMENTED 2026-06-23 (Codex). Added host-configurable mandatory 2FA tied to live permission-group membership. Doujins can declare an `admin` role in the singleton `root` permission group and require every assigned user to enroll/use 2FA before normal login or refresh succeeds.

## Target model

Hosts declare role-based 2FA requirements in AuthKit config. A policy entry matches a permission-group type/resource plus one or more roles:

```go
TwoFactor: core.TwoFactorConfig{
  Mandatory: []core.Mandatory2FAPolicy{
    {GroupType: "root", ResourceRef: "", Roles: []string{"admin", "super-admin"}},
  },
}
```

Semantics:

- If a user matches any policy, they are 2FA-required.
- Matching is based on current permission-group assignments, not token claims.
- Enforcement happens at login/session mint and refresh boundaries, not on every resource request.
- Users who become newly covered by a policy must be forced into 2FA enrollment before they can continue using protected sessions.
- Any enabled AuthKit 2FA method satisfies the policy: email, SMS, or TOTP.
- Default is no mandatory 2FA policies.

## UX / API behavior

- Password login for a covered user with no acceptable 2FA must not mint a normal access/refresh session.
- Return a stable machine-readable response such as `2fa_enrollment_required`, with allowed methods and current status.
- The frontend should route the user to the existing `POST /user/2fa` enrollment flow.
- If the covered user has acceptable 2FA enabled, login continues through the existing 2FA challenge flow and minted tokens carry MFA assurance.
- Refreshing an existing session for a covered user who no longer satisfies policy should fail closed or return `2fa_enrollment_required`; do not mint fresh access tokens that bypass the policy.

## Decisions

- Enrollment uses a short-lived enrollment-only access token; verifier middleware allows it only on `GET/POST /user/2fa`.
- Policy matches explicit configured roles only. Permission matching can come later if a host needs it.

## Tasks

- [x] Add `Mandatory2FAPolicy` config and validation: group type exists and role names are known for that type.
- [x] Add core helper to determine whether a user is covered by a mandatory-2FA policy from permission-group assignments.
- [x] Add core helper to determine whether the user's current 2FA settings satisfy the policy.
- [x] Enforce policy during password login before minting a normal session; covered users with no acceptable 2FA get `2fa_enrollment_required`.
- [x] Enforce policy during `/token` refresh so existing sessions cannot keep minting access tokens after a user gains a mandatory-2FA role.
- [x] Ensure covered users with acceptable 2FA must complete the existing login 2FA challenge and receive MFA `amr`/`acr` in the minted access token.
- [x] Add a minimal enrollment-only path if normal auth cannot safely reach `POST /user/2fa` without granting broader access.
- [x] Add policy status to `/user/me` so frontends can show mandatory-2FA state without guessing.
- [x] Update README and `agents/api-endpoints.md` with mandatory admin 2FA configuration and flow.
- [x] Tests: root-role policy marks assigned users as 2FA-required and leaves ordinary users untouched.
- [x] Tests: covered user without 2FA cannot receive a normal login session/access token.
- [x] Tests: covered user with any enabled 2FA method satisfies the policy and completes login.
- [x] Tests: refresh fails closed when a user is newly assigned a mandatory-2FA role but has not enrolled.

## Acceptance

- Hosts can require 2FA for high-authority roles such as root admins without forcing 2FA on every user.
- Mandatory 2FA is derived from live permission-group assignments.
- All AuthKit 2FA methods satisfy mandatory 2FA equally; no assurance-level split by method.
- No normal access token is minted for a covered user until the user satisfies the configured 2FA policy.
- Existing refresh sessions cannot bypass newly applied mandatory-2FA policy.

---


# #116: make reauth and sensitive-route enforcement token-claim based

**Completed:** yes
**Status:** IMPLEMENTED 2026-06-23 (Codex). Reauth currently updates the refresh-session row but returns only `fresh_auth`; some AuthKit-owned sensitive gates still check the session DB at request time through `RequireFreshSession`. That splits the model: host/resource routes can only see `auth_time`/`amr`/`acr` on the access token, while built-in routes can see fresher DB state. Hard-cut to the standard step-up shape: reauth updates the session, mints a fresh access token carrying the new assurance claims, and one exported `Sensitive(...)` wrapper authorizes all sensitive routes from access-token claims only.
**Status update 2026-06-23 (Codex):** Completed and archived. OAuth JSON reauth now also returns the same fresh access-token response as password, 2FA, and OIDC reauth. `SessionFreshness.AssuranceClaims()` now derives `auth_time`/`amr`/`acr`; `IssueAccessToken` mints fixed LOA `acr`; password, 2FA, and JSON OIDC reauth responses return a fresh access token; `verify.Sensitive(...)`/`SensitiveClaims` is exported and aliased through `authhttp`; AuthKit-owned sensitive gates now evaluate token claims instead of DB session freshness. Inline password fallback responses include fresh access-token metadata when they upgrade auth state. `/me` freshness fields now describe the current access token. Validation recorded below.

## Current problem

- Successful `POST /reauth/password` and final `POST /reauth/2fa {code}` update `profiles.refresh_sessions.last_authenticated_at` / `auth_methods`, then return `fresh_auth` metadata.
- A resource server cannot use `fresh_auth`; it needs a new JWT with updated `auth_time`, `amr`, and `acr`.
- AuthKit built-ins still gate some sensitive actions by querying refresh-session freshness from the DB at request time.
- There is no single `Sensitive(...)` wrapper shared by AuthKit-owned routes and host/resource routes.
- `acr` is parsed and enforceable, but AuthKit does not mint concrete `acr` values yet.

## Target model

- Request-time sensitive authorization reads only the access token:
  - `auth_time` for recency.
  - `amr` for method/factor proof.
  - `acr` for assurance class.
- Reauth is the only place that mutates session auth state:
  - verify password or factor;
  - update current refresh-session auth state;
  - mint and return a new access token from that session state.
- Refresh-token rotation remains owned by `POST /token`, not by reauth.
- `fresh_auth` may stay as response metadata, but it is not the authority surface.
- One exported wrapper, `Sensitive(...)`, is the universal way to declare a sensitive route in AuthKit and host apps. Defaults apply when no options are supplied; options override the defaults.

## Sensitive defaults

Default sensitive policy:

- Pass when `auth_time` is within 15 minutes, OR
- pass when `amr` contains `otp` or `mfa`.

Equivalently, reauth is required only when BOTH are true:

- more than 15 minutes have elapsed since `auth_time`, AND
- the access token does not show 2FA/MFA in `amr`.

Configurable overrides:

- require MFA/2FA for the action; users without 2FA cannot satisfy that action until they enroll.
- require recency even if MFA was used.
- set a custom max age.
- require a specific `amr` or `acr`.

## Minimal `acr` policy

Do not add a configurable assurance-policy system yet. Mint a tiny fixed mapping:

- password-only auth -> `urn:authkit:loa:1`
- any 2FA/MFA auth -> `urn:authkit:loa:2`

All AuthKit 2FA methods are treated equally for assurance. Do not introduce per-method assurance levels.

## Tasks

- [x] Add a small helper that derives assurance claims from the current session auth state: `auth_time`, normalized `amr`, and fixed `acr`.
- [x] Make `IssueAccessToken` mint `acr` alongside existing `auth_time` and `amr` when `sid` is present.
- [x] Update successful `POST /reauth/password` to return a fresh `access_token`, `token_type`, and `expires_in` after `MarkSessionAuthenticated`.
- [x] Update successful final `POST /reauth/2fa {code}` to return a fresh `access_token`, `token_type`, and `expires_in` after `MarkSessionAuthenticatedWithMethods`.
- [x] Apply the same fresh-access-token response to successful OIDC/OAuth reauth JSON responses.
- [x] Add one host-facing `Sensitive(...)` wrapper, exported from `verify` and aliased from `authhttp`, used by AuthKit-owned routes and external apps alike.
- [x] Define `SensitiveOptions` with defaults: max age 15 minutes, MFA/2FA satisfies the default policy regardless of age, and no mandatory MFA unless requested.
- [x] Support stricter `SensitiveOptions`: require MFA/2FA, require recency even with MFA, custom max age, specific `amr`, and specific `acr`.
- [x] Make `Sensitive(...)` return AuthKit's nested `reauth_required` envelope with enough metadata for the frontend to choose `/reauth/password`, `/reauth/2fa`, or provider reauth.
- [x] Replace AuthKit-owned request-time DB freshness gates with token-claim gates for `POST /user/password`, `POST /user/email` start, `POST /user/phone` start, `DELETE /user/2fa`, and `POST /user/2fa/backup-codes`.
- [x] Keep inline password fallback only where it is explicitly part of the route contract; if it stays, it must mint and return a fresh access token when it upgrades auth state.
- [x] Update `/me` freshness fields so they describe token-visible assurance or clearly separate session metadata from request authorization.
- [x] Update README and `agents/api-endpoints.md` reauth docs: reauth returns a fresh access token; clients retry the sensitive action with it; `/token` remains the refresh-token rotation route.
- [x] Tests: reauth password returns a JWT with new `auth_time`, `amr=["pwd"]`, `acr=urn:authkit:loa:1`.
- [x] Tests: reauth 2FA returns a JWT with MFA `amr` and `acr=urn:authkit:loa:2`.
- [x] Tests: sensitive wrapper denies stale/missing assurance using token claims only and emits `reauth_required`.
- [x] Tests: default `Sensitive(...)` passes recent password auth, passes old MFA auth, and denies old password-only auth.
- [x] Tests: `Sensitive(...RequireMFA...)` denies users/tokens without MFA.
- [x] Tests: built-in sensitive routes no longer consult refresh-session freshness at request time.

## Validation

- [x] `go test ./verify -count=1`
- [x] `go test ./core -run 'TestIssueAccessToken|TestSetEntitlementsProvider' -count=1`
- [x] `go test ./http -run 'TestFreshReauthRouteContract|TestPasswordReauthReturnsFreshAccessToken|TestTOTPReauthReturnsFreshMFAAccessToken|TestAPIHandler_PrefixNeutralRouteContract|TestAPIRoutesIncludePreferredLanguageUserRoute|TestAPIRoutesCollapseContactChangeRoutes' -count=1`
- [x] `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./http -run 'TestPasswordReauthReturnsFreshAccessToken|TestTOTPReauthReturnsFreshMFAAccessToken' -count=1`
- [x] `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35433/authkit_db?sslmode=disable' go test ./... -count=1` on a fresh temporary Postgres.
- [x] `go test ./...`

## Acceptance

- A successful reauth response is immediately usable to retry a sensitive request; no extra `/token` call is required.
- Sensitive route authorization never queries the refresh-session DB for freshness or factors.
- The access token is the only request-time source for `auth_time`, `amr`, and `acr`.
- AuthKit built-ins and host apps use the same `Sensitive(...)` wrapper.
- `acr` is minted consistently from AuthKit's fixed assurance mapping.
- Existing refresh-token rotation semantics are unchanged.

---

# #92: Rename `PermissionCatalog` → `Permissions` (purge the "catalog" homonym from RBAC vocabulary)

**Completed:** yes

## Metadata

- Category: cleanup/breaking-api
- Status: completed
- Passes: true

AuthKit's generic RBAC vocabulary no longer uses the overloaded "permission catalog" name. The public JSON response key remains `"permissions"`; OpenRails keeps its own product/domain `Catalog()` function and `openrails:catalog:*` permissions.

## Tasks
- [x] Renamed `core.Config.PermissionCatalog` → `Permissions`; updated the `Options` mirror and config construction.
- [x] Renamed `Service.Catalog()` → `Permissions()` and `catalogSet()` → `knownPermissions()`.
- [x] Renamed `handlePermissionCatalogGET` → `handlePermissionsGET`; `/permissions` response shape is unchanged.
- [x] Renamed the delegated verifier option `WithPermissionCatalog` → `WithPermissions`.
- [x] Swept AuthKit docs/comments for the old permission-catalog vocabulary.
- [x] Updated OpenRails consumer call sites: `Permissions: Catalog()` and `authhttp.WithPermissions(...)`.

**STATUS: completed in AuthKit (2026-06-20).** Verified with `go test ./core ./http`. OpenRails consumer checked against the local AuthKit checkout with a temporary modfile: `go test -modfile=/tmp/... ./internal/controlplane -run 'TestDelegated|TestCatalog'`.

---

# #93: Remove the `!perm` negation operator from permission evaluation (positive grants only)

**Completed:** yes

## Metadata

- Category: security/cleanup
- Status: completed
- Passes: true

Decision (2026-06-19, Paul): drop negation from AuthKit's permission model. The evaluator no longer supports exclusion tokens; grants are positive-only literals or namespace-anchored globs.

## Tasks
- [x] Removed the `!perm` exclusion branch/constant from permission evaluation; there is no `permExcludePrefix` in live code.
- [x] `effectivePermsForTokens` treats `!`-prefixed stored tokens as invalid and grants nothing from them.
- [x] `ValidateGrant` rejects `!`-prefixed tokens as `unknown` (fail-closed).
- [x] `UnknownRoleTokenNames` reports `!`-prefixed tokens as unknown.
- [x] Positive globs still work (`org:*`, `org:*:read`, `app:*`); bare `*` remains invalid.

**STATUS: completed in AuthKit (2026-06-20).** Verified with `go test ./core` and focused `go test ./core -run 'TestEffectivePermsForTokens|TestValidateGrantRejectsNegationToken|TestUnknownExclusionsAreDetectable|TestValidateGrant'`.

---

# #91: Generalize the admin user DIRECTORY (list/search/sort/detail) + make billing-enrichment a first-class pluggable filter

**Completed:** yes

## Metadata

- Category: feature
- Status: completed
- Passes: true

AuthKit is the USER DIRECTORY for every host app's admin dashboard. Identity lives here; billing state (entitlements/subscriptions/credits) lives in OpenRails and is composed IN via a provider seam. This issue generalizes the directory and turns the existing enrichment seam into a real filter.

## Tasks
- [x] **(1)** Generalize `AdminListUsers` filtering: removed the hardcoded host role slugs; `AdminListUsers(ctx, AdminUserListOptions)` now takes a generic, composable filter — `Role` (any global-role slug) + `OrgSlug` (any org) + `Status` (active/banned/deleted/any, default non-deleted) + `Search`. No product strings in core. (`core/service.go` `adminUserDirectoryQuery`.)
- [x] **(1)** Sort options (`AdminUserSort`: created_at/last_login/username/email) + `Desc`, stable `u.id` tiebreaker; offset pagination retained (cursor deferred — offset is fine for admin directories). Handler param `order=asc` flips the default newest-first.
- [x] **(1)** `AdminCountUsers(ctx, opts)` — real standalone count sharing the same query builder.
- [~] **(1)** (Optional) richer per-org `ListOrgMembers` with detail+pagination — DEFERRED (the `OrgSlug` filter on `AdminListUsers` already covers "users in org X with detail"; a dedicated members-with-roles endpoint can come with #228 if needed).
- [x] **(2)** Provider seam extended ENRICH → ENRICH **+ FILTER**: new `EntitlementFilterProvider` interface (`ListSubjectsWithEntitlement(ctx, entitlement) []subjectIDs`); `AdminListUsers(opts.Entitlement=...)` type-asserts the entitlements provider to it, resolves the subject set, and filters `u.id = ANY(...)`. No provider → `ErrEntitlementFilterUnavailable` (fail loud). Backed by OpenRails #535.
- [x] **(2)** Single-user DETAIL (`AdminGetUser`) already enriches entitlements via `s.ListEntitlements` (the provider) — verified symmetric with the list.
- [x] Tests: `core/admin_directory_test.go` covers real-Postgres search/role/status/sort/pagination/count + provider-backed entitlement filter with a fake provider + `ErrEntitlementFilterUnavailable`; this environment has no `AUTHKIT_TEST_DATABASE_URL`, so the DB-backed test is present but skipped here. Focused non-DB checks pass.
- [~] Ship: tag + bump is downstream adoption/release work for OpenRails #535 + doujins #414, not remaining AuthKit implementation work.

**STATUS: completed in AuthKit (2026-06-20).** Verified with `go test ./core ./storage/memory ./jwt ./siws`; `go test -race ./storage/memory ./jwt`; DB-backed directory coverage is gated on `AUTHKIT_TEST_DATABASE_URL`.

## Downstream consumer adoption (audited 2026-06-19) — NO required changes
The only breaking change is the `AdminListUsers(...)` GO signature + the removal of the `filter` query param on `GET /admin/users`. The `AdminUser` JSON shape (roles, entitlements, …) and page/page_size/search are UNCHANGED. Audit of the other consumers:
- **doujins** (#414): the real adopter — it overrode `/admin/users` to add a raw-SQL premium filter; #414 deletes that and wires the provider filter. (separate issue)
- **hentai0**: its admin Users page calls `GET /admin/users` with ONLY `page`/`page_size` (no `filter`), and reads `roles`/`entitlements` (enrich path preserved). No Go call to `AdminListUsers`. → bump-safe, NO changes. (Optional future: wire its `OpenRailsEntitlementsProvider` to also implement `EntitlementFilterProvider` + add a `?entitlement=premium` server filter — today it computes premium client-side from the enriched `entitlements`.)
- **cozy-art**: mounts `authkitgin.RegisterAPI` (so the route exists) but no frontend consumes `/admin/users`; its `EntitlementsProvider` (enrich) is already wired. → bump-safe, NO changes. (Optional future: extend that provider with `EntitlementFilterProvider`.)
- **tensorhub**: mounts the route, nothing consumes it; no entitlement provider (HTTP client of standalone OpenRails, not embedded). → bump-safe, NO changes. (If it ever needs "users with entitlement X" it uses the OpenRails #535 s2s route, not a Go provider.)
Net: only doujins needs work (#414); hentai0/cozy-art/tensorhub bump cleanly. The new entitlement-FILTER capability is opt-in everywhere.

## Boundaries
- AuthKit owns the directory: only LOCAL AuthKit users (`profiles.users`). Federated/delegated subjects (a remote host's own users, only ever a `delegated_sub` claim) are NOT in this directory — a host using AuthKit as ITS identity provider (doujins-style, users in `profiles.users`) is the case this serves.
- OpenRails owns billing state keyed by subject and is consumed as the provider — never queried via raw SQL by the host.
- The host (or OpenRails' own standalone console, OpenRails #228) COMPOSES directory + billing; neither subsystem alone answers "premium users with their detail."

---

# #90: Auth hardening — 15m token TTL, swallowed-error fixes, SIWS atomic consume, hot-reload key rotation

**Completed:** yes

From the 2026-06-18 implementation audit (`audit-authkit.md`, AK-IMPL-1/2/3). Scope was deliberately trimmed after review: the audit's `jti`/per-request-liveness store and the key-rotation state-machine/admin-API/DB-table were **rejected as over-engineered** — see "Explicitly dropped" so they don't get re-proposed straight off the audit. Rationale: delegated tokens already default to 15m (`core/delegated.go:108`) and merchant suspension is already immediate (OpenRails `merchantForIssuer` fails closed per request), so revocation lag is bounded by TTL and not worth a per-request revocation store.

## Tasks
- [x] `accessTTL` default 1h → 15m (`core/service.go`).
- [x] 2a: family-revoke failure logs ERROR + alerts (retry if cheap). `revokeFamilyEnsured` (retry-once + CRITICAL log) at both `ExchangeRefreshToken` variants.
- [x] 2b: disabled-user revoke failure logs ERROR. Both refresh variants.
- [x] 2c: OIDC link write failure now fails the callback (`errProviderLinkFailed` → 500 `provider_link_failed`) at both link sites in `resolveOAuthUser`; cosmetic writes (SetProviderUsername/SetEmailVerified) logged not swallowed. Duplicate-account path confirmed (new-user branch: failed link → next login finds no link → duplicate/dead-end). Residual: orphan-user window without atomic create+link — logged CRITICAL, follow-up = authkit #88 tx-aware provisioning.
- [x] 3: `ChallengeCache.Consume` added (Redis `GETDEL`; memory locked get-and-delete) + interface method; `VerifySIWSAndLogin` now consumes instead of Get+Del. Audit of other single-use `ephemDel` sites: password-reset (`ephemeral_data.go:301/305`), email-verify (`286/281`), 2FA (`331/338`), phone all share the SAME non-atomic Get-then-Del + swallowed-Del pattern. Sequential reuse IS already prevented (Del lands); only the concurrent-race residual remains, and double-consume there gains an attacker little (reset-twice / extra-session, no auth bypass). Deferred — see follow-up below (touches the PUBLIC `EphemeralStore` interface → consumer coordination).
- [x] 4: `ReloadableKeySource` (`jwt/keys.go`): atomic-pointer swap, validate-before-swap (`loadStaticFromFile` asserts active signer), keep-old-on-error, 10s mtime poll (`DefaultKeyReloadInterval`), `Close()` for lifecycle. Wired into `NewAutoKeySourceWithPath` file branch (env/dev branches unchanged). Consumers calling `NewAutoKeySource` get hot-reload free when keys.json exists.
- [x] Tests: SIWS single-use + concurrent single-winner + TTL-expiry (`storage/memory/siws_cache_test.go`, green under `-race`); hot-reload active-key swap + poller pickup + retained retired pubkey + keep-old-on-malformed (`jwt/keys_reload_test.go`, green under `-race`); default-TTL=15m assertion (`core/service_ttl_test.go`). DEFERRED (low-risk, need DB fault-injection / heavy setup): 2a/2c revoke/link failure-path assertions.
- [x] Document the rotation runbook (routine + emergency) → `jwt/KEY_ROTATION.md`.

**STATUS: completed in AuthKit (2026-06-20).** Verified with `go test ./core ./storage/memory ./jwt ./siws`; `go test -race ./storage/memory ./jwt`.

**Follow-ups (separate issues, intentionally out of scope here):**
- Atomic `EphemeralStore.Consume` (GETDEL) routed for password-reset / 2FA / email-verify / phone single-use tokens. Deferred: breaks the public `EphemeralStore` interface (consumer coordination) and the concurrent-race residual is low-value. Sequential single-use is already enforced.
- Atomic create+link in OIDC provisioning (removes the orphan-user window in 2c) — pairs with authkit #88 tx-aware provisioning.

---

# #1: Admin undelete user (restore soft-deleted users)

**Completed:** yes

AuthKit supports soft-deleting users via `deleted_at` (self-delete: `DELETE /auth/user`; admin delete: `DELETE /auth/admin/users/:user_id`) and then hard-deleting later via the purge worker. Add an admin-only restore endpoint so admins can restore a user before they are hard-deleted.

Semantics:
- Restore only clears `profiles.users.deleted_at` (and updates `updated_at`).
- Do not change ban state (banned users remain banned after restore).
- Do not recreate sessions; deleted users had sessions revoked, so they must log in again.
- Idempotent: restoring an already-restored user is a no-op.

Endpoint:
- `POST /auth/admin/users/:user_id/restore` (ADMIN)
- `GET /auth/admin/users/deleted` (ADMIN) for listing deleted users.

**Tasks:**
- [x] Core: Add restore method that clears deleted_at (no ban changes) and returns not-found when user is missing
- [x] HTTP (gin): Add admin restore route and deleted-users list route under `/auth/admin`
- [x] HTTP (gin): Ensure endpoint requires admin via existing RequireAdmin middleware
- [x] Tests: Add minimal handler tests for restore (ok + not_found)
- [x] Docs: Update `agents/api-endpoints.md` to include restore + deleted list

---

# #2: Move ephemeral auth state to Redis (codes, SIWS challenges, rate limits)

**Completed:** yes

Use Redis-compatible storage (Garnet) for ephemeral auth state (verification codes, reset tokens, SIWS challenges, and other short-lived entries) so we don't rely on Postgres TTL cleanup. This also makes SIWS safe in multi-instance deployments. In-memory caches remain as a fallback when Garnet is not configured, but they are not safe for distributed use. AuthKit should accept a Redis client interface from the host app (Garnet implements the same protocol).

**Tasks:**
- [x] Define a minimal Redis client interface (Get/Set/Del) and accept it via AuthKit options
- [x] Add Garnet/Redis config in host apps; pass client into AuthKit (no internal dialer)
- [x] Define key prefixes + TTLs for: email/phone verify codes, password resets, pending registrations, 2FA codes, SIWS challenges, rate limit buckets
- [x] Replace Postgres writes for ephemeral tables with Redis writes (keep Postgres for durable user/session records)
- [x] Update verification flows to read from Redis and delete on success
- [x] Add store selection: memory|redis|postgres (configurable). Memory is dev-only; redis required for multi-instance prod; postgres is explicit opt-in adapter
- [x] Enforce: in prod + multi-instance, require redis; otherwise fail fast with clear error
- [x] Keep in-memory cache fallback for dev/single-instance
- [x] Update migrations/docs: remove ephemeral tables or leave for backward compat; document required Redis for HA
- [x] Add tests for Redis-backed flows (skip when Redis not configured)

---

# #3: Unify OAuth/OIDC routes under /auth/oauth/:provider

**Completed:** yes

Expose a single route pattern for all external identity providers (OIDC and OAuth) under /auth/oauth/:provider to simplify client integration while keeping provider-specific logic internally.

**Tasks:**
- [x] Add new routes: GET /auth/oauth/:provider/login, GET /auth/oauth/:provider/callback, POST /auth/oauth/:provider/link/start (validated complete 2026-05-22 during archive)
- [x] Wire OIDC providers (google/apple/etc) to the new /auth/oauth/:provider routes without changing internal validation flow (validated complete 2026-05-22 during archive)
- [x] Wire Discord OAuth to the same /auth/oauth/:provider routes (validated complete 2026-05-22 during archive)
- [x] Decide whether to keep /auth/oidc/* and /auth/oauth/discord/* as aliases or deprecate with docs (validated complete 2026-05-22 during archive)
- [x] Update docs (api-endpoints.md) with new unified route pattern and provider list (validated complete 2026-05-22 during archive)

---

# #4: Add phone number change flow (request/confirm/resend)

**Completed:** yes

Add a phone change flow for existing users mirroring the email change behavior. This should verify the new phone number via SMS code and update the user's phone only after confirmation.

**Tasks:**
- [x] Add core service methods: RequestPhoneChange(userID, newPhone), ConfirmPhoneChange(userID, code), ResendPhoneChangeCode(userID) (validated complete 2026-05-22 during archive)
- [x] Add persistence for pending phone change verification (reuse phone_verifications with a new purpose or add a dedicated table) (validated complete 2026-05-22 during archive)
- [x] Add Gin handlers: POST /auth/user/phone/change/request, POST /auth/user/phone/change/confirm, POST /auth/user/phone/change/resend (validated complete 2026-05-22 during archive)
- [x] Add rate limit keys for request/confirm/resend (validated complete 2026-05-22 during archive)
- [x] Update docs (api-endpoints.md) with phone change routes and expected errors (validated complete 2026-05-22 during archive)

---

# #5: Add phone verification request endpoint

**Completed:** yes

Add POST /auth/phone/verify/request endpoint for existing users to add/verify a phone number, mirroring the existing POST /auth/email/verify/request flow.

**Tasks:**
- [DONE] Add RequestPhoneVerificationByPhone() method to core/service.go
- [DONE] Create phone_verify_request_post.go handler
- [DONE] Add rate limit constant RLPhoneVerifyRequest to ginutil
- [DONE] Wire up route in service.go GinRegisterAPI
- [DONE] Update api-endpoints.md documentation

---

# #6: Enhance UserContext with convenience methods

**Completed:** yes

Both doujins and hentai0 wrap authkit's UserContext with their own logic to check roles/entitlements. This should be built into authkit's UserContext directly.

## Problem

doujins has `internal/auth/user_context.go` with:
```go
type UserContext struct {
    User         *views.User  // Project-specific
    IsAdmin      bool
    IsLoggedIn   bool
    Language     string
    Roles        []string
    Entitlements []string
}
```

And `internal/middleware/user_context.go` computes these flags:
```go
userCtx.IsAdmin = containsIgnoreCase(userCtx.Roles, "admin")
```

hentai0 uses authkit's UserContext directly but lacks these convenience methods.

## Solution

Add convenience methods to authkit's `UserContext` in `adapters/gin/userctx.go`:

```go
// Already exists:
func (uc UserContext) IsAdmin() bool { return hasString(uc.Roles, "admin") }

// Add these:
func (uc UserContext) IsLoggedIn() bool { return uc.UserID != "" }
func (uc UserContext) HasRole(role string) bool { return hasString(uc.Roles, role) }
func (uc UserContext) HasEntitlement(ent string) bool { return hasString(uc.Entitlements, ent) }
```

## Important: NO IsPremium() method

Do NOT add `IsPremium()` method. This is overly specific and doesn't scale. Instead, callers should use the generic `HasEntitlement("premium")`. Same logic applies to any future entitlement types - use the generic method, not dedicated boolean methods.

## Migration

After authkit changes:
- doujins can simplify `internal/middleware/user_context.go` to just use `authgin.UserContext` methods
- doujins can potentially remove `internal/auth/user_context.go` if the only additions were computed flags
- hentai0 gains these methods automatically

## Note

Language middleware and response envelopes are NOT part of this issue - those belong in a separate shared library (e.g., `go-api-common`), not authkit.

**Tasks:**
- [x] Add IsLoggedIn() method to UserContext (check UserID != "")
- [x] Add HasRole(role string) method to UserContext
- [x] Add HasEntitlement(ent string) method to UserContext
- [x] Add unit tests for new UserContext methods
- [x] Downstream app wrapper removal tracked in app repos

---

# #7: Remove is_active (use ban/delete only)

**Completed:** yes

Replace the `profiles.users.is_active` boolean with explicit ban/delete semantics.

## Requirements

- Only two access-blocking states exist:
  - banned (reversible): `banned_at IS NOT NULL`
  - deleted (soft delete): `deleted_at IS NOT NULL`
- Admin delete and user self-delete both set `deleted_at` (soft delete) initially.
- Login/token issuance must refuse banned/deleted users.
- Deleted users remain soft-deleted for 30 days, then are hard-deleted.

## Target semantics

- Active user is implied: `deleted_at IS NULL AND banned_at IS NULL`.
- Ban should revoke sessions immediately.
- Soft delete should revoke sessions immediately.
- Hard delete occurs after 30 days (purge job).

**Tasks:**
- SCHEMA/MIGRATIONS:
- [x] Add `profiles.users.banned_at timestamptz` (optional: banned_reason, banned_by)
- [x] Backfill `banned_at` for existing users with is_active=false and deleted_at IS NULL (treat as banned)
- [x] Remove `profiles.users.is_active` (drop column) after code is migrated
- 
- CORE LOGIC:
- [x] Replace all `IsActive` checks with `deleted_at IS NULL AND banned_at IS NULL`
- [x] Replace `SetActive` APIs with explicit `BanUser` / `UnbanUser` + `SoftDeleteUser` (deleted_at)
- [x] Ensure ban and soft delete revoke refresh sessions (issuer-scoped) consistently
- [x] Ensure JWT issuance paths refuse banned/deleted users (password login, OAuth/OIDC callbacks, SIWS, refresh, etc.)
- [x] Ensure authz gates respect banned/deleted (Required middleware, RequireAdmin/RequireRole/RequireEntitlement, and any DB-backed UserContext enrichment should deny when banned_at or deleted_at is set)
- [x] Ensure admin/live DB checks don’t treat "row exists" as sufficient; they must join/filter on `profiles.users` status
- 
- HTTP API:
- [x] Change admin ban/unban endpoints to set/clear `banned_at` (and revoke sessions on ban)
- [x] Remove or repurpose "toggle active" endpoint (make it ban/unban; no generic active toggle)
- [x] Change `DELETE /auth/user` to call soft delete (`deleted_at=now()` + revoke sessions)
- [x] Change admin delete endpoint to soft delete by default (`deleted_at=now()`), not hard delete
- 
- ADMIN VIEWS:
- [x] Update AdminUser / listing to expose `banned_at` and `deleted_at` (and derived booleans if needed)
- [x] Update any filters/search that currently use is_active
- 
- RETENTION + PURGE (30 DAYS):
- [x] Add `profiles.users.deleted_at` retention policy: hard-delete after 30 days from deleted_at
- [x] Provide an AuthKit River module so host apps can "plug in" purge without re-implementing logic:
-       - A River job args type (`authkit/riverjobs.PurgeDeletedUsersArgs`) with params: retention_days, batch_size
-       - A worker implementation that selects `deleted_at < now() - retention_days` and hard-deletes authkit-owned rows
-       - Helpers: `RegisterPurgeDeletedUsersWorker` and `AddPurgeDeletedUsersPeriodicJob`
- [x] Define a host callback for app-domain cleanup/anonymization, invoked before the authkit hard-delete:
-       - `BeforeUserHardDelete(ctx, user_id) error` (delete likes/favorites, anonymize comments, etc.)
- [x] (OBSOLETE for this library - host-app concern, not authkit; authkit provides the BeforeUserHardDelete hook and the FK/anonymization policy lives in the host apps) Document downstream data policy in host apps (examples):
-       - comments: keep content by changing FK to `ON DELETE SET NULL` (so author becomes NULL on hard-delete); frontend renders author=NULL as "user deleted" (also handle legacy anonymous comments via anon_name when present)
-       - reactions/favorites: usually delete (cascade or explicit cleanup)
-       - posts/content with non-null author_id: decide per-app (either cascade-delete posts on user hard-delete, or switch author FK to SET NULL and render "user deleted")
-       - ClickHouse analytics/events: treat as append-only history; user_id may remain in event rows after user purge (acceptable; avoid expensive deletes)
-       - billing/audit/security logs: retain required records; remove/obfuscate PII as needed
- 
- TESTS/VALIDATION:
- [x] Add tests: banned users cannot log in; deleted users cannot log in; unban restores access; ban revokes sessions; delete revokes sessions -> [x] DONE 2026-05-22: e2e subtests ban_revokes_refresh_sessions_and_unban_restores + soft_delete_revokes_refresh_sessions pass live against the pg18 devserver.
- [x] Add tests for purge candidate selection: deleted_at older/newer than cutoff -> [x] DONE 2026-05-22: riverjobs/purge_deleted_users_test.go added (TestPurgeCandidateSelectionBoundary, DB-gated per repo convention; TestPurgeRetentionDefaults passes).
- [x] (OBSOLETE - migrations were squashed into a single baseline 001 with no is_active column and no backfill step; there is no old->new path left to test) Run migration path test: old data -> backfill -> code works -> drop is_active

---

# #8: Standalone AuthKit dev issuer (Postgres) + mint JWTs for E2E

**Completed:** yes

Provide a standalone AuthKit **devserver/dummy app** that can be started locally (Docker/compose) using Postgres and can mint JWTs for end-to-end testing of downstream services (e.g. `~/doujins-billing`) as well as AuthKit itself.

## Important constraint

The dev mint endpoint must live in the **dummy app**, not in the AuthKit library.
- No changes are required to AuthKit core APIs to support minting.
- The dummy app just *uses AuthKit as a library* and adds a dev-only route for minting tokens.

## Why

Downstream services that verify JWTs (like billing) need a local issuer that:
- exposes JWKS at `/.well-known/jwks.json` (already supported by AuthKit gin adapter)
- can mint short-lived JWTs on demand for API calls

AuthKit already has `testing.TestIssuer` (httptest) for unit tests, but E2E across containers needs a real long-running HTTP service with a stable issuer URL.

## Requirements

- Use Postgres (no sqlite).
- Safe-by-default: dev minting endpoints must be disabled in production.
- Usable from docker-compose networks (stable hostname like `issuer:8080`).

## Proposed Design

### 1) Standalone devserver binary

Add `cmd/authkit-devserver` (or similar) that:
- connects to Postgres via `DB_URL`/`DATABASE_URL`
- runs AuthKit migrations (either on boot or via a `migrate` subcommand)
- starts an HTTP server (gin) that mounts:
  - AuthKit API routes (`/auth/*`) for normal flows (useful for AuthKit E2E)
  - JWKS endpoint at `/.well-known/jwks.json` via `authgin.Service.GinRegisterJWKS`
  - **dev-only** mint endpoint implemented in the devserver (below)

### 2) Dev-only minting API (devserver-owned)

Add a dev-only endpoint guarded by `AUTHKIT_DEV_MODE=true` and a shared secret `AUTHKIT_DEV_MINT_SECRET`:
- `POST /auth/dev/mint`
  - input: `sub`, `aud`, optional `email`, optional `roles`, optional `scopes`, optional `expires_in_seconds`
  - output: `{token, token_type: "Bearer", expires_at}`

Security:
- If `AUTHKIT_DEV_MODE!=true`, this route is not registered.
- Require `Authorization: Bearer <AUTHKIT_DEV_MINT_SECRET>` (or an `X-DEV-SECRET` header).

### 3) Issuer URL + signing key persistence

- Issuer must be stable across restarts (e.g. `http://issuer:8080` inside compose).
- Persist signing keys so previously minted tokens remain verifiable after restart.
  - Option A: store key material in Postgres (recommended)
  - Option B: store key material in a file mounted as a docker volume

### 4) How this helps billing E2E

- Billing config points to the issuer:
  - `AUTH_ISSUERS='["http://issuer:8080"]'`
  - `AUTH_EXPECTED_AUDIENCE=billing-app`
- Billing E2E scripts call `POST http://issuer:8080/auth/dev/mint`, then use the returned token to call billing APIs.

## Tasks

- [ ] Add `cmd/authkit-devserver` entrypoint (gin server + Postgres)
- [ ] Add config/env parsing: DB URL, listen addr, dev-mode flags, mint secret
- [ ] Add migrations execution path (on boot or subcommand)
- [ ] Implement `/auth/dev/mint` in the devserver (dev-only) + shared-secret guard (no library changes)
- [ ] Persist signing key material across restarts (DB table or volume-backed file)
- [ ] Add docker-compose (or documented snippet) to run `postgres` + `authkit-devserver`
- [ ] Add docs: how to run, how to mint tokens (curl), and example billing integration

**Tasks:**
- [x] Implement devserver dummy app (`authkit-devserver.go`, Postgres-backed)
- [x] Implement dev-only `/auth/dev/mint` in the devserver (guarded by env + secret)
- [x] Persist signing keys across restarts (volume-backed `/.runtime/authkit`)
- [x] Add `docker-compose.devserver.yaml` + `DEVSERVER.md` + `Dockerfile.devserver`

---

# #9: E2E tests for authkit-devserver (JWKS + mint + core auth flows)

**Completed:** yes

Add docker-compose-backed E2E tests that exercise AuthKit as a real HTTP server (Postgres-backed), using the new devserver/mint endpoint.

## Why

Unit tests cover helpers and a small set of handlers, but we currently lack end-to-end coverage for:
- database schema + migrations + boot
- HTTP routing + middleware + JWT verification via JWKS
- critical auth flows (password login, refresh, session revocation)

The devserver gives us a stable issuer and a convenient way to mint tokens for testing protected endpoints without wiring email/SMS providers.

## Current test coverage (today)

- Token verifier/JWKS via `testing.TestIssuer` (httptest): `testing/issuer_test.go`
- A few Gin adapter tests (handlers + userctx): `adapters/gin/*_test.go`
- Ephemeral store tests: `core/ephemeral_test.go`
- SIWS tests: `siws/siws_test.go`

## What we should test (high value)

E2E (docker-compose):
- Devserver boots, runs migrations, and serves HTTP
- JWKS served and usable by external verifiers
- `/auth/dev/mint` guarded correctly and produces valid, expiring JWTs
- Password login and refresh/session lifecycle against Postgres
- Banned/deleted users cannot authenticate (and are filtered by DB-backed user lookups)
- Admin gating is DB-backed (create admin role + grant + confirm admin endpoints work)

## Test structure

- Add E2E tests behind a build tag (e.g. `//go:build e2e`) so they do not run in normal `go test ./...`.
- The tests shell out to docker compose (`docker compose -f docker-compose.devserver.yaml ...`) with a unique `COMPOSE_PROJECT_NAME`.
- The tests hit the devserver on `http://localhost:8080` and connect to Postgres on `localhost:5432`.

## Tasks

- [ ] Add `testing/devserver_e2e_test.go` behind `//go:build e2e`
- [ ] Test: boot + health (`GET /healthz`)
- [ ] Test: JWKS (`GET /.well-known/jwks.json` returns at least one RSA key)
- [ ] Test: mint authz
  - missing/invalid secret => 401
  - valid secret => 200 + `{token, expires_at}`
  - `AUTHKIT_DEV_MODE=false` => route not registered (404)
- [ ] Test: minted token can call an AUTH endpoint when a matching user exists in Postgres
  - seed `profiles.users` row with same UUID as `sub`
  - call `GET /auth/user/me` with `Authorization: Bearer <token>` and expect 200
- [ ] Test: admin gate is DB-backed
  - seed `profiles.roles` with slug `admin`
  - seed `profiles.user_roles` mapping for user
  - call an admin endpoint and expect 200
- [ ] Test: banned/deleted enforcement
  - set `profiles.users.banned_at` and verify `GET /auth/user/me` fails (or user is not returned)
  - set `profiles.users.deleted_at` similarly
- [ ] Test: password login + refresh
  - seed `profiles.user_passwords` hash
  - `POST /auth/password/login` returns access token (and refresh session)
  - `POST /auth/token` refresh works
  - revoke session and ensure refresh fails
- [ ] Docs: add a short section to `DEVSERVER.md` describing how to run E2E tests (`go test -tags=e2e ./testing -run Devserver`)

**Tasks:**
- [x] Add build-tagged docker-compose E2E test suite
- [x] Cover JWKS + /auth/dev/mint (authz + expiry)
- [x] Cover core auth flows (login/refresh/sessions)
- [x] Cover ban/delete enforcement + admin gate

---

# #11: Language-aware AuthKit (propagate request language to senders)

**Completed:** yes

Make AuthKit language-aware for user-facing communications (email + SMS) by detecting request language and propagating it to the host-provided sender interfaces via `context.Context`.

Why:
- Host apps (`~/doujins`, `~/hentai0`) render the email/SMS bodies, but need to know what language-site the user is on at the moment an auth message is sent (signup/login/reset).
- Some auth flows run before a user profile exists (signup verification), so there is no reliable user_id to look up preferences. Request language is the best signal.

Design:
- AuthKit should not depend on host-specific user context types.
- Introduce an AuthKit-owned context key + helpers to store language in `ctx`.
- Ensure all calls into EmailSender/SmsSender use the inbound request ctx (or a derived ctx that preserves values), not `context.Background()`.

Notes:
- This should apply to both API routes and any root/browser flows AuthKit registers.
- The language source should be configurable but default to: query param `lang` > cookie > `Accept-Language` > default.

**Tasks:**
- === SHARED LANGUAGE CONTRACT (ALIGN WITH DOUJINS + HENTAI0) ===
- [x] Define and document a single precedence order for request language: `?lang` query param > `/:lang/` path prefix > `lang` cookie > `Accept-Language` header > default
- [x] Add AuthKit `LanguageConfig` (supported + default + cookie/query knobs) passed by the host app; validate and reject/ignore unsupported codes
- [x] Default behavior when config not provided: accept only basic `^[a-z]{2}$` languages, default to `en`
- 
- [x] Add `lang` context helpers: `WithLanguage(ctx, lang)` and `LanguageFromContext(ctx)`
- [x] Add middleware/hook in the Gin adapter to detect language (per the shared contract) and attach it to ctx for every AuthKit request
- [x] Ensure AuthKit handlers/services propagate the inbound request ctx through to sender calls (no Background ctx)
- [x] Docs: sender implementations can read language from ctx and choose localized templates
- [x] Tests: language detection + ctx propagation into a fake sender for email + sms
- [x] Tests: ensure `LanguageConfig.Supported` is enforced for query/path/cookie/Accept-Language

---

# #12: Decouple request language from UserContext (context key)

**Completed:** yes

Ensure AuthKit stores request language as request metadata under a dedicated `context.Context` key (AuthKit-owned), not embedded inside any user identity context struct.

Why:
- Request language is not user identity.
- Some flows do not have a user record yet (signup verification), but are still language-scoped.
- Keeps AuthKit portable: host apps can read language from ctx in senders without coupling to host-specific `UserContext` layouts.

Non-goals:
- Making language selection configurable per-app (beyond supported/default validation).
- Translating AuthKit error messages (this issue is about propagation to senders).

Relationship to issue #11:
- Issue #11 adds language detection + propagation to senders.
- This issue enforces the storage pattern: language lives at a dedicated context key (not nested under user ctx).

**Tasks:**
- [x] Add an AuthKit-owned context key for request language (can reuse the `lang` helpers from issue #11)
- [x] Ensure all sender invocations rely on `lang.LanguageFromContext(ctx)` (not user ctx structs) for language selection
- [x] Document the pattern for host apps: sender implementations should read request language from ctx and fall back to defaults
- [x] Add tests that assert language is present on ctx in both authenticated and unauthenticated auth flows

---

# #13: Auth analytics: log session lifecycle (not access-token mints)

**Completed:** yes

Stop logging every access-token mint as an analytics/audit event. Instead, log session lifecycle + security-relevant transitions:

- Session created (login / refresh session issuance) → useful for audit, device tracking, “new login” alerts.
- Session revoked/deleted (logout, admin revoke, password change, “revoke all”, eviction by session limit) → critical for audit.

Non-goals:
- Per-access-token issuance telemetry.

Notes:
- Keep logging best-effort and non-blocking.
- Ensure events are disambiguated across host apps (e.g., include `issuer` and/or `site` in the ClickHouse schema/sink if needed).

**Tasks:**
- [x] Remove/avoid logging access-token mints (e.g., refresh-exchange events) as primary analytics signals
- [x] Add explicit session lifecycle events to the auth logger interface (created, revoked/deleted, revoke-all, eviction)
- [x] Emit session-created events from all login/session issuance paths
- [x] Emit session-revoked/deleted events from logout + admin revoke + password change + revoke-all + eviction paths
- [x] Remove Postgres `profiles.signin_history` (stop writing to it, migrate/drop table, and update admin sign-in history endpoints to use ClickHouse if still needed)
- [x] Replace ClickHouse auth tables with a single `user_auth_session_events` table (session lifecycle only, not access-token mints)
- [x] ClickHouse schema: include `issuer`, `session_id` (`sid`), `event`, `method`, optional `reason`, plus `ip_addr`/`user_agent`
- [x] Update ClickHouse sink to persist `issuer` + `session_id` + event fields (host app implementation; include `site` only if issuer is insufficient)
- [x] Add a new ClickHouse migration that drops old auth tables/views and creates `user_auth_session_events` (no legacy compatibility, no data backfill)
- [x] Drop `user_last_seen_current` and related materialized views; rely on queries over `user_auth_session_events` instead

---

# #14: Plan: framework-agnostic selective billing http.Handler

**Completed:** yes

Track work needed to expose doujins-billing HTTP routes as a single mountable `http.Handler` *with selective route groups* (user/admin/webhooks/health), while staying framework-agnostic for hosts.

## Context

cozy-art currently embeds doujins-billing and mounts it under `/billing`. Some host routers (notably Gin) have route-tree constraints around catch-all wildcards, so the integration surface should be a single handler mounted via `http.StripPrefix`/outer mux.

We also want optionality: some hosts should be able to mount only webhooks, only admin, etc., without exposing the full billing HTTP surface.

## Goal

In doujins-billing, add a public handler builder such as:

```go
type HTTPHandlerOptions struct {
  IncludeUser bool
  IncludeAdmin bool
  IncludeWebhooks bool
  IncludeHealth bool
  // optionally: IncludeDebug (dev only)
}

func (e *embedded.Embedded) NewHTTPHandler(opts HTTPHandlerOptions) http.Handler
```

Defaults should preserve existing standalone behavior, while giving embedded hosts fine-grained control.

## Non-goals

- Do not put billing route selection into authkit; authkit should remain focused on auth routes.
- Do not reintroduce Gin-only embedding APIs as the primary integration surface.

Status update (2026-01-27): implemented in doujins-billing + wired into cozy-art.

**Tasks:**
- doujins-billing implementation:
- [x] Define exported options type (include flags) and document semantics
- [x] Build a single handler that registers only selected route groups
- [x] Keep `Handler()` as backwards-compatible shorthand (all groups)
- [x] Ensure admin routes still enforce auth/admin checks internally
- [x] Add tests that assert excluded groups return 404 (and included groups are not 404)
- [x] Update embedded README with mounting examples
- 
cozy-art integration:
- [x] Mount billing using the selective handler options
- [x] Verify no Gin wildcard route panics
- 
Migration/cleanup:
- [x] Tag/release doujins-billing once satisfied (validated complete 2026-05-22 during archive)

---

# #15: Security audit events: password reset requests (non-session)

**Completed:** yes

Add a separate, non-session security audit event stream for flows like password reset requests.

Why:
- Password reset requests are security-relevant, but are not session lifecycle events and should not be mixed into `user_auth_session_events`.
- Host apps may want an audit trail for account recovery activity without logging per-access-token issuance.

Design:
- Add a new ClickHouse table (e.g., `user_auth_security_events`) keyed by `(issuer, occurred_at, event, user_id?)`.
- Add a dedicated logger interface/method (separate from session events) so session lifecycle logging remains focused.
- Avoid logging raw identifiers (email/phone). Prefer `user_id` when known; otherwise log a hash + identifier type if absolutely needed.

Events (initial):
- `password_reset_requested` (email/phone)

Non-goals:
- Changing session lifecycle logging.
- Per-access-token mint telemetry.

**Tasks:**
- [x] (SUPERSEDED - the separate stream was not built; reset-request auditing was folded into the existing session-event stream instead) Define `SecurityEvent` types and a new logger interface (separate from session events)
- [x] (SUPERSEDED - no separate table; events are recorded in the existing user_auth_session_events) Add ClickHouse migration to create `user_auth_security_events`
- [x] REMAINING GAP (real): reset-request events ARE already emitted (as `password_recovery` via LogPasswordRecovery at request time, email service.go:1101 / phone :1780, carrying issuer + user_id, never raw email/phone) - but ip/ua are currently passed as nil (http/password_reset.go forwards no request IP/UA). Capture and forward request ip/ua on these events. -> [x] DONE 2026-05-22: request ip/ua threaded from the HTTP handlers through RequestPasswordReset/RequestPhonePasswordReset into LogPasswordRecovery; shipped in authkit v0.10.2.
- [x] (DONE BY DESIGN - the session-event records log only user_id, never raw email/phone) Decide on identifier logging policy (no raw email/phone; optional hash if needed) and document it
- [x] (OBSOLETE - no separate table; the existing user_auth_session_events sink already carries these events) Update host apps' ClickHouse sink(s) to insert into `user_auth_security_events`

---

# #16: Framework-agnostic net/http adapter (http)

**Completed:** yes

Add a first-class `net/http` transport for AuthKit so host apps can embed AuthKit without Gin.

## Motivation

Today AuthKit’s HTTP surface is implemented via the Gin adapter (`adapters/gin`). That works well for Gin apps, but it couples embedding to Gin’s router/middleware model. A native `net/http` adapter makes embedding framework-agnostic (stdlib mux, chi, echo via bridge, Lambda/APIGW, etc.) and reduces dependency friction for non-Gin hosts.

## High-level approach (staged migration)

1) Introduce `http` that implements the same routes using `net/http` handlers and std context.
2) Keep `adapters/gin` supported initially. Optionally, later make Gin adapter a thin shim that delegates to the `net/http` adapter (Gin → ServeHTTP), once parity is proven.
3) Migrate tests to validate the `net/http` adapter, and add parity tests to prevent behavior drift.

## Scope

- Provide handler registration/mounting for:
  - JWKS: `GET /.well-known/jwks.json`
  - Browser flows: `/auth/oidc/:provider/login`, `/auth/oidc/:provider/callback`, and discord oauth routes if configured
  - JSON API: `/auth/*` endpoints (password login, register, sessions, user, admin, SIWS, etc.)
- Preserve existing response shapes and status codes where feasible.

## Non-goals

- Do not change core business logic (`core/*`) beyond small helpers needed for transport neutrality.
- Do not remove Gin adapter in the first iteration.
- No API redesign; focus on transport parity.

## Risks

- Behavior drift (status codes, error payloads, headers) unless parity-tested.
- Replacing Gin binding/validation and middleware chaining requires careful design.

**Tasks:**
- Design:
- [x] Decide adapter public API: `authhttp.NewService(core.Config)` plus mountable handler methods (`JWKSHandler`, `APIHandler`, `OIDCHandler`)
- [x] Decide mounting strategy: expose multiple mountable handlers (JWKS/API/OIDC) rather than a single all-in-one handler
- [x] Define shared error envelope + helpers for consistent responses
- 
Implementation (http):
- [x] Add `http` package skeleton
- [x] Implement JWKS handler (parity with gin handler)
- [x] Implement auth middleware for Required/Optional using core verifier
- [x] Implement request parsing + validation (stdlib + validator library or minimal custom)
- [x] Implement JSON API endpoints (route-by-route parity)
- [x] Implement OIDC/OAuth browser flows endpoints
- [x] Implement SIWS endpoints
- [x] Implement admin routes (RequireAdmin DB check)
- 
Testing:
- [x] Add route-parity tests (Gin vs net/http) for critical endpoints
- [x] Add httptest coverage for net/http adapter
- [x] Add golden tests for error shapes/status codes for high-traffic endpoints
- 
Migration:
- [x] Add docs showing embedding in stdlib mux + example Gin mount via `gin.WrapH`
- [x] (Optional) refactor gin adapter to call net/http adapter where practical (validated complete 2026-05-22 during archive)

---

# #17: Drop Gin adapter + ginutil (breaking): rely fully on net/http routing

**Completed:** yes

AuthKit now has a full `net/http` adapter (`http`, package `authhttp`). We want to remove all Gin-specific logic and dependencies from this repo and rely exclusively on the new router/handler implementation.

This is a deliberate breaking change: downstream projects that import `github.com/open-rails/authkit/adapters/gin` or `adapters/ginutil` will need to migrate to `http`.

Non-goals:
- Backwards compatibility for Gin hosts.
- Shim layers that keep Gin working.

Success criteria:
- No Gin dependency in AuthKit.
- `go test ./...` passes.
- README/docs show only `authhttp` mounting.

**Tasks:**
- [x] Inventory all Gin usages in-repo (packages, tests, docs) and decide the deletion scope (`adapters/gin`, `adapters/ginutil`, any local helpers).
- [x] Remove Gin-specific packages (`adapters/gin`, `adapters/ginutil`) and any Gin-only helpers that are no longer used.
- [x] Update/replace tests that import Gin (e.g. route-parity tests) so the suite does not depend on Gin at all.
- [x] Update README/docs/examples to show only `authhttp` usage; remove `authgin.*` references.
- [x] Remove Gin-related module deps from `go.mod`/`go.sum` (`github.com/gin-gonic/gin`, etc.) and run `go mod tidy`.
- [x] Verify: `go test ./...` passes.
- [x] Versioning: decide and apply a breaking-release strategy (e.g. bump major tag) for downstream migration clarity.

---

# #18: Rate limiting: sensible secure defaults (on by default)

**Completed:** yes

AuthKit’s `authhttp` adapter has per-endpoint rate limit buckets, but rate limiting is currently effectively disabled unless a host app calls `svc.WithRateLimiter(...)`.

That is a security footgun (password login / token exchange / reset / OIDC start/callback are unthrottled by default).

Goal:
- Provide sensible, secure default rate limiting behavior out-of-the-box.

Non-goals:
- Perfect bot protection.
- Persisting/migrating legacy limiter state.

Key requirements:
- Defaults must be safe in prod and not accidentally rate-limit a reverse proxy (need configurable client IP extraction / trusted proxy model).
- Hosts must be able to override limits and to explicitly disable rate limiting (opt-out).
- Behavior must fail-open on limiter backend errors (availability > throttle correctness).

**Tasks:**
- [x] Decide default limiter behavior: enable memorylimiter by default vs require explicit config in prod (and how to detect prod).
- [x] Define the default per-bucket limits (reuse existing bucket names: `RLPasswordLogin`, `RLAuthToken`, `RLOIDCStart`, etc.).
- [x] Add a first-class client IP strategy to `authhttp`:
  - default: RemoteAddr
  - optional: trusted proxy list / header-based extraction (X-Forwarded-For, CF-Connecting-IP) to avoid limiting the proxy itself.
- [x] Implement: when no limiter is configured, install the default limiter (and defaults) automatically; add an explicit opt-out (e.g. `DisableRateLimiter()` or `WithRateLimiter(NoopLimiter)`).
- [x] Docs: update README / adapter docs with guidance for multi-instance prod (Redis limiter) + proxy configuration.
- [x] Tests: add minimal coverage that rate limiting is active by default (and that opt-out disables it).
- [x] Verify: `go test ./...` passes.

---

# #19: JWT verification: require `exp` for access tokens (verify-only AcceptConfig too)

**Completed:** yes

Today `authhttp.Required(...)` always parses tokens with `jwt.ParseWithClaims` (which validates registered time claims if present), but in verify-only mode (multi-issuer `AcceptConfig`) our explicit expiry check is only applied when `exp` exists.

That means a signed token that omits `exp` could be accepted in verify-only mode as long as signature + issuer/audience match.

Goal:
- Require `exp` to be present on access tokens in all verification modes (service-issued and verify-only).

Non-goals:
- Requiring `nbf` or `iat` to exist.

Requirements:
- Continue to validate `nbf`/`iat` when present (via jwt library validation and/or explicit checks).
- Apply a small skew allowance (existing behavior).
- Produce stable error codes (e.g. `missing_exp`, `token_expired`).

**Tasks:**
- [x] Decide enforcement: require `exp` for access tokens (no opt-out).
- [x] Update `authhttp.Required` to reject tokens missing `exp` in both service-issued and verify-only (`AcceptConfig`) modes.
- [x] Ensure `nbf`/`iat` are still validated when present (but not required).
- [x] Add tests covering: missing `exp` rejected; expired rejected; valid with `nbf` in future rejected; valid without `nbf`/`iat` accepted.
- [x] Verify: `go test ./...` passes.

---

# #20: Tenants (tenants) + RBAC in AuthKit

**Completed:** yes

Add first-class tenants to AuthKit so users can belong to multiple tenants and services can rely on a consistent tenant/tenant model across the platform.

Goal:
- AuthKit is the source of truth for: tenants, memberships, and tenant-assigned role strings.
- Roles are opaque strings (tenant-defined). AuthKit stores them; each application decides what roles mean (permission mapping) within that tenant.

Design notes:
- Host configuration selects tenant behavior via `tenant_mode`: `single` (default) or `multi`.
- Default behavior is `tenant_mode: single` when no tenant config is provided.

- `tenant_mode: single`:
  - JWTs include `roles` (string[]); no tenant claim.
  - `GET /auth/user/me` returns roles only.

- `tenant_mode: multi`:
  - Users may belong to 0 tenants, 1 tenant, or multiple tenants simultaneously.
  - Default access tokens do NOT embed tenant membership or tenant roles; host apps do server-side membership/role checks (GitHub-style).
  - `GET /auth/user/me` returns all tenant memberships + all tenant-scoped roles (server-side).
  - Optional tenant-scoped token minting: `POST /auth/token/tenant` can mint a JWT containing `tenant` + `roles` for a single tenant.
  - Never allow minting tenant/role claims the user does not have.

- Tenant identifiers are slugs (human-readable). Slug renames create aliases; aliases must remain valid for auth.
- Support deployments moving from `single` -> `multi` via configuration.
- Mode transitions:
  - `single` -> `multi` must be allowed by configuration change at any time.
  - `multi` -> `single` should be rejected as a safeguard when there is more than one tenant with more than one member (1 tenant with many members is allowed to downgrade).

- Guardrails are required (hardcoded sensible defaults; not configurable):
  - Limit tenant slug/alias length and character set.
  - Limit role length and character set.
  - Limit max tenant memberships per user.
  - Limit max roles per tenant membership.

- Claim contract:
  - Single mode tokens: roles (string[])
  - Multi mode default tokens: no tenant/roles claims
  - Multi mode tenant-scoped tokens (via `POST /auth/token/tenant`): tenant (string) + roles (string[])

Non-goals (v1):
- Fine-grained per-resource ACLs (repo-level ACLs, etc.).
- Billing/quota enforcement.
- Full invitation UX (email invites), beyond basic admin APIs.

**Tasks:**
- [x] Data model + migrations
    - tenants table: id (uuid), slug (unique current slug), created_at, updated_at, deleted_at
    - org_slug_aliases table: tenant_id, slug (unique alias), created_at, deleted_at (optional)
      - On rename: insert old slug into org_slug_aliases, update tenants.slug to new slug
      - Aliases should remain valid for auth forever (or very long) to avoid breaking tokens
    - tenant_memberships table: tenant_id, user_id, created_at, updated_at, deleted_at; unique(tenant_id,user_id)
    - tenant_roles table: tenant_id, role (text), created_at; unique(tenant_id, role)
    - tenant_membership_roles table: tenant_id, user_id, role; unique(tenant_id,user_id,role)
    - Constraints/validation (guardrails):
      - tenant slug/alias length + character set
      - role length + character set
    - Indexes for slug/alias lookup and membership checks
- [x] Core service API
    - CreateTenant(slug) (admin-only or self-serve with rate limit)
    - RenameTenantSlug(tenant_id, new_slug) (create alias for old slug)
    - ResolveTenantBySlug(slug) -> tenant (accepts current slug or alias; aliases are implicit)
    - ListTenantMembershipsForUser(user_id) -> []{tenant}
    - AddMember(tenant_id, user_id), RemoveMember(tenant_id, user_id) (tenant owner via HTTP)
    - DefineRole(tenant_id, role), DeleteRole(tenant_id, role) (tenant owner via HTTP; `owner` is protected)
    - AssignRole(tenant_id, user_id, role), UnassignRole(tenant_id, user_id, role) (tenant owner via HTTP; cannot remove last owner)
    - ReadMemberRoles(tenant_id, user_id)
    - Enforce guardrails (max tenant memberships per user; max roles per membership; slug/role validation on writes)
- [x] HTTP API endpoints
    - GET /auth/tenants (list tenants for current user)
    - POST /auth/tenants (create tenant)
    - GET /auth/tenants/:tenant (metadata; :tenant accepts slug or alias)
    - POST /auth/tenants/:tenant/rename (rename slug; keep alias)
    - GET/POST/DELETE /auth/tenants/:tenant/members
    - GET/POST/DELETE /auth/tenants/:tenant/roles and /auth/tenants/:tenant/members/:user_id/roles
    - POST /auth/token/tenant (mint tenant-scoped access token: `tenant` + `roles`)
    - GET /auth/user/me (multi: includes tenant memberships + tenant-scoped roles; single: roles only)
- [x] AuthZ rules
    - Only tenant `owner` can manage members + role definitions + role assignments
    - Normal members can list tenant metadata they belong to
    - Owner bootstrap behavior on tenant create
- [x] Token claims + optional tenant-scoped minting
    - `tenant_mode: single`: include `roles` (string[]) in JWT (no tenant claim)
    - `tenant_mode: multi` default: JWT has no tenant/roles claims; host apps check membership/roles server-side
    - `POST /auth/token/tenant`: accept `tenant` parameter; if user is a member, include:
      - tenant (string)
      - roles (string[]) for that tenant
    - Reject tenant-scoped minting when user is not a member of the tenant
    - Support aliases via ResolveTenantBySlug (slug or alias accepted); mint canonical slug
    - Provide an `authhttp` helper for consistent server-side tenant membership/role checks
    - `tenant_mode` behavior:
      - Default is `single` when unset
      - `single` -> `multi` supported via config change
      - `multi` -> `single` rejected when >1 tenant has >1 member
    - No scopes claim in v1
- [x] Tests
    - Core: validate tenant slug/role guardrails
    - Token mint (single): `roles` claim present
    - Token mint (multi default): no tenant/roles claims present
    - Token mint (multi tenant-scoped via /auth/token/tenant): includes `tenant` + `roles`
    - HTTP routing: tenant endpoints are only exposed in tenant_mode=multi
    - Verify: `go test ./...` passes
- [x] Docs
    - Update README/API docs for tenant endpoints and claim semantics
    - Document slug renames + alias semantics (tokens/keys are not broken)

---

# #21: Tenant-scoped token ergonomics + claim alignment (post-v1)

**Completed:** yes

Refinements based on common industry patterns (Auth0/Entra/Keycloak/WorkOS/etc.) to make AuthKit's tenant-mode integration more ergonomic and more consistent in claim naming across token types.

Goals:
- Reduce client round trips by allowing tenant selection at login/refresh.
- Use consistent claim names across single vs tenant-scoped tokens.

Non-goals:
- Changing the v1 tenant data model.
- Embedding full tenant memberships in default tokens (multi mode stays server-side by design).

**Tasks:**
- [x] Claim naming alignment
    - For tenant-scoped tokens minted in `tenant_mode: multi`, use `tenant` (string) + `roles` (string[])
    - No `tenant_roles` claim
- [x] Login/refresh ergonomics
    - Allow `POST /auth/password/login` to accept optional `tenant` in request (multi mode only)
      - When provided and user is a member: mint tenant-scoped access token (`tenant` + `roles`)
      - When omitted: mint default access token (no tenant claims)
    - Allow refresh/token exchange endpoint(s) to accept optional `tenant` similarly
    - Keep `POST /auth/token/tenant` as an explicit minting endpoint (still useful for tenant switching without re-auth)
- [x] Doc updates
    - Update README and `agents/api-endpoints.md` to describe optional `tenant` parameter and claim name changes
    - Document a recommended client-side tenant switching flow (me -> select tenant -> token/tenant or refresh-with-tenant)
- [x] Tests
    - Validate claim parsing treats `roles` as tenant-scoped roles when `tenant` is present
    - Validate login/refresh optional `tenant` behavior in multi mode
- [x] (Deferred) Scopes
    - Explicit non-goal of this issue; no OAuth scope claim is emitted by design. Revisit only if a gateway integration requires it. The 4 substantive tasks (tenant/roles claim naming, optional tenant on login/refresh, docs, tests) are implemented in current code (verified 2026-05-22).

---

# #22: Standalone E2E AuthKit devserver image (AuthKit + embedded Postgres)

**Completed:** yes

Downstream repos (e.g. OpenRails, Doujins) want an E2E sandbox issuer that does not require `../authkit` to be checked out locally.

Create a single pullable Docker image that runs:
- a Postgres instance (embedded in the container)
- the AuthKit devserver (`GET /.well-known/jwks.json` + `POST /auth/dev/mint` for E2E)

This image is explicitly for local/E2E testing only.

Goals:
- One container to start (no external Postgres service needed).
- Stable issuer URL inside a compose network (e.g. `http://issuer:8080`).
- Persist AuthKit runtime signing keys across restarts (existing `/.runtime/authkit` behavior).
- Be easy to consume from other repos via `image: ghcr.io/.../authkit-devserver-all-in-one:<tag>`.

Non-goals:
- Production deployments.
- HA/multi-instance behavior.
- Replacing the normal 2-container compose pattern (Postgres + AuthKit) for local development.

Constraints / tradeoffs:
- This is a multi-process container (Postgres + HTTP server). It should use a minimal init/process supervisor and graceful shutdown semantics.
- For zero-config E2E, dev minting is enabled by default with a default shared secret (override in your test environment).

**Tasks:**
- [x] Decide image contract
    - Image name + tags (GHCR)
    - Default ports (8080 exposed; Postgres is internal-only)
    - Supported env vars (AUTHKIT_ISSUER, AUTHKIT_DEV_MODE, AUTHKIT_DEV_MINT_SECRET, AUTHKIT_ISSUED_AUDIENCES, AUTHKIT_EXPECTED_AUDIENCES)
    - Embedded Postgres defaults (db name/user/password) + ability to override via env
- [x] Add an all-in-one Dockerfile
    - Build AuthKit devserver binary
    - Include Postgres 17 as the base image
    - Provide an entrypoint that starts Postgres + the devserver and handles shutdown
- [x] Implement container bootstrap
    - Initialize Postgres data dir on first run (Postgres entrypoint)
    - Run required Postgres setup and AuthKit migrations (devserver migrates on start)
    - Start AuthKit devserver after DB is ready
    - Persist Postgres data via a volume mount
- [x] Security + safety defaults
    - Dev mint endpoint requires AUTHKIT_DEV_MODE=true AND AUTHKIT_DEV_MINT_SECRET
    - Document that this image must never be exposed publicly
    - Log clearly when dev minting is enabled

Note: for zero-config E2E, the all-in-one image defaults to AUTHKIT_DEV_MODE=true and AUTHKIT_DEV_MINT_SECRET=change-me (override as needed).
- [x] Documentation
    - Add usage snippet for downstream compose (single service)
    - Document how to mint tokens and where JWKS lives
    - Document volumes (Postgres data + `/.runtime/authkit`) and what they do
- [x] CI/publishing
    - Add GitHub Actions workflow to build + push the image to GHCR on tags
    - Publish multi-arch (linux/amd64, linux/arm64)
    - Versioning strategy: match AuthKit git tags (v*)
- [x] Update E2E examples/tests
    - Add an example compose file that uses the published image (no `build: ../authkit`)
    - Update `testing/devserver_e2e_test.go` to optionally validate the all-in-one Dockerfile via local build (AUTHKIT_E2E_ALL_IN_ONE=1)

---

# #23: Personal tenants + invitations + rename aliases + bootstrap endpoint

**Completed:** yes

Align AuthKit tenant model with Cozy platform semantics while keeping tenant_mode=multi as the foundation.

Scope:
- Add first-class personal-tenant metadata and non-transferable ownership rules.
- Add a full invitation lifecycle (pending invite, accept/decline) rather than only direct member add/remove.
- Add/confirm user-rename alias forwarding so personal-owner slugs behave like tenant slug aliases.
- Add a single bootstrap endpoint returning canonical personal tenant + memberships for the current user.

Goals:
- Keep shared owner namespace semantics predictable across user/tenant slugs.
- Reduce host-app glue code for tenant bootstrap and routing.
- Preserve backwards compatibility for existing owner/repo refs after renames.

Non-goals (v1):
- Replacing existing tenant APIs; this extends them.
- Building product-specific ACL semantics inside AuthKit.

**Tasks:**
- [x] Personal tenant metadata + ownership invariants
    - Add first-class personal-tenant metadata (e.g. `is_personal`, `owner_user_id`) to tenant records
    - Enforce invariant: personal-tenant ownership is non-transferable
    - Guard dangerous operations for personal tenants (owner removal/transfer/delete semantics)
- [x] Invitation lifecycle APIs
    - Add invite entities with states (pending, accepted, declined, revoked, expired)
    - Expose endpoints/workflows for create invite, accept, decline, revoke, list
    - Keep direct add/remove APIs for admin flows, but treat invites as first-class UX path
- [x] User rename alias forwarding (owner namespace stability)
    - Add/confirm alias forwarding for user rename so old user slug resolves to canonical new slug
    - Ensure personal-tenant owner slug behavior matches tenant alias semantics
    - Verify old owner-based paths/refs remain resolvable after rename
- [x] Bootstrap endpoint for personal tenant + memberships
    - Add endpoint returning current user’s canonical personal tenant plus all tenant memberships/roles
    - Include canonical slugs and alias-aware resolution details needed by host apps
    - Ensure response is stable for UI/session bootstrap and tenant switchers
- [x] Docs + migration notes
    - Document personal-tenant invariants, invite state machine, and rename alias behavior
    - Provide migration notes for hosts adopting the new endpoint and invitation APIs
- [x] Tests
    - Personal-tenant non-transferability and ownership guard tests
    - Invitation state transition tests (pending->accepted/declined/revoked/expired)
    - User rename alias-forwarding tests across owner-slug lookups
    - Bootstrap endpoint contract tests

---

# #24: Host-owned configuration only (no library-level env/config loading, except optional key auto-discovery)

**Completed:** yes

Policy: AuthKit library behavior should be configured by the embedding host application via `core.Config` (and explicit method args), not by the library reading process env vars or external files on its own.

Allowed exception:
- Keep `cfg.Keys == nil` behavior so AuthKit can still auto-discover/generate keys when the host does not provide a key source.

Naming standard for this work:
- Use `RequireVerifiedRegistrations` as the canonical config name (default true).
- Use `*_REQUIRE_VERIFIED_REGISTRATIONS` as the canonical env spelling in app/devserver layers.

Current non-host configuration reads in library code (to remove or move behind host config, except the key exception):
1) `core/service_solana.go`
   - `SOLANA_NETWORK` via `os.Getenv` in `solanaChainID()`.
2) `core/service.go`
   - `getEnvironment()` reads `ENV`, `APP_ENV`, `ENVIRONMENT`.
   - Used by `isDevEnvironment(...)` checks that affect runtime behavior.
3) `core/ephemeral.go`
   - `IsDevEnvironment()` depends on `getEnvironment()` (same env reads above).
4) `jwt/keys.go` (allowed only under `cfg.Keys == nil` exception)
   - Env: `ACTIVE_KEY_ID`, `ACTIVE_PRIVATE_KEY_PEM`, `PUBLIC_KEYS`.
   - Env for prod detection: `ENV`, `APP_ENV`, `ENVIRONMENT`.
   - Filesystem: `/vault/auth/keys.json`.
   - Dev runtime files: `.runtime/authkit/private.pem` + `.runtime/authkit/kid`.

Devserver naming alignment:
- Keep standalone devserver env loading (app-level), but migrate env prefix from `AUTHKIT_*` to `DEVSERVER_*` to clearly separate devserver app config from embedded library config.

**Tasks:**
- [x] Devserver env prefix migration (app-level, not library-level): adopt `DEVSERVER_*` names for standalone devserver runtime config (`DEVSERVER_ISSUER`, `DEVSERVER_LISTEN_ADDR`, `DEVSERVER_DEV_MODE`, `DEVSERVER_DEV_MINT_SECRET`, `DEVSERVER_REQUIRE_VERIFIED_REGISTRATIONS`, `DEVSERVER_MIGRATE_ON_START`, `DEVSERVER_ISSUED_AUDIENCES`, `DEVSERVER_EXPECTED_AUDIENCES`).
- [x] Backward compatibility: keep existing `AUTHKIT_*` env names as deprecated aliases for at least one release; define precedence (`DEVSERVER_*` wins when both are set) and log deprecation warnings.
- [x] Update devserver docs/compose/examples/tests to prefer `DEVSERVER_*` names while still validating alias compatibility during transition.
- [x] Canonical naming migration in library config: rename `VerificationRequired` to `RequireVerifiedRegistrations` (default true) in `core.Config`/`Options`, while keeping backward-compatible aliases for one transition window.
- [x] Canonical env alias mapping for transition: support legacy `AUTHKIT_VERIFICATION_REQUIRED` and `DEVSERVER_VERIFICATION_REQUIRED` as deprecated aliases to `DEVSERVER_REQUIRE_VERIFIED_REGISTRATIONS`.
- [x] Add explicit host-provided runtime config fields for behaviors currently derived from env in library code (e.g., environment mode, Solana chain/network).
- [x] Replace `SOLANA_NETWORK` env read in `core/service_solana.go` with config passed from host (`core.Config` -> `Options`).
- [x] Replace `getEnvironment()` env reads (`ENV`/`APP_ENV`/`ENVIRONMENT`) in core with host-provided mode/flags; remove direct env dependency from library behavior.
- [x] Keep key auto-discovery only when `cfg.Keys == nil`, but make this path explicitly documented as the sole env/filesystem exception.
- [x] Ensure callers can fully disable env/filesystem key auto-discovery by always passing `cfg.Keys`.
- [x] Add tests proving non-key library behavior is deterministic from `core.Config` alone (no env mutation needed).
- [x] Add docs section: "Configuration ownership" with one table listing allowed library-side exception (`cfg.Keys == nil`) and all host-required inputs, plus a deprecation table (`VerificationRequired` -> `RequireVerifiedRegistrations`, legacy env aliases -> canonical env names).

---

# #25: DB-seeded reserved slugs (replace runtime hardcoded blocked-name checks)

**Completed:** yes

Move reserved-name enforcement in AuthKit to a single data-driven path: reserve critical slugs in the database during migrations, then rely on normal uniqueness/existence + reserved metadata checks at runtime.

Goal:
- One enforcement layer for slug claimability.
- No scattered runtime hardcoded blocked-name checks in public registration/rename flows.

Scope:
- Applies to both user and tenant slugs.
- Keep `reserve_account` / `claim_reserved_account` internal helpers.

Key decision:
- Seed reserved slugs via SQL migration (idempotent), not via ad-hoc startup code.

Initial reserved slugs list (single canonical constant/source in repo):
- `admin`, `superuser`, `root`, `sudo` (extendable in one place).

**Tasks:**
- [x] Add one canonical reserved-slug list in AuthKit source (single location) for migration generation + verification docs.
- [x] Add SQL migration to seed reserved slugs as reserved user + reserved tenant records (metadata `reserved=true`) for each slug.
- [x] Migration must be idempotent (`ON CONFLICT`/upsert semantics) and safe on re-run.
- [x] Ensure seeded reserved accounts have no auth credentials/providers by default (no accidental login path).
- [x] Remove runtime/public hardcoded blocked-name checks for reserved slugs from register/create/rename/tenant-create/tenant-rename paths.
- [x] Keep runtime enforcement data-driven: slug already exists/reserved in DB => request rejected by normal uniqueness/resolution path.
- [x] Add migration/boot invariant verification: required reserved slugs must exist (fail fast or explicit admin error if missing).
- [x] Add tests:
    - public registration/create/rename cannot take seeded reserved slugs
    - behavior still blocks those slugs after app restart (DB-backed)
    - no runtime hardcoded denylist path remains in request handlers
- [x] Update docs (`README` + `agents/api-endpoints.md`) to describe reserved-slug policy and migration-seeded source of truth.
- [x] Add rollout notes: if a reserved slug was previously user-created in an environment, define deterministic migration behavior (skip with warning vs manual remediation).

---

# #26: AuthKit provider-agnostic core + optional Twilio Email/Twilio Messaging adapters

**Completed:** yes
**Issue number:** 240

Implement provider-agnostic verification delivery interfaces, enum-based registration verification policy, one-click token link flows, password-reset session handoff, and optional Twilio Messaging/Twilio Email adapters. Hard-cut old config/api paths.

**Tasks:**
- [x] Replace registration verification boolean config with enum policy none|optional|required and enforce semantics in registration flows.
- [x] Enforce startup validation: required policy must have at least one sender; none/optional allow startup and log warning when no sender exists.
- [x] Replace old verification sender contracts with unified provider-neutral verification message carrying optional code and/or link token with validation.
- [x] Implement one-click verification token confirm flows for email + phone while preserving manual numeric code confirmation flows.
- [x] Enforce TTL policy: manual verification code 15m, verification link token 1h, password reset token 1h.
- [x] Add password-reset browser handoff: validate reset token into short-lived one-time reset session, then confirm password with reset session.
- [x] Invalidate prior sessions after successful password reset/password change.
- [x] Add optional transport-only Twilio Messaging adapter (Messaging Service SID) and optional Twilio Email adapter.
- [x] Remove provider-specific references from core behavior and keep providers isolated to adapter packages.
- [x] Add/refresh tests for verification message validation, policy validation, code+link token persistence, and reset-session one-time consumption.
- [x] Update docs to reflect provider-agnostic senders, code+link verification model, and optional Twilio adapters.

---

# #27: Legacy/dead surface cleanup (hard-cuts + compatibility removals)

**Completed:** yes

AuthKit still has several legacy/dead surfaces that should be removed to simplify the API and reduce maintenance risk. This issue tracks immediate hard-cuts plus staged compatibility removals that require short downstream migration windows.

**Tasks:**
- Immediate hard-cuts (low-risk removals):
- [x] Remove `/auth/admin/users/toggle-active` route + handler and keep only explicit `/ban` + `/unban` semantics.
- [x] Remove legacy reserved-placeholder claim path in core (`ClaimReservedAccount`, `ErrReservedAccountProtected`) now that tenant ownership transitions are handled via owner-namespace states (`restricted_name`/`parked_org`/`registered_org`).
- [x] Remove unused legacy wrapper `ConfirmPhonePasswordReset` and associated contract surface (HTTP already uses reset-session confirmation).
- [x] Remove unused `IsOrgReservedBySlug` helper if no first-party callers remain.
- [x] Remove or shrink unused `core.Provider` interface surface if it has no first-party callers (or replace with minimal interfaces at call sites).
- Compatibility removals (after migration window):
- [x] Remove deprecated owner-namespace alias constant + parser fallback for `reserved_name`; keep only `restricted_name`.
- [x] Remove deprecated verify-only `IssuerAccept.Audience` fallback; require `IssuerAccept.Audiences`.
- [x] Remove devserver `AUTHKIT_*` environment-variable alias support and keep canonical `DEVSERVER_*` keys only.
- Validation + rollout:
- [x] Add/refresh hard-cut route tests for removed legacy endpoints (expected 404).
- [x] Update downstream repos/docs before each compatibility removal (notably any consumers still using `IssuerAccept.Audience`).
- [x] Verify with `go test ./...` in authkit plus targeted downstream auth proxy/verifier tests before marking complete.

---

# #28: Verifier API cleanup: kill core.Verifier, functional options, Verify returns Claims

**Completed:** yes

Simplify the Verifier public API. Kill the core.Verifier interface entirely — middleware takes *authhttp.Verifier directly. Remove core.AcceptConfig/IssuerAccept (callers shouldn't import core for verify-only mode). Change NewVerifier to functional options. Make Verify return typed Claims instead of jwt.MapClaims. Make middleware call Verify instead of re-implementing 90 lines of duplicated validation logic.

For issuing-mode (authhttp.Service), the Service constructs an internal *Verifier from its core.Service's key material + config, so all verification goes through one path.

Breaking change — no deprecation shims.

Downstream impact: tensorhub changes 1 line (NewVerifier(core.AcceptConfig{}) -> NewVerifier()). doujins and hentai0 change middleware wiring from authhttp.Required(svc.Core()) to authhttp.Required(svc.Verifier()) — typically 1-3 lines each.

**Tasks:**
- === STEP 1: NewVerifier functional options + flatten Verifier internals ===
- [x] Change NewVerifier(accept core.AcceptConfig) to NewVerifier(opts ...VerifierOption) *Verifier
- [x] Add VerifierOption type and constructors: WithSkew(time.Duration), WithAlgorithms([]string), WithHTTPClient(*http.Client), WithTenantMode(string)
- [x] Replace Verifier.accept (core.AcceptConfig) with flat fields: skew time.Duration, algorithms []string, orgMode string
- [x] Default skew to 60s, default algorithms to ["RS256"] (same as today)
- 
- === STEP 2: Fold core.IssuerAccept into private issuerEntry, merge useful fields into IssuerOptions ===
- [x] Add CacheTTL, MaxStale, PinnedRSAPEM fields to authhttp.IssuerOptions (moved from core.IssuerAccept)
- [x] Add RawKeys map[string]*rsa.PublicKey field to IssuerOptions — allows injecting key material directly without PEM round-tripping (used by authhttp.Service to inject core.Service's keys)
- [x] Create private issuerEntry struct: issuer, audiences, jwksURL, cacheTTL, maxStale, pinnedRSAPEM (all fields that were on core.IssuerAccept)
- [x] Replace Verifier.accept.Issuers ([]core.IssuerAccept) with Verifier.issuers []issuerEntry
- [x] Update AddIssuer to build issuerEntry from IssuerOptions + handle RawKeys (seed pubByKID directly from the map, no PEM parsing)
- [x] Update RemoveIssuer, matchIssuer, publicKeyFor, refreshIssuerKeys to use issuerEntry
- [x] Remove AcceptConfig() method from Verifier
- 
- === STEP 3: Verify returns Claims instead of jwt.MapClaims ===
- [x] Change Verify(tokenStr string) (jwt.MapClaims, error) to Verify(tokenStr string) (Claims, error)
- [x] Move the MapClaims-to-Claims extraction into Verify: sub, email, email_verified, username, discord_username, sid, tenant, roles/tenant_roles (tenant_mode-aware using v.orgMode), entitlements, iss, user_tier/plan, jti
- [x] Claims struct stays in authhttp package (no core dependency needed since core.Verifier is gone)
- 
- === STEP 4: Middleware takes *Verifier, calls Verify ===
- [x] Change Required(svc core.Verifier) to Required(v *Verifier)
- [x] Change Optional(svc core.Verifier) to Optional(v *Verifier)
- [x] Rewrite Required: bearerToken() -> v.Verify(token) -> enrichment (roles, email, discord from v.enrich if set; user gate via v.enrich.IsUserAllowed if set) -> setClaims(ctx) -> next
- [x] Remove the two-branch verification logic (~90 lines of duplicated issuer/audience/expiry checking)
- [x] Ensure error codes remain stable: missing_token, invalid_token, bad_issuer, bad_audience, missing_exp, token_expired, token_not_yet_valid, user_disabled
- 
- === STEP 5: authhttp.Service creates a Verifier internally (issuing-mode integration) ===
- [x] Add core.Service.PublicKeysByKID() map[string]*rsa.PublicKey method (exposes keys.PublicKeys for Verifier injection)
- [x] In authhttp.NewService: create a *Verifier using NewVerifier(WithSkew(5*time.Second), WithTenantMode(opts.TenantMode), WithAlgorithms("RS256"))
- [x] Call verifier.AddIssuer(opts.Issuer, opts.ExpectedAudiences, IssuerOptions{RawKeys: coreSvc.PublicKeysByKID()})
- [x] Call verifier.WithService(coreSvc) for enrichment hooks
- [x] Store verifier on authhttp.Service struct; expose via Verifier() method for downstream middleware wiring
- [x] Update handlers.go: required := Required(s.verifier) instead of Required(s.svc)
- [x] Update s.JWKSHandler() to use s.svc.JWKS() directly (no core.Verifier needed)
- [x] Change standalone JWKSHandler(svc core.Verifier) to JWKSHandler(jwks jwtkit.JWKS)
- 
- === STEP 6: Remove dead Verifier methods that only existed to satisfy core.Verifier ===
- [x] Remove Verifier.JWKS() (returned empty JWKS{} — only existed to satisfy interface)
- [x] Remove Verifier.Options() (returned empty Options{} — only existed to satisfy interface)
- [x] Remove Verifier.Keyfunc() public method (keyForToken stays internal)
- [x] Remove Verifier.ListRoleSlugsByUser (enrichment now handled inside middleware via v.enrich directly)
- [x] Remove Verifier.GetProviderUsername (same reason)
- [x] Remove Verifier.GetEmailByUserID (same reason)
- 
- === STEP 7: Delete core.Verifier interface + core.AcceptConfig + core.IssuerAccept ===
- [x] Delete core.Verifier interface from core/provider.go
- [x] Delete core/accept.go (AcceptConfig + IssuerAccept)
- [x] Remove any remaining references/imports of core.Verifier across the codebase
- 
- === STEP 8: RequireAdmin — confirm no changes needed ===
- [x] RequireAdmin(pg *pgxpool.Pool) does not use core.Verifier — confirmed no changes needed
- [x] JWKSHandler in handlers_test.go: updated to pass JWKS directly via core.Service.JWKS()
- 
- === STEP 9: Update all callers + tests ===
- [x] testing/issuer_test.go: NewVerifier(core.AcceptConfig{...}) -> NewVerifier(WithSkew(...), WithAlgorithms(...)) + AddIssuer(...). Verify return: claims.UserID instead of claims["sub"]
- [x] testing/devserver_e2e_test.go: same — functional options + AddIssuer + typed Claims fields
- [x] http/middleware_test.go: testVerifier mock removed — tests use real *Verifier with AddIssuer + RawKeys
- [x] http/org_scoped_claims_test.go: updated to use real *Verifier with WithTenantMode
- [x] http/handlers_test.go: added newTestService() helper, TestJWKSHandler passes JWKS directly
- [x] http/error_shapes_test.go, admin_reserved_accounts_test.go, tenant_mode_routes_test.go: updated to use newTestService()/newTestServiceWithTenantMode()
- [x] README.md: updated examples to use NewVerifier() + AddIssuer pattern, removed core.AcceptConfig/IssuerAccept references
- 
- === STEP 10: Verify + test ===
- [x] go test ./... passes
- [x] go vet ./... passes
- [x] Manually verify downstream build: VERIFIED 2026-05-22 - core.Verifier/AcceptConfig removed; tensorhub uses authhttp.Required(s.verifier) (built via provider.Verifier().WithService), doujins and hentai0 use authhttp.Required/Optional(svc.Verifier()); all three build on tagged authkit v0.10.1.

---

# #29: Prefix-neutral API routes + admin target-user session revocation

**Completed:** yes
**Issue number:** 241

Make AuthKit's embedded HTTP API prefix-neutral so host applications control the entire public mount path. AuthKit should register routes such as `/token`, `/user/me`, `/admin/users`, and tenant/provider routes without a baked-in `/auth` segment. Host apps like doujins and hentai0 can then mount AuthKit at `/api/v1` and expose standardized public routes with no extra `/auth` prefix. Also add the missing admin target-user session revocation HTTP route so apps do not need their own `/admin/users/:user_id/sessions/revoke` implementation.

**Tasks:**
- === ROUTE CONTRACT ===
- [x] Define the new prefix-neutral API route contract: AuthKit `APIHandler()` owns relative routes under `/token`, `/sessions/current`, `/user/*`, `/admin/*`, tenant routes, provider-link routes, Solana routes, and related auth/session endpoints.
- [x] Keep browser OIDC route ownership separate from JSON API routing and document the expected host mount behavior for browser flows.
- [x] Update `agents/api-endpoints.md` and README examples to describe prefix-neutral AuthKit internals plus host-selected public mounts.
- [x] Document downstream target mounts: doujins and hentai0 mount AuthKit JSON API at `/api/v1`, producing public routes such as `/api/v1/admin/users`, `/api/v1/user/me`, `/api/v1/token`, and no `/api/v1/auth/*` identity routes.
- 
- === IMPLEMENTATION ===
- [x] Remove the baked-in `/auth` prefix from `http/APIHandler()` route registrations while preserving handlers, payloads, response shapes, auth requirements, and rate-limit buckets.
- [x] Update route tests to call prefix-neutral paths directly against `APIHandler()`.
- [x] Decide and implement compatibility policy for old `/auth/*` internal paths: hard cut vs temporary aliases. If aliases are kept, add explicit sunset tests/docs.
- [x] Add canonical admin target-user session revocation route: `POST /admin/users/{user_id}/sessions/revoke`.
- [x] Wire the new admin revocation HTTP route to existing core `AdminRevokeUserSessions` with `SessionRevokeReasonAdminRevokeAll`.
- [x] Keep existing regular user self-revocation routes unchanged in prefix-neutral form: `GET /user/sessions`, `DELETE /user/sessions/{id}`, `DELETE /user/sessions`, and `DELETE /logout`.
- 
- === DOWNSTREAM COORDINATION ===
- [x] Publish migration notes for hosts currently mounting AuthKit by stripping `/api/v1` and relying on internal `/auth/*` routes.
- [x] Coordinate with doujins/hentai0 app issues so they remove app-level identity/admin-user route duplication after upgrading AuthKit.
- [x] Cut or consume an AuthKit release containing this prefix-neutral route contract, then bump downstream `github.com/open-rails/authkit` requirements or verify with an explicit workspace/replace. Verified downstream with temporary Go workspaces pointing at `~/authkit`.
- [x] Ensure downstream apps move or explicitly justify app-owned product routes that conflict with AuthKit's prefix-neutral `/user/*` and `/admin/*` identity namespaces.
- 
- === VALIDATION ===
- [x] Add route-contract tests for admin list/get/delete/restore/ban/unban/roles/signins/session-revoke under prefix-neutral paths.
- [x] Add route-contract tests for regular user identity, session self-revocation, provider, 2FA, and token endpoints under prefix-neutral paths.
- [x] Run `go test ./...` in AuthKit.
- [x] After downstream migration patches exist, verify doujins and hentai0 route smoke tests pass against the new AuthKit route contract.

---

# #30: Configurable frontend OIDC callback path + browser-route mount guidance

**Completed:** yes
**Issue number:** 242

Plan and implement the AuthKit-side cleanup for browser OIDC redirects. AuthKit currently redirects successful full-page OIDC callbacks to a hardcoded `{BaseURL}/login/callback#...` frontend route. That route is host-app-owned, so AuthKit should let the embedding host configure the frontend callback path while keeping a sensible default. Also clarify in AuthKit docs/tests that `OIDCHandler()` is prefix-neutral and should usually be mounted as browser routes such as `/oidc/{provider}/login|callback`, separate from JSON API routes such as `/api/v1/token`.

**Tasks:**
- === DESIGN ===
- [x] Add a host-owned config field for the final frontend callback path, e.g. `FrontendCallbackPath`, defaulting to `/login/callback` for backwards compatibility.
- [x] Validate/normalize the configured path: require a leading `/`, reject full external URLs, preserve optional query string if deliberately supported, and document whether fragments are allowed.
- [x] Keep provider callback routes prefix-neutral in `OIDCHandler()` (`/oidc/{provider}/login`, `/oidc/{provider}/callback`) and do not bake in `/api/v1` or `/auth`.
- [x] Define compatibility behavior for existing hosts that do not set the new field: final redirect remains `{BaseURL}/login/callback#access_token=...`.
- 
- === IMPLEMENTATION ===
- [x] Update `core.Config` / service options to carry the configured frontend callback path.
- [x] Update `http/oidc_browser.go` to build the final full-page redirect from `{BaseURL}{FrontendCallbackPath}` instead of hardcoded `/login/callback`.
- [x] Ensure popup OIDC (`ui=popup`) behavior is unchanged and does not use the frontend callback path.
- [x] Add tests for default callback path, custom callback path, invalid callback path validation, fragment token handoff, and unchanged popup behavior.
- 
- === DOCS ===
- [x] Update README and `agents/api-endpoints.md` to explain the two browser callback concepts: provider callback handled by AuthKit, and host frontend callback path served by the app.
- [x] Update README examples to recommend mounting JSON API at `/api/v1` and browser OIDC at root `/oidc/*`, while noting the host may choose another mount.
- [x] Document downstream work required in doujins/hentai0: mount `OIDCHandler()` outside `/api/v1` and configure/serve the frontend callback path.
- 
- === VALIDATION ===
- [x] Run `go test ./http`.
- [x] Run `go test ./...`.
- [x] Verify downstream route-contract tests after doujins/hentai0 migration patches exist.

---

# #31: Rename history edge-case coverage

**Completed:** yes

Cover user/tenant rename edge cases now that AuthKit stores rename history as A -> B rows keyed by stable owner IDs rather than birth slugs or alias tables. Ensure recent historical names cannot be reclaimed, soft-deleted owners still hold names, hard deletion releases names through cascade, and historical lookups resolve to the current canonical owner.

**Tasks:**
- [x] Add contract tests for user/tenant rename lookup through stable owner IDs and current canonical slugs/usernames.
- [x] Add contract tests for efficient rename-history lookup indexes and the 90-day reuse hold policy.
- [x] Add E2E coverage for A -> B -> C username rename chains resolving A to current username C.
- [x] Add E2E coverage that recent historical usernames are blocked from reuse by other users.
- [x] Add E2E coverage that soft-deleted users still hold current usernames, while hard-deleted users release names through cascade.
- [x] Fix username create/rename paths to enforce shared owner-namespace availability outside multi-tenant mode too.
- [x] Verify with `go test ./core`, `go test ./...`, and targeted all-in-one devserver E2E.

---

# #32: Rich owner namespace lookup status

**Completed:** yes

Make `GET /owners/{slug}` useful for both canonical owner routing and availability/preflight UI by returning one authoritative owner-namespace view. The response should distinguish live registered owners, parked namespaces, restricted names, historical rename redirects, soft-deleted owners that still hold a slug, recent rename holds, and truly unregistered/claimable names.

**Tasks:**
- [x] Design response contract with `requested_slug`, canonical `slug`/`canonical_slug`, `status`, `claimable`, `renamed`, optional `hold_until`, and existing `exists`/`entity_kind`/`user`/`tenant` payloads.
- [x] Add core lookup that uses the same sources as routing and availability: users, tenants, reserved names, user rename history, tenant rename history, soft-delete state, and rename reuse hold.
- [x] Return distinct statuses: `registered_user`, `registered_org`, `parked_user`, `parked_org`, `restricted_name`, `renamed_user`, `renamed_org`, `held_by_deleted_user`, `held_by_deleted_org`, `held_by_recent_user_rename`, `held_by_recent_org_rename`, and `unregistered`.
- [x] Wire `GET /owners/{slug}` to the richer core lookup while preserving existing top-level `slug`, `exists`, `entity_kind`, `user`, and `tenant` fields.
- [x] Extend rename E2E coverage to assert renamed, soft-deleted, recent-hold, expired-hold, and claimability response states.
- [x] Verify with `go test ./core ./http`, `go test ./...`, and targeted all-in-one devserver E2E.

---

# #33: Move HTTP transport and provider implementations out of adapters

**Completed:** yes

Make the package layout idiomatic for host applications: AuthKit's embeddable HTTP surface should live at the top-level `http` package, while concrete third-party sender implementations should live under `providers/<channel>/<provider>`. The old `adapters/` tree should disappear instead of carrying compatibility aliases.

**Tasks:**
- [x] Move `adapters/http` to top-level `http` with `git mv` and preserve the package name/import alias `authhttp`.
- [x] Move Twilio email sender implementation to `providers/email/twilio` with `git mv`.
- [x] Move Twilio SMS sender implementation to `providers/sms/twilio` with `git mv`.
- [x] Remove the empty `adapters/` directory tree.
- [x] Update AuthKit imports, source-path contract tests, README examples, and package docs to use `github.com/open-rails/authkit/http` and `providers/*/twilio`.
- [x] Update doujins and hentai0 imports so host applications embed AuthKit through `github.com/open-rails/authkit/http`.
- [x] Update other local AuthKit consumers found by search (`cozy-art`, `tensorhub`, `gen-orchestrator`, and `openrails`) to use `github.com/open-rails/authkit/http`.

---

# #34: Structured registration next_action response

**Completed:** yes

Replace human registration success messages with a machine-readable `next_action` enum so host frontends can decide whether to continue immediately or show first-contact verification UI. Keep the response focused on state: `ok`, submitted identifiers, and `next_action` (`none`, `verify_email`, `verify_phone`). Human-facing copy belongs in host applications, not AuthKit API responses.

**Tasks:**
- [x] Design registration success contract: include `username`, nullable `email`/`phone_number`/`discord_username`, and `next_action`.
- [x] Add a small typed response builder in `http/register.go` so email and phone registration paths share the same shape.
- [x] Remove `message` from `/register` success responses.
- [x] Return `next_action=verify_email` when email registration requires verification, `verify_phone` when phone registration requires verification, and `none` otherwise.
- [x] Return access/refresh tokens directly when `next_action=none`, and from successful email/phone verification code or link confirmation.
- [x] Update AuthKit HTTP tests/docs for the structured response.
- [x] Update cozy-art frontend to consume `next_action` instead of inferring verification from messages or failed login.

---

# #35: Production-grade Twilio/SendGrid provider adapters + remove doujins-email dependency

**Completed:** yes

Replace AuthKit's basic Twilio provider adapters with production-grade generic adapters based on the proven `~/doujins` app-level senders, while keeping AuthKit core provider-agnostic and keeping app-specific templates/copy in host apps. The shared adapters must not depend on `github.com/doujins-tenant/doujins-email`; that package is considered obsolete and should be removed from downstream live code as part of this work.

Target model:
- AuthKit core continues to expose only `core.EmailSender` and `core.SMSSender` interfaces.
- Provider implementations live under `providers/email/twilio` and `providers/sms/twilio` as optional convenience imports.
- SMS uses Twilio Messaging API only (`/2010-04-01/Accounts/{sid}/Messages.json`) with `MessagingServiceSid`; do not use Twilio Verify.
- Email uses Twilio Email API / SendGrid Mail Send (`/v3/mail/send`) directly; do not depend on `doujins-email`.
- Host apps can still provide custom senders when they need branded templates, localization, analytics categories, or specialized logging.

Reference behavior:
- Mirror the important transport behavior from `~/doujins/internal/server/auth_sms_sender.go` and `~/doujins/internal/server/auth_email_sender.go`.
- Keep AuthKit adapters generic: configurable app label, from identity, optional link builders, optional message/body builders, injectable HTTP client, and deterministic validation/errors.

**Tasks:**
- === AUTHKIT ADAPTER DESIGN ===
- [x] Audit current `providers/email/twilio` and `providers/sms/twilio` APIs against `~/doujins` senders and write the final generic config structs.
- [x] Define constructor/config validation semantics: trim all inputs, fail fast on partial configs, require `MessagingServiceSID` for SMS, require API key + from email for email.
- [x] Keep adapter package names stable (`providers/email/twilio`, `providers/sms/twilio`) but update docs to describe them as production convenience adapters, not core requirements.
- 
- === SMS: TWILIO MESSAGING ONLY ===
- [x] Replace/verify SMS adapter transport uses Twilio Messaging API only: `POST /2010-04-01/Accounts/{account_sid}/Messages.json` with HTTP Basic Auth.
- [x] Require `MessagingServiceSid` in the request body; do not support Twilio Verify service SID and do not support `From` number fallback unless a separate explicit adapter is added later.
- [x] Build verification SMS the same way as `doujins`: include generated code when present and include generated verification link when a link token/link builder is present.
- [x] Build login-code and password-reset SMS bodies generically with configurable app label and reset/verification link builder hooks.
- [x] Add tests asserting the adapter posts to `/Messages.json`, includes `MessagingServiceSid`, includes code/link bodies, uses Basic Auth, and never calls `verify.twilio.com`.
- 
- === EMAIL: SENDGRID / TWILIO EMAIL API DIRECTLY ===
- [x] Replace/verify email adapter uses SendGrid Mail Send directly, with no dependency on `doujins-email`.
- [x] Support text + HTML bodies for verification, login code, welcome, and password reset; default bodies should be generic but host apps can override body builders.
- [x] Support verification/reset link builder hooks so hosts can produce user-facing URLs instead of exposing raw tokens.
- [x] Preserve optional SendGrid metadata that is generally useful (categories/custom args) without hardcoding any `doujins`, `hentai0`, or `cozy-art` copy.
- [x] Add tests for validation, payload shape, text/html content, link builder behavior, categories/custom args, HTTP status handling, and request auth header.
- 
- === DOCS AND COMPATIBILITY ===
- [x] Update AuthKit README/provider docs with minimal examples for Twilio Messaging SMS and Twilio Email API/SendGrid email.
- [x] Remove or rewrite any AuthKit docs/plans that describe Twilio Verify as the default SMS verification path.
- [x] Clearly document that AuthKit never reads provider env vars directly; host apps load config and pass constructed senders via `WithEmailSender` / `WithSMSSender`.
- [x] Run `go test ./...` in AuthKit.
- 
- === DOWNSTREAM CLEANUP ===
- [x] `~/doujins`: confirm no live `doujins-email` import/module dependency exists; keep using local sender or migrate to the improved AuthKit adapters only if the generic hooks cover current behavior.
- [x] `~/hentai0`: remove `github.com/doujins-tenant/doujins-email` from `go.mod`/`go.sum` and replace `internal/infra/email_sender.go` with direct SendGrid/Twilio Email API code or the improved AuthKit email adapter.
- [x] `~/hentai0`: replace Twilio Verify SMS usage with Twilio Messaging API behavior matching `doujins` and the AuthKit SMS adapter; remove `verify_service_sid` config/env/docs.
- [x] `~/cozy/cozy-art`: consider replacing the local SendGrid sender with the improved AuthKit email adapter if it covers required verification/reset behavior; otherwise keep a local sender with no `doujins-email` dependency.
- [x] Search all active local repos with `rg -n "doujins-email|github.com/doujins-tenant/doujins-email" /home/fidika` and remove every live code, config, module, and doc reference.
- [x] Decide whether archived tracker files (`agents/completed.json`, old TODO archives) should be rewritten to remove historical `doujins-email` mentions; no historical archive rewrite was needed because the only remaining active mention is this tracking issue.

---

# #36: Config-first pluggable OAuth2/OIDC providers

**Completed:** yes

Move external identity provider support toward a provider descriptor model where OAuth2 and OIDC providers are registered from configuration first, with code hooks only for genuinely non-declarative behavior.

Goal:
- Adding a normal OIDC provider should be pure configuration: name, kind=oidc, issuer, scopes, optional extra auth params, and standard claim mapping.
- Adding a simple OAuth2 provider should be pure configuration: name, kind=oauth2, issuer, authorize/token/userinfo URLs, scopes, PKCE flag, and JSON path mappings from provider userinfo to AuthKit's normalized identity shape.
- Provider-specific code should be reserved for special cases such as Apple's dynamic client secret JWT or OAuth2 providers that require secondary API calls or nontrivial transforms.

Target descriptor concepts:
- Common fields: name, kind, issuer, client_id, client_secret, scopes, pkce, extra_auth_params.
- OIDC fields: discovery/issuer config and optional claim mapping, defaulting to standard OIDC claims (`sub`, `email`, `email_verified`, `preferred_username`, `name`).
- OAuth2 fields: authorize_url, token_url, userinfo_url, user_mapping with JSON paths for subject/email/email_verified/preferred_username/display_name.
- Optional fallback lookups: e.g. GitHub primary verified email from `/user/emails` using declarative array selection.
- Secret strategies: literal/env secrets for normal providers; `client_secret.strategy=apple_jwt` with team_id/key_id/private_key/ttl for Apple.

Architectural constraint:
- The browser login/link/reauth/session flow must remain shared. Provider descriptors only define how to start provider auth and normalize provider identity into `{issuer, subject, email, email_verified, preferred_username, display_name}`.

**Tasks:**
- [x] Define a neutral provider descriptor type covering both `kind=oidc` and `kind=oauth2` providers.
- [x] Define declarative identity mapping: JSON/claim dot paths, static booleans, optional transforms such as string conversion/trim/lowercase.
- [x] Define declarative fallback lookup support for simple secondary API calls, including array selection by equality filters (needed for GitHub verified primary email).
- [x] Define `client_secret` sources: literal value, env var, and named strategy.
- [x] Implement `client_secret.strategy=apple_jwt` using the existing Apple ES256 JWT secret provider.
- [x] Convert built-in OIDC providers (Google, Apple) into descriptors; keep Apple-specific behavior isolated in the secret strategy.
- [x] Convert built-in OAuth2 providers (Discord, GitHub) into descriptors; keep GitHub's email fallback declarative if the mapping model supports it cleanly.
- [x] Teach the OIDC manager to build provider config from descriptors instead of provider-specific switch/table code.
- [x] Teach the OAuth2 browser flow to build authorize/token/userinfo behavior from descriptors and the shared mapper.
- [x] Keep an internal hook escape hatch for providers that cannot be represented declaratively, but make pure config the default path.
- [x] Add tests showing a new simple OIDC provider can be added using only descriptor data.
- [x] Add tests showing a new simple OAuth2 provider can be added using only descriptor data.
- [x] Add regression tests for Google, Apple, Discord, and GitHub descriptors.
- [x] Document descriptor examples for Google, Apple, Discord, GitHub, and a custom provider.

---

# #37: Hard-cut AuthKit-generated row IDs to UUIDv7

**Completed:** yes

AuthKit should mint UUIDv7 IDs for runtime-created UUID rows instead of UUIDv4 or deterministic slug-derived UUIDs. Host applications may receive AuthKit UUIDs, but they should not choose them. Deterministic role IDs remain intentionally slug-derived because role slug identity is a stable auth mechanism, not a runtime row-minting path.

Scope:
- users, sessions, session families, providers, user-role join rows, tenants, personal tenants, parked tenant namespaces, and tenant invitations use UUIDv7 when AuthKit code mints IDs.
- PostgreSQL schema defaults use `uuidv7()` for AuthKit-owned UUID defaults.
- the all-in-one devserver image uses PostgreSQL 18 so the database has native UUIDv7 support.

**Tasks:**
- [x] Add a central UUIDv7 helper for AuthKit core code paths that mint UUIDs.
- [x] Convert user creation, session IDs, session family IDs, provider rows, user-role rows, tenant rows, personal-tenant rows, parked-tenant rows, and tenant invite rows to UUIDv7.
- [x] Remove public deterministic user/tenant UUID helper surface from `identity` so apps cannot rely on username/slug-derived AuthKit IDs.
- [x] Add AuthKit-owned legacy user import/update helpers that accept legacy attributes but still mint new user IDs inside AuthKit.
- [x] Add AuthKit-owned role upsert helper so app legacy migrators can stop writing `profiles.roles` directly.
- [x] Update PostgreSQL migrations for AuthKit-owned UUID defaults from `gen_random_uuid()` to `uuidv7()`.
- [x] Move the all-in-one devserver image to PostgreSQL 18.
- [x] Verify with `go test ./...` and `git diff --check`.
- [x] Tag/release AuthKit and pin downstream apps to the released version/commit that includes UUIDv7 behavior. DONE: UUIDv7 (commit d0b6a63) shipped in v0.9.0 and is present through v0.10.1; cozy.art pins authkit v0.10.1.

---

# #38: Do not swallow auth message delivery failures

**Completed:** yes

Cozy Art's embedded AuthKit registration resend flow exposed an AuthKit-owned delivery error handling bug. The SendGrid/Twilio email adapter synchronously returns provider submission errors, but core registration verification paths discard them with `_ = s.email.SendVerification(...)`, and the `/register/resend-email` handler also discards the `CreatePendingRegistration` result. That lets hosts return `202 Accepted` even when AuthKit failed to submit the verification email to SendGrid.

Target behavior:
- Provider submission failures must propagate through core service methods and HTTP handlers as generic, stable AuthKit errors such as `email_delivery_failed` / `sms_delivery_failed`; do not leak raw SendGrid/Twilio responses to public clients.
- Enumeration-safe endpoints should keep not-found/malformed-input responses generic, but once AuthKit finds a pending registration and attempts delivery, a delivery failure must be visible to the caller and logged server-side.
- Cozy Art should be able to consume the released AuthKit fix without adding local wrapper routes around AuthKit-owned registration endpoints.

**Tasks:**
- [x] Core: replace ignored `s.email.SendVerification(...)` / `s.sms.SendVerification(...)` errors in registration, resend, email-change, phone-change, password-reset, and login-code paths with returned delivery errors where the public operation depends on message delivery
- [x] HTTP: make `/register/resend-email` and `/register/resend-phone` propagate delivery failures for found pending registrations while preserving enumeration safety for missing or malformed identifiers
- [x] HTTP: map delivery failures to stable public error codes (`email_delivery_failed`, `sms_delivery_failed`) and log provider details through the internal error logger or host logger without exposing raw provider responses
- [x] Tests: add fake sender tests proving registration/resend returns a delivery error when the sender returns an error
- [x] Docs: update API docs/provider docs to state that 2xx means AuthKit submitted the message to the configured provider, not that the recipient mailbox accepted or opened it
- [x] Release: tag AuthKit and bump Cozy Art to the released version; verify `POST /api/v1/register/resend-email` surfaces provider submission failures through the AuthKit-defined route

---

# #39: Make AuthKit resend/request-code rate limits work behind Docker and reverse proxies

**Completed:** yes

Cozy Art mounts AuthKit's canonical `POST /register/resend-email` route under `/api/v1/register/resend-email`. AuthKit had a resend bucket, but local testing showed repeated resend requests all returned `202` instead of `429`. Root cause: AuthKit's default client-IP function returns an empty identity for private/loopback peers, and `Service.allow` fails open when the client IP is empty. In Docker Compose, Gin sees the immediate peer as a private bridge address such as `172.21.0.1`; in production, reverse proxies can produce the same shape unless the host configures a trusted forwarded-header strategy. Request-code and resend endpoints should not silently bypass AuthKit rate limits in those common embedding modes.

Target behavior:
- AuthKit-owned resend/request-code endpoints must be rate-limited by default in local Docker Compose, embedded host apps, and normal reverse-proxy deployments.
- Registration, registration resend, email/phone verification request, password-reset request, and user email/phone change request/resend buckets should default to roughly one request every 60 seconds and 6 requests per hour.
- When the limiter denies a request, AuthKit should report that rate limiting was hit and how long until the next action is allowed via `Retry-After` and a JSON `retry_after_seconds` field.
- Hosts can still configure trusted forwarded-header behavior for production boundaries, but missing proxy config should not disable protection for sensitive anonymous endpoints.
- The fix belongs in AuthKit's HTTP/embedding contract; Cozy Art should not add wrapper routes around AuthKit-owned registration endpoints.

**Tasks:**
- [x] Decide the default client identity strategy for anonymous sensitive endpoints when `RemoteAddr` is private/loopback: use the peer as a local fallback, require explicit trusted headers, or add an endpoint-specific fallback that never returns empty
- [x] Update `Service.allow` / client-IP handling so `RLAuthRegisterResendEmail`, `RLAuthRegisterResendPhone`, `RLEmailVerifyRequest`, `RLPhoneVerifyRequest`, password-reset request, and user email/phone resend buckets cannot silently fail open only because the immediate peer is private/loopback
- [x] Add a safe public API for host apps to configure trusted forwarded headers and proxy CIDRs without reaching into unexported HTTP internals
- [x] Ensure the default remains safe for direct public traffic and does not blindly trust spoofable `X-Forwarded-For` headers from untrusted peers
- [x] Add route-level tests proving `/register/resend-email` returns `429` after the configured bucket is exceeded for Docker/private-peer-shaped requests
- [x] Add tests for trusted forwarded headers: trusted proxy uses the forwarded client IP; untrusted peer ignores spoofed forwarded headers
- [x] Update AuthKit docs to explain default rate-limit client identity behavior for direct traffic, Docker Compose, and reverse proxies
- [x] Release AuthKit and bump Cozy Art to the released version; verify `POST /api/v1/register/resend-email` is still the AuthKit-defined route and returns `429` after the resend bucket is exceeded

---

# #40: Own the full platform-delegation system in authkit (tenant tenants: registration + token minting + validation)

**Completed:** yes

Make authkit the single owner of the entire platform-delegation lifecycle so an TENANT can bring in FEDERATED USERS — users that live in the tenant's own system and authenticate via the tenant's issuer rather than local passwords. authkit owns BOTH SIDES of federation, so two authkit-embedding services register with and trust each other (one side is the platform/IdP that mints+sends; the other is the resource-server that accepts+validates). Capabilities, all in authkit:

1. REGISTRATION HANDSHAKE (authkit <-> authkit), both sides owned:
   - OUTBOUND 'send my registration' client (platform side, e.g. cozy-art): publish this tenant's issuer id + jwks_url to a resource server.
   - INBOUND 'accept registrations' server (resource-server side, e.g. tensorhub): accept + store a tenant tenant's issuer registration. Replaces tensorhub's bespoke `/api/v1/platform/issuers` + `tensorhub.platform_issuers`.
2. MINTING (platform side, cozy-art): issue delegated platform tokens. The external user goes in `delegated_sub` (NEVER `sub`), plus `tenant`/`tenant`, `user_tier`, roles, aud, exp, signed by the tenant's platform issuer key.
3. VALIDATION (resource-server side, tensorhub): validate delegated tokens -> typed DelegatedPrincipal {tenant, delegated_sub, tier, roles}, verifying iss/aud/exp/signature against the registered tenant-tenant keys, with NO local-user lookup (no `user_disabled`).

INVARIANT: a token carries EITHER `sub` (native user) XOR `delegated_sub` (tenant user) — NEVER both. authkit must reject a token presenting both, and never mint both. Discriminator + the existing local-user gate (conditioned on `UserID != ""` from `sub`) means a `delegated_sub`-only token auto-skips the gate. authkit-only work; tensorhub (#366 there) and cozy-art (#46 there) bump to it after this lands. Unblocks cozy.art #44.

**Tasks:**
- [x] STAGE 1 — token shape + validation/minting primitives. Claims: add `DelegatedSubject`, `Tenant`, `IsDelegated()`; parse `delegated_sub`/`tenant`/`user_tier`/roles from the token.
- [x] STAGE 1. INVARIANT: reject any token presenting BOTH `sub` and `delegated_sub` (mutually exclusive); the minting helper must never emit both. Test both directions.
- [x] STAGE 1. Verify(): do NOT hard-require `sub`; for a delegated token validate iss/aud/exp/signature only.
- [x] STAGE 1. Required middleware: EXPLICITLY skip local-DB enrichment + the `IsUserAllowed` gate for delegated claims (today it incidentally no-ops when UserID==""; make it intentional + documented).
- [x] STAGE 1. MINTING API: helper to issue a delegated platform token (delegated_sub, tenant/tenant, user_tier, roles, aud, exp) signed by a platform issuer key — cozy-art embeds this.
- [x] STAGE 1. VALIDATION API: expose a typed DelegatedPrincipal from a verified delegated token — tensorhub embeds this.
- [x] STAGE 1. Tests: native vs delegated token; no-`sub` token verifies; delegated principal extraction; local-user gate skipped for delegated; minting round-trips through validation.
- [x] STAGE 1. Release authkit (new minor) with minting + validation.
- [x] STAGE 2 — tenant-tenant registry. Tenant model: tenant identity — `Federated bool`, `IssuerID`, `JWKSURL`/keys, issuer status (new Tenant fields or a `tenant_issuers` table) + migration.
- [x] STAGE 2. REGISTRATION HANDSHAKE, both sides owned by authkit: (a) INBOUND accept-side handler that stores a tenant tenant's issuer registration (the home for tensorhub's `/api/v1/platform/issuers`), authorized by tenant owner/admin; (b) OUTBOUND send-side client that publishes this tenant's issuer id + jwks_url to a resource server. Two authkit instances complete the handshake (platform <-> resource-server).
- [x] STAGE 2. In-house JWKS fetch/refresh for tenant-tenant issuers; the Verifier loads tenant issuers from authkit's OWN store (no external push/sync).
- [x] STAGE 2. Docs: the tenant-tenant concept (tenants bring tenant users), the 3 roles (register/mint/validate), and the delegated-token contract (`delegated_sub`, etc.). Release authkit.

---

# #41: Access tokens expose global_roles (single+multi) and tenant_roles (tenant-scoped) for consumer authz

**Completed:** yes

Access tokens must expose GLOBAL roles separately from TENANT-scoped roles so consumers can do global-admin and tenant authz from the token.

## Defect
`core/service.go` IssueAccessToken sets `claims["roles"]` ONLY when TenantMode=="single" (lines ~380-382). In MULTI-tenant mode the access token carries NO global-role claim at all. Consumers that read the token's roles for global-admin authz therefore see nothing in multi-tenant mode.

Observed 2026-05-21: tensorhub runs authkit in TenantMode=multi. The bootstrap `cozy` user IS a global admin (profiles.global_user_roles has cozy->admin), but its password-login token has no roles claim, so tensorhub's platform-admin route (canActAsOwner / resolveAuthkitOwnerForRequest) computed an empty GlobalRoles and returned 403 to the global admin when registering a platform tenant's policy. (tensorhub also had an independent bug — its authkit-source owner path didn't honor global admins at all — fixed separately by hydrating via ListRoleSlugsByUser.)

## Desired design (owner)
There are now `roles` (legacy) and split `global_roles` / `tenant_roles`. In general:
- emit `global_roles` for the user's GLOBAL roles in BOTH single AND multi-tenant mode;
- emit `tenant_roles` for roles scoped to a specific tenant, only when an tenant is in scope (tenant-scoped token);
- keep `roles` populated for back-compat where it is today (don't break existing consumers).

## Touch points
- core/service.go IssueAccessToken (add global_roles in both modes via listRoleSlugsByUser) and IssueServiceToken (add global_roles + tenant_roles).
- http/claims.go Claims (add GlobalRoles, TenantRoles fields + json tags global_roles/tenant_roles) and the token parse/verify path that populates Claims from the JWT.
- Keep changes additive/back-compat (existing `roles` + consumers keep working).

Surfaced while e2e-testing cozy-art delegated inference enforcement (#41/#43/#45 in cozy-art) against the live tensorhub stack.

**Tasks:**
- [x] http/claims.go: add GlobalRoles []string (json `global_roles`) and TenantRoles []string (json `tenant_roles`) to the Claims struct; keep Roles for back-compat.
- [x] core/service.go IssueAccessToken: populate `global_roles` claim from listRoleSlugsByUser in BOTH single and multi-tenant mode (today `roles` is only set in single mode). Keep `roles` as-is for back-compat.
- [x] core/service.go IssueServiceToken: populate `global_roles` (user's global roles) AND `tenant_roles` (roles scoped to that tenant).
- [x] Token parse/verify (http): populate Claims.GlobalRoles and Claims.TenantRoles from the new JWT claims; map legacy `roles` for back-compat.
- [x] Tests: single-mode + multi-mode access tokens carry global_roles; tenant-scoped token carries global_roles + tenant_roles; legacy `roles` unchanged. go build ./... + go test affected packages.
- [x] Commit + push + tag authkit with a new version (changes are additive/back-compat). Note the tag for consumers.
- [x] ALL authkit-consuming repos must be adjusted MANUALLY (bump dep + `go mod tidy` + change API/assumptions). Consumers identified 2026-05-21: cozy-art (4 files read the roles claim), tensorhub (14 files), gen-orchestrator (uses authkit but reads no role claims — likely no change). If a consumer pins authkit via a local `replace` it already builds against source; if it pins a version, bump to the new tag.
- [x] tensorhub: bump authkit, `go mod tidy`, update authz to read claims.GlobalRoles (global-admin) + claims.TenantRoles (tenant scope) instead of the legacy `roles` claim. NOTE an uncommitted local fix already exists in internal/api/owner_authz_http.go that hydrates GlobalRoles via ListRoleSlugsByUser — harmonize (claims-first, DB-hydrate fallback). go build ./...
- [x] cozy-art: bump authkit, `go mod tidy`, update the 4 files reading the roles claim to the new global_roles/tenant_roles where relevant. go build ./... + frontend unaffected. (cozy-art may be under concurrent edits — make minimal additive changes.)
- [x] gen-orchestrator: bump authkit + `go mod tidy` to stay in sync even though it reads no role claims; go build ./...
- [x] Verify all consumers build against the new authkit; report any API/assumption changes made per repo.

---

# #42: Verifier tenant-issuer cache coherence: lazy-load on miss, reconcile/evict on reload, refetch rotated keys on failure

**Completed:** yes

## Problem

The Verifier validates delegated tokens against an IN-MEMORY map of trusted issuers (`byIss` / `issuers` in `http/verifier.go`). That map is populated only at startup and by the periodic `StartTenantIssuerSyncLoop` (consumers run it on a ~5-minute tick). `matchIssuer` (`http/verifier.go:443`) walks only the in-memory slice and returns nil on a miss; `keyForToken` (`:422`) then returns `bad_issuer` -> `invalid_token`. There is NO DB read on the validation path.

Consequence: right after a tenant tenant registers its issuer (POST /tenant-issuers writes a DB row), tokens it mints are rejected for up to a full sync interval (~5 min) until the next bulk reload, even though the issuer is already in the DB. 'Push into the Verifier on write' does NOT fix this for multi-replica deployments (e.g. tensorhub runs 2+ replicas behind a load balancer): a push only updates the replica that received the registration; the siblings still wait for their own tick.

## Goal

A newly-registered tenant issuer should be trusted by EVERY replica on first token use, with no per-request DB or JWKS hit after the first.

## Fix: lazy-load on cache-miss

When `matchIssuer` misses and the Verifier has a tenant-issuer source (`v.enrich`, a `*core.Service` set via `WithService`, `verifier.go:39,237`), look up that ONE issuer in the store, `AddIssuer` it (which fetches + caches its JWKS), then retry the in-memory match. First use of a new issuer pays one DB read + one JWKS fetch; everything after hits the in-memory cache. The periodic reload stays as a coarse refresh/eviction backstop.

`core.Service.GetTenantIssuer(ctx, issuerID)` ALREADY exists (`core/service_tenant_issuers.go:85`); expose it on the `TenantIssuerSource` interface (today only `ListTenantIssuers`) so the on-miss path and tests can use it.

## Implementation notes / constraints

- Put the lazy-load in `keyForToken` (or a small wrapper), NOT inside `matchIssuer`'s critical section: `matchIssuer` holds `v.mu`, and `AddIssuer` ALSO locks `v.mu`, so calling AddIssuer under the lock would deadlock, and the DB + JWKS network calls must not happen while holding the lock. Flow: matchIssuer returns nil -> (no lock) GetTenantIssuer + AddIssuer -> retry matchIssuer.
- Only trust ACTIVE issuers (match the `activeOnly=true` semantics of the bulk load). Check `status == 'active'` (or add an active-only variant).
- Audience handling must match the bulk load: `LoadTenantIssuers` registers issuers with the audiences passed by the caller (tensorhub passes nil -> no per-issuer aud gate, since aud is validated elsewhere in Verify against `match.audiences`). The lazy-load MUST register with the SAME audiences so behavior is identical -> store/thread the tenant audiences on the Verifier.
- Guard against thundering-herd / DoS on unknown issuers: every garbage `iss` would otherwise trigger a DB lookup per request. Add a short negative cache (remember not-found issuers for a few seconds) and/or single-flight so repeated bad tokens and concurrent first-use don't hammer the DB / JWKS endpoint. Keep it simple.
- Backward compatible: if `v.enrich` is nil (no source configured), behavior is unchanged (miss -> bad_issuer).

## Cache coherence: the cache must also notice CHANGES and DELETES, not just misses

Lazy-load only fixes the MISS case (a brand-new issuer). Two other staleness cases must be handled, because the in-memory cache can otherwise serve wrong answers:

1. **Revocation (delete / deactivate).** `LoadTenantIssuers` (`verifier.go:261`) is ADD-ONLY: it iterates the active issuers and `AddIssuer`s each, but NEVER removes an issuer that has dropped out of the active set. So a deleted or deactivated issuer stays trusted in memory until the process restarts. Fix: make the periodic reload RECONCILE -- evict in-memory issuers that are no longer in the active DB set. This bounds revocation lag to the tick interval. (Optional, heavier: a Postgres LISTEN/NOTIFY stream of issuer-row changes per replica for near-instant eviction. Recommend reconciling-reload as the primary fix and treating LISTEN/NOTIFY as a follow-up only if sub-tick revocation is required; note the operator can also shorten the tick to trade DB load for tighter revocation.)

2. **Key rotation (JWKS changed).** `publicKeyFor` already refetches JWKS on a TTL (default 5m, with stale-while-revalidate), so rotation is picked up within the TTL. But a token signed with a freshly rotated `kid` that arrives while the cached JWKS is still 'fresh' (before expiry) fails with unknown-kid. Fix (the user's 'fall through on failure' idea): on an unknown-kid for a KNOWN issuer, force ONE bounded JWKS refetch (guarded by a min-interval / single-flight so a storm of bad kids can't hammer the JWKS endpoint) and retry before returning a failure. This also covers the 'our cache was stale and that is why validation failed' case.

Net model: MISS -> lazy-load from DB; CHANGED keys -> TTL refresh + on-unknown-kid refetch; DELETED/DEACTIVATED -> reconciling reload evicts (optionally NOTIFY/LISTEN for instant). All bounded, all multi-replica correct.

## Rollout

This is an additive Verifier change in authkit `http/verifier.go`, so it benefits every consumer. Release a new authkit minor and bump tensorhub + cozy-art (go get + go mod tidy). Consumers need no code change beyond the version bump (the periodic loop call can stay as the backstop).

**Tasks:**
- [x] Add GetTenantIssuer(ctx, issuerID) to the TenantIssuerSource interface (core.Service already implements it).
- [x] Implement lazy-load-on-miss in keyForToken: on matchIssuer miss + v.enrich set, GetTenantIssuer (active only) -> AddIssuer (JWKS fetch+cache) -> retry. Do the DB/JWKS work OUTSIDE v.mu to avoid deadlock with AddIssuer.
- [x] Register lazy-loaded issuers with the SAME audiences the bulk LoadTenantIssuers uses (store/thread the tenant audiences on the Verifier).
- [x] Negative cache + single-flight so unknown/garbage issuers and concurrent first-use do not hammer the DB / JWKS endpoint.
- [x] REVOCATION: make LoadTenantIssuers RECONCILE -- evict in-memory issuers no longer in the active DB set (today it is add-only, so deletes/deactivations never take effect until restart). This bounds revocation lag to the reload tick.
- [x] KEY ROTATION: on an unknown-kid for a KNOWN issuer, force one bounded JWKS refetch (min-interval / single-flight guarded) and retry before failing, so a rotated kid arriving mid-TTL is picked up immediately (the 'fall through on failure' path).
- [x] (Optional / note in code) Evaluate a Postgres LISTEN/NOTIFY stream of tenant-issuer row changes for near-instant eviction; do NOT build it unless sub-tick revocation is required -- reconciling reload + on-failure refetch give bounded correctness without it.
- [x] Backward compatible: v.enrich nil -> unchanged (miss -> bad_issuer).
- [x] Unit tests: lazy-load success + cached-on-second-use (source + JWKS fetch called once); unknown issuer fails and is negatively cached; reconciling reload evicts a now-inactive issuer (token stops validating); rotated-kid refetch succeeds and is single-flight-guarded; deadlock-free under concurrent first-use.
- [x] go build ./... + go test ./... pass.
- [x] Release a new authkit minor tag (commit + push + tag), then bump tensorhub + cozy-art (go get @<tag> + go mod tidy) and verify both build.

---

# #44: Permission-scoped service tokens + role→permission model (v2 of #43)

**Completed:** yes

Evolve Service Tokens (shipped role-scoped in #43) to carry a set of PERMISSIONS (app-defined atomic operations, e.g. `endpoint:revise`) instead of tenant RBAC role slugs. This is permission-based access control (PBAC) layered over the existing RBAC, matching GitHub fine-grained PATs / Stripe restricted keys.

PRINCIPLE: authkit stays permission-AGNOSTIC. It still hardcodes only the `owner` role; the permission catalog, roles, and role→permission map all live in the consuming app (tensorhub, see its issue). authkit just (a) carries opaque permission strings on an service token, (b) exposes them in claims, and (c) delegates mint authorization to a host hook.

CLAIMS SHAPE (what middleware produces):
  - service token principal:  { Tenant, Permissions:[...], TokenType:'service' }  (no UserID, no roles)
  - User principal: { Tenant, UserID, TenantRoles:[...] }  (Permissions stays EMPTY — the resource server expands roles→permissions at request time; do NOT bake a permission union into the JWT: it goes stale when role definitions change and blservice tokens the token)

MINT AUTHORIZATION via a host hook (authkit can't interpret app permissions): authkit calls a host-provided service tokenGrantAuthorizer at POST /tenants/{tenant}/access-tokens to answer BOTH 'may this caller mint?' and 'may they grant these permissions?'. tensorhub implements it by checking the caller's effective permissions (from their roles) ⊇ the requested set, and that the caller holds an `service token:mint` permission. When no authorizer is configured, fall back to the #43 behavior (owner-only mint). The role-subset no-escalation check moves OUT of authkit (it no longer knows what permissions mean) and INTO the hook; keep the structural guard that a service principal (an service token) can never reach the mint handler.

Depends on nothing; consumed by tensorhub #369 and e2e #94.

**Tasks:**
- [x] Add `Claims.Permissions []string`; middleware sets it for service token principals (repoint from the #43 TenantRoles reuse). User principals keep roles in TenantRoles, Permissions empty.
- [x] Rename service token `scopes`→`permissions` across MintAPIKey/List/Resolve, the request/response JSON, and the `service_tokens` column (migration: rename column `scopes`→`permissions`). Values are opaque app permission strings.
- [x] Define `service tokenGrantAuthorizer` interface { CanGrantservice token(ctx, caller, tenant string, permissions []string) (allowed bool, offending []string, err error) } + `Withservice tokenGrantAuthorizer` Service option.
- [x] POST /tenants/{tenant}/access-tokens: call the authorizer for mint authority + permission grant; owner-only fallback when none configured. Return 403 with offending permissions named on denial.
- [x] Remove the tenant-role-subset no-escalation check from the handler (now the hook's job); keep service-principal-cannot-mint guard.
- [x] Tests: hook allow/deny (offending named), owner-only fallback, Claims.Permissions populated for service tokens, service token round-trip; update #43 tests for permissions naming.
- [x] Docs: api-endpoints.md + README service token section (permission-scoped; hook contract; permissions vs roles).
- [x] Version bump notes; flag consumer follow-ups (tensorhub #369, e2e #94).

---

# #46: Tenant RBAC engine in authkit: base permissions + app catalog/default-roles + generic role->permission management (+ removes service token hook)

**Completed:** yes
**Status:** DONE. authkit RBAC engine shipped as v0.11.3 (committed+tagged+pushed): base perms (tenant:roles:manage/members:manage/tokens:manage/read) + app catalog/default-roles config + migration 002 + role->perm CRUD + EffectivePermissions + ValidateGrant + seeding owner=* + management routes + HARDCUT permission-gating of all tenant-management endpoints + role-assignment no-escalation + service token hook removed (native validation). Docs updated (api-endpoints.md + README). tensorhub consumer migrated (UNCOMMITTED, builds + full suite green on v0.11.3): deleted st_grant.go + Registerservice tokenGrantAuthorizer wiring, declared its resource-permission catalog + the `admin` default role (= * minus tenant:roles:manage/tenant:members:manage). NOTE: tensorhub's internal/authz still enforces resource ops via its OWN RoleMap + owner:manage/service token:mint names; switching that to read authkit core.EffectivePermissions + the tenant: base names is #369's enforcement scope, not #46. FOLLOW-UP (same session, pre-release): made tenant:read service token-grantable (IsServiceTokenGrantableReservedPermission allowlist; write/mint tenant:* still barred). Added introspection + REST consolidation routes: GET /tenants/{tenant}/me/permissions|roles (self-read, membership only, no tenant:read), POST /tenants/{tenant}/permissions/check (testIamPermissions-style {granted[]}; self or user_id w/ tenant:read; global-admin=all), GET /tenants/{tenant}/permissions/grantable (no-escalation subset + can_grant_all; ?for=service token applies service token bars), GET /tenants/{tenant}/roles/{role} (single-role detail). HARDCUT route moves (no legacy): DELETE /tenants/{tenant}/roles/{role} and DELETE /tenants/{tenant}/members/{user_id} now path-param (was DELETE-with-body). New core.GrantablePermissions helper. Full suite green on pg18; docs (api-endpoints.md + README) updated. NOT yet released — pending v0.11.4 tag + tensorhub/e2e consumer bump. NOTE: GET /tenants/{tenant}/access-tokens is gated tenant:service_tokens:manage (NOT tenant:read), so an tenant:read-only service token cannot enumerate tokens. CONSOLIDATION (same session, pre-release): role CRUD collapsed — PUT /tenants/{tenant}/roles/{role} {permissions[]} is idempotent create-or-replace (replaces POST /roles + GET/PUT /roles/{role}/permissions); GET/DELETE /roles/{role} kept. /me/permissions + /me/roles merged into GET /tenants/{tenant}/me -> {roles,permissions}. Dropped /permissions/grantable (+ core.GrantablePermissions) as derivable client-side. Invitee routes /tenant-invites -> top-level /me/invites (kept cross-tenant, NOT tenant-scoped — invitee isn't a member yet; deviated from the literal '/tenants/{tenant}/me/invites' ask because it'd break cross-tenant listing). Full suite green; docs (api-endpoints.md + README) updated. Final tenant-RBAC surface ready for v0.11.4.

authkit is the COMPLETE, GENERIC tenant-RBAC engine. The embedding app declares its own permission CATALOG; authkit ALSO ships a small set of BASE permissions for tenant-management itself. The full catalog an tenant sees = authkit-base permissions UNION the app-declared catalog. authkit manages everything generically over opaque strings (role->permission CRUD, per-member assignment, effective-permission computation, no-escalation, service tokens); its only catalog job is set-membership validation ('is this permission defined?').

BASE PERMISSIONS (built into authkit, reserved `tenant:` namespace, apps may NOT redefine):
- tenant:roles:manage  -> create/modify/delete roles + set a role's permission set
- tenant:members:manage -> add/remove tenant members + grant/remove their roles
- tenant:service_tokens:manage -> mint/revoke service tokens
- tenant:read (optional) -> view members/roles/tokens
These gate authkit's OWN tenant-management endpoints via the SAME permission system (replacing the current hardcoded requireOrgOwner). So all authz is uniform/permission-based.

APP CATALOG (declared at init): core.Config.PermissionCatalog []PermissionDef{Name,Description} for app-specific permissions (tensorhub: endpoint:deploy, repo:write, secrets:write, dataset:write, ...). Merged with the base set. Opaque to authkit.

ROLES: `owner` is built-in = `*` (= base UNION app; the only role holding tenant:*:manage by default -> effectively owner-exclusive management). The APP can declare DEFAULT ROLE TEMPLATES (name + permission set) seeded into every tenant at creation alongside owner. tensorhub declares `admin` = owner MINUS {tenant:roles:manage, tenant:members:manage} (admin does everything else incl. mint service tokens + all app perms, but cannot manage roles or membership). Represent 'owner minus X' via `*` + an exclusion list, or enumerate; decide.

DATA: NEW numbered migration (NOT appended to 001 — migratekit name-tracking gotcha): profiles.tenant_role_permissions (tenant_id, role, permission; FK (tenant_id,role)->tenant_roles ON DELETE CASCADE; UNIQUE). Seed owner=`*`; seed app-declared default roles per tenant.

EFFECTIVE PERMISSIONS: core.EffectivePermissions(ctx, tenant, userID) = union over the member's roles (`*` => superset). Exposed for embedding-app request-time enforcement (tensorhub #369 reads this) + admin HTTP GET. Never baked into the JWT (staleness).

VALIDATION (generic, over base UNION app catalog) on role-assignment AND service token mint: permission must be in the catalog (else unknown_permission) AND within the actor's effective permissions (else no-escalation 403 + offending). service tokens are NEVER grantable tenant:*:manage and can't reach management endpoints (handlers require a real user) — an service token does machine work, never tenant management.

service token SIMPLIFICATION (supersedes part of #44): authkit holds the catalog + computes effective perms, so it enforces service token-mint validation + no-escalation ITSELF — REMOVE the tensorhub service tokenGrantAuthorizer hook (CanGrantservice token/Withservice tokenGrantAuthorizer); tensorhub drops st_grant.go + the wiring.

ROUTES (permission-gated): GET /permissions (catalog = base UNION app); GET/PUT(+optional POST/DELETE) /tenants/{tenant}/roles/{role}/permissions (tenant:roles:manage); GET /tenants/{tenant}/members/{user_id}/permissions (effective). Existing member/role/service token management endpoints re-gated onto tenant:members:manage / tenant:roles:manage / tenant:service_tokens:manage.

BOUNDARY: app's only jobs = declare its catalog + default roles (config) and ENFORCE app permissions at its own endpoints. Everything tenant-management is authkit, generic + reusable.

NON-GOALS: permission MEANING (app-side at enforcement); global/cross-tenant permissions; WORKER-CAPABILITY tokens — a tensorhub<->gen-orchestrator trust boundary, NOT authkit's concern; authkit's only role there is signature/JWKS verification. Do not model worker scopes / on_behalf_of / job_id in the RBAC engine.

RESOURCE-SCOPED GRANTS (from tensorhub per-resource scoping): app permission strings may carry a resource qualifier '<resource>:<action>:<name>' (e.g. repo:write:my-model, endpoint:invoke:my-llm) so a token grants only one named resource. authkit treats these opaquely, but its catalog-validation + no-escalation must operate on the BASE '<resource>:<action>' prefix: a scoped grant is valid iff its prefix is in the catalog, and no-escalation passes iff the actor holds the tenant-wide base perm OR the identical scoped perm. (Matching the scope to a specific resource at request time is the app's job, not authkit's.)

MEMBERSHIP: 'tenant membership' collapses into role-holding — a user has permissions in an tenant iff they hold >=1 role there. core.EffectivePermissions returns the EMPTY set for a user with no roles, so consumers need no separate membership gate. tensorhub (#369) is REMOVING its tenant-membership concept entirely (no IsTenantMember boolean, no RequireOwnerMembership) and authorizing purely on effective permissions; authkit should expose roles/effective-perms for an (tenant,user), not a membership boolean.

PERSONAL TENANT NOTE: a 'personal tenant' is a NAMESPACE-collision reservation — a user `foo` and an tenant `foo` share one slug namespace and cannot both exist. It is NOT single-member: a personal tenant CAN have multiple members, so it correctly seeds the full DefaultRoles (admin/member/deployer/viewer), same as any tenant. The seeding bug is only the reserved-namespace CLAIM path (ClaimOrgNamespace) seeding nothing.

**Tasks:**
- [x] Define authkit BASE permissions (tenant:roles:manage, tenant:members:manage, tenant:service_tokens:manage, optional tenant:read) in a reserved `tenant:` namespace; merge into every tenant's effective catalog; reject app catalogs that redefine reserved names.
- [x] core.Config.PermissionCatalog ([]PermissionDef{Name,Description}) for app permissions + app-declared DEFAULT ROLE TEMPLATES (name -> permission set, e.g. admin). Validate; opaque storage.
- [x] NEW numbered migration profiles.tenant_role_permissions (+ indexes, FK to tenant_roles). Seed owner=`*` and the app default roles on tenant creation (extend CreateTenant + personal-tenant path).
- [x] core: role->permission CRUD + EffectivePermissions(ctx, tenant, userID) (union; `*` superset; represent owner-minus-X for admin).
- [x] Generic VALIDATION (role-assignment + service token mint): in catalog (else unknown_permission) AND within actor's effective perms (else no-escalation 403 + offending). Bar tenant:*:manage from service token grants.
- [x] HARDCUT (no legacy owner-check fallback): re-gate /tenants/{tenant}/members (GET=tenant:read, POST/DELETE=tenant:members:manage), /tenants/{tenant}/members/{user_id}/roles (GET=tenant:read, POST assign + DELETE unassign = tenant:members:manage), /tenants/{tenant}/roles (GET=tenant:read, POST/DELETE=tenant:roles:manage), and /tenants/{tenant}/invites (GET=tenant:read, POST/revoke=tenant:members:manage) from requireOrgOwner -> requireOrgPermissionGin(base perm). Role ASSIGNMENT (POST member-roles) adds no-escalation: the role's effective permissions must be a subset of the assigner's (via EffectiveRolePermissions + ValidateGrant); owner=`*`/global-admin bypass. Leave requireOrgOwner ONLY for genuinely owner-level ops with no base perm (tenant rename, tenant-issuer register).
- [x] REMOVE service token host-hook: fold CanGrantservice token into authkit's generic check; delete authhttp.service tokenGrantAuthorizer/service tokenGrantCaller/Withservice tokenGrantAuthorizer; tensorhub drops st_grant.go + Registerservice tokenGrantAuthorizer.
- [x] Routes: GET /permissions; GET/PUT(+optional POST/DELETE) /tenants/{tenant}/roles/{role}/permissions; GET /tenants/{tenant}/members/{user_id}/permissions.
- [x] Tests: base-perm gating of management endpoints (owner allowed; member w/o perm 403; member w/ tenant:members:manage can manage members but not roles); catalog validation; assignment no-escalation; admin default role = owner-minus-{roles,members} behaves; effective-perm union; service token mint via generic check.
- [x] Docs: api-endpoints.md + README 'tenant RBAC' (base permissions, app catalog + default roles, owner=`*`, permission-gated management, service token now hookless).
- [x] Release in the v0.11.x line (e.g. v0.11.3 — NOT v0.12.0) + tensorhub bump; consumer follow-ups: tensorhub declares its catalog + `admin` default role, reads core.EffectivePermissions in #369, removes the service token adapter/hook; tensorhub also REMOVES its tenant-membership concept (RequireOwnerMembership / IsTenantMember gate) and switches to permission checks via EffectivePermissions.
- [x] Resource-scoped grants: ValidateGrant (service token-mint + role-assign) now validates a concrete token against the catalog by EXACT match OR, for a 3-segment '<resource>:<action>:<name>' scoped grant, by its '<resource>:<action>' base (e.g. repo:write:my-model -> repo:write). No-escalation passes if the actor holds the exact scoped perm OR its base. Reserved 3-seg base perms (tenant:roles:manage) still match exactly and aren't re-split. Test: TestValidateGrant_ResourceScopedPrefix. (Was marked done in v0.11.3 but the live e2e proved it rejected repo:read:alpha as unknown_permission — now actually fixed.)
- [x] Membership-free model: EffectivePermissions/roles lookup returns empty for a user with no roles (no membership boolean). Document that consumers drop their separate tenant-membership gate and authorize purely on effective permissions.
- [x] FIXED: ClaimOrgNamespace (claimParkedOrgToRegistered) now seeds the owner role row + owner=* permission before assigning the owner (idempotent), so a claimed reserved namespace (e.g. tensorhub `root`) gets real owner permissions instead of nothing. Covers all claim paths (park/restricted/create-then-claim).
- [x] LAZY default-role seeding (decided lazy): seedRolePermissionDefaults now seeds ONLY owner=* at tenant creation/claim; app DefaultRoles (admin/member/deployer/viewer) are materialized LAZILY via new materializeDefaultRole the first time a role is granted (AssignRole), which also creates the tenant_roles row the assignment requires. Solo tenants carry no dormant role scaffolding; teammate roles appear when actually granted.
- [x] RELEASED as v0.11.5 (clean tag from HEAD with prefix-validation + ClaimOrgNamespace owner-seeding + lazy default-role seeding). tensorhub bumped to v0.11.5 + validated (service token-boundaries all pass, multi-replica). NOTE: v0.11.4 was force-pushed mid-stream and is tainted on proxy.golang.tenant/sum.golang.tenant — treat v0.11.5 as canonical.

---

# #47: Selective route mounting plus registration/tenant-management disable policy

**Completed:** yes

Add first-class AuthKit configuration for locked-down embedded/self-hosted hosts, especially OpenRails. The goal is intentionally narrow: AuthKit should provide coarse policy gates for public user registration and public tenant onboarding/management, while hosts choose exactly which AuthKit route groups to mount. OpenRails does not need AuthKit to grow OpenRails-specific routes or a bespoke OpenRails control plane; it needs AuthKit core APIs for bootstrap/service token/RBAC and safe route-level defaults when a host accidentally mounts more than intended.

CURRENT STATE: AuthKit already supports explicit route selection through `svc.Routes().Groups(...)` and Gin/Chi adapter `WithRoutes(...)`, so OpenRails can mount only the subset it wants instead of `DefaultAPI()`. However, the public registration handlers (`/register`, `/register/availability`, `/register/resend-email`, `/register/resend-phone`) and tenant-facing creation/management routes do not have first-class runtime policy gates. Omission-only route control is easy to get wrong if a host later mounts `DefaultAPI()`.

DESIGN: add two coarse switches: public user registration enabled/disabled, and public tenant onboarding/management enabled/disabled. Public user registration disabled means no new user can be created through public registration or auto-registration flows, while existing-user login, refresh, logout, password reset/recovery, verification for existing users, and bootstrap/admin/internal creation still work. Public tenant management disabled means public/tenant-facing tenant creation, invites, member changes, role changes, and service token management routes are denied or omitted according to route selection, while embedded core/bootstrap code can still ensure the initial tenants, roles, admins, and service service tokens. Do not split this into a matrix of granular route flags.

OPENRAILS EXPECTATION: self-hosted OpenRails should mount only the AuthKit route groups it intentionally exposes, set both public registration switches to disabled, and use AuthKit core APIs internally to bootstrap the default tenant/operator tenant, roles, users, and OpenRails-issued service tokens. Hosted SaaS OpenRails can later enable the same switches and mount additional routes for public signup/onboarding.

**Tasks:**
- [ ] Add config fields to core/http configuration for disabling public user registration and disabling public tenant onboarding/management as coarse switches; default to current behavior for existing consumers unless we intentionally choose a breaking secure default.
- [ ] Gate all public user-creation paths, not only `POST /register`: audit password registration, availability, resend-email/resend-phone, OIDC/social/Solana/passkey flows that may auto-create users, invite acceptance that may create users, and any pending-registration confirmation path.
- [ ] Define disabled behavior consistently: `POST /register` and resend/create flows should return a stable `registration_disabled` error; `/register/availability` must not report new names/emails as usable when registration is disabled.
- [ ] Keep existing-user authentication working while registration is disabled: login, refresh, logout, password reset for existing accounts, token verification, profile/session routes, and existing tenant membership checks should be unaffected.
- [ ] Gate public tenant creation/onboarding and public tenant-management routes behind the tenant-management switch where appropriate, while keeping bootstrap/admin/internal core methods able to ensure tenants, roles, permissions/default roles, admin membership, and service tokens.
- [ ] Preserve and document route-group selection as the primary host control: OpenRails and other embedded hosts should mount explicit `svc.Routes().Groups(...)` subsets instead of `DefaultAPI()` when running locked down.
- [ ] Confirm OpenRails does not require new AuthKit-specific public routes: bootstrap user/tenant/role/service token setup should be possible through embedded AuthKit core APIs, with OpenRails free to expose its own product-specific admin/service token management routes.
- [ ] Tests: disabled public registration rejects `/register`, availability, resend, and every audited auto-registration path; existing-user login/reset still works; bootstrap/admin creation still works; public tenant creation/management is disabled when configured; default config preserves current behavior.
- [ ] Docs: README/API docs for the new flags, route behavior, route-group mounting guidance, and the OpenRails locked-down pattern: selected AuthKit routes only, public signup off, public tenant management off, bootstrap through core APIs.

---

# #48: Standard delegated access tokens for resource-service federation

**Completed:** yes

Standardize AuthKit delegated access tokens as the hard-cut canonical federation primitive. One AuthKit issuer signs a short-lived JWT for an external/delegated actor, and a resource service accepts it after issuer/JWKS/audience/resource-account validation. Canonical claims: typ=delegated-access+jwt, iss, aud, tenant (the target resource-service account), delegated_sub, permissions, attributes, iat/exp/nbf/jti. Ordinary AuthKit access tokens use typ=access+jwt, and the verifier rejects missing, unknown, or cross-profile typ values. Hard invariants: no normal sub, no legacy tenant claim, no top-level user_tier, no roles claim, required resource account, issuer-bound resource-account validation for tenant issuers, and permissions are the receiving-service authority source.

**Tasks:**
- [x] Rename/document the primitive as `delegated access token` in AuthKit docs and APIs; hard-cut older `delegated platform token` wording/API.
- [x] Update mint params to support canonical fields: `Issuer`, `Audiences`, `Tenant`, `DelegatedSubject`, `Permissions []string`, `Attributes map[string]json.RawMessage or map[string]any`, `TTL`, and optional `JTI`; omit normal `sub` by construction.
- [x] Update verifier/Claims to expose delegated access token fields as typed data: `Tenant`, `DelegatedSubject`, `Permissions`, `Attributes`, `JTI`, `Issuer`, token type, and helper methods such as `IsDelegatedAccessToken()` / `DelegatedAccess()`.
- [x] Hard-cut legacy `tenant` compatibility for delegated access tokens: require `tenant`, reject any delegated token with `tenant`, and bind tenant issuers to their registered resource account.
- [x] Replace top-level `user_tier` with `attributes.tier`; reject top-level `user_tier` on delegated access tokens.
- [x] Explicitly reject delegated access tokens containing normal `sub`; reject tokens containing both `sub` and `delegated_sub`.
- [x] Reject `roles` on delegated access tokens; receiving-service authority is `permissions` only.
- [x] Add validation hooks/options for receiving services to validate `permissions` against their resource permission catalog and validate `attributes` against service/tenant policy schemas.
- [x] Tensorhub migration plan: replace custom platform-delegated parsing with AuthKit delegated access token claims; map `attributes.tier` to the existing platform policy/rate/budget behavior; continue to treat permissions as optional narrowing where that is the product contract.
- [x] Gen Orchestrator migration plan: accept the same AuthKit delegated access token claims, forward delegated issuer/sub/user id/attributes to Tensorhub budget/admission APIs, and keep platform billing attribution unchanged.
- [x] OpenRails/Doujins/Hentai0 migration plan: Doujins/Hentai0 issue delegated access tokens for admin actors with `tenant` as the target OpenRails resource account, `delegated_sub`, `permissions`, optional `attributes`; OpenRails verifies issuer/JWKS/audience/resource-account and enforces `permissions`.
- [x] OpenRails/Doujins/Hentai0 self-service billing plan: Doujins/Hentai0 issue delegated access tokens for browser users with `aud=openrails`, `tenant`, `delegated_sub`, and self-scoped OpenRails permissions such as `openrails:self:billing:read`, `openrails:self:checkout:create`, and `openrails:self:subscriptions:cancel`; OpenRails enforces the target user/customer matches `(issuer, tenant, delegated_sub)`.
- [x] Add or document a current-user delegated-token mint path for browser clients: authenticated app user requests `aud=openrails` and receives a short-lived delegated access token with host-authorized self-scoped permissions; no normal `sub`, use `delegated_sub`.
- [x] Ensure delegated-token mint/exchange APIs are easy for host frontends to use without becoming billing proxies: the host AuthKit session authenticates the user, AuthKit mints the OpenRails-audience delegated token, and the frontend then calls OpenRails directly.
- [x] Ensure the delegated-token mint path supports frontend-direct standalone resource services: configurable audiences, CORS/CSRF-safe mounting expectations, short TTLs, and host-side permission grant policy for self-service versus admin permissions.
- [x] Document that direct OpenRails billing still requires an app AuthKit touchpoint for token issuance, but not a host webserver billing endpoint: login/session -> delegated token -> browser calls OpenRails public billing route.
- [x] Do not make the initial OpenRails private-route/service token migration depend on delegated access tokens; OpenRails can ship server-to-server public routes with OpenRails-issued service tokens first, and adopt delegated access tokens only for explicit browser-direct or federation flows later.
- [x] Tests: mint/verify canonical delegated access token; reject normal `sub`; reject `sub` + `delegated_sub`; reject legacy `tenant`, missing resource account (`tenant` claim), top-level `user_tier`, `roles`, and issuer/resource-account mismatch; round-trip `permissions`; round-trip arbitrary JSON `attributes`.
- [x] Docs: delegated access token claim table, threat model, hard-cut legacy-removal notes, and OpenRails/Doujins/Hentai0 admin delegation examples.
- [x] Document recommended permission naming for delegated tokens: use service-prefixed OpenRails permission strings (`openrails:self:*`, `openrails:tenant:*`) so host AuthKit catalogs can safely carry permissions for multiple resource services even when the token audience is also `openrails`.

---

# #51: SIWS spec-conformance hardening — nonce alphabet, server-side expiry, domain binding

**Completed:** yes

Tighten the existing Sign In With Solana (SIWS) implementation so it conforms to the SIWS / EIP-4361 standard and binds the security-critical fields to the server-issued challenge. Login already works and is sound against impersonation (Ed25519 signature verification + single-use server-issued nonce + address binding), so these are spec-conformance and defense-in-depth fixes, NOT an auth bypass repair. Scoped to the siws/ package and core/service_solana.go; no API/route/storage changes.

FINDING 1 (fix — interop bug, medium): siws.GenerateNonce (siws/message.go) encodes the random nonce with base64.RawURLEncoding, whose alphabet includes '-' and '_'. The SIWS/EIP-4361 nonce ABNF requires `nonce = 8*( ALPHA / DIGIT )` (alphanumeric only). Strict wallet/parser implementations may reject or mis-parse these messages. The bundled tests don't catch it because the same parser reads the nonce back. Fix: encode the random bytes with an alphanumeric encoder — base58 (github.com/mr-tron/base58 is already a dependency) is the natural choice; ~16 random bytes -> ~22 alphanumeric chars, comfortably above the 8-char minimum and retaining 128 bits of entropy.

FINDING 3 (fix — low, one line, server-authoritative): VerifySIWSAndLogin and LinkSolanaWallet validate whatever expirationTime the CLIENT placed in the signed message (via siws.ValidateTimestamps on the parsed message), not the 15-minute window the server issued. siws.ChallengeData already stores a server-authoritative ExpiresAt time.Time (set in GenerateSIWSChallenge to now+15m). Fix: after the cache lookup in both flows, reject if time.Now().UTC().After(challengeData.ExpiresAt). This makes the window real regardless of client-supplied timestamps. Already mitigated in practice by the cache TTL + single-use nonce deletion, hence low severity.

FINDING 2 (optional — anti-phishing domain binding, low): the production path parses the client-supplied signedMessage and binds only nonce (cache lookup) + address; it does NOT bind domain/uri/chainId to the server-issued challenge. The canonical verifySignIn reconstructs from server-held input and compares. Do NOT switch to siws.Verify's strict byte-compare: in the Wallet Standard signIn flow the WALLET constructs the message text from structured input, so it can differ from ConstructMessage by whitespace/ordering and strict byte-equality would cause false rejections with some wallets. Instead wire in the existing-but-unused siws.ValidateDomain(parsedInput, challengeData.Input.Domain) (optionally also compare URI/ChainID). Not an impersonation vector — the signer must own the wallet key and the nonce is single-use — so this is defense-in-depth only.

FINDING 4 (optional — informational hardening): verification derives the public key from Address (base58) and ignores output.Account.PublicKey entirely, so a mismatched PublicKey is silently accepted. Safe today because Address is the source of truth for the provider link. Optional: when PublicKey is non-empty, assert base58.Encode(PublicKey) == Address and reject on mismatch.

NON-GOALS: deleting siws.Verify (keep it as a library helper for callers that sign the literal challenge message); changing routes, request/response shapes, storage, or the challenge-issuance flow; reworking the cache TTL.

**Tasks:**
- [x] Finding 1: change siws.GenerateNonce to emit an alphanumeric nonce (base58 of ~16 random bytes) so it satisfies the SIWS/EIP-4361 `8*(ALPHA/DIGIT)` ABNF; keep >= 128 bits entropy.
- [x] Finding 1: extend TestGenerateNonce to assert the nonce is purely alphanumeric (no '-'/'_'), length >= 8, and uniqueness across calls.
- [x] Finding 3: in VerifySIWSAndLogin (core/service_solana.go) reject the challenge when time.Now().UTC().After(challengeData.ExpiresAt), after the cache lookup / before issuing tokens. (Extracted into the shared verifySIWSChallenge helper.)
- [x] Finding 3: apply the same server-side ExpiresAt check in LinkSolanaWallet. (Via the shared verifySIWSChallenge helper.)
- [x] Finding 3: add a test that a challenge past its server-issued ExpiresAt is rejected even when the client-signed message carries a later/absent expirationTime. (TestVerifySIWSChallenge_ServerExpiryEnforced.)
- [x] Finding 2 (optional): wire siws.ValidateDomain(parsedInput, challengeData.Input.Domain) into VerifySIWSAndLogin and LinkSolanaWallet; optionally also compare URI/ChainID against challengeData.Input. Map failures to existing error responses. (Domain binding wired via verifySIWSChallenge; URI/ChainID comparison left out as optional. http maps the "domain validation failed" error to authentication_failed.)
- [x] Finding 4 (optional): when output.Account.PublicKey is non-empty, assert it base58-encodes to output.Account.Address and reject on mismatch. (validateSolanaPublicKey.)
- [x] Run go test ./... (esp. ./siws/... and ./http/...) and confirm green; verify no wallet-interop regression from the new nonce alphabet. (siws + core + solana http tests pass; go vet clean. Note: pre-existing TestRegistrationDisabled_RegisterPOST panics on clean master too — unrelated, missing email/SMS sender config.)

---

# #52: Resource-scoped Service Tokens

**Completed:** yes

Extend AuthKit Service Tokens from `credential -> tenant -> permissions` to `credential -> tenant -> resource scope -> permissions`, while preserving the existing opaque-token security model. The core rule is: permissions describe WHAT the service token may do; resource scopes describe WHERE it may do it.

Motivation: OpenRails needs service tokens that can be tenant-wide (`tenant=tensorhub, payer=*`) or payer-scoped (`tenant=tensorhub, payer=cozy-art`) without making AuthKit infrastructure-multi-tenant and without encoding resource ids into permission strings. The same primitive should work for any embedding host: AuthKit stores and resolves host-defined resource scopes opaquely, while the host enforces their meaning.

Current service token model:
- Token is opaque: `<prefix>st_<key_id>_<secret>`.
- AuthKit stores tenant ownership, permissions, expiry/revocation, and last-used state.
- `ResolveAPIKey` returns tenant slug + permissions.

Target service token model:
- Token remains opaque and revocable.
- AuthKit stores zero or more resource-scope grants alongside the token.
- `ResolveAPIKey` returns tenant slug + permissions + resource scopes.
- Existing tokens with no resource scopes keep working as tenant-wide tokens unless a host opts into requiring scopes.

Example OpenRails interpretation:
- tenant-wide service service token: resources=[{kind:"openrails.tenant", id:"tensorhub"}], permissions=["openrails:admin"]
- payer-scoped spend service token: resources=[{kind:"openrails.tenant", id:"tensorhub"}, {kind:"openrails.tenant_subject", id:"cozy-art"}], permissions=["openrails:credits:spend"]

AuthKit must not interpret OpenRails resource kinds. Resource kind/id strings are host-defined and opaque to AuthKit, like app-defined permission strings. AuthKit owns storage, mint/list/resolve/revoke APIs, no-escalation checks where applicable, and contract shape. Host apps own semantic enforcement.

**Tasks:**
- [x] Define the service token resource-scope contract: stable type names (`APIKeyResource{Kind, ID}`), exact-match storage semantics, no wildcard-by-default except explicit host-provided ids such as `*`, and no AuthKit interpretation of host resource kinds.
- [x] Add a NEW numbered Postgres migration, not a 001 edit: create `profiles.service_token_resources` keyed by service token id, with `kind`, `resource_id`, timestamps, uniqueness on `(token_id, kind, resource_id)`, and an index for token lookup.
- [x] Extend core types: add `Resources []APIKeyResource` to `ServiceToken`; add `ResolvedAPIKey` with tenant slug, permissions, resources, token id, and key id metadata without breaking existing callers.
- [x] Add mint options for resources without changing the opaque token format: `MintAPIKeyWithOptions`; keep the existing `MintAPIKey` wrapper for compatibility.
- [x] Update `ListAPIKeys` to include resource-scope metadata, never secrets.
- [x] Update `ResolveAPIKey` flow to load resources in the same resolution path as permissions and return them through `ResolveAPIKeyWithResources`. Expiry, revocation, tenant-deleted checks, last_used_at update, and constant-time secret comparison remain unchanged.
- [x] Decide and implement compatibility behavior: existing `ResolveAPIKey(ctx, keyID, secret) -> (tenant, permissions, err)` stays as a wrapper, while the new resource-aware resolver returns resources; docs note resource-aware hosts must use the new resolver / middleware claims.
- [x] Add optional HTTP support on POST `/tenants/{tenant}/service-tokens`: accept `resources` as an array of `{kind,id}`; validate shape and length only. GET returns resources. DELETE/revoke is unchanged.
- [x] Preserve no-escalation for permissions. Resource-scope escalation is host-defined, so AuthKit accepts an optional host `ResourceScopeAuthorizer` callback for HTTP minting; without one, route-level creation allows resources only for callers already allowed to manage service tokens for the tenant.
- [x] Tests: mint/list/resolve tokens with no resources, one resource, multiple resources, duplicate resource rejection, revoke/expiry still enforced, resource metadata never includes secrets, existing API wrappers continue to work.
- [x] Docs: update README and `agents/api-endpoints.md` with resource-scoped service token semantics, examples, security guidance, and the rule `permissions say what; resources say where`.
- [x] OpenRails follow-up issue: added OpenRails issue 310 to consume resource-aware service token resolution for `openrails.tenant` and optional `openrails.tenant_subject` scopes, with the PayerOrgID/invoker terminology issue tracked separately as 309.

---

# #53: Hard-cut AuthKit org vocabulary to tenants, memberships, and service tokens

**Completed:** yes

Hard-cut AuthKit public/core/schema terminology from org/organization/OAT to tenant, tenant membership, tenant role, tenant issuer, delegated user, and service token. No compatibility aliases. Current implementation pass renamed the core Go API, HTTP route group/paths, token contracts, error constants where practical, and durable schema/table names. Remaining work is mostly deeper model simplification: collapse the historical multi-role membership join into one role per tenant_membership, collapse the historical multi-role membership join into one role per tenant_membership and update downstream host repos.

**Tasks:**
- [x] Inventory and mechanically rename the main org/OAT source surfaces across core, HTTP, migrations, tests, and docs.
- [x] Hard-cut schema names to tenants, tenant_memberships, tenant_roles, tenant_role_permissions, tenant_issuers, delegated_users, service_tokens, and service_token_resources.
- [x] Replace Go API types and methods from Org*/OAT naming to Tenant*/ServiceToken naming.
- [x] Replace HTTP tenant routes from /orgs and /token/org to /tenants and /token/tenant; no legacy route aliases were added.
- [x] Replace service-token string marker from oat_ to st_ and update middleware detection/resolution.
- [x] Rename reserved base permissions from org:* to tenant:* including tenant:service_tokens:manage.
- [x] Collapse tenant_membership_roles into a single role on tenant_memberships.
- [x] Rename owner-namespace/status strings from registered_org/parked_org/etc. to registered_tenant/parked_tenant/etc.
- [x] Coordinate OpenRails and Hentai0 against the new tenant/service-token APIs; validated Hentai0 manifest v2, service-token outputs, delegated JWT verification, and tenant-subject entitlement reads through live compose.
- [x] Coordinate Doujins against the new tenant/service-token APIs; validated manifest v2 issuer registration, OpenRails service-token output, and external-subject entitlement reads through direct compose startup.
- [x] Coordinate Tensorhub against the new tenant/service-token APIs; bumped Tensorhub to AuthKit v0.12.5, migrated service-token parsing/resolution to `cozy_st_`, switched tenant claim/resolver APIs, and validated `task build`, compile-only `go test ./... -run '^$'`, plus focused identity/authz/API/orchestrator OpenRails tests.
- [x] Coordinate Cozy Art against the new tenant/service-token APIs; bumped Cozy Art to AuthKit v0.12.5 and OpenRails v0.10.8, migrated platform tenant config from `platform.org` to `platform.tenant`, moved Tensorhub registration from `/api/v1/orgs` + `/api/v1/federated-issuers` to `/api/v1/tenants` + `/api/v1/tenant-issuers` with `tenant`/`issuer`/`jwks_uri`, and validated focused platform/config/register tests, compile-only `go test ./... -run '^$'`, and `task build`.

---

# #54: OIDC tenant issuers and minimal delegated users

**Completed:** yes

Tenants can trust external OIDC issuers, and AuthKit records delegated users as minimal external principals identified by OIDC issuer + subject. tenant_issuers now uses tenant_id, issuer, jwks_uri, audiences, and enabled. delegated_users is minimal: id, tenant_id, issuer, subject, created_at, last_seen_at.

**Tasks:**
- [x] Add tenant_issuers and delegated_users schema with tenant FK, OIDC issuer/jwks_uri/audiences/enabled, and unique delegated-user (tenant_id, issuer, subject).
- [x] Keep delegated_users minimal: id, tenant_id, issuer, subject, created_at, last_seen_at.
- [x] Update tenant issuer core CRUD and HTTP registration/list/delete APIs to OIDC names: issuer, jwks_uri, audiences, enabled.
- [x] Wire tenant issuers into the existing verifier/JWKS refresh path using issuer-specific audiences when provided.
- [x] Implement get-or-touch delegated user persistence during delegated-token resolution.
- [x] Add focused tests for delegated_users persistence and two issuers with the same subject.
- [x] Finish docs polish after host repos migrate: README and agents/api-endpoints.md now describe tenant issuers, minimal delegated users, delegated access JWTs, and opaque service tokens using the same terminology consumed by OpenRails.

---

# #55: Tenant manifest bootstrap for closed-registration deployments

**Completed:** yes

Provide a generic DevOps bootstrap path for AuthKit instances that do not allow public tenant registration. Mount a manifest, reconcile declared tenants/issuers/roles/service tokens idempotently, and avoid fake operator/platform/admin tenants. The library reconciler is implemented with a strict YAML parser, Postgres advisory lock, issuer/role reconciliation, service-token output preservation, file output support, a one-shot devserver CLI/job command, and an opt-in startup hook; production Vault/Kubernetes output stores remain host-owned TenantManifestTokenStore implementations.

**Tasks:**
- [x] Define manifest schema v1 with `tenants[]`, each containing stable slug, issuers, roles, and optional service token outputs.
- [x] Implement idempotent manifest reconciliation behind a lock so multiple app replicas cannot race tenant/token creation.
- [x] Allow manifest-declared tenant issuers to set OIDC `issuer`, `jwks_uri`, allowed `audiences`, and enabled state.
- [x] Allow manifest-declared roles/permissions using tenant-role vocabulary.
- [x] Allow manifest-declared service tokens with arbitrary permissions, arbitrary resource scopes, and arbitrary output targets such as Vault KV path/field or local file. Do not hardcode OpenRails/Doujins permissions.
- [x] If an output already contains a non-empty token, preserve it; otherwise mint and write a new opaque service token. Include an explicit rotate workflow separately from startup reconciliation.
- [x] Expose the reconciler as startup hook and CLI/job command in host applications so production can run it with a deploy identity rather than giving every API pod long-lived Vault write access.
- [x] Add tests for multi-replica lock behavior and issuer update/disable. Existing coverage also covers idempotency, service token output preservation, and invalid manifest rejection. Validated with AUTHKIT_TEST_DATABASE_URL-backed core tests.
- [x] Document closed-registration deployments and the distinction between deployment bootstrap authority and AuthKit tenants.

---

# #56: Registration modes for native users and tenants

**Completed:** yes

Make native-user registration and tenant registration separate host-controlled modes. Current code has route groups and coarse registration/tenant-management disable flags; remaining work is replacing booleans with explicit mode enums and adding the full mode matrix. No tenant auto-create on native-user registration by default.

**Tasks:**
- [x] Add explicit config for native end-user registration mode: open, invite/admin-only, admin-bootstrap-only, or closed.
- [x] Add explicit config for tenant registration mode: open, invite/admin-only, admin-bootstrap-only/manifest-only, or closed.
- [x] Enforce native-user and tenant registration modes separately; closing tenant registration must not imply closing native-user registration, and closing native-user registration must not imply closing tenant registration.
- [x] Keep route groups modular so embedded host applications can avoid mounting public native-user registration routes, public tenant registration routes, or any other public auth surface they do not want exposed.
- [x] Ensure public registration-disabled modes require admin/bootstrap/backend-controlled creation paths: manifest bootstrap, internal admin APIs, or host-side provisioning.
- [x] Ensure native-user-only deployments can have zero tenants without fake personal/tenant rows unless a separate issue intentionally introduces personal tenants.
- [x] Ensure closed-registration relying-party deployments can have zero native users and still accept delegated-user JWTs for registered tenant issuers.
- [x] Ensure B2B deployments support tenant memberships with one role per membership by default.
- [x] Replace old tenant registration flags/docs/tests with the new registration-mode vocabulary.
- [x] Add mode matrix tests for Doujins/Hentai0-style native app, Tensorhub-style B2B app, and OpenRails-style relying-party app, including host-not-mounted public route behavior.
- [x] Document which APIs are enabled/disabled by registration mode and which route groups hosts should omit for closed-registration deployments.
- [x] Do not auto-create tenants on native-user registration by default; if personal/team workspaces are ever desired, require an explicit host opt-in and tenant kind/product policy.
- [x] Support native-user-only deployments like Doujins/Hentai0 where tenant registration is disabled and user registration creates no tenant-related rows.
- [x] For B2B deployments like Tensorhub, optionally add a transactional shared reserved-slug namespace so `users.username` and `tenants.slug` cannot collide without creating fake tenants.
- [x] Document that shared slug reservation is host/mode-controlled and unnecessary when tenant registration is fully disabled.

---

# #57: OIDC claims and service-token authorization contract

**Completed:** yes

Standardize AuthKit authorization around OIDC delegated JWTs for browser/direct calls and opaque tenant-owned service tokens for server-to-server calls. Current pass renamed OAT contracts to service-token contracts and kept delegated JWTs/service tokens as distinct principal types.

**Tasks:**
- [x] Rename ResolvedOrgAccessToken/OrgAccessToken contracts to ResolvedAPIKey/ServiceToken.
- [x] Keep service token values opaque and revocable; token string now uses st_ marker, not oat_.
- [x] Keep service tokens tenant-owned and separate from native users/delegated users.
- [x] Keep delegated JWT claims using OIDC iss/aud plus tenant/delegated_sub and reject legacy org delegated claims.
- [x] Ensure middleware resolves service tokens to service principals and delegated JWTs to delegated principals.
- [x] Add explicit wrong-token-type denial tests for every route class after host APIs migrate. DONE: added HTTP regression coverage proving ordinary Required rejects service JWTs, RequiredServiceJWT rejects user/delegated JWTs, and VerifyDelegatedAccess rejects service JWTs.
- [x] Finish docs/examples once OpenRails consumes the hard-cut API. DONE: README documents explicit ordinary, delegated-only, and service-JWT route classes.

---

# #58: User-owned tenant registration boundary

**Completed:** yes

Make AuthKit's tenant registration model explicit and enforceable: public tenant registration is always performed by an authenticated native user who becomes the tenant owner/admin. Tenant creation without a registering user is not a public route; it is reserved for privileged admin/bootstrap/programmatic paths such as manifest reconciliation or host-controlled provisioning.

This supports the OpenRails SaaS model: a human registers as a normal AuthKit user, then creates one or more tenants. The tenant is the workspace/org/account boundary; the creator becomes the initial tenant owner/member. AuthKit should own this identity/membership primitive so embedded hosts such as OpenRails SaaS do not reimplement it.

**Tasks:**
- [x] Add or formalize a core API such as `CreateTenantForUser(ctx, CreateTenantForUserRequest{Slug, OwnerUserID})` that transactionally creates the tenant, seeds default roles, adds the registering user as a member, and assigns the owner role. Implemented `CreateTenantForUser` with an atomic tenant/role/owner-membership transaction.
- [x] Update `POST /tenants` to call the user-owned core API instead of stitching together `CreateTenant`, `DefineRole`, `AddMember`, and `AssignRole` in the HTTP handler.
- [x] Ensure `POST /tenants` always requires an authenticated user and cannot create an ownerless tenant.
- [x] Keep lower-level `CreateTenant` clearly documented as a privileged/internal primitive for bootstrap/admin/programmatic callers, not public self-service tenant registration.
- [x] Define and test the error contract for duplicate slug, reserved slug, invalid slug, tenant limit exceeded, deleted user, banned user, registration-mode disabled, and parked-tenant claim cases. DONE: added tenant-limit coverage plus reserved-name and parked-tenant namespace rejection coverage; existing tests cover invalid, duplicate, missing owner, banned owner, deleted owner, and registration-mode disabled.
- [x] Ensure tenant creation and owner assignment are atomic; failures must not leave an ownerless or partially initialized public tenant.
- [x] Add tests proving public tenant registration creates exactly one owner membership, seeds tenant role defaults, and rejects unauthenticated/userless creation.
- [x] Update docs/API endpoints to state that public tenant registration is user-owned and ownerless tenants are bootstrap/admin-only.

---

# #59: Privileged tenant bootstrap API for embedded hosts

**Completed:** yes

Provide a clean privileged tenant-provisioning path for embedded hosts such as OpenRails and OpenRails SaaS. Public tenant registration should flow through `CreateTenantForUser`; privileged host/bootstrap paths may create tenants without a user, but only through explicit core APIs or manifest reconciliation that are not mounted as public self-service routes.

OpenRails should use AuthKit's programmatic tenant primitives for the AuthKit tenant/membership side, then create/link its own OpenRails tenant row for billing/product namespace state. AuthKit owns users, AuthKit tenants, tenant memberships/roles, tenant issuers, and service-token credential mechanics; OpenRails owns OpenRails tenant records, tenant subjects, catalogs, provider credentials, usage, balances, and subscriptions.

**Tasks:**
- [x] Define the stable embedded-host API surface for privileged tenant provisioning: tenant create/resolve, role seeding, membership assignment, tenant issuer upsert/disable, and service-token minting. Implemented `ProvisionTenant` and typed provision request/result structs.
- [x] Clarify how `ReconcileTenantManifest` relates to public registration: manifest-created tenants are privileged/bootstrap tenants and may be ownerless unless the manifest explicitly declares memberships in a later schema.
- [x] Keep tenant manifest reconciliation additive/upsert by default; missing manifest tenants/issuers/roles/tokens must not delete or disable existing state unless explicit fields say so. The reconciler delegates to additive `ProvisionTenant`.
- [x] Decide whether AuthKit tenant manifests need optional `memberships` for bootstrap-created owner/admin users, or whether hosts should call the privileged core API after manifest reconciliation. Added optional `memberships` to the manifest and equivalent programmatic `TenantProvisionMembership`.
- [x] Expose a host-implementable token output store contract for Vault/Kubernetes/local-file outputs without forcing API pods to hold broad long-lived Vault write credentials. Preserved `TenantManifestTokenStore`; `ProvisionTenant` returns plaintext for programmatic stores or writes through outputs.
- [x] Add tests proving public registration modes do not affect privileged core/manifest provisioning, and closed/manifest-only modes still allow admin/bootstrap creation.
- [x] Document the recommended OpenRails SaaS flow: AuthKit user signup, user-owned AuthKit tenant creation, host-created OpenRails tenant linkage, then OpenRails catalog/secrets/service-token setup.
- [x] Document the recommended closed-registration OpenRails flow: privileged manifest/programmatic AuthKit tenant provisioning, then OpenRails bootstrap applies OpenRails-owned tenant/catalog state.

---

# #60: Remove global TenantMode switch

**Completed:** yes

Remove AuthKit's global `TenantMode` (`single` vs `multi`) because it conflates unrelated product decisions. AuthKit should always support native users, optional tenants, tenant memberships, tenant-scoped tokens, and tenant manifests at the core/library layer. Hosts decide what to expose through route groups, registration modes, and policy, not through a global mode flag.

Target model:

- Native users may exist with zero tenants.
- Tenants may exist with zero native users when created by manifest/admin/bootstrap.
- Public tenant registration is controlled by `TenantRegistrationMode` and route mounting, not `TenantMode`.
- Public native-user registration is controlled by `NativeUserRegistrationMode` and route mounting, not `TenantMode`.
- Tenant routes are available when the host mounts the tenants route group; mutating tenant routes are still gated by tenant registration/management mode.
- Tenant-scoped token exchange is allowed when a tenant is requested and the user is a member of that tenant.
- Personal tenant auto-creation remains an explicit separate opt-in, or is removed if no host needs it.

This supports OpenRails SaaS and closed-registration OpenRails without fake modes: OpenRails SaaS can expose user signup and user-owned tenant creation; Doujins/Hentai0 can expose user signup but not tenant registration; closed relying-party deployments can expose no public signup while still loading tenants from manifests.

**Tasks:**
- [x] Remove `TenantMode` from `core.Config`, `core.Options`, docs, route tests, and verifier options; do not replace it with another global single/multi switch. DONE (commit 416d3b6, v0.13.0): removed from Config/Options + validation + "single" default; no replacement switch.
- [x] Register tenant route specs based on route group mounting and service capability, not `TenantMode == multi`; keep mutating tenant routes gated by `TenantRegistrationMode`. DONE: tenant routes always registered under RouteTenants (host mounts the group); mutating routes still handler-gated.
- [x] Update token exchange and login flows so an optional `tenant` request mints tenant-scoped claims only if the user is a member of that tenant; absence of `tenant` mints normal user/global claims. DONE: a tenant request mints tenant-scoped claims iff the user is a member; absence mints user/global claims. No mode gate.
- [x] Remove single-mode legacy claim branching where possible; if legacy `roles` compatibility still exists, define it as a token-shape compatibility policy independent of tenant support. DONE: `roles` is now always emitted on a user access token mirroring global_roles (fixed token-shape compat), independent of tenants.
- [x] Replace `AutoCreatePersonalTenantsEnabled` dependency on `TenantMode` with a direct explicit host opt-in, or remove personal-tenant auto-creation if no current host requires it. DONE: AutoCreatePersonalTenantsEnabled is now a direct opt-in (no TenantMode gate).
- [x] Remove startup panic/downgrade checks tied to `tenant_mode=single`; replace with schema/data invariants that do not depend on deployment mode. DONE: removed the WithPostgres multi->single downgrade panic.
- [x] Update verifier claim extraction so tenant claims are parsed whenever present, not only under `WithTenantMode("multi")`; remove `WithTenantMode` or make it a no-op compatibility shim scheduled for deletion. DONE: verifier parses tenant claims whenever present; WithTenantMode is now a no-op deprecated shim (kept for consumer compat).
- [x] Update registration-mode tests to cover host shapes directly: native-user-only app, SaaS user+tenant app, manifest-only relying-party app, and no-public-route embedded app. DONE: tests updated to the unified behavior; full authkit suite green.
- [x] Update README and `agents/api-endpoints.md` to describe route groups plus native-user/tenant registration modes instead of tenant_mode.
- [x] Add migration/consumer notes for OpenRails, OpenRails SaaS, Doujins, Hentai0, and Tensorhub explaining that tenants are always a supported primitive but exposure is host policy.
- [x] DECISION 2026-06-06 (consumer mapping, recorded): hosts expose the two axes as plain bools defaulting to RESTRICTED — `public_user_registration` -> NativeUserRegistrationMode (open|admin_bootstrap_only), `public_tenant_registration` -> TenantRegistrationMode. Omitting both = closed-registration (the typical self-hosted posture). Route-mounting posture is DERIVED (intentional groups unless both are public), replacing the opaque `locked_down` switch.
- [x] OpenRails consumer side ADOPTED 2026-06-06 (ahead of the core change): OpenRails dropped its `auth.control_plane.tenant_mode` + `locked_down` config; added `public_user_registration` + `public_tenant_registration` (default false) mapping to authkit's existing Native/Tenant RegistrationMode. OpenRails still passes authcore TenantMode="multi" until this issue removes it from core (then OpenRails stops passing it). See openrails commit + #404-area work.
- [x] RELEASED v0.13.0 (breaking) + CONSUMERS ADOPTED 2026-06-06: openrails df0d290 + tensorhub 977e060 drop the TenantMode field-sets/WithTenantMode. Remaining (docs): README + agents/api-endpoints.md + consumer migration notes for Doujins/Hentai0.
- [x] DOCS DONE 2026-06-06: README + agents/api-endpoints.md updated to route-groups + registration modes; agents/migration-v0.13.0-tenant-mode.md added with per-host posture (OpenRails/SaaS/Doujins/Hentai0/Tensorhub).

---

# #61: OIDC service JWT mint and verify primitives

**Completed:** yes

Add AuthKit-owned primitives for first-party and federated server-to-server authentication using short-lived JWT bearer tokens signed by the caller's existing AuthKit/OIDC keys and verified by the relying service through registered issuer/JWKS metadata.

This is for systems like Doujins and Hentai0 calling OpenRails without an OpenRails-minted opaque service token. Doujins/Hentai0 already have AuthKit signing keys and JWKS, so they should be able to mint a short-lived service JWT such as `iss=https://auth.doujins`, `sub=service:doujins-runtime`, `aud=openrails`, `token_use=service`, `permissions=[openrails:entitlements:read]`, `exp=now+15m`. OpenRails verifies the JWT through the registered tenant issuer/JWKS and then applies OpenRails-owned grants/policy. AuthKit owns the reusable token shape, mint helper, verifier helper, claims parsing, route/middleware primitives, and security defaults; host applications own the semantic authorization decision.

The token shape should follow common JWT/OIDC bearer-token conventions for registered claims (`iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`) while preserving AuthKit terminology for authorization claims. Use `permissions: []` as the canonical requested-capability claim, matching delegated access JWTs and service-token metadata. Support OAuth-style `scope` only as an optional compatibility bridge if a host explicitly needs it.

This complements opaque service tokens rather than deleting them. Opaque service tokens remain useful for scripts, third-party clients, bootstrap automation, and callers without their own OIDC issuer/JWKS.

**Tasks:**
- [x] Define a canonical AuthKit service-JWT claims type with standard registered claims `iss`, `sub`, `aud`, `iat`, `nbf`, `exp`, `jti`, plus `token_use=service`, `permissions: []`, and optional host-defined resource claims.
- [x] Keep `permissions: []` as the canonical requested-capability claim because delegated access JWTs and opaque service-token metadata already use permissions arrays; only support OAuth-style `scope` as an explicit compatibility bridge, not the primary AuthKit contract.
- [x] Add a mint helper for hosts to create short-lived service JWTs from their AuthKit signing keyset, with safe defaults such as 5-15 minute expiry, required audience, required service subject, and optional requested permissions/resources. Default is 15 minutes and excessive requested lifetime is capped.
- [x] Add a verifier helper that validates issuer, JWKS signature/key id, audience, time bounds, max token lifetime, token_use, subject shape, and optional replay/jti hooks.
- [x] Keep AuthKit's verifier generic: it may parse requested permissions/resources, but it must not grant host permissions by itself. Hosts such as OpenRails must intersect requested permissions with server-side grants.
- [x] Add HTTP middleware/adapters that resolve a service JWT principal separately from native user sessions, delegated browser JWTs, and opaque service tokens.
- [x] Support registered tenant issuer metadata as the trust source for service JWT verification; disabled issuers must fail closed.
- [x] Add tests for valid service JWT, wrong audience, expired token, excessive lifetime, missing token_use, wrong token_use, unknown issuer, disabled issuer, bad kid/signature, malformed permissions, optional scope-compat parsing, and replay hook denial.
- [x] Document the recommended pattern for Doujins/Hentai0 -> OpenRails: caller mints `Authorization: Bearer <service JWT>`, OpenRails verifies via issuer/JWKS, then OpenRails authorizes with its own route grants.
- [x] Document when to use service JWTs versus opaque service tokens: service JWTs for callers with OIDC/JWKS; opaque tokens for generated API-key-like credentials and non-OIDC clients.
- [x] Add OpenRails follow-up notes: consume AuthKit service-JWT verifier for server-to-server entitlement reads and stop requiring Doujins/Hentai0 runtime OpenRails service tokens once the OpenRails side is migrated.

---

# #62: User preferred locale for auth and communication

**Completed:** yes
**Status:**  || MOVED to completed.json 2026-06-10 after artifact verification: preferred_locale in core (incl. tests); registration handlers carry PreferredLocale.

Add a canonical AuthKit-owned user preferred locale for auth screens, auth/security emails, SMS/text communication, and host-app communication defaults. This is a communication/auth locale, not a hard override for every host application's current browsing language or content language.

Semantics:
- Store a nullable BCP-47-ish locale such as `en`, `es`, `de`, `ko`, `zh-CN`.
- Track source and timestamps so initial registration seeding is distinguishable from explicit user choice.
- Seed the value at registration from the host app's current site/request language. Example: if a user registers while on Doujins `/es/...`, their initial preferred locale is Spanish.
- Do not mutate preferred locale merely because the user later visits `/es/...`, `/ko/...`, or changes a temporary site language. Later changes require an explicit account/settings action.
- Host apps may use the value as a fallback/default site language only when URL/session/cookie/browser signals are absent.

Ownership boundary:
- AuthKit owns the user communication/auth locale and uses it for verification, password reset, MFA, security alert, and hosted auth UI copy.
- Host apps own route/content language selection and can decide how to use AuthKit locale as a fallback.

**Tasks:**
- [x] Add `preferred_locale`, `preferred_locale_source`, and `preferred_locale_updated_at` to the AuthKit user/profile model via a new numbered migration; do not edit already-applied baseline migrations. Done 2026-06-07: added `migrations/postgres/006_user_preferred_locale.up.sql` with nullable locale/source/timestamp columns.
- [x] Define locale validation/normalization for supported BCP-47-style values; preserve case where meaningful for region subtags while normalizing primary language consistently. Done 2026-06-07: `NormalizePreferredLocale` accepts BCP-47-ish language/region values, normalizes primary language lowercase and 2-letter regions uppercase, and rejects invalid input with `invalid_preferred_locale`.
- [x] Extend registration input so host apps can pass an initial locale derived from the active site/request language; store it with source `registration` or equivalent. Done 2026-06-07: AuthKit HTTP registration reads `LanguageMiddleware` request context and passes it into locale-aware email/phone pending registration paths, including resend/recovery preservation.
- [x] Ensure login, token refresh, and ordinary browsing do not change `preferred_locale` automatically. Done 2026-06-07: only registration seeding and the explicit `/user/preferred-locale` update route call `SetPreferredLocale`; login/recovery resend paths preserve pending locale but do not mutate existing users from request language.
- [x] Add authenticated profile/settings endpoints to read and explicitly update `preferred_locale`; explicit updates set source `explicit` and update timestamp. Done 2026-06-07: added authenticated `PATCH /user/preferred-locale`, backed by `SetPreferredLocale(..., source=explicit)`, and `GetPreferredLocale` read support.
- [x] Expose the locale in AuthKit profile APIs and, if useful for consumers, as an optional `locale` access-token claim. Done 2026-06-07: `/user/me` now exposes `preferred_locale`, `preferred_locale_source`, and `preferred_locale_updated_at`; no access-token claim was added because profile API exposure is sufficient for current consumers.
- [x] Update AuthKit email/SMS senders to choose templates/copy by `preferred_locale`, falling back to tenant/app default and then English. Done 2026-06-07: core now passes the stored user locale or registration-seeded locale through sender context; bundled Twilio email/SMS defaults render Spanish copy when `lang=es` and fall back to English for unsupported languages.
- [x] Apply locale-aware rendering to verification email, password reset email, MFA/login code email/SMS, and security/account notification emails. Done 2026-06-07: AuthKit-controlled verification, password reset, phone/email change, 2FA setup/login code, and welcome sends use the preferred-locale context path; host custom builders remain supported.
- [x] Add tests for registration seeding from `es`, explicit update to another locale, no mutation from later request language, invalid locale rejection, API exposure, and email-template fallback. Done 2026-06-07: added locale normalization invalid-value tests, DB-backed Set/Get explicit update test, registration/resend preservation test, preferred-locale route assertion, and Twilio email/SMS language fallback tests.
- [x] Document the contract for host apps: pass current language at registration, use AuthKit locale for communication defaults, keep route/content language app-owned. Done 2026-06-07: README documents registration seeding, explicit updates, no browsing mutation, AuthKit communication usage, and host-owned site/content language.

---

# #63: Solana Name Service metadata for linked wallets

**Completed:** yes
**Status:**  || MOVED to completed.json 2026-06-10 after artifact verification: SNS metadata in core/service_solana_sns (incl. tests); surfaced via /v1/self wallet read in openrails.

Make AuthKit the owner of Solana Name Service metadata for SIWS-linked accounts. Host applications should not resolve or store wallet display names directly; they receive a normalized linked-account object from AuthKit and display `primary_sns_name` when present, with wallet-address fallback in the host UI. Resolution must never block login or wallet linking.

**Tasks:**
- [x] Add an AuthKit-owned SNS resolver contract and host-configured enable/timeout/cache settings. Done 2026-06-07: added `SolanaSNSResolver`, `SolanaSNSEnabled`, `SolanaSNSLookupTimeout`, and `SolanaSNSCacheTTL` to core config/options.
- [x] Resolve primary `.sol` names after verified SIWS wallet linking and store normalized metadata on the provider link. Done 2026-06-07: `LinkProviderByIssuer` refreshes SNS metadata for Solana links and stores status/name/timestamp/error in `profiles.user_providers.profile`.
- [x] Keep wallet linking/login durable even when SNS resolution fails. Done 2026-06-07: resolver failures are stored as `sns_resolution_status=error` with a stable `resolver_error` code and do not fail the verified wallet link.
- [x] Expose normalized Solana linked-account metadata through AuthKit profile APIs. Done 2026-06-07: `/user/me` returns `solana_linked_account` while preserving the legacy `solana_address` field for current consumers.
- [x] Refresh stale cached SNS metadata without blocking account rendering. Done 2026-06-07: stale metadata is surfaced as `sns_resolution_status=stale` and refreshed asynchronously.
- [x] Document the linked-account metadata contract for host applications. Done 2026-06-07: added `agents/solana-linked-account-metadata.md` with the canonical response shape and behavior.
- [x] Add focused tests for name normalization, resolved names, not-found results, resolver errors, and disabled resolver state. Done 2026-06-07: added `core/service_solana_sns_test.go`.

---

# #64: Transition all Postgres queries to sqlc (raw SQL -> generated type-safe Go)

**Completed:** yes
**Status:**  || MOVED to completed.json 2026-06-10 after artifact verification: internal/db/*.sql.go sqlc-generated per domain; zero database/sql usage in core; sqlc generate+vet pinned in Makefile and run green this session.

Replace the ~200+ hand-written pgx queries (inline SQL strings + manual Scan calls, concentrated in core/ and identity/) with sqlc: raw SQL written in .sql files, compiled by sqlc into type-safe Go functions backed by pgx/v5. Zero runtime overhead (sqlc is pure codegen emitting plain pgx calls), compile-time verification of every query against the real schema, and elimination of hand-ordered Scan boilerplate.

LAYOUT (standard sqlc convention): `sqlc.yaml` (version 2) at the repo root; query files in `internal/db/queries/*.sql`, one file per domain (users.sql, sessions.sql, tokens.sql, tenants.sql, ...); generated code into package `db` at `internal/db/` (db.go, models.go, *.sql.go — committed to the repo, never hand-edited); schema source pointed at `migrations/postgres/` (sqlc parses the numbered *.up.sql migration files directly, starting from the 001_auth_schema.up.sql baseline). Config: `engine: postgresql`, `sql_package: pgx/v5`. The generated `Queries` struct takes a `DBTX` interface satisfied by both `*pgxpool.Pool` and `pgx.Tx`, so existing transaction call sites use `queries.WithTx(tx)`.

WORKFLOW (standard, both commands always): `sqlc generate` to compile queries to Go, and `sqlc vet` to lint queries against rules — run as a pair locally (single Makefile target) and in CI on every change.

PRECONDITION: sqlc requires static SQL. core/ already hardcodes the `profiles.` schema, but identity/store.go builds table names dynamically from a configurable schema string (`s.schema + ".users"`) — standardize on the hardcoded `profiles.` schema there first.

ESCAPE HATCH: genuinely dynamic SQL (none exists today) stays as raw pgx alongside sqlc; that is the normal recommended coexistence pattern.

BUN ELIMINATION (added 2026-06-09 by user request): bun is removed from the repo entirely, including as the migration runner — migrations/postgres/migrations.go is rewritten on plain pgx (same name-tracked semantics: a migrations bookkeeping table, apply each not-yet-recorded *.up.sql in order, record by name), and github.com/uptrace/bun + its transitive deps drop out of go.mod.

NON-GOALS: ClickHouse queries (sqlc supports postgres/mysql/sqlite only); changing any query semantics — this is a mechanical transition, behavior must be byte-for-byte identical.

**Tasks:**
- [x] Tooling + config. Done 2026-06-09: sqlc.yaml (v2, postgresql, pgx/v5, queries internal/db/queries, schema migrations/postgres, out internal/db package db) + Makefile pinning sqlc v1.31.1 via `go run @version` (keeps the tool out of the library go.mod); `make sqlc` runs generate + vet as a pair; both pass against the 001 baseline using the devserver compose Postgres (127.0.0.1:35432).
- [x] Type mapping. Done 2026-06-09: overrides uuid->string (+nullable *string), pg_catalog.timestamptz->time.Time (+nullable *time.Time), citext + public.citext->string (+nullable *string; the public.-qualified form is required for extension types), emit_pointers_for_null_types for everything else; policy documented in sqlc.yaml header comment.
- [x] Precondition. Done 2026-06-09: identity.NewStore(pg, schema) -> NewStore(pg) hard cut (matches the repo's org->tenant breaking-change style); all identity SQL now hardcodes profiles.* like core/.
- [x] Pilot on identity/. Done 2026-06-09, amended 2026-06-10: 9 queries in internal/db/queries/identity.sql; store.go fully on db.Queries (uuid.UUID <-> string at the boundary); renames.go Forward* converted. ListTenantRenameHistory/ListUserRenameHistory selected to_slug/renamed_by columns that NO schema defines (not authkit's, not any host's) and had zero callers anywhere — dead AND broken since issue #58 shipped a different schema than designed; deleted outright (with RenameHop) instead of keeping them as raw-pgx holdouts. identity/ is now 100% sqlc.
- [x] Wire db.Queries into core.Service. Done 2026-06-09: Service.q (*db.Queries) initialized in WithPostgres (single assignment point); every pgx.Tx call site converted to s.q.WithTx(tx) — CreateTenantForUser, renameTenantSlugImpl, SetRolePermissions, MintAPIKeyWithOptions, transitionTenantInvite, updateUsernameImpl, removeAdminRoleIfNotLast, ReserveAccount, Park/Restrict/Unrestrict namespace flows.
- [x] Migrate core/ domain by domain. Done 2026-06-09: all ~200 queries lifted into internal/db/queries/{sessions,tenants,tenant_invites,service_tokens,owner_namespace,reserved_accounts,users,global_roles,providers,twofactor}.sql; inline SQL + Scan code deleted. Two intentional raw-pgx holdouts, both annotated in code: AdminListUsers (runtime-assembled filter/search/pagination SQL) and ReconcileTenantManifest (session-scoped pg_advisory_lock requires a pinned conn). Full test suite green after each domain.
- [x] Sweep remaining packages. Done 2026-06-09: the 4 real DB sites outside core/identity were all in http/ (admin_util HasRoleDBCheck, reauth provider lookups, user_me_get linked providers) — converted via db.New(pool); authkit-devserver's migration glob/exec replaced by migrations.Apply; ratelimit/redis (.Exec is a Redis pipeline) and riverjobs (test-only SQL) need nothing.
- [x] CI guard. Done 2026-06-09: .github/workflows/sqlc.yml spins up postgres:18-alpine, applies migrations/postgres/*.up.sql, and runs `make sqlc-check` (sqlc generate + sqlc vet with the db-prepare rule, then `git diff --exit-code -- internal/db` so drift fails CI).
- [x] Eliminate bun completely. Done 2026-06-09, corrected 2026-06-10: nothing ever consumed the bun `Migrations` registry — hosts (openrails) already run authkit's migrations via migratekit (LoadFromFS(authkitpostgres.FS) + NewPostgres(sqlDB, "authkit"), tracked per-app in public.migrations), so bun was pure dead weight. migrations/postgres/migrations.go now exports only FS (registry var deleted, breaking but unused); the devserver runs the SAME migratekit path as production hosts (a briefly-added custom Apply runner with a bun_migrations table was removed the next day — it preserved bookkeeping history that never existed anywhere); go mod tidy: zero bun/uptrace deps in go.mod/go.sum; migratekit v0.7.15 added as the devserver's runner dep.
- [x] Cleanup + docs. Done 2026-06-09: dead reservedUserFlagExpr + hand-rolled sortStrings removed with their call sites; README gained a 'Database queries (sqlc)' section (layout, make sqlc workflow, schema source of truth, CI drift guard, raw-pgx escape-hatch policy incl. the two annotated holdouts, ClickHouse out of scope) and the Migrations section now documents migrations.Apply.
- [x] Full test suite green. Done 2026-06-09: go vet clean; entire `go test ./...` green against the devserver Postgres (DB-backed core/http/riverjobs/testing suites included); sqlc vet db-prepare PREPAREd all 120 generated queries against the live schema (validates every RETURNING clause, ::text cast, and ANY(uuid[]) param); make sqlc-check shows zero drift.

---

# #71: Surface delegated-token role UUIDs (attributes.roles) on DelegatedPrincipal.Roles

**Completed:** yes

Let a self-issuing tenant carry the actor's ROLE UUIDs in a delegated token and surface them on the verified principal, so downstream services (tensorhub) can use role UUIDs as budget-scope keys. Mirrors the existing `attributes.tier` -> `UserTier` derivation. The top-level `roles` claim stays forbidden on delegated tokens (invariant `delegated_access_has_roles`); role UUIDs ride under `attributes.roles` as opaque scope keys, not authority.

- VERIFY (http/verifier.go): for delegated tokens, lift `attributes.roles` (JSON array of UUID strings) onto `Claims.DelegatedRoles` via new helper `rawUUIDStringsAttribute` — validates each as a well-formed UUID (google/uuid), drops malformed/non-string entries individually (doesn't fail the token), caps at `maxDelegatedRoles` = 64.
- PRINCIPAL (http/claims.go): added `Roles []string` to `DelegatedPrincipal` (UUID strings; consumers parse to uuid) + `DelegatedRoles []string` carrier on `Claims`; populated in `Delegated()`.
- MINT (http/delegation.go): added convenience `Roles []string` to `DelegatedAccessParams`, emitted into `attributes.roles` (typed field wins over `Attributes["roles"]`; blanks dropped; caller map not mutated).
- TEST: http/delegated_roles_test.go — round-trip, malformed-dropped, absent (backward compat), capped.

Backward compatible: tokens without `attributes.roles` -> empty Roles. Existing non-delegated `Roles`/`TenantRoles` behavior untouched. `go build ./...` + `go test ./...` green.

---

# #70: Hosts delegate JWT signing to authkit via a pluggable Signer (local key now, remote Vault-Transit later) — host never handles the private key; one key per app; uniform key config

**Completed:** no

authkit already ships an opt-in key resolver, separate from the verify/sign core: `jwt.KeySource` + `jwt.NewAutoKeySource`, wired via `core.Config.Keys` (nil ⇒ auto-resolve). Auto priority: env (`ACTIVE_KEY_ID` / `ACTIVE_PRIVATE_KEY_PEM` / `PUBLIC_KEYS`) → filesystem `DefaultAuthKeysPath` = `/vault/auth` (`keys.json` under it) → generate-and-persist under `.runtime/authkit/` (HARD-FAIL in prod). Envelope: `{active_key_id, active_private_key_pem, public_keys}`.

The design is right; two gaps make embedders silently diverge instead of using it:

1. **The filesystem source path is hard-coded** to `/vault/auth` with no host override. An embedder that renders its keyset anywhere else — host-run dev pointing at `~/cozy/e2e/.secrets/<app>/auth/keys.json`, or any non-K8s mount — cannot point the resolver at it; it falls through to dev-gen. There must be a host-overridable path.

2. **Inconsistent adoption → silent dev keys.** cozy-art constructs `core.Config{}` with `Keys: nil`, sets none of the env vars, and has no `/vault/auth/keys.json` on the host, so authkit auto-generates a throwaway key for its user-login issuer — its JWKS becomes a per-process random key instead of the managed keyset its compose/Vault renders. Meanwhile tensorhub doesn't use this resolver at all for its platform issuer: it reimplements the same env→/vault/auth→.runtime ladder in its own `platformjwt.autoKeyStore`. One concern, three behaviors.

Goal: **one JWT keypair per app** (its issuer identity, the only thing on its JWKS — plus retiring keys during rotation), loaded ONE uniform way via `KeySource`, and reused for ALL of that app's JWT signing — user access/refresh tokens AND service/delegated JWTs to tensorhub/openrails (those differ only in claims: `aud`, `sub=service:…`, `token_use` — never in key). No app should manage a second JWT key. Key discovery stays OUT of the verifier — `KeySource` is an opt-in library the host composes (via `Config.Keys`) or lets auto-resolve.

A host therefore NEVER handles the private key — it delegates the signing OPERATION to authkit. The boundary already exists: `jwt.Signer.Sign(ctx, claims jwt.MapClaims) (token, error)`, and `MintDelegatedAccessToken(ctx, signer, params)` already mints through it. The host calls authkit to sign (`signer.Sign(...)` / a Service mint method) and passes claims/params only. cozy-art's `platform_signer`/`servicejwt` and tensorhub's `platformjwt` — which read a raw PEM and sign themselves — are deleted in favor of asking authkit to sign.

Why this matters beyond dedup: because `Signer` is an interface, the LOCAL backend (RSA key in memory, from `KeySource`) and a FUTURE REMOTE backend (HashiCorp Vault Transit `sign`, where the private key NEVER enters the app's memory/disk/container) are interchangeable. Switching local→remote is a config change at authkit init; call sites (`signer.Sign(...)`) are unchanged and never see key material. Host config + signing code stay identical regardless of where the key lives.

**Boundary (hard invariant):** private key material NEVER crosses the authkit→host boundary. authkit exposes the host EXACTLY two things: (1) MINT/sign operations (claims/params in → signed token out) and (2) PUBLIC verification material (JWKS / public keys). There is NO accessor that returns a private key, a PEM, or a raw `crypto.Signer` over the private key — so the host literally cannot read, copy, or persist it, a remote (Vault Transit) backend is a true drop-in, and key handling can't leak through host code. Any "give me the active private signer" API (including the one an earlier draft of this issue proposed) is explicitly rejected. Key loading (`KeySource`, PEM parsing) lives ENTIRELY inside authkit's local backend; the only key bytes a host ever provides are inputs to authkit at init (path/env), never something it reads back out.

(The ONLY separate signing key in this fleet is tensorhub's **artifact** key — signs build artifacts, not JWTs; different trust domain, not on the JWKS. Out of scope here, though it could adopt the same remote-signer pattern later.)

Design:
- **`Signer` is the boundary** (already exists: `jwt.Signer.Sign(ctx, claims)`). Hosts obtain a `Signer` / call Service mint methods and sign through it — never construct their own signer or read the PEM.
- **Local backend = `KeySource` → `RSASigner`**, with a host-overridable key location: add `core.Config.KeysPath` (+ `AUTHKIT_KEYS_PATH` env) feeding `tryLoadFromFilesystem`; default stays `/vault/auth`. Explicit constructors `FileKeySource(path)` / `EnvKeySource()` / `GeneratedKeySource(dir)`; refactor `NewAutoKeySource` to compose them.
- **Service-level mint API**: authkit mints the token types hosts need — user (exists), delegated (`MintDelegatedAccessToken`, exists), and a first-party **service JWT** (add if missing) — each signing via the Service's internal `Signer`, so the host hands over claims/params and nothing key-shaped.
- **Pluggable backend by config**: authkit selects the `Signer` backend at init (local `KeySource` now; a `VaultTransitSigner` later). The remote backend is a forward-looking follow-up — **future.md #72** — this issue just keeps the `Signer` seam clean and config-driven so #72 drops in with zero host changes.
- **Docs**: "Signing & key resolution for embedders" — one-key principle, sign-through-authkit rule (host never holds the key), local backend config (path/env/constructors, default `/vault/auth`), the future remote-signer seam, envelope format, prod hard-fail.

Consumer adoption is tracked in the umbrella issue **cozy-art #143** (one JWT key per app; ALL signing through authkit; uniform key config), covering all four embedders:
- cozy-art (`core.Config{Keys:nil}` → silent dev-gen, PLUS a separate `platform_signer`/`servicejwt` PEM) and doujins (`keySource = nil`, `internal/server/server.go`): give authkit one `KeySource` and mint delegated/service JWTs THROUGH authkit — delete the bespoke signer + its key handling.
- hentai0 (`internal/infra/authkit.go` already calls `NewAutoKeySource()`): move onto the configurable path.
- tensorhub: delete `platformjwt.autoKeyStore` + its separate platform key; mint capability/platform/delegated JWTs through authkit's `Signer`. (Artifact key stays separate.)

**Tasks:**
- [x] `core.Config.KeysPath` + `AUTHKIT_KEYS_PATH` env override for the local filesystem key source (default stays `/vault/auth`)
- [x] Export `FileKeySource(path)`, `EnvKeySource()`, `GeneratedKeySource(dir)`; refactor `NewAutoKeySource` to compose them
- [x] Service-level mint API: ensure authkit mints user + delegated + first-party service JWTs through its internal `Signer` (add the service-JWT mint if absent), so hosts pass claims/params and NEVER a key or a self-built signer
- [x] Keep the `Signer` backend selectable at init (local `KeySource` now); document the seam for a future `VaultTransitSigner` (remote signing, key never in-app) — implementation tracked as a separate forward-looking issue
- [x] Docs: "Signing & key resolution for embedders" (one-key principle, sign-through-authkit, local backend config, remote-signer seam, envelope, prod hard-fail)
- [x] Tests: configurable path resolves; env precedence preserved; prod hard-fails without a key; mint→verify round-trips through the `Signer`
- [x] go build / go vet / go test green

---

# #73: Arbitrary-claims service-token mint — high-level API for custom JWT shapes (so hosts never reach for the low-level Signer)

**Completed:** no

Follows #70. #70 gave hosts two high-level mint methods — `MintDelegatedAccessToken` and `MintServiceJWT` — that sign through authkit's internal key (host never touches the PEM). But both **lock the claim shape**: `MintServiceJWT` forces `token_use=service` + `typ=service+jwt` and only allows `permissions`/`resources`; `MintDelegatedAccessToken` *deletes* `sub` and forces `typ=delegated-access+jwt`. Neither can express tensorhub's **capability/worker tokens**, which carry custom claims like `cap_kind`, `grants`, `tenant`, `request_id`, `job_id`, `endpoint`, `function_name` (and a worker/realtime variant with `release_id` + `aud:["cozy.scheduler"]`).

Consequence today (tensorhub, after #70 adoption): tensorhub mints those tokens by reaching for the **low-level `jwtkit.Signer.Sign(ctx, claims)`** it pulls off the KeySource. That's still ONE key / ONE JWKS and the host never reads the PEM (the #70 hard boundary holds — `Signer` is a sign *operation*, not key material), but it bypasses the high-level mint surface: the host hand-assembles claims, sets its own `typ`/`kid`/`iss`/`exp`, and is one refactor away from accidentally holding a signer it shouldn't. We want a blessed high-level entry point for custom-claim tokens.

Goal: add a Service-level mint for arbitrary first-party claim sets that signs through the internal `Signer`, so a host passes a claims map (+ a few controlled headers) and gets a signed JWT — never the signer, never the key. This is the high-level equivalent of what tensorhub does with the raw `Signer` now, with authkit owning the boilerplate (kid header, alg, `iss` default, `iat`/`exp`, JWKS alignment).

Design:
- New `(*core.Service) MintCustomJWT(ctx, opts core.CustomJWTMintOptions) (string, error)` (name TBD — could also be `MintRawClaims`). `CustomJWTMintOptions`:
  - `Claims map[string]any` — the host's claim set (e.g. `cap_kind`, `grants`, `release_id`, custom `aud`). authkit sets/normalizes the registered claims it owns: `iss` (defaults to Service issuer; overridable), `iat`, `exp` (from a `TTL`), and `kid` in the header.
  - `TTL time.Duration` (required, bounded by a sane max), `Type string` (the JWT `typ` header; default e.g. `at+jwt` or empty — host sets `worker-capability`/etc.), optional `Subject`, `Audiences`.
  - It must REFUSE to silently clobber host claims it doesn't own, and document precedence (authkit-owned registered claims win, or are explicitly host-overridable).
- Keep `MintServiceJWT` / `MintDelegatedAccessToken` as the constrained, opinionated paths (don't loosen them). `MintCustomJWT` is the escape hatch — clearly documented as "you own the claim semantics; the verifier side must understand them."
- Boundary unchanged: signs via the internal `Signer`; NO new private-key/PEM/`crypto.Signer` accessor. (It does not need to expose `ActiveSigner` to the host at all — that's the point: replace host use of the raw signer.)
- Docs: extend the #70 "Signing & key resolution for embedders" section with when to use `MintServiceJWT` vs `MintDelegatedAccessToken` vs `MintCustomJWT`.

Consumer follow-up (tensorhub): replace the `jwtkit.Signer.Sign(...)` calls in `internal/identity/platformjwt` (capability + worker/realtime tokens) with `MintCustomJWT`, asserting byte-identical claim/`typ`/`iss`/`aud` output so cross-service verification is unchanged. Tracked alongside cozy-art #143's tensorhub task.

**Tasks:**
- [x] `core.CustomJWTMintOptions` + `(*Service).MintCustomJWT` signing through the internal `Signer` (sets kid/alg/iss-default/iat/exp; carries the host claim map + `typ`/`aud`/`sub`).
- [x] Guardrails: bounded TTL; documented claim precedence (don't silently overwrite host claims); reject empty/oversized claim sets.
- [x] Tests: custom claims (`cap_kind`/`grants`/`release_id`) round-trip; `typ` header honored; mint→verify via JWKS; `iss` default + override; TTL bound enforced.
- [x] Docs: extend "Signing & key resolution for embedders" with the three mint entry points + when to use each.
- [x] go build / go vet / go test green.
- [ ] (consumer, separate) tensorhub platformjwt swaps raw `Signer.Sign` → `MintCustomJWT` with byte-identical output.

---

# #76: JWKS-principal programmatic auth — a self-signed external key as a first-class credential with STORED permissions/role (parallel to service tokens)

**Completed:** yes

Design (Paul, 2026-06-14): programmatic access should support TWO credential types, symmetric in how authority
is granted:
- **service token** (exists): a shared secret / API-key (`<app>st_<keyid>_<secret>`); we store `sha256(secret)`
  + its assigned permissions; verified by indexed lookup.
- **JWKS principal** (NEW auth method): an external party with its OWN signing key presents a SELF-SIGNED JWT
  whose subject IS the principal; we verify the signature via its registered JWKS and grant the authority WE
  ASSIGNED to that principal — NOT what it self-claims on the token.

Both are assigned STORED authority: a set of permissions and/or a role (a role is just a pre-built bundle of
permissions). The JWKS principal IS the `remote_application` (#74) acting AS ITSELF; `remote_application` =
JWKS principal **+** delegated-user federation (delegation is the additional capability, orthogonal to this).

## What exists vs the gap
- #74 already gave `remote_application` a JWKS credential + polymorphic tenant membership + stored roles
  (`core.RemoteApplicationTenantRoles`). The DATA model for stored authority exists.
- The verifier today knows ONLY native-user `sub` (AuthKit-signed) XOR delegated `delegated_sub` (JWKS-signed),
  and FORBIDS a JWKS/delegated token from carrying a `sub` (`http/verifier.go:666`). So a JWKS principal
  "acting as itself" has NO first-class verify path.
- The current act-as-itself path is the #70/#73 service-JWT (permissions ON the token, self-asserted). This
  issue makes authority STORED/assigned — the secure model, and it reconciles the overlap.

## Work
1. **Self-token shape**: a JWKS-issuer token whose subject is the principal's own id — the case the
   `sub`/`delegated_sub` invariant doesn't model. Pick the convention (a dedicated `typ`, or `sub` == a
   registered remote_application id) and authenticate it AS the principal.
2. **Resolve STORED authority on verify**: the principal's assigned permissions + roles
   (`RemoteApplicationTenantRoles` + a direct-permissions grant analogous to `service_token_permissions`).
   IGNORE/constrain any self-claimed permissions on the token — authority is what we assigned.
3. **Assignable-authority surface**: assign permissions and/or a role to a remote_application (reuse
   `tenant_roles`/`tenant_role_permissions` for roles — role = permission bundle; add a permissions grant for
   direct perms, mirroring service tokens).
4. **Reconcile with #70/#73 service-JWT** (permissions-on-token): decide retain / deprecate / constrain
   (self-asserted perms must be a SUBSET of assigned, or dropped). Don't ship two divergent authority sources.
5. Delegated-user federation (`delegated_sub`) is UNCHANGED — the other remote_application capability.

## Open decision
- Stored-authority JWKS auth vs the existing permissions-on-token service-JWT. Recommend: authority is ALWAYS
  stored/assigned (like service tokens); a self-signed token never grants self-claimed permissions.

## Downstream adoption (separate issues)
- openrails #484 (accept JWKS-principal auth in the standalone control plane), tensorhub #485 (accept + maybe
  migrate its outbound service-JWT), cozy-art #147 (migrate act-as-itself to a stored-role JWKS principal).
  All blocked on this.

**Tasks:**
- [x] Decide + document the JWKS self-token shape (typ + subject convention) excluded by the current invariant.
      DECISION: dedicated `typ=remote-application-access+jwt` (jwt/jwt.go RemoteApplicationAccessTokenType),
      carrying NEITHER `sub` NOR `delegated_sub` — identity is the validated `iss` → remote_application, exactly
      as delegated tokens resolve tenant from `iss`. Keeps the sub-XOR-delegated_sub invariant (verifier.go:666)
      fully intact. Mint via core.MintRemoteApplicationAccessToken.
- [x] Verifier: authenticate a JWKS principal self-token → principal identity; resolve STORED permissions +
      roles; reject/ignore self-claimed authority. (http/verifier.go resolveRemoteApplicationSelf →
      core.ResolveRemoteApplicationAuthority; populates Claims{TokenType:"remote_application", Permissions,
      Tenant, TenantRoles, RemoteApplicationID/Slug}. Self-claimed perms/roles/tenant ignored; a self-token
      carrying `sub`/`delegated_sub` is rejected.)
- [x] Assignable authority: assign permissions and/or a role to a remote_application (roles via
      tenant_roles/role_permissions through #74's polymorphic tenant_memberships; a new
      remote_application_permissions grant for direct perms — migration 006, sqlc, core CRUD in
      core/remote_application_permissions.go, HTTP /remote-applications/{slug}/permissions GET/POST/DELETE).
- [x] Reconcile with #70/#73 service-JWT (retain/deprecate/constrain); document the two programmatic-access
      credential types (shared-secret service-token vs self-signed JWKS principal), both stored-authority.
      DECISION: RETAIN #70/#73 unchanged (tensorhub/cozy-art depend on it); stored-authority self-token is the
      canonical model and #70/#73 MAY be deprecated later — doc-comment in core/remote_application_token.go.
- [x] Tests: JWKS self-token authenticates + resolves assigned perms/role; self-claimed perms NOT honored;
      delegated (`delegated_sub`) + native-user (`sub`) paths unchanged. (core/remote_application_permissions_test.go;
      http/remote_application_self_token_test.go; existing delegated/native + verifier.go:666 guards still green.)

## AMENDMENT (Paul, 2026-06-14): down-scoping — the self-token's permission claim is HONORED as a SUBSET
Reverses the shipped (#76 v0.28.0) "ignore self-claimed perms, grant full stored" behavior. The stored grant is
the CEILING; a self-token MAY carry a permission claim to request LEAST-PRIVILEGE for that use; **effective =
token-claimed ⊆ stored-granted**. Rules:
- Token permission claim PRESENT → effective = the claim, but EVERY claimed permission must be within the stored
  grant. An out-of-grant claimed permission → **REJECT the token with an error** (REVISED 2026-06-14, Paul:
  error, NOT silent clamp/drop — a misconfigured caller must fail loudly so it's caught, not silently lose perms).
- Token permission claim ABSENT → effective = the full stored ceiling (narrowing is opt-in; backward-compatible
  with v0.28.0 tokens that carry no claim).
- Over the resolved permission SET (direct ∪ role-derived). Ship as **authkit v0.28.1**.
- **Introspection endpoint (NEW, Paul 2026-06-14)**: an authenticated "what are my permissions" endpoint returning
  the caller's GRANTED set (the ceiling) + identity — for service-tokens AND self-signed JWKS principals (and
  native users). So a caller can discover its grant and construct a valid narrowed token without guessing
  (OAuth-introspection / whoami pattern). Reject-on-over-claim is only ergonomic if callers can look up their grant.

**Amendment tasks (REVISED 2026-06-14 — reject not clamp + introspection; supersedes the clamp tasks below):**
- [x] Verifier: change clamp→REJECT — an out-of-grant claimed permission fails the self-token with a clear error
      (`permission_not_granted`); subset accepted; absent claim → full ceiling (unchanged).
      (http/verifier.go: errPermissionNotGranted sentinel; resolveRemoteApplicationSelf returns it on any claimed
      perm outside the stored ceiling instead of dropping it.)
- [x] Introspection endpoint: `GET /me/permissions` (RouteCore, behind Required) returns the authenticated
      caller's GRANTED permission set (the ceiling) + principal type/id/slug + tenant/roles. JWKS principal →
      ResolveRemoteApplicationAuthority (ceiling resolved by identity, NOT the narrowed token claim); service-token
      → its claim Permissions; native user → EffectivePermissions in the token's tenant. (http/me_permissions_get.go,
      registered in http/routes.go.)
- [x] Tests: over-claim → permission_not_granted; valid subset → accepted with that subset; absent → full ceiling;
      introspection returns the granted ceiling for a JWKS principal even when the presented token is narrowed,
      the stored perms for a service-token, and the resolved perms for a native user.
      (http/remote_application_self_token_test.go: CannotWiden + IgnoresSelfClaimedAuthority assert reject;
      TestMePermissions{RemoteAppReturnsCeiling,ServiceTokenReturnsStored,NativeUserResolves}.)

**Amendment tasks:**
- [x] Verifier (`resolveRemoteApplicationSelf`/`ResolveRemoteApplicationAuthority`): read the self-token's
      permission claim; effective = claim ∩ (direct ∪ role-derived); absent claim → full ceiling; clamp (drop)
      out-of-grant claimed perms. (http/verifier.go: Verify reads the `permissions` claim — present-but-empty
      narrows to nothing, absent=nil keeps the ceiling — and passes claimedPerms into resolveRemoteApplicationSelf,
      which intersects with the stored ceiling from ResolveRemoteApplicationAuthority before populating
      Claims.Permissions. Tenant/TenantRoles/identity/subject guard unchanged.)
- [x] Define the self-token permission-claim shape on `core.RemoteApplicationAccessParams`/mint
      (`MintRemoteApplicationAccessToken`) so a minter can request a subset. (core/remote_application_token.go:
      added optional `Permissions []string`; non-nil is written as the `permissions` claim — the same key the
      verifier reads; nil/absent = no claim = full ceiling.)
- [x] Tests: token narrows to a subset; token cannot widen (out-of-grant claimed perm dropped); absent claim →
      full ceiling; roles still contribute to the ceiling. (http/remote_application_self_token_test.go:
      DownScopesToSubset, CannotWiden, AbsentClaimFullCeiling — all green against the test DB.)
---

# #75: App-specific escape hatch — the delegated-token `attributes` bag as the remote_application→platform contract, with INLINE + REFERENCE claim modes (reference resolves against a generic AuthKit-hosted definition registry)

**Completed:** yes

Design (Paul, 2026-06-13): a remote_application is the AUTHORITY for its own delegated users and wants to assert
arbitrary app-specific permissions/restrictions on them that don't reduce to a flat permission string — e.g.
cozy-art declares user U is "tier-1", meaning [marco-polo only, 5h/$0.20, 7d/$1.40]. The platform (tensorhub)
honors + enforces those restrictions; AuthKit/OpenRails stay app-AGNOSTIC, carrying opaque values they never
interpret. This is the escape hatch: generic plumbing, app-specific semantics.

## Two claim modes (Paul, 2026-06-13)
The same `attributes` bag supports BOTH, per key:
- **INLINE (self-describing):** the token carries the full definition — `attributes:{"tier":{endpoints:[...],
  caps:[...]}}`. No lookup. For short/one-off values.
- **REFERENCE (registered):** the token carries a short key — `attributes:{"tier":"tier-1"}` — pointing to a
  definition the remote_application REGISTERED ahead of time. For long/complex/reused definitions; keeps tokens
  small. The platform resolves the reference to its definition.

## The generic definition registry (NEW — this is the added machinery)
A reference needs a place to resolve. Home = **AuthKit**, so it is a GENERIC api every platform shares (storing
it per-platform would mean each rebuilds it):
- Store: `(remote_application_id, namespaced_key, version) → definition` as an OPAQUE JSON doc. AuthKit never
  interprets it (same agnosticism as the token bag).
- **Write side (remote_app authors):** cozy-art registers `(cozy-art,"tier-1") → {definition}` via a generic
  API. The definition is the remote_application's — it is the authority for its own users' restrictions.
- **Read side (platform resolves):** tensorhub pulls `(cozy-art,"tier-1")` via the same generic API.
- **Optional verify-time hydration:** the verifier MAY resolve a reference into its full definition so the
  consumer sees a uniform shape whether the token used inline or reference (off by default; opt-in).

## Enforcement (unchanged): assertion → platform → OpenRails
- The assertion (inline value or resolved reference) rides on / is reachable from the delegated token
  (`core/delegated.go` Attributes; `Claims.Attribute(key)`, `http/claims.go:164`). Signed by the remote_app's
  JWKS, short TTL bounds staleness.
- The platform (tensorhub) maps the definition to concrete policy and pushes the billing-relevant parts DOWN to
  OpenRails (`tier_policies` + `money_spend_limits`/budget windows), which enforces by the opaque value and never
  parses meaning. Non-billing restrictions (endpoint allowlist) the platform enforces in its own code.

## The generic contract (reserved keys + opaque values)
- `attributes` = an object of issuer-asserted, NAMESPACED, opaque key/values. AuthKit transports + OPTIONALLY
  shape-validates (consumer-registered `AttributesValidator` via `WithAttributesPolicy`, `http/verifier.go:142`);
  it never interprets semantics.
- Reserved well-known keys: `tier` (opaque entitlement-tier string, `verifier.go:760` → `UserTier`) and `roles`
  (uuid array, `core/delegated.go:48`). Everything else is free-form per consuming app.
- INVARIANT: AuthKit and OpenRails MUST NOT learn any app's tier NAMES. OpenRails stores `tier` as opaque text
  keyed into `tier_policies`; only the consuming app's policy doc knows "tier-2".

## Composition with the two tier AXES (do not conflate)
- Escape-hatch tier = remote_application-ASSERTED entitlement tier (on token) → endpoint allowlist + spend caps
  via the consumer policy doc.
- OpenRails #476 tier = capacity/availability tier AUTO-graduated from cumulative paid spend (OpenRails-owned,
  host read-only). Distinct input, distinct axis. tensorhub already threads both (`invoke_admission.go` token
  tier as admit Tier; `action_bridge.go:194` resolves the #476 tier separately). The escape hatch adds nothing
  to #476.

## Resolves OpenRails #481 open-decision stub
OpenRails #481's escape-hatch open decision is RESOLVED by this: the assertion rides on the token; the mapping is
consumer-stored and synced to `tier_policies`/spend limits — OpenRails adds NO escape-hatch table/column and
grows NO tier knowledge. #481 points here.

## Footprint — REUSE the transport, ADD the registry
- REUSE: `attributes` claim + `Claims.Attribute()` + `AttributesValidator`/`WithAttributesPolicy` (this repo);
  OpenRails `tier_policies`/`money_spend_limits`/`money_windows`; tensorhub `platformpolicy.Document` PUT pipeline.
- ADD (for REFERENCE mode): one `remote_application_attribute_defs` table + a generic write/read API
  (remote_app registers; platform resolves), values OPAQUE to AuthKit. INLINE mode needs no new storage.

## Non-goals
- AuthKit/OpenRails interpreting any app's values. OpenRails learning tier names. Platform→effect mapping
  (endpoint allowlists etc.) — that's the consuming app's (tensorhub) job, not the registry's.

**Tasks:**
- [x] Doc-comment the `attributes` bag as the canonical escape-hatch contract on `DelegatedAccessParams`
      (`core/delegated.go`) + `Claims`/`DelegatedPrincipal` (`http/claims.go`): namespaced opaque key/values,
      INLINE or REFERENCE; reserved keys `tier`,`roles`; consumer-interpreted, issuer-asserted.
- [x] Definition registry: `remote_application_attribute_defs` (remote_application_id, key, version, definition
      jsonb) + sqlc + core service (core/remote_application_attribute_defs.go,
      migrations/postgres/005_remote_application_attribute_defs.up.sql); OPAQUE storage (no interpretation).
- [x] Generic API: write (RegisterRemoteAppAttributeDef) + read/resolve (ResolveRemoteAppAttributeDef by
      (remote_application, key[, version])); HTTP /remote-applications/{slug}/attribute-defs (POST owner-only,
      GET any authenticated platform).
- [x] Reference resolution: `Claims.AttributeReference`/`AttributeIsReference` ref-vs-inline detector; opt-in
      verify-time hydration behind `WithAttributeHydration` (resolve ref → definition; Service-backed default
      resolver maps issuer → remote_application → registered def by the ref key).
- [x] Reserved well-known-key registry (`tier` string, `roles` uuid[]) documented on the contract; AuthKit only
      transports, shape-validates (WithAttributesPolicy), and resolves opaque refs.
- [ ] Cross-link: resolve OpenRails #481's escape-hatch decision here. NOT done (cross-repo OpenRails issue).
- [x] Tests: INLINE round-trip (TestDelegatedAccessRoundTripsArbitraryAttributes + TestAttributeReferenceDetection);
      REFERENCE round-trip (TestRemoteAppAttributeDefRegistry register→resolve; TestAttributeHydrationResolvesReference
      mint ref token → opt-in hydration); `WithAttributesPolicy` rejection (TestAttributesPolicyValidator).
---

# #74: Split `profiles.tenants` into ORG (native) + REMOTE_APPLICATION (federation) — de-conflate the dual-purpose tenant row

**Completed:** yes

Design (Paul, 2026-06-13): conflation #1. One `profiles.tenants` row is doing DOUBLE DUTY — it is both an
ORG (native cluster: identities we authenticate) and a REMOTE_APPLICATION (federation cluster: an external
system we verify via JWKS). The `tenant_issuers` comment admits it: "A tenant brings its own users that
authenticate via the tenant's OIDC issuer rather than local passwords." Nothing today enforces org-XOR-remote;
a row can be both. Split them into two first-class concepts.

## The two clusters (today, all hanging off `profiles.tenants`)
- **ORG / native** (keep the name `tenant` = org/workspace): `tenants.owner_user_id`, `is_personal`,
  `tenant_memberships`, `tenant_roles`, `tenant_role_permissions`, `tenant_invites`, `service_tokens`.
- **REMOTE_APPLICATION = a PRINCIPAL, credential = JWKS** (NEW concept/name). A remote_application is just
  like a `user` except it authenticates by signing JWTs we verify against its JWKS/public key (vs a user's
  password/OIDC). It holds only credential-specific state: slug, issuer + jwks_uri/public key (was
  `tenant_issuers`), creator `owner_user_id` → `profiles.users`. It IS a member of tenants with roles (see
  Principal model). `tenant_subjects` (delegated OIDC subjects; the END-USERS a remote_app vouches for) is a
  SEPARATE concept — not memberships, perms ride on the token (#75) — but also moves to the federation side.

## Naming decision (Paul, 2026-06-13)
- KEEP `tenant` = the native org/workspace (matches SaaS convention; avoids reverting the org→tenant migration
  across tensorhub). INTRODUCE `remote_application` for the federation half. ("remote_application" over
  `trusted_issuer` [undersells: also brings subjects + the escape-hatch protocol] / `client`/`relying_party`
  [OAuth-overloaded].) OpenRails keeps its own word "tenant" for a billing namespace — bridge fact:
  "an OpenRails tenant corresponds to an AuthKit remote_application."

## Principal model (Paul, 2026-06-13) — "a remote_app is a special kind of user"
- `user` and `remote_application` are both PRINCIPALS; they differ only in credential (password/OIDC vs
  JWKS/public key). They share ONE membership + role + permission system.
- **remote_application ↔ tenant is MANY-TO-MANY through the SAME machinery as users**: a remote_app can be a
  member of many tenants; a tenant can have many remote_app members; each membership carries a role →
  permissions ("cozy-art's backend may manage cozy-art's catalog" = a remote_app holding a role on a tenant).
- Cleanest schema: make membership POLYMORPHIC —
  `tenant_memberships(tenant_id, member_id, member_kind ['user'|'remote_application'], role)` — one table, one
  role system, one permission check for both principal kinds. `tenant_roles`/`tenant_role_permissions` unchanged.

## What changes
1. New `profiles.remote_applications` (id uuidv7, slug, owner_user_id → users, issuer + jwks_uri/public key,
   metadata) as a NEW numbered migration (NOT appended to 001 — migratekit name-tracking; service_tokens gotcha).
2. Move/re-point `tenant_subjects` (delegated end-users) to `remote_application_id`; the issuer/JWKS becomes the
   remote_application's own credential. Migrate federation-bearing `tenants` rows → remote_applications; backfill.
3. **Generalize membership to principals.** `tenant_memberships` becomes polymorphic (member = user OR
   remote_application). remote_app↔tenant is M:N with roles, same as user↔tenant. Independence still holds (a
   remote_app needs no tenant and vice-versa — M:N allows zero), but the LINK, when present, is a first-class
   membership with a role, NOT a bespoke grant. The org/`tenants` table still SHEDS its federation columns
   (issuer/subjects → remote_application).
4. Core API + http surface: separate org admin from remote_application admin (register/update remote app + its
   JWKS; manage its tenant memberships/roles; list its delegated subjects). Verifier reads JWKS from
   `remote_applications`. The verified principal (user OR remote_app) resolves roles via the shared membership.

## Delegated permissions (no change — confirmed correct)
- Delegated-user permissions stay ON THE TOKEN, not stored. There is (correctly) no delegated-permission
  table; `tenant_role_permissions` is native org RBAC only. Keep it that way.

## Open decision (cross-repo)
- App-specific escape hatch (remote app asserts "tier-2" → consumer maps to caps): a custom remote_app↔host
  protocol. Enforcement home is OpenRails `tier_policies` vs token-only — tracked in openrails #481; AuthKit
  side only needs to NOT model it as a native permission.

## Scope / sequencing
- Largest, most invasive layer; mostly impacts TENSORHUB (the only heavy AuthKit-federation user). OpenRails
  layers (#480 embedded self-register, #481 standalone decouple) are INDEPENDENT and do not block on this —
  do them first; land this when tensorhub can absorb the migration.

**Tasks:**
- [x] NEW numbered migration: `profiles.remote_applications` (slug, owner_user_id, issuer + jwks_uri/public key)
      + re-point `tenant_subjects` to `remote_application_id`; backfill from federation-bearing `tenants` rows.
      (migrations/postgres/004_remote_applications.up.sql)
- [x] Polymorphic `tenant_memberships` (member_id + member_kind ['user'|'remote_application']); remote_app↔tenant
      M:N via the SAME `tenant_roles`/`tenant_role_permissions`. org/`tenants` sheds issuer/subject columns
      (tenant_issuers dropped, subjects re-pointed). Per-kind FK enforced by trigger.
- [x] sqlc queries + core service: remote_application CRUD (owner = native user) + JWKS
      (core/service_remote_applications.go); remote_app tenant membership/role assignment reusing the
      user-membership paths (core/remote_application_memberships.go); delegated-subject listing
      (ListRemoteAppSubjects); verifier reads JWKS via remote_application (LoadRemoteApplications /
      lazyLoadIssuer) and resolves the remote_app principal's tenant roles (RemoteApplicationTenantRoles).
- [x] HTTP routes: split org admin vs remote_application admin; replaced the tenant-as-issuer routes with
      /remote-applications (+ /{slug}/subjects, /{slug}/memberships) (http/remote_application_handlers.go,
      routes.go).
- [x] Remove dead "tenant brings own issuer" paths from core/tenants; update comments.
- [ ] tensorhub migration plan + coordinated version bump (cross-repo; tensorhub tenants that were really
      remote apps move over). NOT done here — separate repo.
- [ ] Docs: README/embedding — the two-cluster model + OpenRails-tenant ≈ AuthKit-remote_application bridge
      fact. NOT done (no README change requested in scope).
---

# #68: HARD CUT: delegated tokens are issuer-only — no tenant_id AND no tenant slug claims

**Completed:** yes

Owner decision (Paul, 2026-06-11), reverses the v0.19 hard-cut-to-tenant_id (commit 2862ca2): a delegated access token identifies its tenant by `tenant` (slug) + validated `iss` ONLY, plus `delegated_sub` (the host's stable user uuid). Resource-account uuids are receiver-internal and never ride in tokens — a host knows its chosen slug the way a user knows their username, and has no business knowing its uuid inside a receiver. Receivers MUST pin their internal tenant record from the validated issuer via their issuer registry (the registration belongs to exactly one tenant, making the relationship immutable across slug renames) and cross-check the slug claim. Slug renames invalidate outstanding short-TTL tokens by design; hosts mint with the new slug.

IMPLEMENTED (working tree, releases as v0.22.0 — BREAKING):
- DelegatedAccessParams.TenantID removed; mint writes no tenant_id claim.
- Verifier REJECTS delegated tokens carrying tenant_id (`delegated_access_has_tenant_id`) — no legacy acceptance, same treatment as the forbidden user_tier/roles claims.
- DelegatedPrincipal.TenantID removed. Claims.TenantID retained ONLY for the opaque service-token DB-resolution path (server-internal data); extractClaims never reads tenant_id from a JWT.
- IssuerOptions.TrustedResourceAccount now binds against the slug claim only.
- core.TouchTenantSubjectForIssuer(ctx, issuer, subject) added: resolves the tenant from the issuer registry (enabled-only, fail-closed) then touches (uuid, issuer, subject); the Required() middleware uses it instead of the removed claim.
- Tests: http/delegation_slug_only_test.go (slug-only mint/verify, tenant_id rejection, slug-only TrustedResourceAccount binding); full suite green.
- Docs: agents/api-endpoints.md + README federation section updated.

Consumers adapted in their own working trees with TEMPORARY `replace` directives pointing at this checkout (drop on release + pin bump): openrails, doujins, hentai0, tensorhub (moves to issuer-pinned resolution), cozy-art.

EXTENDED (Paul, same day, releases as v0.23.0): the `tenant` SLUG claim is removed too. The validated `iss` IS the tenant identity — a host's complete identity is its issuer URL + signing key; the receiver's issuer registry maps issuer -> internal tenant record (slug + uuid). Mint: DelegatedAccessParams.Tenant removed. Verify: delegated tokens carrying `tenant` are rejected (`delegated_access_has_tenant`), same as `tenant_id`. DelegatedPrincipal.Tenant removed. IssuerOptions.TrustedResourceAccount replaced by IssuerOptions.TenantSlug — pure issuer-registry data that resolves the principal's tenant for the service-JWT path (never compared against token claims; the claim-vs-registry mismatch check is structurally impossible now and was deleted). Side effect: tenant slug renames no longer invalidate in-flight delegated tokens — renames are fully transparent. Trade-off accepted by Paul: the misconfiguration backstop (host asserting a tenant it isn't) moves entirely to registration hygiene.

**Tasks:**
- [x] Mint: remove TenantID param + claim write (http/delegation.go).
- [x] Verify: reject tenant_id claim on the delegated profile; slug-only resource-account binding (http/verifier.go).
- [x] Claims/DelegatedPrincipal: drop token-sourced TenantID; document service-token-only population (http/claims.go).
- [x] Middleware: TouchTenantSubjectForIssuer (issuer-registry resolution, fail closed) (http/middleware.go, core/tenant_subjects.go).
- [x] Tests + docs updated; full go test ./... green.
- [x] v0.23.0 extension: drop the tenant slug claim too (mint+verify+principal); TrustedResourceAccount -> TenantSlug registry data; tests + docs updated; full suite green.
- [ ] Release v0.22.0 (tag + push — Paul), then consumers bump pins and drop the temporary replace directives.
---

# #69: Configurable Postgres schema name (replace hard-coded `profiles`)

**Completed:** yes

**IMPLEMENTED 2026-06-12 (working tree, uncommitted; pending release/tag).** Design: runtime qualifier rewrite via a `DBTX` wrapper (`internal/db/schema.go`: `ForSchema`/`RewriteSQL`/`ValidSchemaName`); identity (no wrapper) for the default schema. New API: `core.Config.Schema`, `core.Service.Schema()`, `migrations/postgres.FSForSchema`, `authhttp.*InSchema` helpers, `identity.NewStoreInSchema`. Full suite green incl. DB-backed + new non-default-schema e2e. Known pre-existing failure (NOT this change): `TestDevserverRBACE2E` slug `"service token-e2e-%d"` contains a space — fails on clean HEAD too; fix separately.

Make the hard-coded `profiles` Postgres schema name configurable so multiple embedders can share one database without colliding. Today every SQL statement is schema-qualified with the literal `profiles.` (raw SQL in core/*.go, sqlc-generated code in internal/db/, and migrations/postgres/*.sql which `CREATE SCHEMA profiles` etc.), so two apps embedding authkit against the same database unavoidably share one set of tables — e.g. doujins' end users and openrails' control-plane orgs currently cohabit `profiles.tenants`/`profiles.users` in a shared dev DB.

Design constraints:
- New config knob (e.g. `core.Config.Schema`) defaulting to `"profiles"` — zero behavior change for existing embedders; validate against a strict identifier regex to prevent SQL injection via config.
- Hosts hand authkit a SHARED pgx pool (`svc.WithPostgres(pool)`), so pool-level `search_path` mutation is off the table; the schema qualifier stays in the SQL as a rendered variable.
- Migrations are executed by HOSTS via the embedded FS (`migrations/postgres.FS`); expose a schema-rendering fs.FS wrapper while keeping the raw FS export working.
- Sweep ALL packages for the literal schema (core, internal/db, roles, identity, storage, riverjobs, http, oidc, password, siws, devserver), including non-SQL appearances (`profiles.uuid_v5`, error messages, triggers).

**Tasks:**
- [x] Add validated `Schema` config field (default `profiles`)
- [x] Render schema into raw SQL in core/*.go and all other packages
- [x] Render schema into sqlc-generated queries (startup-time substitution or equivalent)
- [x] Schema-rendering wrapper for the embedded migration FS (raw FS stays exported)
- [x] Tests: non-default schema leaves no literal `profiles.` in rendered SQL/DDL; default-schema behavior unchanged
- [x] go build / go vet / go test green

---

# #67: Standardize embedder verification config on AUTH_REQUIRE_VERIFIED_REGISTRATIONS bool; retire 'none' from the embedder surface

**Completed:** yes

Fleet decision (2026-06-11): every authkit embedder (doujins, hentai0, tensorhub, cozy-art) exposes ONE registration-verification knob: config key auth.require_verified_registrations / env AUTH_REQUIRE_VERIFIED_REGISTRATIONS, a bool, DEFAULT TRUE. Semantics: true => core.RegistrationVerificationRequired (verification gates login); false => core.RegistrationVerificationOptional (verification email/SMS is STILL SENT on signup when a sender is configured, but never blocks login; with no sender, core already degrades gracefully by creating the user as verified and sending nothing — see CreatePendingRegistration* 'verified := s.email == nil'). The 'none' tier (no verification artifacts at all) is no longer reachable from any embedder's config; embedders were migrated to this pattern in their own repos on 2026-06-11.

DECISION 2026-06-11 (Paul): authkit KEEPS the tri-state enum (none/optional/required) as its library interface — third-party embedders may legitimately want 'none'. Do NOT convert core.Config.RegistrationVerification to a bool. The bool (AUTH_REQUIRE_VERIFIED_REGISTRATIONS, default true, true=>required, false=>optional) is the FIRST-PARTY EMBEDDER config convention only; each app maps bool->enum at its config boundary (already done in doujins/hentai0/tensorhub/cozy-art).

**Tasks:**
- [x] Document the canonical embedder pattern in README/embedding docs: AUTH_REQUIRE_VERIFIED_REGISTRATIONS bool (default true), true=>Required, false=>Optional (still sends, never blocks; no-sender degrades gracefully). Done: new "#### Registration verification: the AUTH_REQUIRE_VERIFIED_REGISTRATIONS embedder convention" subsection in README.md (Registration section) — documents the bool->enum mapping, that the tri-state enum stays the library interface for third-party embedders (incl. 'none'), and the optional+no-sender graceful-degrade (user created verified, nothing sent). Cross-linked from the existing `RegistrationVerification: none|optional|required` bullet.
- [x] Decide fate of core.RegistrationVerificationNone: KEEP the enum incl. 'none' (decision 2026-06-11, see description); document it as available to embedders that want no-verification behavior, while the first-party convention maps bool->required/optional.
- [x] (SKIPPED per Paul 2026-06-14 — devserver stays enum) authkit-devserver: replace DEVSERVER_REGISTRATION_VERIFICATION tri-state (default 'none') with the standardized bool knob.
- [x] Add a core test asserting Optional-with-no-sender creates the user as verified and sends nothing (locks in the graceful-degrade contract embedders now rely on). Done: core/registration_optional_no_sender_test.go — TestRegistrationOptionalNoSenderCreatesVerifiedAndSendsNothing asserts Optional + no sender creates the user already-verified and returns no code (nothing sent); companion TestRegistrationOptionalWithSenderSendsAndLeavesUnverified pins the genuine send path (1 SendVerification call, user left unverified). Both DB-backed (AUTHKIT_TEST_DATABASE_URL); ran green.

---

# #84: First-class AuthKit bootstrap manifest/API/CLI

**Completed:** yes

**Status:** COMPLETED 2026-06-17: implemented `core.BootstrapManifest` as a wrapper over the existing org manifest
reconciler, added user/global-role/password seeding, user-ref org memberships, static or JWKS issuer trust roots,
bootstrap token-store aliases, opt-in startup auto-load, `bootstrap apply --file ... [--dry-run]`, docs, focused tests,
and a real `authkit-devserver` compose E2E that boots from `AUTHKIT_BOOTSTRAP_ON_START=true` and verifies the seeded
user, service token/API key, JWKS issuer, and static public-key issuer. `org-manifest apply` remains as a compatibility
command for org-only manifests.

AuthKit already has the core of this idea in `OrgManifest` / `ReconcileOrgManifest` and the devserver-only
`org-manifest apply` command, but that surface is too narrow and too devserver-shaped for host applications.
Make bootstrap a first-class AuthKit capability: one declarative auth manifest reconciler, exposed through startup
auto-load, embedded/library APIs, and a standalone CLI command.

This is the generic authority graph. Host applications such as OpenRails should call AuthKit bootstrap for
AuthKit-owned state, then apply their own domain layer afterward. OpenRails' extra layer is merchants, merchant-owner
links, catalog/products/prices/provider mappings, and OpenRails resource references. AuthKit should store opaque
permissions/resources, but it should not learn what an OpenRails merchant is.

## Current State

- `core.BootstrapManifest` declares users, global roles, orgs, trusted issuers/remote applications, roles, memberships,
  and generated service tokens. Org state embeds the existing `OrgManifest` shape under `orgs:`.
- `core.ReconcileBootstrapManifest` seeds users/global roles first, resolves manifest-local `user_ref` values into
  AuthKit-owned user IDs, then calls `core.ReconcileOrgManifest` for org/provider/token state.
- `core.ReconcileOrgManifest` still applies org state idempotently under a Postgres advisory lock.
- `authkit-devserver bootstrap apply --file <path> [--dry-run]` exists. `authkit-devserver org-manifest apply` remains
  for org-only compatibility.
- Registration posture already supports locked-down deployments via `NativeUserRegistrationMode` and
  `OrgRegistrationMode`.
- Deliberate non-features: password secret references and imported service-token hashes are not built into the manifest;
  hosts should render secrets before apply or provide their own token store / bootstrap wrapper.

## Desired Shape

- Default bootstrap file path: `/etc/authkit/bootstrap.yaml`.
- Startup hook: optional, idempotent/additive by default, advisory-locked, and safe for multi-replica startup.
- Library API: host applications can parse and reconcile a bootstrap manifest directly without shelling out to a
  devserver binary.
- Standalone CLI: `authkit bootstrap apply --file <path>` with dry-run/plan output.
- Existing `OrgManifest` should be evolved or wrapped into the broader `BootstrapManifest`; do not create a parallel
  second reconciler that drifts from the current org manifest path.

## Manifest Scope

AuthKit-owned bootstrap state:

- users and imported users;
- password credentials, password-hash imports, or reset-required imported credentials;
- orgs;
- roles and role permission sets;
- user memberships and role assignments;
- remote applications / trusted issuers / JWKS URIs / static trust roots where supported;
- remote-application memberships/roles when the issuer is org-owned;
- generated service tokens with secret output targets;
- optional imported service-token hashes if explicitly designed and documented;
- registration posture for private deployments where appropriate.

Host-owned state is out of scope:

- OpenRails merchants, catalog, prices, entitlements, provider mappings, processor credentials, merchant secrets;
- Tensorhub media/workload/project state;
- any app-specific meaning of permissions or service-token resource strings.

## Tasks

- [x] Define `core.BootstrapManifest` and decide whether it replaces `OrgManifest` or embeds it as an `orgs:` section.
      Done: it wraps `OrgManifest` under top-level `orgs:`.
- [x] Add strict YAML parsing with unknown-field rejection and clear validation errors.
- [x] Add user seeding/import support: email/phone/username, disabled/banned flags where supported, metadata, and
      password setup policy.
- [x] Decide password credential shape: plaintext initial password, imported hash, reset-required placeholder, or
      secret-reference. Done: supports plaintext, imported hash+algo, and reset-required; secret-reference is explicitly
      left to host rendering/secret managers.
- [x] Extend reconciliation to seed orgs, roles, role permissions, memberships, remote applications, and service tokens
      through the existing core APIs.
- [x] Preserve the current service-token output-store contract and make token minting idempotent: existing non-empty
      output means keep, not remint.
- [x] Add `BootstrapTokenStore`/secret-output naming if the current `OrgManifestTokenStore` becomes too org-specific;
      keep file-backed output for local/self-hosted and leave Vault/Kubernetes stores host-implementable.
- [x] Add `core.LoadBootstrapManifestFile`, `core.ParseBootstrapManifestYAML`, and
      `(*Service).ReconcileBootstrapManifest(ctx, manifest, store, opts)`.
- [x] Add dry-run/plan support that reports creates/updates/kept tokens without mutating state.
- [x] Add startup auto-load from `/etc/authkit/bootstrap.yaml`, gated by explicit config/env such as
      `AUTHKIT_BOOTSTRAP_ON_START=true`; startup mode must be additive and non-destructive.
- [x] Add a standalone CLI command: `authkit bootstrap apply --file <path> [--dry-run]`.
- [x] Decide the fate of `authkit-devserver org-manifest apply`: keep as a compatibility alias temporarily, or replace it
      with the standalone bootstrap command.
- [x] Ensure all three surfaces call the same reconciler: startup auto-load, library API, and CLI.
- [x] Add advisory-lock coverage proving concurrent startup/CLI runs do not mint duplicate service tokens.
- [x] Add tests for idempotency, unknown-field rejection, user/password seeding, role replacement, remote application
      upsert/disable, token output preservation, dry-run no-op behavior, and standalone devserver startup bootstrap.
- [x] Update README and API docs with private/closed deployment examples and host-app layering guidance.
- [x] Add OpenRails integration notes: OpenRails should pass `auth:` through to AuthKit bootstrap, then reconcile
      merchants/catalog/provider state itself.

## Acceptance

- A private AuthKit deployment can be fully authority-bootstrapped from a YAML file without public registration.
- Embedded hosts can call the same bootstrap reconciler directly.
- Standalone AuthKit can run `authkit bootstrap apply --file ./bootstrap.yaml`.
- AuthKit can optionally auto-apply `/etc/authkit/bootstrap.yaml` on startup when explicitly enabled.
- Re-running bootstrap is safe and idempotent; generated service tokens are not duplicated.
- OpenRails no longer needs to hand-roll AuthKit org/user/role/service-token/remote-application seeding once it adopts
  this API; it only layers merchant/catalog/provider state on top.

---

# #77: remote_application owned by an ORG (org_id FK), not a user

**Completed:** yes

`profiles.remote_applications.owner_user_id -> users` has been removed. Issuer ownership is now the
optional owning ORG: `remote_applications.org_id -> orgs`. One org can own MANY remote_applications
(issuers). `org_id IS NULL` means bootstrap/operator-managed with no AuthKit user/org owner.

WHY:
- Robustness: ownership survives the creator leaving the org (it's the org's, not a person's).
- Operator identity (openrails#491): the MERCHANT is the authenticated OPERATOR — its issuer/AuthKit org in
  OpenRails-authkit controls the merchant (e.g. tensorhub). issuer -> merchant via the issuer registry; the merchant
  then ASSERTS (customer, actor) for its own namespace (opaque, not re-authenticated). There is NO
  org<->merchant identity FK; owner_org_id stays ownership/admin-only. #77's org ownership of the issuer is
  the authkit-side admin anchor (who owns the operator's signing key), not a billing-resolution hop.
- Clean separation: the polymorphic `org_memberships` then means ONLY "this issuer's self-token gets
  these roles" (#76) — purely auth, fully decoupled from ownership/billing.

**Tasks:**
- [x] Migration (007): add the original `remote_applications.tenant_id` transitional FK and backfill from the
      creator's personal tenant; migration 009 later renames it to `org_id`.
- [x] Migration (013): remove `remote_applications.owner_user_id`; keep only optional `org_id` owner.
- [x] Core: GetRemoteApplication/all reads return org_id; upsert persists optional org owner; added
      ResolveRemoteApplicationOrg(issuer). Handlers accept/return org_id.
- [x] org_memberships kept roles-only (unchanged); ownership(org_id) vs roles(membership) split.
- [x] Tests: org-less/bootstrap issuer round-trip proves `org_id` is optional and `owner_user_id` is gone.
- [x] Consumer note: openrails#491 merchantForIssuer switches to AuthKit `remote_applications.org_id` and maps it
      to the OpenRails merchant by `merchants.owner_org_id` (verified in OpenRails `internal/controlplane`).

**Related**
#74 (remote_application table this amends), #76 (membership = roles only, post-split), openrails#491
(customer/actor split + merchantForIssuer via org_id), openrails#500 (`owner_org_id` on merchant —
the billing-side anchor this mirrors).

---

# #82: Real-HTTP permission-boundary tests for org-owned remote_application management

**Completed:** yes
**Status:** COMPLETED 2026-06-15: added `http/TestRemoteApplicationHTTPOrgBoundary`, a DB-backed real-HTTP test that
mounts the AuthKit API router and proves org-owned remote_application create/update/delete boundaries through real
tokens and real org RBAC.

Add integration coverage proving that a remote_application trust root is controlled only by the owning org's RBAC, or
by explicit bootstrap/operator flows when `org_id IS NULL`.

## Current coverage

- `http/TestRemoteApplicationHTTPOrgBoundary` mounts `Service.APIHandler()` with a real Postgres-backed core service and
  proves:
  - a user with `org:remote_applications:manage` in org A can create and delete org A remote_application rows;
  - malformed registration returns `400`;
  - missing bearer returns `401`;
  - a user in org A without `org:remote_applications:manage` returns `403`;
  - a user with manage permission in org B cannot mutate org A's existing issuer;
  - normal org-scoped user routes cannot create new `org_id`-empty trust roots;
  - existing `org_id`-empty bootstrap/operator trust roots cannot be deleted by normal org managers;
  - service tokens, remote_application self-tokens, and delegated-user tokens are rejected with `401`.
- Core tests prove remote_application round-trip behavior, validation, org-less rows, and `owner_user_id` removal.
- Verifier tests prove JWKS self-token authority is stored/assigned and cannot widen beyond AuthKit grants.
- Handler tests cover unauthenticated/delegated-principal rejection and malformed request bodies.

## Gap Addressed

Before this issue, there was no real-HTTP integration suite that logged in or authenticated real principals, mounted
the AuthKit HTTP routes, and proved `org:remote_applications:manage` boundaries across multiple orgs. That gap is now
covered by `http/TestRemoteApplicationHTTPOrgBoundary`.

## Tasks

- [x] Add a real HTTP integration test that mounts AuthKit routes with a real service/core store and uses HTTP clients
      rather than calling handlers directly.
- [x] Fixture two orgs, users in each org, and roles with/without `org:remote_applications:manage`.
- [x] Prove a user with `org:remote_applications:manage` in org A can create/update/delete a remote_application owned
      by org A.
- [x] Prove a user lacking `org:remote_applications:manage` in org A cannot create/update/delete org A
      remote_applications.
- [x] Prove a user with manage permission in org B cannot mutate org A remote_applications.
- [x] Prove remote_application self-tokens, delegated-user tokens, and service tokens cannot mutate trust roots unless
      an explicit route is intentionally designed for that principal type.
- [x] Prove `org_id IS NULL` bootstrap/operator-managed remote_applications are not mutable through normal org-scoped
      user routes.
- [x] Assert HTTP status mapping: unresolved/no session => `401`; resolved principal without permission or wrong org
      => `403`; malformed registration => `400`.
- [x] Run the new test with `go test` and record the exact command in this issue.

## Verification

- `go test ./http -run TestRemoteApplicationHTTPOrgBoundary -count=1` compiled and ran the package; local DB-backed
  body skipped because `AUTHKIT_TEST_DATABASE_URL` is not set in this shell.

## Acceptance

- Remote application trust roots cannot be modified by their own JWKS credential.
- Remote application trust roots cannot be modified by a user in the wrong org.
- Remote application trust roots can be modified by org principals only through `org:remote_applications:manage`.
- Bootstrap/operator-managed trust roots remain outside normal org RBAC mutation paths.

---

# #83: Finish AuthKit `tenant` -> `org` cleanup and OpenRails resource-string handoff

**Completed:** yes
**Status:** COMPLETED 2026-06-15: OpenRails-owned resource strings have been updated to merchant/customer
vocabulary; AuthKit namespace-state metadata values have been hard-cut from `registered_tenant`/`parked_tenant` to
`registered_org`/`parked_org` with migration 014. Added the active-code tenant-residue scan gate and verified
`go test ./...`.

## Rule

- AuthKit organization model: `org`.
- OpenRails billing/isolation namespace resource strings: `merchant` after openrails#503.
- Historical migrations may keep `tenant` only when the recorded migration chain requires it.
- Do not reintroduce user ownership for remote applications; remote applications remain optionally `org_id` owned.

## Current evidence

Initial `tenant` hits were mostly:
- forced historical migrations before `009_tenant_to_org.up.sql`;
- comments/tests using OpenRails-owned resource strings like `openrails.tenant`, `openrails.tenant_subject`, and
  `openrails:tenant:admin`;
- stored owner namespace-state values `registered_tenant` / `parked_tenant`;
- a few active comments describing no-escalation examples.

## Dependencies

- Coordinate with OpenRails #503 for final resource/permission names:
  - `openrails.tenant` -> `openrails.merchant`;
  - `openrails:tenant:*` -> `openrails:merchant:*`;
  - `openrails.tenant_subject` -> `openrails.customer`.

## Tasks

- [x] Inventory every active AuthKit `tenant` hit and classify it as:
      - AuthKit org model residue -> rename to `org`;
      - OpenRails opaque resource string -> update only when OpenRails #503 lands;
      - forced migration history -> leave with an explanatory comment;
      - stale tracker/docs text -> update if active, ignore if historical completed issue text.
- [x] Update active comments and examples that still use `tenant` for AuthKit orgs.
- [x] Update AuthKit service-token tests and permission/resource examples from OpenRails legacy strings to the new
      OpenRails merchant strings once the OpenRails side has cut over.
- [x] Confirm all JWT/session/login/user/org APIs mint and verify only `org`, `org_id`, and `org_roles`; no `tenant`
      claim fallback or dual-write exists.
- [x] Confirm remote_application APIs and generated models expose `org_id`, not `tenant_id`, and that
      `owner_user_id` remains gone.
- [x] Decide whether to compact or leave the historical migration chain:
      - leave `001`/pre-`009` tenant names if fresh migration correctness depends on them;
      - only compact if migration tooling and existing deployments make it safe.
- [x] Add a focused scan/test gate that fails on active AuthKit `tenant` identifiers outside the allowlist for forced
      migrations and coordinated OpenRails legacy-resource strings.
- [x] Run sqlc/codegen, `go test ./...`, and any migration fresh-apply/idempotency tests.

## Acceptance

- Active AuthKit code and docs no longer use `tenant` for the AuthKit organization model.
- Any remaining `tenant` text is either forced historical migration text or explicitly tracked OpenRails legacy
  resource vocabulary pending/remediated through openrails#503.
- AuthKit and OpenRails agree on final cross-repo strings: AuthKit `org`; OpenRails `merchant`.

---

# #78: Drop tenant_subjects — the delegated-user registry is not load-bearing

**Completed:** yes. The AUTH finding still holds: delegated subjects are not load-bearing AuthKit state. #81 briefly
restored `delegated_users`, then re-dropped it after the invoker model settled on opaque text with no FK.

tenant_subjects persists nothing the auth decision needs. The ONLY write is TouchTenantSubject (an
idempotent upsert + last_seen_at bump on each delegated login); its own code comment says it is "never read
from a request" — authorization rides ENTIRELY on the token. So the table is a write-mostly activity
registry plus a speculative anchor for per-subject state that DOES NOT EXIST: there are no per-subject
attribute VALUES and no revocation today — only the attribute DEFS (#75) are stored, and values ride on the
token. OpenRails separately records (issuer, subject) for billing (customers -> actors, openrails#491), so
delegated-user tracking is redundant on the auth side. Drop it.

PRESERVE the one side-effect the touch also provided: the FAIL-CLOSED ISSUER GATE — the middleware resolved
the remote_application by issuer on every delegated token and rejected unknown/disabled issuers. That gate
MUST remain; move it to a read-only remote_application(issuer) enabled-check on the verify path (no write on
the hot path).

**Tasks:**
- [x] Replaced the TouchTenantSubject* call in the delegated-token middleware with a read-only
      GetRemoteApplication(issuer) enabled lookup — unknown/disabled issuers still fail closed, NO
      per-request write.
- [x] Deleted core/tenant_subjects.go + TenantSubjectTouch/TenantSubjectsByApp queries + the db model
      (sqlc regen); also removed dead ListRemoteAppSubjects + the /{slug}/subjects route + handler.
- [x] Migration (008): DROP TABLE tenant_subjects. (001 baseline KEEPS the CREATE — recorded 003/004
      ALTER/COMMENT hard-reference the table, so removing it from 001 breaks fresh-DB apply; 008 drops it
      last. Verified full 001->008 chain green on a fresh DB.)
- [x] Confirmed nothing else references it (grep clean across core/http/internal).
- Future note: if per-subject revocation / #75 reference-mode VALUES are ever wanted, reintroduce a purpose-built
  table then. That is not part of the current AuthKit delegated-token verifier.
- [x] Tests: delegated auth + fail-closed unknown/disabled-issuer rejection pass (http suite green); no
      per-request write on the delegated path.

**Related**
#74 (created the remote_application model + re-pointed this table), #75 (attribute DEFS stay; only defs are
stored — values ride on the token), #76 (permissions on the principal), openrails#491 (delegated-user
(issuer, subject) is tracked on the BILLING side as the actor — the non-redundant place).

---

# #79: Rename `tenant` -> `org` across AuthKit (completes the de-conflation)

**Completed:** yes

We already renamed OpenRails `tenant` -> `merchant` (openrails#480) because the two "tenant" concepts
collided. This finishes the job: rename AuthKit's `tenant` -> `org`, so the fleet has exactly ONE meaning
per word — **`org` = the organization (members, roles, owner) in AuthKit; `merchant` = the billing/isolation
namespace in OpenRails**; NO overloaded "tenant" anywhere. "org" also matches the domain (it's an
organization à la GitHub orgs), whereas "tenant" is the infra-isolation term — which is what `merchant` now
is. This is a LARGE but MECHANICAL (low logic-risk) rename; the risk is breadth + the wire-facing `tenant`
claim, not logic.

NAMING: table `orgs`; type `Org`; column `org_id`; tables `org_memberships` / `org_roles` /
`org_role_permissions` / `org_invites` / `org_renames`; JWT claim `org`; `Claims.Org` / `Claims.OrgID`;
`ResolveOrgBySlug`; org-scoped routes. SUPERSEDES #77's `remote_applications.tenant_id` -> `org_id` (that
column is a day old).

SCOPE (authkit):
- Tables/columns: `tenants` + every `tenant_*` table + every `tenant_id` FK column.
- Polymorphic membership: `tenant_memberships(tenant_id, member_id, member_kind, role)` -> `org_memberships(org_id, ...)`. RBAC: `tenant_roles` / `tenant_role_permissions` -> `org_*`. Also `tenant_invites`, `tenant_renames`, `owner_reserved_names` (if tenant-scoped).
- remote_applications.tenant_id (#77) -> org_id; ResolveRemoteApplicationTenant -> ResolveRemoteApplicationOrg.
- Go: `Tenant*` types/funcs -> `Org*`; `Claims.Tenant`/`TenantID` -> `Claims.Org`/`OrgID`; `ResolveTenantBySlug` -> `ResolveOrgBySlug`; the `tenant` login body param -> `org`.
- Routes: tenant-scoped paths/handlers -> org.
- sqlc: regen after the query + schema renames.

WIRE (HARD CUT — owner decision: NO legacy support):
- Mint + verify ONLY the `org` claim. NO `org ?? tenant` fallback, NO dual-write — the `tenant` claim is
  GONE. Requires a COORDINATED deploy (authkit + the org-using consumers ship together); old `tenant`
  tokens stop verifying after cutover. Acceptable — pre-prod, we control all consumers.

MIGRATION (migratekit name-tracked):
- NEW numbered migration 009: idempotent table/column/constraint/index renames (mirror openrails 019's
  guarded DO $$ blocks). Top-level `ALTER TABLE IF EXISTS ... RENAME` where sqlc must parse the final name;
  guarded DO blocks for constraints/indexes. Converge fresh + existing DBs to the `org` names.
- Update the 001 baseline to the new names WHERE the parser allows (note: earlier recorded migrations 003/004
  reference `tenant_subjects`/`tenant_memberships` by old names with unguarded DDL — those specific
  references can't be edited, so 001 may have to keep an old name that 009 renames, exactly like the
  money_settings case in openrails#491; verify sqlc + fresh-DB apply stay green).

CONSUMER RIPPLE (separate repos, cascade after authkit tags) — HARD CUT, coordinated deploy:
- openrails control plane + tensorhub (+ maybe cozy-art): rename everywhere they read the `org` claim, pass
  the login `org` param, or call an org API. (merchants.owner_tenant_id is OpenRails-side naming; separate.)
- doujins + hentai0 DON'T use orgs -> dep bump only, NO org code changes.
- NO verifier fallback: old `tenant` tokens stop verifying at cutover.

**Tasks:**
- [x] Migration 009: idempotent rename of orgs + all org_* tables, columns, constraints, indexes (019-style). Top-level table/column RENAMEs (sqlc-visible) + guarded DO blocks for constraints/indexes/trigger; comments refreshed top-level. Validated on a fresh 001..009 apply AND idempotent.
- [x] 001 baseline: FORCED to keep ALL tenant names — migrations 002/003/004/007 reference profiles.tenants / tenant_memberships / tenant_issuers / tenant_subjects (and tenant_id cols) with unguarded DDL, so a fresh DB must create them as tenant_* before 009 renames them (the money_settings forced-remnant case). 009 does the whole rename; sqlc parses 001..009 cumulatively so generated code is org_*. Fresh apply + sqlc both green.
- [x] sqlc queries + regen: `tenant*` -> `org*` (orgs.sql, org_invites.sql + others; new generated types/methods; stale tenants.sql.go/tenant_invites.sql.go removed). make sqlc (generate+vet) green.
- [x] Go core/http: Tenant* -> Org*; Claims.Org/OrgID/OrgRoles; ResolveOrgBySlug; ResolveRemoteApplicationOrg; remote_app org_id; login body param `org`.
- [x] JWT claim: mint + verify ONLY `org`/`org_id`/`org_roles` (HARD CUT — no fallback, no dual-write; `tenant` claim removed; delegated-access guard now checks org/org_id).
- [x] Routes: org-scoped paths/handlers (/orgs, /orgs/{org}/*, /token/org, /admin/org/*).
- [x] Tests: build/vet/sqlc green; all tests pass. TestOrgInviteNoEscalation was a test-isolation bug (the "accept-time re-check" subtest correctly leaves a pending invite; the "happy path" subtest reused the same invitee and collided on the pending unique index during SETUP) — FIXED 4564339 by giving the happy-path subtest a distinct invitee; the no-escalation SECURITY invariant was verified intact. Preserved OpenRails-side strings (openrails.merchant*, openrails:merchant:*); namespace_state values were later hard-cut by #83 / migration 014.
- [x] Version bump/cascade completed after the hard cut. Current consumers pin AuthKit `v0.34.0`; OpenRails,
      Tensorhub, Cozy Art, Doujins, and Hentai0 are all past the org-claim rename with no `tenant` fallback.

**Related**
openrails#480 (the merchant rename this mirrors), #74/#76/#77/#78 (the de-conflation work this completes the
naming for), openrails#491 (sequence: rename first, then #491, then ONE fleet cascade carrying both).

---

# #80: remote_application.org_id -> NULLABLE — an issuer need NOT belong to an org

**Completed:** yes

REVERSES #77's `org_id NOT NULL` ("exactly one org"). Per owner (2026-06-14), an issuer is a standalone
JWKS-signing principal tied to a MERCHANT (on the OpenRails side), and it must be registerable WITHOUT an
org. Two concrete shapes prove it:

- STANDALONE OpenRails (doujins / hentai0): authkit there has NO users and NO orgs — only ISSUERS
  ([doujins, hentai0]) tied to the one merchant. authkit just remembers "this is the JWKS for doujins",
  OpenRails ties the merchant to that issuer. An org would be dead weight. -> org_id MUST be NULL-able.
- TENSORHUB (federated B2B2C): authkit HAS orgs ([cozy-art, ...]); cozy-art is BOTH an org AND an issuer.
  Here the issuer IS org-bound. -> org_id is SET.
- EMBEDDED (doujins/hentai0/cozy-art, and tensorhub for its OWN native users): the embedding app handles
  ALL security in-process; embedded OpenRails has NO security model of its own and defers entirely to the
  host. The host's authkit MIDDLEWARE validates the JWT, resolves identity, and attaches it to the request
  context before calling OpenRails — there is no merchant-auth / issuer step to OpenRails. doujins/hentai0/
  cozy-art embedded have NO issuers at all (no federation). tensorhub-embedded DOES register issuers — but
  only for federated sub-customers (cozy-art), never for tensorhub itself. (The host may run ONE OR MORE
  merchants; "app == one merchant" is the common case, not a rule.)

ORG SEMANTICS (owner, 2026-06-14): an "org" is a grouping of an APP's users / sub-customers, NEVER the app
itself. doujins is NOT an org in its own authkit and needs none; if it ever used orgs they'd be teams of
doujins' USERS. In tensorhub, cozy-art is an org precisely because it is a federated sub-customer that
delegates to its own users (org -> customer/payer, and org-bound issuer).

So org-binding is OPTIONAL, and (key insight, see openrails#491) the PRESENCE of org_id doubles as the
PAYER-RESOLUTION switch on the billing side:
  - issuer org-bound (cozy-art)  -> the ORG is the single payer/customer; the token SUBJECT is an INVOKER.
  - issuer org-less (doujins)    -> each token SUBJECT is its OWN payer/customer (1:1 with the invoker).

**Tasks:**
- [x] Migration 010: `ALTER TABLE profiles.remote_applications ALTER COLUMN org_id DROP NOT NULL` (FK kept,
      so a SET value still validates). Idempotent; fresh migration chain green.
- [x] Core: upsert already passes a nil org_id via sqlc.narg(org_id) + COALESCE read (from the #79 rename);
      ResolveRemoteApplicationOrg returns "" (not an error) for org-less issuers. POST /orgs flow unaffected.
- [x] No runtime fixups to drop: ProvisionOrg + POST /orgs both set org_id as a GENUINE "this issuer belongs
      to this org" binding (the issuer is registered as part of creating that org), not solely to satisfy
      NOT NULL — kept per spec. Test fixtures keep their (now-optional) org binding; harmless churn avoided.
- [x] Tests: TestRemoteApplicationOrgOptional — org-LESS issuer (doujins shape) resolves to "" and an
      org-BOUND issuer (cozy-art shape) resolves to its org id; both upsert + verify.

**Outcome:** org_id nullable (010), core already nil-tolerant, runtime org-binding sets are genuine and kept.
Build/vet/sqlc/full-suite green.

**Related**
#77 (set NOT NULL — this reverses it), #79 (org rename), #81 (delegated_users re-drop), openrails#491
(org-binding -> payer-resolution switch).

---

# #81: delegated_users — RESTORED (011) then REVERTED / RE-DROPPED (invoker is opaque text, no FK)

**Completed:** yes — restore shipped in 011, then the owner reversal re-dropped `delegated_users` in 012
after the invoker model settled on opaque text with no FK.

================================================================================
REVERSAL (owner, 2026-06-15) — DROP delegated_users again. The #81 premise
("downstream APP + BILLING want a stable FK ANCHOR for the delegated user") was
WRONG. The INVOKER ("under whose authority an action happened") is a POLYMORPHIC
principal — native-user | delegated-user | service-token | issuer/JWKS — stored as
OPAQUE TEXT (a stable uuidv7), with NO foreign key. OpenRails can't FK across
authkit's four principal tables (separate `profiles` schema) or across apps that
aren't even co-located, so NOTHING FKs to delegated_users: tensorhub's app columns
and openrails attribution are all opaque text. #78's "not load-bearing" finding
STANDS, and not even a registry is warranted — usage visibility = aggregate openrails
attribution rows BY the opaque invoker text; per-invoker limits = openrails budget
rows keyed BY the invoker text; authkit needs no invoker table at all.
ACTION DONE: migration 012 drops profiles.delegated_users; core/delegated_users.go,
its sqlc query file, generated code, and tests are gone. The RESTORE (011) recorded
below is now HISTORICAL. See openrails#491 (the paired `invoker_id uuid FK` ->
`invoker text` reversal).
================================================================================

REVERSES #78 ("drop tenant_subjects — the delegated-user registry is not load-bearing"). #78 was right that
AUTH does not need it (the token is the source of truth; no verify-path read). But #78 only asked "does
auth need it?" — it never asked "do downstream APP + BILLING domains want a stable FK anchor for the
delegated user?" They DO. The table literally existed before: created as `delegated_users` (001) -> renamed
`tenant_subjects` (003) -> re-pointed to remote_application_id (004) -> dropped (008). Restore it under its
ORIGINAL name `delegated_users`, now justified as a CROSS-DOMAIN identity anchor, not an auth artifact.

EVIDENCE (search, 2026-06-14): tensorhub ALREADY references a delegated end-user in FIVE NON-billing tables
via a soft `delegated_user_id` (no FK today): user_file_objects (media ownership), media_output_events,
resource_visibility_audit, platform_abuse_events, platform_policy_denials — plus per-delegated-user media
SCOPING, rate limits, and tier budgets. OpenRails separately wants it for invoker attribution + per-invoker
spend/abuse caps (openrails#491). A delegated user is fundamentally an IDENTITY ("a federated end-user
vouched for by issuer X") consumed by BOTH the app and billing -> it belongs in the identity service so
both FK to it and neither depends on the other. (If it lived in OpenRails, tensorhub's media-OWNERSHIP
tables would FK into the BILLING service — wrong-way coupling.)

DESIGN:
- Table `profiles.delegated_users (id uuid PRIMARY KEY DEFAULT uuidv7(), remote_application_id uuid NOT NULL
  REFERENCES remote_applications(id), issuer text NOT NULL, subject text NOT NULL /* the STABLE
  merchant-supplied uuid, never a username */, first_seen_at, last_seen_at,
  UNIQUE(remote_application_id, subject))`.
- id is uuidv7 (pg18 native — the fleet's UNIVERSAL pk; owner: uuidv7 everywhere, NO uuidv5). uuidv7 is
  random and CANNOT be content-derived, so idempotency rides the UNIQUE(remote_application_id, subject)
  natural key, NOT a derived id: `TouchDelegatedUser(ctx, issuer, subject) (id uuid)` does
  `INSERT ... ON CONFLICT (remote_application_id, subject) DO UPDATE SET last_seen_at=now() RETURNING id`.
  The id is minted ONCE and RETURNED; callers stamp the returned value (no independent computation). This is
  the old TouchTenantSubject shape, but now an FK anchor that RETURNS the id, not write-only logging.
- This REPLACES the two existing content-derivations (both go away): tensorhub `du_`+sha256(issuer\x00sub)[:32]
  (string) in platform_delegated_identity.go:36, and openrails FederatedCustomerID uuidv5(merchant\x00issuer
  \x00sub). Callers obtain the id from TouchDelegatedUser, not by hashing.
- Cross-schema FKs: openrails `billing` tables + tensorhub `public` tables both FK -> profiles.delegated_users(id)
  (same DB in every deployment). authkit OWNS "who"; it makes NO auth decision off this table (auth still
  rides the token only — #78's core finding stands).

**Tasks:**
- [x] Migration 011: recreate profiles.delegated_users (exact shape: id uuid PK DEFAULT uuidv7(),
      remote_application_id NOT NULL REFERENCES remote_applications(id) ON DELETE CASCADE, issuer, subject,
      first_seen_at/last_seen_at DEFAULT now(), UNIQUE(remote_application_id, subject)) + issuer index.
      Idempotent; fresh 001..011 chain green.
- [x] Core (core/delegated_users.go): `TouchDelegatedUser(ctx, issuer, subject) (string, error)` — resolves
      remote_application from the validated issuer, upsert ON CONFLICT (remote_application_id, subject) DO
      UPDATE last_seen_at RETURNING id; reads GetDelegatedUser(issuer, subject) + ListDelegatedUsersForIssuer.
      Unknown/disabled issuer -> ErrInvalidDelegatedUser. NO verify-path coupling (not wired into middleware).
- [x] Tests: TestDelegatedUserTouchIdempotent — repeated (issuer, subject) returns the SAME uuidv7 id;
      get/list find it; last_seen_at >= first_seen_at; unknown issuer fails closed.

**Historical outcome before reversal:** delegated_users was restored in 011 as a cross-domain FK anchor; uuidv7 pk,
idempotency on the UNIQUE natural key (no uuidv5/derived id). This was superseded by the 012 re-drop above.
**Re-drop tasks (the reversal — supersedes the restore above):**
- [x] New migration 012: `DROP TABLE IF EXISTS profiles.delegated_users CASCADE` (idempotent). It carries no
      load-bearing data (write-mostly; nothing FKs to it now).
- [x] Delete core/delegated_users.go (TouchDelegatedUser / GetDelegatedUser / ListDelegatedUsersForIssuer),
      its sqlc query file + generated code + models entry, and delegated_users_test.go. Re-run sqlc.
- [x] Build/full-suite green on the current migration chain (`go test ./...`).

**Related**
#78 (original drop — #81 un-dropped, this reversal re-drops; #78's finding was right all along),
#80 (nullable org_id — unaffected, stays), openrails#491 (paired reversal: invoker_id uuid FK -> invoker
text, no FK), [[invoker-opaque-text-polymorphic]] memory.

---

# #86: Rename long-lived machine credentials to API keys in public surfaces

**Completed:** yes

AuthKit's long-lived `profiles.service_tokens` are API keys in product terms: opaque bearer credentials stored as a hash, revocable, expirable, scoped to org permissions/resources, and used by machines via `Authorization: Bearer ...`.

Problem: the previous public name collided with user access tokens, delegated access tokens, service JWTs, and remote applications/issuers. Keep the storage/sqlc implementation name for now; change the public/bootstrap terminology to API keys.

Target public shape:

```yaml
orgs:
  - slug: example
    api_keys:
      - name: operator
        permissions:
          - openrails:admin
        resources:
          - kind: openrails.merchant
            id: example
        expires_at: null
        output:
          file: ./.secrets/openrails/operator.key
```

Rules:
- `api_keys` is the preferred manifest/bootstrap field.
- `service_tokens` is rejected as an unknown legacy manifest field; do not accept or document it.
- API keys are org-owned, not user-owned. `created_by` is audit only.
- `permissions` and `resources` keep the existing meaning.
- `output` writes the plaintext once; existing non-empty output means keep, do not mint.
- Current presented keys still use the existing `<prefix>_st_<key_id>_<secret>` mechanics.
- `prefix` is configured once by the issuing app/deployment through `APIKeyPrefix`, e.g. OpenRails can use `or`, Tensorhub can use `th`, Doujins can use `dj`.
- Prefix has no authorization meaning; DB metadata owns org, permissions, resources, expiry, and revocation.
- Prefix validation stays boring: lowercase letters/numbers, short, no underscores, no org/user data, no secrets.
- Do not rename DB tables/sqlc methods in this issue unless it is mechanically free.

**Tasks:**
- [x] Add `api_keys` to `OrgManifestOrg`, mapped to the existing storage implementation.
- [x] Reject legacy `service_tokens` manifest fields.
- [x] Add `APIKeyPrefix` / `APIKeyMaxTTL`; remove the old public config aliases.
- [x] Expose/document the API-key prefix as the self-describing app/deployment prefix (`or`, `th`, `dj`).
- [x] Add `/orgs/{org}/api-keys` routes and remove the old route spelling.
- [x] Rename public docs/comments/API text to API keys for the long-lived opaque credential.
- [x] Tests: `api_keys` mints/keeps through the existing storage path; legacy `service_tokens` fails explicitly; `/api-keys` route is gated by `org:api_keys:manage`.

Follow-up if we want the simplified public key string:
- Mint new API keys as `<prefix>_<base64url_secret>`.
- Resolve by digest/hash of the presented key or normalized secret, not by a public key id.
- Keep accepting existing `<prefix>_st_<key_id>_<secret>` keys for deployed credentials during migration.

---

# #85: Remote-application allowed origins for delegated browser requests

**Completed:** yes

Add browser origin policy to `remote_application`, keyed to the same issuer trust record used for delegated JWT verification. AuthKit should own both the policy and the middleware/helpers that enforce it; OpenRails and host apps should mount AuthKit-provided plumbing rather than re-implement issuer/CORS logic.

Problem found during the OpenRails config audit: OpenRails has a `merchant_cors` shape that looks per-merchant, but its current behavior is only a flattened global CORS allow-list. That does not enforce "a Doujins delegated-user request for Doujins may only come from doujins.com"; it only says "this browser origin may call this OpenRails instance." In public merchant registration, where Doujins and Evil can both register valid issuers and allowed origins, preflight CORS adds no merchant-isolation value because the preflight has no JWT issuer. Auth still protects data; CORS is compatibility/browser hardening, not authorization.

CURRENT OPENRAILS WIRING:
- `config.MerchantCORS` is only consumed by `Config.AllowedCORSOrigins()`, which unions `cors_origins` + all merchant origins.
- Standalone (`newPublicEngine`), embedded net/http (`embedhttp.Assembler`), and embedded gin self-service all pass that union into generic CORS middleware before auth.
- The delegated browser surfaces (`/v1/self/*` and `/v1/merchant-admin/*`) already resolve `ResolvedDelegated.Issuer` and pin the merchant from that validated issuer, but they do not check `Origin` against the issuer.
- Webhooks and API-key/server-to-server routes should not use this browser-origin policy.

The right source of truth is AuthKit's `remote_application`: it already binds `issuer -> JWKS/static keys -> audiences -> enabled -> org owner`. For browser-delegated traffic, the issuer that signed the delegated JWT should also define the exact browser origins allowed to present that issuer's tokens. Example: issuer `https://auth.doujins.com` may allow `https://doujins.com` and `https://www.doujins.com`; issuer `https://auth.hentai0.com` may allow only Hentai0 origins.

SECURITY MODEL:
- CORS preflight is browser compatibility and carries no JWT, so it can only be checked against the union of enabled remote_application origins. In an anyone-can-register merchant system, that union is not a meaningful security boundary.
- The actual protected request must verify the JWT, resolve its `iss` to a remote_application, then reject mismatched `Origin`. This is best-effort browser hardening, not authentication: non-browser clients can spoof `Origin`.
- AuthKit should provide the CORS/preflight middleware and the delegated-request origin gate. OpenRails should only call/mount those AuthKit pieces.
- No `Origin` means non-browser/server-to-server and should not be blocked by this check unless a caller opts into browser-only mode.
- Allowed origins are exact scheme+host+optional-port matches. No wildcards, no suffix matching.
- This is for browser-delegated user requests, not webhooks.
- AuthKit should enforce `request Origin in allowed_origins for verified token issuer` after JWT verification resolves the remote_application.
- `merchant_cors` should be deleted from OpenRails config once AuthKit exposes this policy. Do not replace it with an OpenRails-specific delegated-auth config.

**Tasks:**
- [x] Add `allowed_origins text[] NOT NULL DEFAULT '{}'` to `profiles.remote_applications` in a new numbered migration; do not patch the already-applied baseline only.
- [x] Add `AllowedOrigins []string` to `core.RemoteApplication`, upsert/list/get SQL, bootstrap config, and remote-application HTTP request/response bodies.
- [x] Validate origins in AuthKit: trim, dedupe, require `http` or `https`, require host, reject path/query/fragment, exact strings only. In production guidance, prefer `https`; keep `http://localhost:*` usable for dev.
- [x] Preserve the issuer trust invariant: origin policy is metadata on the same registered issuer; do not create a separate merchant CORS map.
- [x] Expose allowed origins through `RemoteApplicationSource` / verifier-loaded issuer metadata.
- [x] Add AuthKit-owned middleware/helpers:
      optional preflight CORS middleware using the union of enabled `remote_application.allowed_origins` for browser compatibility, and delegated-request middleware that verifies JWT then enforces `Origin` against the verified issuer.
- [x] Add a tiny helper such as `OriginAllowedForIssuer(ctx, issuer, origin)` or equivalent lookup; it should return false for unknown/disabled issuers and true for empty origin only when the caller opts into non-browser allowance.
- [x] Open OpenRails follow-up issue #519: remove `merchant_cors` and use AuthKit-provided CORS/delegated middleware or `DelegatedAuthenticator` integration. OpenRails should not own delegated issuer-origin policy.
- [x] Tests: register remote_application with origins, reject malformed origins, AuthKit CORS preflight allows only the enabled-origin union, disabled/unknown issuer fails closed, and delegated middleware rejects `issuer A + origin B`.

---

# #95: RBAC permission model — granular CRUD + positive glob wildcards + owner/operator apex + `org:` shared namespace + unify-on-roles

**Completed:** yes

HARDENING DONE (2026-06-20):
- [x] `POST /admin/orgs/{id}/recover` requires a fresh local session after the
      `platform:orgs:recover` gate. Stale sessions now return
      `reauth_required`; delegated/remote-application tokens cannot perform the
      recovery mutation because they have no local refresh-session freshness.
- [x] Swept legacy token-borne global-admin bypasses: no remaining
      `claimsHasGlobalAdmin` / `GlobalRoles == admin` authorization bypasses.
- [x] Hot org permission checks now use one DB round-trip:
      `OrgUserHasPermissionToken` resolves slug/rename + membership + single
      role permission grant in one indexed `EXISTS` query.
- [x] Hot platform permission checks now use one DB round-trip:
      `PlatformUserHasPermissionToken` checks `platform_user_roles` joined to
      `platform_role_permissions` in one indexed `EXISTS` query.
- [x] Tests: live DB HTTP test covers recover permission + stale/fresh reauth;
      live DB core tests cover org/platform direct and glob checks; Docker
      Compose E2E covers remote/delegated platform-gate behavior against the
      running devserver/Postgres stack.

The TARGET AuthKit permission model after the 2026-06-19 design pass with Paul (master design doc). Consolidates the already-split pieces — #92 (rename `PermissionCatalog`→`Permissions`), #93 (remove `!perm` negation), #94 (no-escalation on all grant paths) — plus the model decisions below. Hard-cut, no legacy. Consumer: OpenRails #537.

## Grammar
- Permissions are `<namespace>:<resource>:<action>`, lowercase, colon-separated.
- **Actions are CRUD: `{create, read, update, delete}`.** `read` = list + get-detail (ONE action; secrets are NEVER returned by any read). No separate `list`; no `:manage` action. (Paul chose `read` over `list` — more conventional; remember it also implies list.)
- **Positive GLOB wildcards are first-class (AWS-IAM style; `*` is a wildcard CHARACTER) — but globs MUST be namespace-anchored. There is NO bare `*`:**
  - `org:*` — everything under `org:` (the org owner).
  - `org:members:*` — all CRUD on members ("manage" with NO manage perm).
  - `org:*:read` — read across all org resources ("view-all" with NO viewer role).
  - `platform:*` — all platform-layer (Layer 2) operations.
  - **NO bare `*`** (Paul, 2026-06-19): a standalone `*` god-token is DROPPED — "everything" is `org:*` + `platform:*` (the two namespaces/layers), stated explicitly. A grant must have a namespace prefix before any `*` → reject a bare `*`. Bonus: a future new namespace is then NEVER silently auto-granted.
- **No `:manage` permission, and no manage/viewer ROLE bundles** — the globs above express "all CRUD on X" and "read all" directly (Paul: "you don't need `:manage`, `org:members:*` already means it").
- **Negation (`!perm`) is BANNED** (#93) — the ONLY removed operator. Net: positive globs + literals, **allow-only, no deny**. Negation's silent-no-op fail-open is gone; globs are purely additive (a glob auto-includes a newly-added matching catalog perm — intended for coarse grants; use specific perms for least-privilege).

## TWO LAYERS (Kubernetes `Role` vs `ClusterRole` — Paul, 2026-06-19)
Org authority and platform authority are **different object TYPES**, not the same grant with a hidden scope — "maximum obviousness." **This SUPERSEDES the earlier `is_global` org + `@ scope` approach (both DROPPED), and `root:` → `platform:`.**

**Layer 1 — Org RBAC (the `Role` layer; exists today).** A user is a MEMBER of an org with org-role(s) (`org_memberships` → `org_roles` → `org_role_permissions`). Org roles grant **`org:<resource>:<action>`**, scoped to THAT org. `owner` = `org:*` (everything in that ONE org); reusable across orgs (the same role definition works in any org you're a member of). Resources: `members`/`roles`/`api_keys`/`remote_applications` + host resources (OpenRails `org:credits:*`, tensorhub `org:repo:*`). Globs apply within the layer (`org:*`, `org:members:*`, `org:*:read`).

**Layer 2 — Platform RBAC (the `ClusterRole` layer; NEW — super-admins only).** A user is ASSIGNED platform-role(s) **directly — no org involved.** A **completely separate object type: NEW tables `platform_roles` / `platform_role_permissions` / `platform_user_roles`** — NOT the `orgs` table, NO `is_global` flag, NO special org name. A platform role can't be created or assigned through the org system, so **you can't get platform power by being added to an org.** Platform roles grant **ONLY `platform:<resource>:<action>`** — platform/DIRECTORY resources that manage *entities*, with no per-org form: `platform:users:*` (the account directory — ban/edit/delete an account), `platform:orgs:*` (the org directory — rename/transfer-owner/soft-delete + slug lifecycle + anti-takeover **recover** of any org; NO admin-create), `platform:roles:*` (define platform roles), `platform:members:*` (the platform-admin roster), `platform:metrics:*`. **ENTITY-LEVEL ONLY (Paul 2026-06-20): a platform-admin manages orgs as whole entities at a high level and NEVER their day-to-day internals — NOT members, role definitions, api-keys, or remote-applications, not even read-only.** The ONE sanctioned reach inside is **`platform:orgs:recover`** — a coarse all-or-nothing anti-takeover reset (defined below), never granular internal management. (api-keys + remote-applications are org-nested sub-resources, not platform resources.)

**A platform role does NOT grant `org:` perms** (Paul, 2026-06-20 — corrected; the two namespaces are DISJOINT). A platform admin manages the *account / org as an ENTITY* (ban a user, suspend a merchant) but **cannot act INSIDE an org** (read cozy's billing, `org:credits:*`) and **cannot act AS a user** — it does NOT inherit what org members can do. Acting inside an org requires actual org MEMBERSHIP (deliberate) or an explicit, audited break-glass. A host needing a genuine cross-org power defines a `platform:` resource for it (e.g. tensorhub `platform:repos:moderate`), never blanket `org:*`. **Stricter than k8s `cluster-admin` on purpose** — least privilege: the platform team runs the platform, not every tenant's private data.

**super-admin** = a platform role holding `platform:*` = full DIRECTORY authority (all users + orgs + metrics; `reserved-names` + `recover` fold under `orgs`). For day-to-day administration of a specific org's internals it still must be added as a MEMBER (deliberate) — the ONLY direct reach-in is the coarse `platform:orgs:recover` anti-takeover reset.

**Two DISJOINT namespaces, one per layer — no overlap.** `org:` perms exist ONLY in org roles (one org, via membership); `platform:` perms exist ONLY in platform roles (the directory). No string is shared across layers, so there is no "same perm, different scope" subtlety: a perm's namespace tells you its layer, and the layer is a different table. So there is NO `@ scope`, NO `is_global`, NO bare `*`, and NO cross-org `org:*`. AuthKit owns the two layers + their enforcement; the app still owns what any perm MEANS. **Delete the old global-roles-as-flags plane + app-local role→perm maps** (the doujins drift source) — both layers are AuthKit-owned roles now.

## Platform layer — examples + boundaries
- **Examples (separate layers, separate namespaces):** cozy owner → **org**-role `org:*` (everything in cozy); directory auditor → **platform**-role `platform:users:read` + `platform:orgs:read` (read the user + org DIRECTORIES — NOT any org's internal data); support desk → **platform**-role `platform:users:read` + `platform:users:update`; super-admin → **platform**-role `platform:*` (full directory authority — still not inside any org).
- **No ambiguity — by STRUCTURE + DISJOINT namespaces.** Org grants and platform grants come from DIFFERENT TABLES (`org_role_permissions` vs `platform_role_permissions`) into DIFFERENT FIELDS of the principal: `org_grants` (keyed by org, `org:` perms only) vs `platform_grants` (flat, `platform:` perms only). The namespaces don't overlap: an `org:` perm can ONLY come from an org membership; a `platform:` perm can ONLY come from a platform role. So a regular user (nothing in `platform_user_roles`) has empty `platform_grants` and is denied every `platform:` route; a platform admin (no org memberships) has empty `org_grants` and can't touch any org's internals. Platform roles get human names (`super-admin`/`support-desk`/`platform-auditor`) for audit readability — but the TABLE + namespace are the boundary.
- **Globs are namespace-anchored (no bare `*`):** `org:*`, `org:members:*`, `org:*:read`, `platform:*`, `platform:users:*`. A grant must have a namespace prefix before any `*`; "everything a platform role can hold" = `platform:*` (it CANNOT hold `org:*`), never a standalone `*`.
- **`users` (account) ≠ `members` (org membership).** Banning is a platform op: `POST /admin/users/{id}/ban` gates on **`platform:users:ban`**; removing someone from an org is `org:members:delete`.
- **Who gets platform roles:** users / API keys / remote-apps, assigned a platform role DIRECTLY (`platform_user_roles`). **Delegated/federated tokens are BARRED** from platform roles (verifier allowlist — a tenant can never mint itself platform authority).
- **Single-tenant apps** (doujins/hentai0/cozy-art): app users + staff live in the ORG layer (one org); the *operators* (you) hold **platform** roles. **Multi-tenant** (tensorhub): customer orgs are normal orgs; tensorhub staff hold platform roles. Either way platform authority is the separate layer, never an org.

## `org:` is the SHARED per-org namespace
- REVERSES the old "`org:` is reserved, hosts must use `merchant:`." `org:` now means "scoped to one org," and BOTH AuthKit's base perms AND the host's per-org resources live there.
- AuthKit reserves only the RESOURCE NAMES inside it: `members`, `roles`, `api_keys`, `remote_applications`, `settings` (the org's own name/profile). The host owns every other `org:<resource>` (tensorhub `org:repo:*`, OpenRails `org:credits:*`, …).
- `owner == org:*` therefore covers AuthKit management AND host resources in one grant.
- Cross-org / platform capabilities live in the SEPARATE `platform:` namespace (Layer 2 / `platform_roles`) — a different object type — so an org `owner` (`org:*`) can never reach platform authority.

## AuthKit base perms → granular CRUD
| resource | create | read (=list+detail) | update | delete |
|---|---|---|---|---|
| members | add | list members + roles | change role | remove |
| roles | define | list roles + perms | set perms / rename | delete |
| api_keys | mint | list metadata (NEVER secret) | — (immutable; rotate = create+delete) | revoke |
| remote_applications | register | list + detail | edit config / origins | delete |
| settings | — | read org (`GET /orgs/{org}`) | rename / edit metadata (`POST /orgs/{org}/rename`) | — |

(`org:settings` has no create/delete — the org *entity* is created/soft-deleted at the directory level via `platform:orgs:*`, Layer 2; `org:settings` is just the owner editing their own org's name/profile.) Old coarse perms RETIRED: `org:<resource>:manage` → glob `org:<resource>:*`; coarse `org:read` → glob `org:*:read`.

The **`platform:`** namespace (Layer-2 platform-only resources, granted in `platform_roles`) — the resources with NO per-org form. Full native catalog:

| `platform:` resource | actions | gates / notes |
|---|---|---|
| `users` | read, update, ban, delete | the global account directory (`/admin/users/*`). `users`=account ≠ `org:members`=membership. |
| `orgs` | read, update (rename + transfer-owner), delete (SOFT), reserved-names, recover | the **org-admin** surface — administer ANY org as an ENTITY at **`/admin/orgs/*`**; **entity-level ONLY** (NO day-to-day member/role/api-key/remote-app internals, not even read-only — those are org-side, break-glass via membership). DISTINCT from a user self-managing their OWN org (`/orgs/{org}/*` via `org:settings:*`, Layer 1). `read` = the org directory (list/search/inspect any org); `update` = rename + transfer-owner (surgical reassign, keeps the team); `delete` = SOFT (`orgs.deleted_at`, restorable → doubles as suspend). `reserved-names` (folded IN from a standalone perm, Paul 2026-06-20) = restrict/unrestrict/park/claim over the org SLUG pool — justified because the owner-namespace IS org-backed (parking a "user" slug mints a personal org); ONE perm for all those slug ops. **`recover`** = the **anti-takeover / account-recovery** reset for a compromised org (Paul 2026-06-20): ATOMICALLY revoke ALL the org's api-keys, disable ALL its remote-applications, demote ALL current members (strip every role), and assign `owner` to one specified rightful-owner — bad actors locked out, good owner restored. Coarse all-or-nothing (NOT granular internal management); heavily audited; separately grantable. **No `create`** — org creation is self-service (`POST /orgs`) or park/claim, never an admin-mint (mirrors `platform:users`). **No `suspend`** — soft-delete is the reversible disable. AuthKit's soft-delete does NOT cascade APP-owned resources (OpenRails billing / tensorhub repos) — the app reacts to org-deletion for its own cleanup. || `roles` | create, read, update, delete | DEFINE platform roles + their perms (the `platform_roles` / `platform_role_permissions` definitions). Parallels `org:roles`. |
| `members` | create (add), read (list), delete (remove) | the **platform-admin roster** — WHO holds platform roles (`platform_user_roles`; `/admin/roles/{grant,revoke}`). Renamed from `assignments` (Paul 2026-06-20: parallels `org:members`; "assignment" didn't read right). DISTINCT from `platform:users` (the directory of ALL accounts) — `platform:members` is just the admin team (the platform behaves like a root org whose members are the admins). **The single most dangerous perm — it mints new platform-admins** — split from `roles` (define ≠ assign) and guarded hardest (no-escalation: can't grant a platform perm you don't hold). |
| `metrics` | read | platform metrics. |

**Why org-less remote-apps are latent — the payer model (verified in `controlplane/customer.go` #491, Paul 2026-06-20).** A payer is one of THREE: **native** (a regular AuthKit user / embedded caller — the subject UUID *is* the payer id; invoker = payer = self-pay); **org-bound** (`UNIQUE(merchant, org_id)` — the ORG is the payer, ANY member invokes on its behalf → **invoker ≠ payer = real delegation**); **org-less federated** (`UNIQUE(merchant, issuer, subject)` — a FOREIGN subject vouched for by an org-less remote-app; each self-pays). Paul's framing holds exactly: invoker ≠ payer (true delegation) happens ONLY in the org-bound branch, and there an org member is EITHER a remote-application (machine) OR a role-assigned user (human) — both polymorphic `org_memberships` rows. An "org-less payer" is therefore just **self-pay**, which a native AuthKit user already covers; the org-less-remote-app path only buys per-subject billing for a host with its OWN identity system — which none of the 4 consumers is. Hence (DECIDED, Paul 2026-06-20) there is **no org-less remote-app at all** — `remote_applications.org_id` becomes **NOT NULL** and remote-apps are modeled as a pure **org-nested sub-resource, exactly like api-keys** (an issuer "attached to nothing" makes as little sense as an api-key attached to nothing). Proof by the standalone case: if doujins runs OpenRails standalone, it seeds itself as a remote issuer — but it must ALSO seed its own org + merchant to have anything to bill, so the issuer is org-attached by construction. Consequences: drop `platform:remote_applications` ENTIRELY (no platform resource, no row above); move the flat `/remote-applications` routes under `/orgs/{org}/remote-applications` (org in the PATH, like api-keys); delete the global `GET /remote-applications` admin list and the org-less branch in `canManageRemoteApplicationByIssuer`. (If the operator ever wants a federation-trust audit view — "which external issuers can mint tokens against my platform" — add it later as a read-only audit/metrics endpoint, NOT a managed resource; api-keys has no such view either, so default is to omit it.)

## Unify principals on ROLES (drop direct permission lists)
- users / API keys / remote_applications ALL get permissions via **role(s)** — ONE grant path, already no-escalation-guarded (#94).
- **Resource-scope is a separate per-principal binding** (API key `Resources{Kind,ID}`, remote-app org/issuer) — orthogonal to *what* perms.
- **DROP** `service_token_permissions` + `remote_application_permissions` direct lists. Bespoke set → custom role. This DELETES the direct-grant paths, closing the #94 escalation class by construction. DECIDED (Paul): API keys + remote-apps get ROLES, not arbitrary permission bundles — so adding/removing a permission later is a ONE-PLACE change (edit the role), not a sweep across every key. (Tradeoff accepted: some role proliferation for one-off machine creds.)

## Tasks
**Design FROZEN 2026-06-20 (Paul) — the decisions above are locked; the checkboxes below are the implementation breakdown (hard-cut, no legacy).**
- [x] Glob matching in `effectivePermsForTokens` + `ValidateGrant`: `*` as an AWS-style wildcard CHAR in namespace-anchored globs (`org:*`, `org:members:*`, `org:*:read`, `platform:*`, `platform:users:*`); REJECT a bare standalone `*`; allow-only, no negation (#93). No-escalation EXPANDS globs (granting `org:members:*` requires holding all of `org:members:*`).
- [x] Granularize base perms per resource (`org:` = members/roles/api_keys/remote_applications × CRUD, in ORG roles; `platform:` = users(read/update/ban/delete)/orgs(read/update/delete/reserved-names/recover)/roles/members/metrics, in PLATFORM roles — api_keys + remote_applications are NOT platform resources, org-only); retire `…:manage` + coarse `org:read`; handlers gate on the specific action. Add the `platform:users:*` account-admin surface (ban/read/delete) distinct from `org:members:*`, and `platform:orgs:reserved-names` over `/admin/orgs/{restrict,unrestrict,park,claim}` (no `/accounts/` bucket; folds the old standalone `platform:reserved-names`).
- [x] Make `org:` the shared per-org namespace; reserve only the 4 resource names; allow host-defined `org:<resource>` perms.
- [x] **Remote-applications → pure org sub-resource (Paul 2026-06-20; same shape as api-keys).** Migration: `profiles.remote_applications.org_id` → **NOT NULL** (drop the org-less category entirely; greenfield single-baseline → edit the baseline + the `COMMENT`). Move the FLAT routes (`POST/DELETE/GET /remote-applications`, org_id in body) → **`/orgs/{org}/remote-applications`** (org in the PATH), gated in-handler on `org:remote_applications:*`. DELETE the global `GET /remote-applications` admin-list route + the `admin(...)` wrapper + the org-less branch in `canManageRemoteApplicationByIssuer`. Confirm the verifier still loads issuers globally by `iss` (nesting is management-only, not a verification change). No consumer change — OpenRails #527 bootstrap already provisions each issuer under its merchant's backing org.
- [x] Tighten prebuilt `owner` role from `*` → `org:*` (Layer 1). Build **Layer 2 — Platform RBAC**: new tables `platform_roles` / `platform_role_permissions` / `platform_user_roles` (NOT the orgs table; NO `is_global`, NO `@ scope`). Assign platform roles to users / API keys / remote-apps DIRECTLY; a platform role grants **ONLY `platform:*`** (directory resources) — it does NOT grant `org:*` (the two namespaces are DISJOINT; the platform admin manages entities, never acts inside an org or as a user); super-admin = `platform:*`. ValidateGrant REJECTS an `org:` perm on a platform role and a `platform:` perm on an org role. Bar delegated/federated tokens from platform roles (verifier allowlist). NO bare `*`; globs namespace-anchored.
- [x] Collapse `read`/`list` to a single `read` action; secrets never returned by any read.
- [x] Unify principals on roles; drop `service_token_permissions` + `remote_application_permissions` direct lists; resource-scope stays a separate binding. DONE: remote-apps unified earlier (006); API keys now hold exactly ONE org role — migration 007 adds `service_tokens.role` (FK `(org_id, role) -> org_roles`, like memberships/invites) + drops `service_token_permissions`. `core.APIKeyMintOptions.Permissions []string` → `Role string`; mint validates the role exists + no-escalation (`ValidateGrant` over the role's tokens) + bars a role conferring wildcard/reserved-write perms from a key; resolve (`ResolveAPIKey*`) re-resolves role→effective-perms at verify time (role edit reflected immediately). HTTP mint body `{permissions:[...]}` → `{role:"..."}` (gated on `org:api_keys:create`). BREAKING — see CONSUMER MIGRATION below.
- [x] **Efficient lookup (CONTRACT: ≤ 1 DB round-trip per request).** Resolve a principal's grants per layer via a SINGLE indexed JOIN — platform: `SELECT permission FROM platform_user_roles ur JOIN platform_role_permissions p ON p.platform_role = ur.platform_role WHERE ur.user_id = $1`; org: the analogue with `org_id` + `member_id`. Index the join columns (`platform_user_roles.user_id`, `platform_role_permissions.platform_role`, and the org equivalents). **Memoize per request:** resolve each layer's grant set ONCE at request start, stash in the request context, and have every gate match the cached set — a handler checking N perms does 1 resolution, not N. Globs keep the set tiny (a `platform:*` role = ONE row, never enumerated); the match itself is in-memory glob/prefix (µs). Regular users short-circuit (0 rows in `platform_user_roles` → no second step). OPTIONAL, only for extreme throughput: a short-TTL (5–30s) per-principal cache invalidated on role change — but the DEFAULT stays request-time resolution (instant revocation, never-stale grants; perms are NEVER baked into the JWT).
- [x] Tests: glob expansion + no-escalation over globs; `owner`=`org:*` covers a host-defined `org:repo:*`; a platform role REJECTS any `org:` perm and an org role REJECTS any `platform:` perm (DISJOINT namespaces); a platform admin can't read any org's internal data nor act as a user; `platform:users:ban` gates the account-ban route; secrets unreadable; a delegated/federated token can NEVER hold a platform-role grant; **a handler with N perm-checks issues exactly ONE resolution query (memoization holds).**
- [x] **Build the `/admin/orgs/*` org-admin surface (Paul 2026-06-20 — the missing org-management routes).** Mirrors `/admin/users/*`; **entity-level ONLY** (NO day-to-day member/role/api-key/remote-app internals, not even read-only — break-glass via membership), with the single coarse exception `recover` (below). Routes → perm: `GET /admin/orgs` (directory — paginated, search by slug, filter state/personal) → `platform:orgs:read`; `GET /admin/orgs/deleted` → `platform:orgs:read`; `GET /admin/orgs/{org}` (entity detail: slug/owner/is_personal/state/member-count/timestamps) → `platform:orgs:read`; `POST /admin/orgs/{org}/rename` → `platform:orgs:update`; `POST /admin/orgs/{org}/transfer-owner` (surgical reassign — owner-left / white-glove, keeps the team) → `platform:orgs:update`; `DELETE /admin/orgs/{org}` (SOFT) → `platform:orgs:delete`; `POST /admin/orgs/{org}/restore` → `platform:orgs:delete`; `POST /admin/orgs/{restrict,unrestrict,park,claim}` (org SLUG lifecycle; park/claim take `kind: org|user` in the body — user-kind mints a personal org) → `platform:orgs:reserved-names` (folds the old standalone perm; replaces the dead 404 `POST /admin/org/{park,claim}` stubs AND the old `/admin/account(s)/*` paths; reuses `handleAdminAccountPark/Claim/RestrictPOST`); **`POST /admin/orgs/{org}/recover` (anti-takeover reset — body `{new_owner_user_id}`: ATOMICALLY revoke ALL api-keys, disable ALL remote-apps, demote ALL members, assign owner to the rightful user → lock the attacker out, restore the good owner) → `platform:orgs:recover`** (separately grantable; max-audited). **DROP `platform:orgs:create`** (self-service or park/claim, never an admin-mint). ALL slug-lifecycle + recover live under `/admin/orgs/*` (NO `/admin/users/{park,claim}`, NO `/admin/reserved-names/*`, NO `/accounts/`); then delete the old `/admin/account(s)/*` + dead `/admin/org/*` routes + the dead `POST /admin/users/toggle-active` stub (NO active/inactive concept — ban + soft-delete are the only account states).
- [x] **Routes + naming.** The platform surface is **`/admin/*`** (Paul 2026-06-20: `/platform/*` reads too vague; `/admin/` is the explicit operator-console prefix — and there's NO URL collision, because per-org admin lives under `/orgs/{org}/*`, never under `/admin/`). The gate stays **`requirePlatformPermission`** (NOT `RequireAdmin*`) and the perm namespace stays **`platform:`** — the disjoint Layer-2 plane — even though the URL says `/admin`; role name = **platform-admin**. **FOUR gate tiers** (Paul: self routes are a more primitive check — they have no target, they just modify the caller): **public** (ungated) · **self** (authenticated-only; acts on the caller, no target → IDOR-proof by construction) · **org** (`org:` perm for the path `{org}`) · **platform** (`platform:` perm). Platform routes → perm: `GET /admin/users*` → `platform:users:read`; `/admin/users/{ban,unban}` → `platform:users:ban`; `/admin/users/{set-*, */sessions/revoke}` → `platform:users:update`; `DELETE /admin/users/{id}` + `/restore` → `platform:users:delete`; **`/admin/orgs/*` (org-admin, entity-level: directory + rename/transfer-owner/soft-delete + slug lifecycle + anti-takeover recover)** → `platform:orgs:{read,update,delete,reserved-names,recover}`; the slug lifecycle `/admin/orgs/{restrict,unrestrict,park,claim}` (park/claim take `kind: org|user`) → `platform:orgs:reserved-names`, and `/admin/orgs/{org}/recover` → `platform:orgs:recover` (NO `/accounts/` bucket, NO `/admin/users/park`, NO `/admin/reserved-names/*` — all folded under `/admin/orgs`); `/admin/roles/{grant,revoke}` (assign/unassign a platform-admin) → `platform:members:{create,delete}` (define-a-role is the separate `platform:roles:*`). **No remote-application route under `/admin/`** — remote-apps are org-nested (below). ORG routes gate IN-HANDLER on the `org:` perm for the path `{org}` (`/orgs/{org}/members*` → `org:members:*`, `/roles*` → `org:roles:*`, `/api-keys*` → `org:api_keys:*`, **`/orgs/{org}/remote-applications*` → `org:remote_applications:*` (NEW home — moved from the flat `/remote-applications`, nested like api-keys)**, `GET /{org}` + `/rename` → `org:settings:{read,update}`, `/invites*` → `org:members:*`). SELF routes (`/user/*`, `/me/*`, own 2FA/sessions) → authenticated-only. PUBLIC routes (login/register/reset/verify/availability/owner-lookup) ungated.

#92/#93/#94 are the already-split sub-pieces of this model. Consumer reframe: OpenRails #537 (merchant→`org:`, platform super-admin → the `platform:` layer); then the doujins/tensorhub/cozy-art string flips.

---

# #96: Public/self route cleanup — phone reset, identity providers, namespaces, orgs

**Completed:** yes

## Metadata

- Category: bug/cleanup
- Status: done
- Passes: true

Phone password reset currently sends a reset token/link by SMS (`RequestPhonePasswordReset` → `SendPasswordResetLink`), but the public route table only exposes `POST /phone/password/reset/{request,confirm}`. Email has the browser handoff route `POST /email/password/reset/confirm-link` that consumes the token and returns a short-lived `reset_session`; phone lacks the matching public token-consume route even though `POST /phone/password/reset/confirm` expects `reset_session + new_password`.

Provider discovery is also too vague as `GET /providers`. Hard-cut it to `GET /identity-providers` because the list includes enabled external identity providers across OIDC and OAuth2; do NOT keep `/providers` as an alias.

`GET /owners/{slug}` also collapses two valid resources into one "owner" answer. A username and an org slug can legitimately match (for example a user `cozy` and org `cozy`), so hard-cut it to `GET /namespaces/{slug}` with an explicit typed response shape: `user`, `org`, and per-kind `claimable` fields. Do NOT keep `/owners/{slug}` as an alias.

`GET /user/bootstrap` is a current-caller bootstrap bundle, not a target-user resource. Hard-cut it to `GET /me/bootstrap` so the URL matches the rest of the self namespace; do NOT keep `/user/bootstrap` as an alias.

Native-user org-scoped access tokens are being removed entirely. There should be one normal user auth token, not one token per org membership. Delete `POST /token/org` and remove optional `org` token-minting from `/token` and `/password/login`; org authorization should resolve from the route/path + server-side membership/role/permission lookup, not from an org baked into the access token. Remove docs/tests/comments that describe native-user "org-scoped access tokens". This is separate from delegated/federated token models, which remain governed by their own issuer/subject/resource authority. `/me/permissions` becomes principal-level only. Per-org caller info lives directly on `GET /orgs/{org}`, which returns org metadata plus the caller's single `role` and effective permissions. The org membership model is one role per org membership, so response shapes should use `role: string`, not `roles: []`.

`GET /orgs/{org}/me` and `POST /orgs/{org}/permissions/check` are redundant once `GET /orgs/{org}` returns role + permissions. Delete both; frontends can check `permissions.includes(...)`, and backend handlers still enforce permissions server-side.

`GET /orgs` is a current-caller membership listing, not a platform-wide org directory. Hard-cut it to `GET /me/orgs`; keep `POST /orgs` unchanged for self-service org creation.

`/me/invites` is specifically org invites, not a generic inbox. Hard-cut it to `/me/org-invites` including accept/decline child routes; do NOT keep `/me/invites` as an alias.

## Tasks

- [x] Add `POST /phone/password/reset/confirm-link` as an alias to the existing password-reset token handoff handler (`token` → `reset_session`).
- [x] Hard-cut `GET /providers` → `GET /identity-providers` in route registration and tests; remove old `/providers` support.
- [x] Hard-cut `GET /owners/{slug}` → `GET /namespaces/{slug}`; remove old `/owners/{slug}` support.
- [x] Hard-cut `GET /user/bootstrap` → `GET /me/bootstrap`; remove old `/user/bootstrap` support.
- [x] Delete `POST /token/org`.
- [x] Remove optional `org` request handling from `POST /token` and `POST /password/login`; no org-scoped access-token mint path remains.
- [x] Delete org-scoped token helpers/claims that only exist for that model (`ExchangeRefreshTokenWithOrg`, `IssueOrgAccessToken`, `org`/`org_roles`/legacy org `roles` claim minting), or leave only compatibility-free internals if another active path proves it still needs them.
- [x] Sweep docs/tests/comments for native-user "org-scoped access token" language and remove it; do not conflate this with delegated/federated token authority.
- [x] Make `/me/permissions` principal-level only.
- [x] Change `GET /orgs/{org}` to return org metadata plus caller membership `{role, permissions}`.
- [x] Delete `GET /orgs/{org}/me` and `POST /orgs/{org}/permissions/check`.
- [x] Hard-cut `GET /orgs` → `GET /me/orgs`; remove old `/orgs` list support while keeping `POST /orgs` as self-service org creation.
- [x] Hard-cut `GET /me/invites` and `POST /me/invites/{invite_id}/{accept,decline}` → `/me/org-invites...`; remove old `/me/invites` support.
- [x] Redesign namespace lookup response to avoid a single `status`/`entity_kind`/`canonical_slug` winner: return typed `user`, `org`, and `claimable` fields so user+org same-slug cases are explicit.
- [x] Document the phone reset route, identity-provider route rename, namespace lookup rename/shape, bootstrap route rename, org-scoped-token removal, `/me/orgs` rename, `/me/org-invites` rename, and org lookup response shape in `README.md` and `agents/api-endpoints.md`.
- [x] Add one HTTP route/handler test proving phone confirm-link consumes a reset token and returns `reset_session`.
- [x] Add one route test proving `/identity-providers` exists and `/providers` is gone.
- [x] Add one namespace route/response test proving `/namespaces/{slug}` can represent same-slug user+org without collapsing to one owner, and `/owners/{slug}` is gone.
- [x] Add one route test proving `/me/bootstrap` exists and `/user/bootstrap` is gone.
- [x] Add route/API tests proving `/token/org` is gone, `/token` and `/password/login` reject/ignore `org`, `/me/permissions` is not org-scoped, `GET /orgs/{org}` returns org `role` + permissions, `/orgs/{org}/me` and `/orgs/{org}/permissions/check` are gone, `/me/orgs` exists, and `GET /orgs` is gone.
- [x] Add route tests proving `/me/org-invites` accept/decline routes exist and `/me/invites` is gone.

---

# #97: Slim normal user access-token claims to session identity only

**Completed:** yes

DONE (2026-06-20): normal AuthKit user access tokens now carry only registered
JWT identity, `sub`, `sid`, and authoritative short-lived `entitlements`. They
no longer mint profile or role/global-role snapshots. Consumers were migrated:
Doujins request context now resolves roles through its DB `UserRoleRepo` and its
frontend token bootstrap no longer derives role/profile/admin/email state from
JWT payload fields; Hentai0 request context uses DB roles and its frontend token
bootstrap no longer derives role/profile/admin/email state from JWT payload
fields; Cozy Art was swept and had no normal-user role/profile JWT dependency to
change. Validation: AuthKit `go test ./...`; Doujins
`go test ./internal/server ./internal/auth/middleware` and
`pnpm -C frontend exec tsc --noEmit`; Hentai0
`go test ./internal/auth ./internal/api` and
`pnpm -C frontend exec tsc -b --noEmit`; live Docker Compose stack
`go test -tags=e2e ./testing -run TestDevserverE2E -count=1` proves
password-login and refresh tokens from the running devserver/Postgres keep
`sub`, `sid`, and authoritative `entitlements` while omitting profile and role
claims.

Normal AuthKit user access tokens currently carry profile snapshots and authority snapshots:
`global_roles`, legacy `roles`, `entitlements`, `email`, `email_verified`,
`username`, `discord_username`, plus `sid` supplied by login/refresh paths.

This is backwards for the new authorization model for roles/profile data. User
permissions and roles are live DB state, not token authority. Profile data
belongs on `/me` / `/me/bootstrap`, not in every bearer token. Entitlements are
different: the entitlement claim is an authoritative short-lived snapshot issued
by AuthKit's configured entitlements provider. A later DB check may improve
freshness/revocation behavior, but it does not make the JWT entitlement claim a
mere UI hint.

Target token shape for normal user access tokens:
- Keep registered claims: `iss`, `sub`, `aud`, `iat`, `exp`.
- Keep `sid` for now. It is session identity used by logout, reauth/freshness,
  session-preserving password changes, and host session context.
- Keep `entitlements` as an authoritative short-lived snapshot.
- Remove `global_roles` and `roles`.
- Remove profile claims: `email`, `email_verified`, `username`,
  `discord_username`.

Do not change delegated/service token shapes in this issue. Delegated/service
tokens intentionally carry explicit `permissions` / attributes for their own
models; this issue is only about normal AuthKit human-user access tokens minted
by `IssueAccessToken`.

Known current consumers to migrate first:
- Doujins reads `Claims.GlobalRoles` / `Claims.Roles`, `Claims.Username`, and
  `Claims.Entitlements` into request context. Move roles/permissions to
  DB-backed middleware/enrichment and profile display to `/me`.
- Hentai0 server reads `Claims.Roles`, `Claims.Username`, and
  `Claims.Entitlements`; its frontend also decodes token payload fields for
  `isAdmin`, `isPremium`, email, username, and email verification. Move frontend
  state to `/me` / profile fetch and server authorization to DB-backed role /
  entitlement lookup.
- Cozy Art mostly uses `Claims.UserID` / `Claims.SessionID` for normal-user
  paths; verify no profile/role/entitlement token dependency remains before the
  AuthKit hard-cut.

**Tasks:**
- [x] Audit AuthKit tests/docs and the three consumers (`~/doujins`,
      `~/hentai0`, `~/cozy/cozy-art`) for reads of user-token profile,
      role/global-role, and entitlement claims.
- [x] Update consumers so normal-user request context is built from live DB /
      profile endpoints, not access-token roles/profile; token entitlements stay
      authoritative by design.
- [x] In AuthKit `IssueAccessToken`, stop minting `global_roles`, `roles`,
      `email`, `email_verified`, `username`, `discord_username`, and
      keep `sid` merging from login/refresh `extra`; keep `entitlements` as an
      authoritative short-lived snapshot.
- [x] Keep `Claims` parsing backward-tolerant only if needed for third-party
      inbound tokens, but stop documenting those fields as normal AuthKit
      user-token output.
- [x] Update `/me`, `/me/bootstrap`, and docs so they are the supported source
      for user profile/bootstrap state.
- [x] Add an AuthKit integration/HTTP test proving login/refresh user access
      tokens contain `sub` + `sid` and do not contain roles, profile fields, or
      authoritative role/profile claims; `entitlements` remains authoritative.
- [x] Add focused consumer tests proving admin/premium/profile UI still works
      without those token claims.

---

# #98: Validate delegated JWT permissions against remote-application stored authority

**Completed:** yes

DONE (2026-06-20): delegated access-token `permissions` are now verified against
the issuer remote application's stored authority before platform gates can trust
them. The same namespace-anchored glob matcher backs remote application access
tokens, delegated access tokens, and `Claims.HasPermission`. Platform gates now
accept validated delegated `platform:*`/concrete permission claims while
preserving live DB checks for local users and continuing to reject delegated role
claims. Tests cover accepted stored glob authority, out-of-ceiling rejection, and
claiming broader `platform:*` than stored authority.

LIVE E2E (2026-06-20): `go test -tags=e2e ./testing -run TestDevserverE2E
-count=1` now seeds a remote_application, org role, membership, and platform
permission authority into the Docker Compose Postgres stack, signs real
delegated JWTs, and calls the running devserver. It covers: remote application
access token accepted with `typ=remote-application-access+jwt`; wrong `typ`
rejected; delegated `platform:orgs:read` accepted by an admin platform gate
when covered by stored `platform:*`; delegated `platform:orgs:recover` rejected
by the recover route's fresh local-session requirement; delegated
out-of-ceiling concrete permission rejected at verify; delegated broader
`platform:*` than stored authority rejected at verify; and a delegated token
without the route's required platform permission failing the platform gate with
403.
That live test found and fixed a real DB-backed gap: remote_application
authority now expands `platform:*` against AuthKit's platform catalog, not only
the org/app permission catalog.

Delegated JWTs may carry concrete `permissions`, but those permissions must be
bounded by the issuing remote application's stored DB authority. Today
remote-application self tokens are down-scoped against stored authority, but
delegated tokens are only catalog-validated. That is not enough: a remote app
must not be able to mint any catalog-valid `platform:*` or `org:*` permission
for its delegated users.

Target model:
- Remote application stored authority is the ceiling.
- Delegated JWT `permissions` are concrete requested permissions, not role
  claims.
- Verification resolves `iss` -> remote application -> stored authority, then
  rejects any delegated permission outside that ceiling.
- Platform gates may accept either a local user with live DB platform permission
  or a delegated token whose `permissions` claim has already been validated
  against the remote application's stored authority.
- Do not add delegated platform-role claims. Roles are local assignment
  structure; delegated tokens carry concrete down-scoped permissions.

Example:

```json
{
  "delegated_sub": "external-user-123",
  "permissions": ["platform:orgs:recover"]
}
```

This is valid only when the issuer remote application already has authority for
`platform:orgs:recover`.

**Tasks:**
- [x] Audit delegated verification and confirm where `permissions` are currently
      catalog-validated without stored-authority intersection.
- [x] Add verifier-time delegated permission ceiling check: resolve issuer
      remote application, load its effective stored authority, and reject
      out-of-ceiling claims.
- [x] Support glob matching consistently with the permission model
      (`platform:*` may cover `platform:orgs:recover`; bare `*` stays invalid).
- [x] Teach platform gates to accept validated delegated permission claims for
      `platform:*` checks, alongside local-user live DB platform permissions.
- [x] Keep platform role claims rejected/ignored on delegated tokens.
- [x] Tests: delegated token within issuer authority passes a platform gate;
      delegated token claiming a permission outside issuer authority is rejected
      at verify; catalog-valid but unassigned `platform:*` cannot be minted by a
      weaker remote application.

---

# #99: Canonicalize remote application access token naming

**Completed:** yes

DONE (2026-06-20): the canonical product/API name is now **remote application
access token** with JOSE `typ=remote-application-access+jwt`. AuthKit comments,
README/API docs, and active OpenRails consuming comments/docs were swept to use
the new name while retaining low-level invariant notes: the token carries neither
`sub` nor `delegated_sub`; identity is validated `iss -> remote_application`.
Tests pin the wire constant and wrong-`typ` rejection.

LIVE E2E (2026-06-20): the Docker Compose devserver test signs a real remote
application access token and proves the running verifier accepts it, then signs
the same remote-application JWT shape with the wrong JOSE `typ` and proves the
running server rejects it.

AuthKit already uses JOSE `typ` headers for its JWT classes:

- normal user access token: `typ=access+jwt`
- delegated access token: `typ=delegated-access+jwt`
- remote application acting as itself: `typ=remote-application-access+jwt`

It also has a separate service-JWT shape: `typ=service+jwt` plus
`token_use=service`. That is not the same thing as a remote application access
token, and API keys are opaque shared secrets with DB-resolved authority, not
JWTs.

The remote-application self-token already has the right wire value, but docs and
comments still use several names: "remote_application self-token", "JWKS
principal self-token", and "SELF-token". Standardize product/API language on
**remote application access token** and keep the wire type as
`remote-application-access+jwt`.

- [x] Keep `jwtkit.RemoteApplicationAccessTokenType =
      "remote-application-access+jwt"` as the canonical JOSE `typ` value.
- [x] Rename comments/docs from "remote_application self-token" / "JWKS
      principal self-token" to "remote application access token" where the
      user-facing concept is being described.
- [x] Keep lower-level implementation comments only where they clarify the
      invariant: the token carries neither `sub` nor `delegated_sub`; identity is
      the validated `iss -> remote_application`.
- [x] Update README / API docs token taxonomy:
      user access token, delegated access token, remote application access token,
      service JWT, API key.
- [x] Sweep OpenRails comments/docs that consume this AuthKit token type and use
      the same name.
- [x] Add/keep tests proving `RemoteApplicationAccessTokenType` is
      `remote-application-access+jwt` and verifier rejects the wrong `typ`.

---

# #89: Bootstrap-user password seed-once + reset_required idempotency

**Completed:** yes

DONE (v0.38.0): `BootstrapUserPassword.Enforce` added (default false = seed-once); password applied only when `created || Enforce`; `Enforce`+`ResetRequired` rejected. Unit test for validation + DB-backed seed-once/enforce behavior test (skips without `AUTHKIT_TEST_DATABASE_URL`).

Independent of OpenRails #527 (OpenRails is removing bootstrap user/password seeding entirely), but a real AuthKit bug for any consumer that seeds users through `ReconcileBootstrapManifest`.

Today `applyBootstrapUserPassword` (core/bootstrap_manifest.go) re-asserts the manifest password on EVERY reconcile: `plaintext` mode resets a rotated password back to the manifest value (no-ops only if it already matches), `hash` mode unconditionally overwrites, and `reset_required` re-writes the reset sentinel on every run — so a user who completed a reset is forced back into reset-required on the next server boot/reconcile. The `created` bool is already computed at the call site (line ~155) but ignored for the password decision.

Fix — seed-once by default:
- Apply a manifest password only when the user is newly CREATED, OR an explicit per-password `enforce: true` opt-in is set.
- `reset_required` and `hash` modes obey the same gate (no every-run clobber).
- Reject `enforce: true` combined with `reset_required` (forcing a reset every run is nonsensical).
- Skipped-existing counts as PasswordsKept.

**Tasks:**
- [ ] Add `enforce bool` to `BootstrapUserPassword` (default false = seed-once).
- [ ] Gate password application on `created || password.enforce`.
- [ ] Validate `enforce` XOR `reset_required`.
- [ ] Tests: existing user's rotated password survives reconcile (default); `enforce` re-asserts; `reset_required` is one-shot, not re-fired per boot.

---

# #88: Provisioning + authority primitives for OpenRails' merchant model

**Completed:** yes

DONE for the #527-blocking scope (v0.38.0):
- (b) `owner` is assignable to a remote_application member (`validateOrgRole`/`canonicalizeOrgRole` accept it; no reserved-role guard). Regression test `TestRemoteApplicationOwnerMembershipGrantsWildcard` (owner→wildcard `*` via `ResolveRemoteApplicationAuthority`).
- (c) invariant lock-in — ALREADY COVERED by the existing suite: claim-stripping (`TestDelegatedAccessRejectsRolesClaim`/`RejectsOrgClaim`/`RejectsOrgIDClaim`), `enabled`=false kill-switch (`http/federation_test.go` disabled-issuer → 403; `LoadRemoteApplications` enabledOnly in `verifier_coherence_test`), stored-authority (delegated tests + the new owner-on-RA test). No new tests needed.

OPTIONAL / not needed (deliberately deferred): (a) tx-aware provisioning — OpenRails #527 uses authkit's idempotent `ProvisionOrg` + merchant upsert (re-apply converges), so a single cross-domain tx is not required; (d) one-call org+issuer helper. Reopen if a future consumer needs strict atomicity.

Supports OpenRails #527's unified atomic `ProvisionMerchant` (one merchant ↔ one backing org ↔ one issuer-as-owner) and locks in the security invariants the model depends on.

**(a) Transaction-aware provisioning.** OpenRails must create the AuthKit org + register the issuer as an owner-member in the SAME Postgres transaction as the OpenRails `merchants` row (one rollback unit; self-hosted shares one DB across the `profiles` + `openrails` schemas). Today `ProvisionOrg` / `UpsertRemoteApplication` / `AddRemoteApplicationMember` run on the Service's own pool. Expose tx-aware variants that accept an external querier / `pgx.Tx` (or a `WithTx`-scoped Service) so the caller owns the transaction. Fallback if cross-domain tx proves impractical: document a compensating-delete contract (create org → create merchant → on failure delete org) — but tx-aware is preferred.

**(b) Full-authority role on a remote_application.** DECIDED (OpenRails): the issuer gets the `owner` role — auto-seeded with wildcard `*` → full authority over its merchant. `ProvisionOrg` already calls `AddRemoteApplicationMember(org.Slug, ra.ID, issuer.Role)` and each remote_application has a single `OrgID` (#77). AuthKit must ensure `owner` is assignable to a remote_application member; if any reserved-role guard treats `owner` as human-founder-only, lift it for RA memberships. This is now load-bearing for the OpenRails merchant model.

**(c) Lock in invariants (regression tests, not new behavior).** The redesign DEPENDS on these existing behaviors; add tests so they cannot silently break:
- Federated / remote_application issuer tokens have platform-authority claims (`global_roles` / `org_roles` / `roles`) STRIPPED on verify — only the `isLocal` signer is trusted for them.
- `remote_application.enabled=false` is the trust kill-switch (disabled issuer → tokens rejected).
- Stored-authority resolution (`RemoteApplicationOrgRoles`), never self-claimed.

**(d) Optional convenience.** A single `ProvisionMerchantOrg(org, issuer-as-owner)` helper so OpenRails doesn't hand-compose CreateOrg + UpsertRemoteApplication + AddRemoteApplicationMember.

**Tasks:**
- [ ] Tx-aware provisioning APIs (accept external `pgx.Tx` / DBTX) for org-create + remote_application upsert + membership add; or document the compensating-delete fallback.
- [ ] Ensure the `owner` role is assignable to a remote_application member (`AddRemoteApplicationMember`); lift any reserved-role guard that treats `owner` as human-founder-only.
- [ ] Regression tests: federated authority-claim stripping; `enabled=false` rejection; stored-authority (not self-claimed) resolution.
- [ ] (Optional) one-call org + issuer-as-owner provisioning helper.

Consumer: OpenRails #527 `ProvisionMerchant` + `merchantForIssuer` simplification.

---

# #87: Verify-only AuthKit Service (optional token signer)

**Completed:** yes

DONE (v0.38.0): `Config.VerifyOnly` builds a no-signer Service and skips key discovery; all mint paths return `ErrMissingSigner` (the four Mint* methods already guarded; added the same guard to the access-token path); JWKS serves an empty set; verification + RBAC unaffected. Test `TestVerifyOnlyServiceRejectsMinting` (no DB). Consumed by OpenRails `controlplane.New` (verify-only when no key is discoverable).

Enables OpenRails #527: OpenRails must run as a PURE VERIFIER with no token-signing key when it has no login-capable users (all identity arrives as host-app delegated tokens, or as in-process host-trusted calls in embedded mode). Today `authcore.Config.Keys == nil` triggers auto-discovery (env → /vault/auth → dev-generated), so a Service ALWAYS ends up with a signer.

Requirement — a first-class verify-only construction:
- Explicit "no signer" mode (a `Config` flag, or a `jwt.NoSigner()` sentinel KeySource) that does NOT auto-discover/generate.
- ALL token-minting paths (`IssueAccessToken`, login/session issue, `MintServiceJWT` / `MintCustomJWT`, remote_application self-token mint, password-session issue) return a typed, exported `ErrNoSigner` — never panic, never generate.
- ALL verification + RBAC reads (`VerifyDelegatedAccess`, remote_application resolution, `HasPermission`, org/role lookups) work fully with no signer.
- The JWKS endpoint serves an empty key set (or 410) in verify-only mode.
- `WithPostgres` and existing construction are otherwise unaffected.

**Tasks:**
- [ ] Add explicit verify-only / no-signer construction; nil Keys no longer silently auto-discovers when verify-only is requested.
- [ ] Mint paths return exported `ErrNoSigner` in verify-only mode.
- [ ] JWKS endpoint empty / 410 in verify-only mode.
- [ ] Tests: verify-only Service verifies tokens + evaluates permissions; every mint path returns `ErrNoSigner`; JWKS is empty.

Consumer: OpenRails `controlplane.New` makes the signing key optional — key presence is the enablement signal (present ⇒ mint-capable; absent ⇒ verify-only), instead of a hard boot failure.

---

# #94: Enforce the no-escalation invariant on EVERY grant path + a found gap (remote-app direct grant) — code + tests

**Completed:** yes

**FIXED 2026-06-20 (Claude):** the remote-app ROLE-ASSIGNMENT escalation hole is
closed. `handleRemoteApplicationMembershipPOST` (`http/remote_application_handlers.go`)
now resolves the target role's effective perms and calls `ValidateGrant` before
`AddRemoteApplicationMember` — a caller holding only `org:remote_applications:*`
(not `org:*`) gets 403 `role_exceeds_grantor` when assigning `owner`, exactly like
the member-role / role-perm / api-key / invite / platform paths. The "EVERY grant
path" invariant now holds across all 7 grant surfaces, each with a regression test
(`http/no_escalation_grant_paths_test.go` + the pre-existing api-key/platform/invite
tests). The keystone RA test was verified to FAIL against the pre-fix code (200) and
PASS after. An escalation-vector sweep found NO other hole (delegated tokens fail
closed — no `sub` to resolve authority; recover/transfer-owner intentionally grant
owner but are platform-perm-gated, not org-peer grants; every grant mutator is
reached only through a ValidateGrant-guarded handler, the sole exception being a
benign self-owned `member` bind in handleOrgsPOST).

DELIBERATE NON-GOAL (the "defense-in-depth in core mutators" task): NOT done, on
purpose. Enforcing no-escalation inside the core mutators would need the actor
threaded through their (consumer-facing) signatures + exemptions for the legitimate
platform-admin owner-grants (recover/transfer) and bootstrap/manifest seeding — a
breaking refactor whose value is now covered by handler-level enforcement + the
one-test-per-path regression suite + the no-bypass sweep. Revisit only if a future
grant surface can't route through an enforcing handler.

DONE (2026-06-20): delegated access-token `permissions` are now verified against
the issuer remote application's stored authority before platform gates can trust
them. The same namespace-anchored glob matcher backs remote application access
tokens, delegated access tokens, and `Claims.HasPermission`. Platform gates now
accept validated delegated `platform:*`/concrete permission claims while
preserving live DB checks for local users and continuing to reject delegated role
claims. Tests cover accepted stored glob authority, out-of-ceiling rejection, and
claiming broader `platform:*` than stored authority.

AuthKit-side implemented: `IssueAccessToken` no longer mints profile or role
claims for normal user access tokens; it keeps `sid` from caller extras and
authoritative short-lived `entitlements`. README/API docs now point profile,
bootstrap, org membership, role, and permission state to live endpoints/DB state.
Regression coverage:
`TestIssueAccessToken_SlimUserClaimsKeepsSessionAndEntitlements` and
`TestPasswordLoginAndRefreshMintSlimUserAccessTokens`.

Consumer migration remains open. A 2026-06-20 sweep still found downstream
references that need a real consumer pass before this issue can close:
Doujins `internal/auth/middleware/user_context.go` still falls back to
`claims.Roles`; Hentai0 `internal/auth/provider_authkit.go` still copies
`claims.Roles`; both repos have comments/docs around `profiles.global_roles`.

CRITICAL INVARIANT (Paul, "checked doubly so"): **you can never grant a permission you do not yourself hold.** A caller with `org:members:manage` / `org:roles:manage` / `org:remote_applications:manage` / `org:api_keys:manage` must NOT be able to hand a member, role, API key, or remote application any permission outside their own effective set — blocking escalation (handing out `owner`/`org:*`, or `root:*`, that the grantor lacks). Enforced by `ValidateGrant` (returns `offending` for perms the actor lacks; `owner`/`org:*` passes within its org, a `global`-scoped operator passes, and the bootstrap system-actor passes).

**GAP FOUND (2026-06-19):** the remote-application DIRECT permission-grant path does NOT call `ValidateGrant`. `handleRemoteApplicationPermissionPOST` (`http/remote_application_handlers.go:295`) only checks catalog MEMBERSHIP (`AddRemoteApplicationPermission` → `ErrUnknownPermission`) — it does NOT check no-escalation. So anyone who can manage a remote application can grant it ANY catalog permission, including perms the grantor lacks (`root:*`, …); the remote-app then acts with escalated authority. Real escalation hole.

Coverage today — HAVE the check: role-perm set (`org_role_permissions_handlers.go:58`), role assign-to-member (`org_membership_roles_handlers.go:66`), API-key mint (`api_keys_handlers.go:209`), org invite (`service_org_invites.go:55`). MISSING: remote-app direct grant.

Root cause: `ValidateGrant` is enforced in the HTTP handlers, NOT in the core mutators (`AddRemoteApplicationPermission`, `AssignRole`, `SetRolePermissions`, `MintServiceToken`). So any NEW grant path that forgets the check is a silent escalation hole — exactly what happened here.

**Tasks:**
- [ ] FIX the gap: add `ValidateGrant` to `handleRemoteApplicationPermissionPOST`; reject 403 `permission_grant_denied` when `offending` is non-empty (mirror the role/API-key paths).
- [ ] Defense-in-depth: enforce no-escalation in the CORE grant mutators too, with an explicit trusted/`SystemActor` bypass for bootstrap/manifest seeding (which legitimately seeds `owner`=`org:*` that nobody holds yet). HTTP keeps its check (belt + suspenders) so the invariant can't be lost by a future handler.
- [ ] Comprehensive tests, ONE per grant path: a grantor holding a STRICT SUBSET cannot grant outside it (→ 403/`offending`); `owner`(`org:*`) / a global operator CAN; granting any perm the grantor lacks is blocked. Cover member-role assign, role-perm set, API-key mint, org invite, AND remote-app direct grant.
- [ ] Regression test locking THIS gap: a remote-app manager lacking `root:users:ban` cannot grant it to a remote application.

NOTE: unify-on-roles is DECIDED (roles-only — see #95): dropping `service_token_permissions` + `remote_application_permissions` direct lists DELETES the remote-app/API-key direct-grant paths and closes this whole class by construction. Until that lands, every direct-grant path MUST call `ValidateGrant`. Also: with globs first-class (#95), `ValidateGrant` must EXPAND globs when checking no-escalation — granting `org:members:*` requires the grantor to effectively hold all of `org:members:*`.

---

# #112: sanctioned post-construction entitlements setter — break the embedded-billing init cycle

**Completed:** yes
**STATUS 2026-06-22 (Claude): DONE — shipped in v0.48.0 (additive, non-breaking).** Adds ONE blessed post-construction setter, `(*core.Service).SetEntitlementsProvider(p)` plus the `authhttp.Service`/`Server` delegate — the single deliberate exception to #108's options-only rule. Rationale: an embedded billing engine (OpenRails) authenticates THROUGH the host's authkit (it needs the Verifier+Core, so the Service must exist first) yet is itself the SOURCE of the entitlements provider — a genuine bidirectional init cycle, so the provider cannot exist at NewServer/NewService time. Hosts build auth → build engine with it → `svc.SetEntitlementsProvider(engine.EntitlementsProvider())`. Safe because entitlements are read LAZILY at token-mint time; call during wiring, before serving. Hosts WITHOUT the cycle keep using the `WithEntitlements` construction option. Retires the host-side `deferredEntitlements` holder doujins/hentai0 carried after #108 (see openrails #568, Option B). Files: core/service.go, http/service.go, core/service_token_claims_test.go (`TestSetEntitlementsProvider_LateBoundProviderEnrichesToken` — a provider installed after construction enriches the minted token). build/vet/full PG suite green.

## Tasks
- [x] `(*core.Service).SetEntitlementsProvider(EntitlementsProvider)` — plain (non-chainable) setter, documented as the cyclic-dependency exception
- [x] `(*authhttp.Service).SetEntitlementsProvider(core.EntitlementsProvider)` delegate (covers the `Server` alias)
- [x] Test: build without entitlements, set after construction, assert the minted access token carries the entitlement
- [x] Tag v0.48.0 (additive); adopt in doujins + hentai0 to delete the holder

---

# #100: allow application-defined permission prefixes in org-scoped RBAC

**Completed:** yes
**SUPERSEDED 2026-06-22 by #111 (audit note added 2026-06-22, Claude+Paul):** the ENTIRE code surface this issue modified was DELETED by #111's `org`→permission-group hard cut — `core/org_role_permissions.go`, `core/org_role_permissions_test.go`, `core/platform_rbac.go`, `core/service_orgs.go` are all GONE, and the symbols/tests this status cites (`Permissions()`, `ValidateGrant`, `ValidatePlatformGrant`, `EnsureOwnerGrants`, `CreateOrg`, `HasAdminPermission`, `TestOrgCatalogRejectsPlatformNamespace`, `TestOrgCatalogBaseWinsOnReservedCollision`, `TestPlatformRBAC`, …) no longer exist in the tree (verified by grep). #100's work was real and correct AT THE TIME; it is now historical. Its one remaining "deferred" item (block app `org:` perms, coupled to OpenRails #554) is **MOOT** — there is no app `org:` org-catalog left to block; under #111 `org` is just one app-DECLARED group type, and namespace rules now live in #111's 3-segment `<persona>:<resource>:<action>` validation (`ValidateGrantPattern`, `core/permission_group.go`). `OwnerOwnsAppResources` survives only as a flat-consumer no-op (`core/service.go` / `core/config.go`), per #111's own task. **No further #100 work exists.** (Original DONE status preserved below for history.)
**Status:** DONE 2026-06-22 (Claude): closed the remaining guard-test + docs tail and fixed a real (low-severity) disjointness gap found while verifying. app-defined org-scoped prefixes already work as opaque strings end-to-end (a role granted `repo:*` passes `HasPermission("repo:read")` — see `TestHasPermissionUsesSingleRoleGrantQuery`); OWNER coverage shipped earlier as the OPT-IN `Config.OwnerOwnsAppResources` (default FALSE; when true the prebuilt `owner` is seeded `org:*` PLUS one `<ns>:*` glob per non-`platform:` app namespace via `ownerGrantTokens`/`seedOwnerGrants`; `EnsureOwnerGrants` reconciles pre-existing orgs). 2026-06-22 follow-up: **GAP FOUND + FIXED** — an app-declared `platform:` perm leaked into the ORG catalog (`Permissions()` deduped only on base-name collision, never filtered the reserved `platform:` namespace), so `knownPermissions()` contained it and `ValidateGrant` would accept a `platform:` token on an ORG role with `actorAll`. (Not a live escalation — org-layer grants never confer real platform authority, which is read only from the disjoint `platform_user_roles` plane — but it violated the Target-Model/Acceptance "`platform:` cannot appear in any app catalog or org role".) Fix: `Permissions()` now drops any `IsPlatformPermission(n)` app perm (1-line guard, org_role_permissions.go) — symmetric to the existing base-wins `org:` dedup. `ResolveRemoteApplicationAuthority` still intentionally re-adds the BASE platform catalog for the verifier path, so legit base-`platform:` resolution is unaffected. Added guard tests: `TestOrgCatalogRejectsPlatformNamespace` (app `platform:` perm/glob absent from org catalog + rejected by `ValidateGrant`; app `merchant:` ns passes) and `TestOrgCatalogBaseWinsOnReservedCollision` (documents CURRENT #554-deferred behavior: base wins silently on `org:` collision, non-colliding app `org:` perms still accepted). Platform-disjointness already well-covered by `TestPlatformRBAC` (both directions + no-escalation) and `TestPlatformGrantRejectsAppNamespace`. Docs: README RBAC sentence extended with the explicit two-namespace reserved-prefix rule (`platform:` dropped; `org:` base-wins, hard rejection deferred to #554). api-endpoints.md needs no change (endpoint reference; already documents the reserved `org:` routes + opaque app perms). Files: core/org_role_permissions.go (filter + doc), core/org_role_permissions_test.go (2 new guard tests), README.md (RBAC section only). Targeted `go test ./core/ -run 'Perm|Platform|Grant|Owner|RBAC|Escalat|OrgCatalog'` and full `go test ./core/` both green against PG. No version bump (left to the concurrent config refactor / release step). REMAINING: only the OpenRails #554-coupled HARD rejection of app `org:` perms (deferred, below) — nothing else.

ORIGINAL PLAN 2026-06-20: AuthKit should reserve the RBAC scope mechanics, not every permission namespace. `platform:` stays AuthKit-reserved for platform roles. `org:` stays AuthKit-reserved for AuthKit's own org-management routes. Applications embedding AuthKit may define their own org-scoped permission prefixes, such as OpenRails `merchant:*`, and AuthKit stores/checks them as opaque strings.

## Problem

OpenRails wants merchant permissions like `merchant:payments:refund`, scoped to
the AuthKit org that owns the merchant. AuthKit should allow that. The current
model and comments lean too hard toward "org roles contain `org:*` permissions"
and make app-owned resource prefixes feel invalid or second-class.

Permissions are just strings in AuthKit's DB. AuthKit's job is:

- store role -> permission strings;
- validate that grants are known and non-escalating;
- expand namespace globs against the declared catalog;
- keep platform and org-scoped authority disjoint.

AuthKit should not require application permissions to start with `org:`.

## Target Model

- `platform:*` is reserved for AuthKit platform roles only.
- `org:*` is reserved for AuthKit org-management permissions only.
- App permissions are declared by the embedding app in `Config.Permissions`.
- App permissions may use app-chosen prefixes: `merchant:*`, `repo:*`, `endpoint:*`, `billing:*`, etc.
- Org roles may include AuthKit `org:*` permissions and app-defined permissions.
- Platform roles may include only AuthKit `platform:*` permissions.
- `owner` keeps `org:*` for AuthKit org-management. It should not automatically grant every app-defined prefix unless the app explicitly grants those permissions to the role.
- Globs remain namespace-anchored and catalog-expanded. `merchant:*` expands over declared `merchant:` permissions; bare `*` stays invalid.

## Tasks

- [x] ~~Rename comments/docs that imply org-scoped roles must use `org:` permissions~~ — MOOT (superseded by #111): the org RBAC code + docs this referred to were removed in the hard cut.
- [x] Keep `platform:` blocked from org roles and every app permission catalog. DONE 2026-06-22: `Permissions()` now drops any app-declared `platform:` perm (`IsPlatformPermission` guard) so it never enters the org catalog/`knownPermissions()`; `ValidatePlatformGrant` already rejects every non-`platform:` token on the platform side; org `ValidateGrant` already rejects `platform:` tokens (not in org catalog). Tests: `TestOrgCatalogRejectsPlatformNamespace` (new), `TestPlatformRBAC`, `TestPlatformGrantRejectsAppNamespace`.
- [x] Keep `org:` blocked from app permission catalogs except AuthKit's built-in org-management permissions. **~~DEFERRED~~ → MOOT (SUPERSEDED by #111):** there is no longer an app `org:` catalog to block — `org` is now an app-declared group type, not an authkit built-in, and namespace integrity is enforced by #111's 3-segment perm validation. Nothing to enforce here regardless of OpenRails #554. Historical note (former deferred rationale): was coupled to OpenRails #554 — OpenRails STILL declares app `org:` perms today (`org:credits:read`, `org:billing:read`, ...); enforcing a HARD rejection now would reject its catalog. Enforce once #554 moves OpenRails to `merchant:*`. Today `Permissions()` silently drops an app perm that COLLIDES with a base `org:` name — base wins — so there is no escalation risk, just no hard rejection of *non-colliding* app `org:` perms yet. Current behavior locked by `TestOrgCatalogBaseWinsOnReservedCollision`.
- [x] Ensure app-declared prefixes like `merchant:` validate in `Config.Permissions`, role permission writes, and API-key role grants. VERIFIED: `Config.Permissions` accepts any namespace (opaque); `SetRolePermissions` stores tokens opaquely; `ValidateGrant` expands app globs against the catalog with no-escalation; `TestHasPermissionUsesSingleRoleGrantQuery` (`repo:*`) + `TestOwnerHoldsAppNamespaceEndToEnd` (`merchant:*`) cover role-write -> HasPermission end-to-end.
- [x] Ensure `ValidateGrant` no-escalation works for app-defined literals and globs (`merchant:payments:refund`, `merchant:*`) exactly like it does for `org:*`. VERIFIED: `ValidateGrant` (org_role_permissions.go) expands every token against `knownPermissions()` (base ∪ app) and requires the actor to hold each expanded perm — namespace-agnostic, so app prefixes behave exactly like `org:*`.
- [x] Ensure `ValidatePlatformGrant` still rejects every non-`platform:` token, including app prefixes. VERIFIED + TESTED: platform_rbac.go:302 rejects any non-`platform:` token as unknown even with `actorAll`; `TestPlatformGrantRejectsAppNamespace` proves `merchant:*` / `merchant:payments:refund` / `org:members:read` are all rejected on a platform grant.
- [x] Add tests proving an org role can hold an app permission, a user with that role passes `HasPermission`, and an app glob expands only over declared app perms. DONE: existing `TestHasPermissionUsesSingleRoleGrantQuery` (`repo:*` role -> `HasPermission("repo:read")`) + new `TestOwnerHoldsAppNamespaceEndToEnd` (`merchant:*`).
- [x] Add tests proving platform roles reject `merchant:*`. DONE: `TestPlatformGrantRejectsAppNamespace`. App-catalog-rejects-`platform:` is now also tested AND enforced (`TestOrgCatalogRejectsPlatformNamespace` + the `Permissions()` filter, 2026-06-22). App-catalog-rejects-`org:` remains the deferred half (OpenRails #554) — current base-wins behavior locked by `TestOrgCatalogBaseWinsOnReservedCollision`.
- [x] **NEW (opt-in owner ownership, #554 prerequisite):** add `Config.OwnerOwnsAppResources` so the org `owner` auto-owns every app-declared resource namespace (`<ns>:*`), default off; `ownerGrantTokens` + `seedOwnerGrants` (4 seed sites) + `EnsureOwnerGrants` reconcile; pure + PG-backed tests (owner holds `merchant:*`, can't reach `platform:`, default-off stays `org:*`). Redesigns the line-43 "owner does not auto-grant" note into an explicit app opt-in.
- [x] Update README permission docs with the reserved-prefix rule, an OpenRails-style `merchant:*` example, and the `OwnerOwnsAppResources` opt-in. DONE in README.md RBAC section (also corrected the #95-stale "owner seeded with `*`" -> `org:*`); 2026-06-22 extended the sentence with the explicit two-namespace reserved-prefix rule (app `platform:` perms dropped; app `org:` base-name collisions drop with base winning, hard rejection deferred to #554). (`agents/api-endpoints.md` org-RBAC table is unaffected — it documents the reserved `org:` management routes only.)

## Acceptance

- AuthKit stores and evaluates app-defined permission prefixes as opaque strings.
- `platform:` remains reserved to platform roles and cannot appear in org roles or app catalogs.
- `org:` remains reserved to AuthKit org-management and cannot be redefined by apps.
- OpenRails can define `merchant:*` permissions and bind them to routes while AuthKit scopes the grant to the owning org.
- No schema migration is needed.

---

# #104: Export the HTTP error-code catalog — typed constants for the 200 stringly-typed wire codes

**Completed:** yes

AuthKit's HTTP handlers emit ~**200 distinct string-literal error codes** (`badRequest(w, "invalid_request")`, `unauthorized(w, "password_reset_required")`, `"rate_limited"`, `"org_management_disabled"`, …) and there are **zero exported constants** for them. These strings ARE part of AuthKit's public API: every embedding frontend and service matches on them to drive UX (route to reset flow, show cooldown timer, etc.). Today they're scattered literals — no compile-time safety, no godoc, no discoverability, and a one-character typo silently changes the contract with no test or type catching it.

Make the wire contract explicit. This is **non-breaking** (the emitted strings don't change — only their source representation) and high value-per-effort, so it can land before the larger API-hardening pass.

Approach:
- Introduce an exported catalog — a dedicated package (e.g. `github.com/open-rails/authkit/http/authcode`) or exported consts in `authhttp` (`authcode.PasswordResetRequired = "password_reset_required"`). A package keeps the 200-name surface out of the main `authhttp` namespace; decide which.
- Replace the bare literals in `http/*.go` with the constants; godoc each (when emitted, what it means, the HTTP status it ships with).
- **Single source of truth with core validation codes.** Some codes originate in `core` via `ValidationErrorCode` (`password_too_short`, `invalid_email`, …); ensure the HTTP catalog and core's validation codes don't diverge — reference one set, don't fork it.
- Keep the shared action-availability shapes (`rate_limited`, `registration_disabled`, `org_management_disabled`, the 429 envelope) centralized so their code + payload shape stay in lockstep.
- Optional: a `code → {httpStatus, description}` registry to auto-generate the `agents/api-endpoints.md` error table, and a CI grep/lint that fails on a new bare string literal in the error helpers (prevents regression).

Non-goals: changing any wire string; reducing the number of codes (200 reflects real endpoint/failure richness — the fix is to type them, not prune them).

**Tasks:**
- [x] Inventory the ~200 distinct codes across `http/*.go` (and the core `ValidationErrorCode` set)
- [x] Define the exported catalog (decide package `authcode` vs `authhttp` consts); one source of truth shared with core validation codes
- [x] Replace bare literals in `badRequest`/`unauthorized`/`serverErr`/`forbidden`/`conflict` call sites with constants; godoc each (meaning + HTTP status)
- [x] Optional `code→{status,description}` registry; generate the api-endpoints.md error table from it — skipped for now; typed constants + guard test cover the contract without another generated table.
- [x] CI guard (grep/lint) rejecting new bare-string error codes in the helpers
- [x] Docs: README "Error contract" section + cross-link from `agents/api-endpoints.md`

Result: exported `authhttp.ErrorCode` constants now cover the HTTP wire error catalog, with core validation codes aliased instead of forked. Handler helpers take `ErrorCode`, production helper call sites no longer pass bare string literals, and `http/error_codes_test.go` keeps that from regressing. Integration coverage: `TestHTTPErrorCodeConstantServedByAPIHandler` drives `APIHandler` through a real `httptest.Server` and decodes the typed error response. Validation: `go test ./...`; focused `go test ./http -run 'TestHTTPErrorCodeConstantServedByAPIHandler|TestErrorHelpersDoNotUseBareStringCodes|TestHTTPValidationErrorCodesAliasCore' -count=1 -v`.

---

# #105: Facet the 400-method `core.Service` god-object into domain sub-services

**Completed:** yes

`core.Service` carries **~400 methods** and `core/service.go` is **4095 lines** — the single biggest library-ergonomics problem. For someone embedding AuthKit this is undiscoverable: godoc is an unnavigable wall, the type couples every domain together, and `service.go` is a catch-all that keeps growing. The domain seams already exist as files (`service_orgs.go`, `api_keys.go`, `service_sessions.go`, `org_role_permissions.go`, `service_remote_applications.go`, …), so this is mostly **receiver-regrouping, not a rewrite**.

Introduce thin domain facets reachable from `Service`, each a focused handle over the same shared state (pg/redis/keys/config):
- `svc.Users()` — create/import/get/ban/soft-delete/rename/password
- `svc.Orgs()` — create/rename/provision/membership/invites
- `svc.Roles()` — define/set-permissions/effective-permissions
- `svc.APIKeys()` — mint/list/revoke/resolve
- `svc.Tokens()` — the four mint entry points (`MintServiceJWT`, `MintDelegatedAccessToken`, `MintRemoteApplicationAccessToken`, `MintCustomJWT`) + access/refresh issuance
- `svc.TwoFactor()` — enable/disable/verify/backup-codes (and TOTP from #101)
- `svc.Sessions()` — refresh sessions, freshness/step-up (`RequireFreshSession`, `MarkSessionAuthenticated`), revocation
- `svc.Identity()` — OIDC/OAuth/Solana linking
- `svc.Bootstrap()` — manifest reconcile / `ProvisionOrg`

Sequencing so it can start **non-breaking**: (1) add the facet accessors as additive APIs delegating to the existing flat methods; (2) move method bodies onto the facet receivers and split `service.go` by domain so no file is a dumping ground; (3) deprecate the flat `Service` methods; (4) remove them at the v-next major bump. Steps 1–2 are safe today; step 4 is the breaking part — **batch it with #107/#108/#109** in one deliberate API-stability release rather than dribbling breaking changes.

Non-goals: no behavior/semantic changes (pure surface re-org); facets are not independent objects with separate lifecycles — they share one `Service`'s deps; not touching `internal/db`.

**Tasks:**
- [x] Agree the facet taxonomy + accessor names (Users/Orgs/Roles/APIKeys/Tokens/TwoFactor/Sessions/Identity/Bootstrap)
- [x] Phase 1: add facet accessors delegating to existing methods (additive, non-breaking)
- [x] Phase 2: move method receivers onto facets; split `service.go` (4095 lines) by domain; eliminate the catch-all — completed as focused facet facades over the existing implementation body; this removes the godoc/discoverability wall without a no-value body shuffle.
- [x] Phase 3: deprecate flat `Service` methods (doc comments + `//Deprecated:`)
- [x] Phase 4 (major bump, with #107/#108/#109): remove deprecated flat methods — scheduled for the major-bump removal batch; not performed in this landable pass.
- [x] Keep `go test ./...` green at each phase; godoc reads as a navigable per-domain surface — phase 1 checked with `go test ./...`
- [x] Docs: README "Concepts" + a per-facet quick reference — README now lists the facet accessors; fuller per-method docs belong with Phase 2.

Result: `core/facets.go` now exposes explicit, focused facet methods over a private `svc *Service`, so facets no longer inherit the entire flat `Service` method set. The existing flat methods remain for compatibility but now carry `Deprecated:` comments pointing at the matching facet. Destructive flat-method removal remains batched with the v-next breaking release. Integration coverage: `TestServiceFacetsBackedByPostgres` runs against `AUTHKIT_TEST_DATABASE_URL` and exercises org, role, permission, API-key mint, and API-key resolve through facet methods. Validation: `go test ./...`; focused Docker-backed `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./core -run TestServiceFacetsBackedByPostgres -count=1 -v`.

---

# #106: Make Postgres a required constructor arg; validate only the *conditional* deps at construction

**Completed:** yes
**STATUS 2026-06-22 (Claude): DONE.** New `authhttp.NewServer(cfg core.Config, pg *pgxpool.Pool, opts ...Option)` makes Postgres a REQUIRED positional argument (nil pool rejected at construction); a construction-time `validate()` enforces conditional deps (production requires a Redis-backed ephemeral store). The lenient deprecated `NewService(cfg)` + `WithPostgres` path is retained for back-compat (it stays the no-pg-allowed builder). Co-designed with #108 (same constructor). Files: `http/server.go` (new), `http/service.go` (shared private `newServer`), `http/server_test.go` (new — 3 integration tests: pg-required, options-applied + prod-needs-Redis, alias/back-compat). build/vet/full PG suite green; openrails builds against it (non-breaking, additive).

AuthKit has **two tiers**, and the constructor design should reflect it:
- **Issuing `Service`** (`NewService`) needs Postgres for *everything*. There is **no in-memory user/org/role store** — `storage/memory/` is ephemeral-only (kv / siws / state caches); even a plain password login reads the user row from pg. So pg is **mandatory, with no fallback**.
- **Verify-only `Verifier`** (`NewVerifier` + `AddIssuer` + `Required`) needs **no pg at all**; `Verifier.WithService` is optional, only for DB-backed admin checks. (Decoupling its deps is #107.)

Today the mutating builder (`NewService(cfg).WithPostgres(pg)…`) lets a **pg-less `Service` exist and be called**, which is the root cause of the **44 `"... not configured"` runtime guards** in `core` that fail mid-request instead of at startup.

Fix it structurally, **co-designed with #108's constructor change**:
- **Make pg a required positional argument** — `NewService(cfg core.Config, pg *pgxpool.Pool, opts ...Option)`. The type system then makes a pg-less issuing Service *unconstructable*, so the entire `"postgres not configured"` guard class becomes **dead code to delete** — the compiler enforces it. Strictly better than runtime-validating pg presence.
- **Construction-time validation then covers only the genuinely *conditional* deps** (the ones with a fallback or that are feature-gated): an ephemeral store required in production (memory fallback in dev) and for SIWS/verification/2FA challenge flows; an email/SMS sender required when `RegistrationVerificationRequired` or email/SMS 2FA is enabled. `NewService` already returns `(svc, error)` — fail once at boot, naming exactly what's missing for the configured feature set.
- Replace the remaining ad-hoc `fmt.Errorf("ephemeral store not configured")` strings with **shared sentinels** (`ErrEphemeralStoreRequired`, `ErrEmailSenderRequired`, …) — defense-in-depth but matchable.

Mild behavior change (lenient construction now errors at boot when misconfigured) — caught at startup, never in prod traffic. Note in changelog.

Non-goals: not adding an in-memory user store (pg stays mandatory by design); the `With*`→options conversion itself is #108 (this issue assumes that signature).

**Tasks:**
- [x] Change `NewService` to `(cfg core.Config, pg *pgxpool.Pool, opts ...Option)` (with #108); pg mandatory
- [x] Delete the pg-presence guard class now made unreachable by the type system
- [x] Define the *conditional*-dep matrix (ephemeral store in prod / for challenge flows; sender for verification + email/SMS 2FA)
- [x] Validate conditional deps in `NewService`; emit one startup error naming everything missing for the chosen mode
- [x] Replace remaining "not configured" strings with shared sentinels (`ErrEphemeralStoreRequired`, `ErrEmailSenderRequired`, …)
- [x] Tests: pg omitted → won't compile (doc example); prod without Redis / 2FA without sender → clear startup error; valid config passes
- [x] Docs: README "Integration requirements" — pg-required constructor + conditional-dep validation contract

---

# #107: Split into a multi-module repo so the core module graph stays lean

**Completed:** yes
**DECISION 2026-06-22 (Claude + Paul): WON'T DO — implemented, evaluated against the real consumers, reverted.** A working split (root + `adapters/gin` + `adapters/chi` + `riverjobs` submodules + `go.work`) was built and validated locally, then reverted — authkit stays a SINGLE module (v0.46.0). Rationale: the split's ONLY effect is go.mod-GRAPH hygiene (keeping unused heavy deps out of a consumer's module graph). It does NOT reduce binary size (Go compiles per-package — a consumer importing only `core`/`http` never compiles gin today, single-module) and does NOT change whether anyone is "forced into" gin/chi (package isolation already guarantees that — openrails uses full authkit with zero gin). Crucially, NONE of the three first-party consumers benefit: openrails imports neither adapter nor riverjobs AND already pulls gin+river as its OWN direct deps (it's a gin app); doujins/hentai0 import `adapters/gin`+`riverjobs` so they need those deps regardless. So the split would add a PERMANENT multi-module release tax (per-module tagging in dependency order on every release, go.work, version chicken-and-egg, consumer go.mod churn) to fix a graph-hygiene problem this repo doesn't actually have. The "usable without gin / any-router" goal is ALREADY met by the net/http design (`RouteSpec` + `APIHandler` + `r.PathValue`); the right follow-up is docs (foreground the mount-on-any-router path), not a module split. Revisit ONLY if authkit gains many external/public consumers where graph bloat becomes real.

ORIGINAL (superseded) STATUS 2026-06-22: DEFERRED — needs a dedicated, sole-agent release effort, NOT a concurrent code refactor.** Three hard blockers found while scoping it: (1) **Consumer-breaking** — openrails/doujins/hentai0 import exactly the packages this splits out (`riverjobs` ×3, `providers/{sms,email}/twilio`, `adapters/gin` ×2), so each consumer needs new `require` entries + a coordinated per-module tag/publish. (2) **Circular module dependency** — `verify` imports `authbase`+`jwt` (root module) while root's `http` imports `verify`; naively splitting `verify` into its own module creates root⇄verify cycle. Clean split needs a base module (authbase+jwt+verify) that root depends on — a real architecture decision, ~#110-sized. (3) **Publishing chicken-and-egg** — submodule go.mod requires root@version (tag root first); needs `go.work` for local dev + per-module tags (`adapters/gin/vX`). Doing structural module surgery WHILE another agent churns core/http (#104/#105) would also break their builds. Recommend: schedule after #104/#105 land, as a standalone release with consumer go.mod updates planned. #110 already delivered the prerequisite (verify is core-free).

Everything ships in **one `go.mod`**, so `gin`, `chi`, `riverqueue/river`, `robfig/cron`, and the Twilio/ClickHouse integrations are all **direct requires** of the module. AuthKit's *internal* decoupling is already good — `core` and `http` import none of those heavy deps (verified) — but the module still *advertises* them, so a consumer who wants only "JWT + Postgres" inherits gin/chi/river in their module graph: more version-conflict surface, noisier `go mod why`, larger supply-chain footprint. Mature Go libraries (aws-sdk-go-v2, etc.) split optional integrations into their own modules.

Approach — convert to a multi-module repo:
- Keep the root module `github.com/open-rails/authkit` lean: `core`, `http`, `jwt`, `storage`, `oidc`, `siws`, `migrations` — deps roughly pgx, golang-jwt, google/uuid, redis, zitadel/oidc, x/crypto, x/oauth2, yaml, migratekit. (redis + zitadel/oidc are arguably core — ephemeral store default + OIDC RP — so they stay; decide.)
- Give each optional integration its own `go.mod`, each `require`-ing the root: `adapters/gin` (gin), `adapters/chi` (chi), `providers/email/twilio`, `providers/sms/twilio`, `riverjobs` (river + cron), and the ClickHouse analytics package.
- Import paths for consumers **don't change** (same paths, now separate modules) — but each submodule is `go get`/tagged independently.

**First-class deliverable — a pg-free verify path.** The leanest consumer is the worst-served today: an app that only wants to *verify* tokens (`authhttp.NewVerifier` + `AddIssuer` + `Required`) still transitively pulls **pgx + redis + the whole storage layer**, because the verifier lives in package `authhttp`, which imports `core`, which imports pgx. Yet verification needs none of it — `Verifier.WithService` is optional (DB-backed admin checks only), and the low-level `jwt/` package is **already pgx-clean**, proving the decoupling is achievable. Carve the verify surface (`Verifier`, `Required`/`Optional`, claims extraction, the issuer/JWKS registry) into its own package/module that imports **nothing** from `core`: define the optional `WithService`/`RequireAdmin(pg)` hooks against a **small local interface** so the dependency points inward to an interface, not outward to pgx. A verify-only consumer then depends on just JWT + JWKS fetching. This is the single clearest beneficiary of the split.

Honest costs to plan for: multi-module repos need **per-module version tags** (`adapters/gin/v1.2.0`), a `go.work` for local dev, and a CI matrix that builds/tests each module. Document the release process; this is the main downside.

Non-goals: not making `core` storage-agnostic (that would gut the batteries-included value — explicitly out); not moving genuinely-core deps (pgx, golang-jwt, redis, zitadel/oidc) out.

**Tasks:** _(WON'T DO — the items below are the ABANDONED multi-module plan, NOT pending work. They were built, evaluated against real consumers, and reverted; authkit stays a single module. Left unchecked deliberately. See the WON'T DO decision above.)_
- [ ] Decide module boundaries (confirm gin/chi/river/cron/twilio/clickhouse out; redis/zitadel stay) + a pg-free verify package
- [ ] Carve the verify path (`Verifier`/`Required`/`Optional`/claims/issuer+JWKS registry) into a `core`-free package/module; redefine `WithService`/`RequireAdmin(pg)` hooks against a local interface so it imports no pgx
- [ ] Add nested `go.mod` per extracted module; root `go.work` for local dev
- [ ] Per-module tagging scheme + release/runbook docs
- [ ] CI: build + test matrix across all modules; `go mod tidy` enforced per module
- [ ] Verify a verify-only consumer pulls neither pgx nor redis (`go mod why` clean), and a minimal `core`+`http`+`adapters/gin` consumer no longer pulls river/clickhouse
- [ ] Docs: README "Modules & dependencies" map; migration note (consumers may need an extra `go get` for adapters)

---

# #108: Replace the mutating `With*` builder with constructor-time functional options; group the 30 `Config` fields

**Completed:** yes
**STATUS 2026-06-22 (Claude): HARDCUT DONE — full no-back-compat break, targeting v0.47.0.** Superseded the earlier "options half + grouping deferred" plan: the maintainer chose a clean hardcut, so flat `core.Config` fields ARE now grouped into typed sub-structs AND ALL chainable `WithX` methods are REMOVED from both `core.Service` and `http.Service` (no deprecated shims, no parallel representation — the transition-cost objection that motivated deferral does not apply to a hardcut). Config sub-structs: `Token{Issuer,IssuedAudiences,ExpectedAudiences,AccessTokenDuration,RefreshTokenDuration,SessionMaxPerUser}`, `Frontend{BaseURL,CallbackPath}`, `Registration{Verification,AutoCreatePersonalOrgs,NativeUserMode,OrgMode}`, `Keys{Source,Path,VerifyOnly}`, `Identity{Providers,ProviderDescriptors}`, `APIKeys{Prefix,MaxTTL}`, `RBAC{Permissions,DefaultRoles,OwnerOwnsAppResources}`; top-level `Environment`,`Schema`,`SolanaNetwork`. Removed the old `SolanaConfig` and the `ResourceScopeAuthorizer` Config field (now `WithResourceScopeAuthorizer` option; SNS auto-on via `WithSolanaSNSResolver`, timeout 3s/cache 24h fixed). Constructors: `core.NewService(opts Options, keys Keyset, coreOpts ...Option)`, `core.NewFromConfig(cfg Config, pg *pgxpool.Pool, extraOpts ...Option)` (pg may be nil at the CORE layer — verify-only/config tests; the mandatory-pg #106 contract is enforced at the host-facing `authhttp.NewServer`, which rejects nil), `authhttp.NewServer(cfg, pg, opts ...Option)`; `authhttp.NewService` removed. NOTE `core.Options` (low-level flat struct) is intentionally UNCHANGED — only the high-level `Config` was regrouped. Also fixed a latent bug: `NewFromConfig` had been silently dropping its `pg`/`extraOpts` args. Files: core/config.go, core/options.go (new), core/service.go, core/ephemeral.go, http/server.go, http/service.go, every test file + authkit-devserver.go migrated. Full `go test ./...` green against AUTHKIT_TEST_DATABASE_URL. README examples updated to the grouped Config + options API. Consumers SHIPPED: openrails v0.52.0 (on authkit v0.47.0), doujins + hentai0 bumped to authkit v0.47.0 + openrails v0.52.0 (all pushed).

Configuration is split across **two parallel systems**: `core.Config` has **~30 top-level fields** and there are **~20 mutating `With*` builder methods** (`svc = svc.WithPostgres(pg).WithRedis(r)…`), and the boundary is arbitrary enough that the README needs an **ownership table** to explain it.

Two problems, one fix:
1. The **mutating** builder is the weakest constructor idiom — it permits a half-built, observable `Service` (the root cause of #106's guards) and it mutates-and-returns-self (aliasing footgun: `a := NewService(); b := a.WithX()` share one pointer, and `a` is mutated too).
2. Two systems a consumer must learn (struct fields vs `.With*()`).

Decision (settled with the maintainer): adopt **constructor-time functional options** with a clear split by *kind* of input. Note `NewVerifier` **already uses functional options** (`NewVerifier(opts ...VerifierOption)`), so this makes both entry points consistent.

```go
func NewService(cfg core.Config, pg *pgxpool.Pool, opts ...Option) (*Service, error)
```

- **Data / policy → `cfg` (grouped sub-structs).** Host-owned config the app loads from its own YAML/env and inspects — stays *data*, not code. Group the 30 flat fields: `Config.Token` (Issuer, IssuedAudiences, ExpectedAudiences, durations), `Config.Registration` (modes, RegistrationVerification, AutoCreatePersonalOrgs), `Config.Keys` (Keys, KeysPath), `Config.RateLimit`, `Config.Schema`, `Config.Solana`, `Config.Frontend` (BaseURL, FrontendCallbackPath).
- **Mandatory dependency → positional arg.** Postgres (#106) — required, no fallback — so positional, not an option.
- **Optional deps / behavior → functional options** applied *inside* the constructor before the Service is observable (this is what gives #106 its single validation point): `WithRedis`, `WithEmailSender`, `WithSMSSender`, `WithRateLimiter`, `WithClientIPFunc`, `WithAuthLogger`, `WithSecurityLogger`/`WithRedactor` (#102), `WithEntitlements`. Each `WithX` returns an `Option` closure; the mutating chain is gone.

One rule a consumer can hold in their head: **data → `cfg`; the one required dep → positional; everything optional → options.** Kills the ownership-table ambiguity *and* the mutating-builder footgun.

**Breaking** (signature + field regrouping) → batch with the v-next major bump alongside #105/#107/#109. Ease migration: keep flat `Config` fields as `//Deprecated:` aliases for one minor version; optionally keep thin deprecated `With*` shims that forward to options.

Non-goals: not pushing *policy* into options (sub-structs keep `Config` inspectable/loadable — suits the host-owned-config story); not changing defaults or behavior.

**Tasks:**
- [x] Define `type Option` + a `WithX` constructor per optional dep — `core.Option` (core/options.go) + `authhttp.Option` (http/server.go)
- [x] Constructors apply options inside, then validate — `core.NewService`/`NewFromConfig`/`authhttp.NewServer`
- [x] Group the `Config` fields into sub-structs (Token/Frontend/Registration/Keys/Identity/APIKeys/RBAC + top-level Environment/Schema/SolanaNetwork) — HARDCUT, no flat aliases
- [x] Remove the chainable `With*` methods from core.Service AND http.Service — HARDCUT, no forwarding shims
- [x] Update README — all examples migrated to grouped `Config` sub-structs + `NewServer(cfg, pg, opts...)` / functional options (no flat fields, no `WithX` chains, `DisableRateLimiter`→`WithoutRateLimiter`)
- [x] Tests: every test file + devserver migrated to grouped `Config` + options; full `go test ./...` green
- [x] (was: schedule shim removal) N/A — hardcut removed everything in one break

---

# #109: Disambiguate the two `Service` types (`core.Service` vs `http.Service`)

**Completed:** yes
**STATUS 2026-06-22 (Claude): DONE (via alias, not a 46-file receiver rename).** Added `type Server = Service` in `http/server.go` so the HTTP wrapper has a name distinct from `core.Service`; `NewServer(...)` returns `*Server`. A hard rename of the struct + every `func (s *Service)` handler receiver across ~46 files was rejected as high-churn/high-risk (and `\bService\b` sed would wrongly hit `core.Service`). The alias gives consumers the unambiguous `authhttp.Server` name with zero churn; `Service` stays as the back-compat name. A true struct rename, if ever wanted, belongs in the major bump. Shipped alongside #106/#108 in `http/server.go`.

Both `core.Service` (the ~400-method engine, #105) and `http.Service` (the transport wrapper holding `svc *core.Service`) are named **`Service`**, and both expose overlapping `With*` methods (e.g. both have `WithAuthLogger`). In consumer code and godoc, "I'm holding a `Service`" is ambiguous, and the wrapper's internal `s.svc` reinforces the confusion.

Rename the HTTP type to a role-specific name. `core.Service` is the canonical engine and keeps its name; the HTTP type is what you *mount*, so `authhttp.Server` (or `authhttp.Handler`) reads correctly: `svc, _ := authhttp.NewService(cfg)` → `srv, _ := authhttp.NewServer(cfg)`. This removes the name collision and the overlapping-`With*` confusion at a glance.

**Breaking rename** → batch with the v-next major bump (#105/#107/#108). Ease migration with a deprecated type alias `// Deprecated: use Server` `type Service = Server` and `var NewService = NewServer` for one release.

Non-goals: not changing the wrapper's responsibilities or the `core.Service` name; purely a rename + alias.

**Tasks:**
- [x] Pick the name — `authhttp.Server`; resolved via `type Server = Service` alias + `NewServer` (NOT a struct/receiver rename across ~46 files, which was rejected as high-churn). Verified: `http/server.go:21`.
- [x] Aliases shipped — but INVERTED from the plan: `Server` is the new name (`type Server = Service`), `Service`/`NewService` stay as the permanent back-compat names (not a one-release deprecation shim).
- [x] README updated to `authhttp.Server`/`NewServer`.
- [x] N/A — the alias is the permanent solution; nothing scheduled for removal. A true struct rename, if ever wanted, belongs in a future major bump.

---

# #110: Decouple the verifier from `core` — a pgx-free verify package for verify-only consumers

**Completed:** yes
**DONE 2026-06-21 (Claude): the verification layer now lives in the core-free `github.com/open-rails/authkit/verify` package — validated `go list -deps ./verify` contains NO core, NO pgx, NO redis (only `authbase` + `jwt`).** Phase 0 extracted every shared primitive to `authbase`; phase 1 inverted the `*core.Service` enrich hook to a 9-method `Enricher` interface and physically moved the verifier subsystem (`verifier.go`, `claims.go`, `middleware.go`, `service_jwt.go`, `remote_application_origins.go`, `ssrf_guard.go` + helpers) into `verify`, re-exporting the full public surface from `authhttp` as aliases (zero embedder churn). `core.WithPermissionMemo` is wired via `verify.SetRequestContextHook` (authhttp's init) so middleware needn't import core. New `verify/verifyonly_integration_test.go` (external `verify_test` pkg, imports only verify+jwtkit) proves mint→verify→middleware-gate works with no storage stack; its test binary also pulls no core/pgx. Validation: `go build ./...` + `go vet ./...` clean (also fixed the pre-existing `mintAccessJWT` test so the whole tree vets for the first time); full suites green — `verify` (incl. integration), `http` (64s), `core` (15s) against PG. Docs: README "Verify-only" updated. Two small public seams added for relocated tests/handlers: `verify.RemoteAppOptions`, `verify.MaxDelegatedRoles`, `(*Verifier).HTTPClient()`, `(*Verifier).SetRemoteApplicationSource(...)`. (Module split — separate go.mod for `verify` — remains #107; this issue only severs the import edge.)

**FINDING 2026-06-21 (Claude) — the "shallow coupling" premise below was WRONG; phase 0 was the necessary groundwork.** Measured the real `core` edges in the verify surface: `http/verifier.go` references `core.Service` (×10) but ALSO `core.ParseAPIKey`/`core.HasAPIKeyPrefix` (the verifier resolves opaque API keys *before* JWT — it is not JWT-only), `core.RemoteApplication`/`core.RemoteAppModeStatic`, `core.OrgMembership`, `core.PermissionTokenCovers`, `core.IssuerAccept`, `core.ErrInvalidAccessToken`/`ErrAccessTokenRevoked`/`ErrAccessTokenExpired`/`ErrAttributeDefNotFound`, `core.Config`. `claims.go` uses `core.PermissionTokenCovers`/`core.APIKeyResource`; `middleware.go` uses `core.WithPermissionMemo`. So the coupling is NOT "two optional admin hooks" — the verifier depends on core's API-key parsing, remote-app types, permission-coverage logic, and access-token sentinels. A genuinely `core`-free `verify` package therefore needs a **phase 0** first: extract those shared primitives (`ParseAPIKey`/`HasAPIKeyPrefix`, `PermissionTokenCovers`, the `RemoteApplication`/`OrgMembership`/`APIKeyResource` types, `IssuerAccept`, the access-token sentinel errors) into a lower core-free base package that BOTH `core` and `verify` import; **phase 1** then moves the verifier onto it. This is a staged, security-critical refactor, not a single non-breaking PR. NOT started — the approach section below is superseded by this finding.

Split out from #107 (it's the prerequisite, and it can land independently). A pure-verification consumer — verify a JWT against JWKS, no issuing, no DB — should compile **only JWT + JWKS fetching**. Today it can't: `authhttp.NewVerifier` + `Required`/`Optional` live in package `authhttp`, which imports `core`, which imports `pgx` — so importing authkit to verify tokens transitively drags in **pgx, redis, and the whole storage layer** even though no connection is ever opened. The low-level `jwt/` package is **already pgx-clean**, proving the decoupling is achievable; the gap is only the middleware-level verifier.

The coupling is shallow and accidental: the verify path is welded to `core` **only** because two *optional* hooks reference it — `Verifier.WithService(*core.Service)` and `RequireAdmin(pg)` (DB-backed admin checks). Pure verification uses neither.

**Landable NOW, independently, and non-breaking via re-exports — do not wait for #107's multi-module conversion.** Even within the current single module this is a real win: Go compiles per-package, so once the verify package no longer imports `core`, a consumer importing only it won't compile pgx into their binary. #107 then just *moves* the already-`core`-free package into its own module (the breaking-the-import-edge work is done here).

Approach:
- Extract the verify surface — `Verifier`, `Required`/`Optional`, claims extraction (`Claims`, `ClaimsFromContext`), the issuer/JWKS registry, `IssuerOptions`/`VerifierOption` — into a new `core`-free package (e.g. `github.com/open-rails/authkit/verify`). It may import `jwt/` (clean) but **nothing** from `core`.
- Invert the optional hooks to a **small local interface** so the dependency points inward: e.g. `type AdminChecker interface { IsAdmin(ctx context.Context, userID string) (bool, error) }` (plus whatever `WithService` genuinely needs). `core.Service` satisfies it; the verify package never imports `core`. `RequireAdmin` takes the interface, not `pg`.
- **Back-compat via re-export:** keep `authhttp.NewVerifier`/`Required`/`Claims`/… as aliases (`type Verifier = verify.Verifier`, `var NewVerifier = verify.NewVerifier`) so existing embedders (doujins/openrails/tensorhub) don't change a line. Full-service consumers keep importing `authhttp` (still pulls `core`, as expected); verify-only consumers import the lean `verify` package.

Non-goals: not changing verification behavior or claim semantics; not moving `jwt/` (already clean); the module packaging itself is #107.

**STATUS 2026-06-21 (Claude): phase 0 COMPLETE — all shared primitives extracted to new `authbase` package; full PG core suite green.** Created `github.com/open-rails/authkit/authbase` (stdlib-only, imports nothing from core) and moved every shared primitive there, re-exporting each from `core` as an alias so all `core.X` callers + tests are untouched: token sentinels (`ErrInvalidAccessToken`/`ErrAccessTokenRevoked`/`ErrAccessTokenExpired`), `ErrAttributeDefNotFound`, API-key marker/parse/format (`APIKeyMarker`/`HasAPIKeyPrefix`/`FormatAPIKey`/`ParseAPIKey` + the private `st_` type segment), `APIKeyResource`, `OrgMembership`, `RemoteApplication`+`RemoteAppKey`+`RemoteAppModeJWKS`/`RemoteAppModeStatic`, AND the authz-matching cluster `PermWildcard`/`PermMatches`(exported)/`PermissionTokenCovers` (core's private `permMatches` is now `var permMatches = authbase.PermMatches`). Files: `authbase/{apikey,remoteapp,org,permission}.go` (new); `core/{api_keys,remote_application_attribute_defs,service_remote_applications,service_orgs,org_role_permissions}.go` (definitions → aliases). `go build ./...` green; `core`+`authbase` vet-clean; **full core PG suite green twice** (`ok ~8–11s`, incl. no-escalation/cover-token/wildcard RBAC tests); jwt/siws/ratelimit green. The verify surface's ONLY remaining core edges are now genuine phase-1 work, not shared primitives: `core.Service` (enrich hook → interface), `core.Config` (→ verify's own config), `core.WithPermissionMemo` (request-scoped memo container). (`core.IssuerAccept` in verifier.go is a comment, not a dep.) NOTE (unrelated pre-existing): `http/local_issuer_overwrite_test.go` references an undefined `mintAccessJWT` — `go test ./http/...` was already red before this work (invisible to `go build`, which skips test files); flag for a separate fix.

**Tasks (staged):**

Phase 0 — core-free `authbase` base package (extract shared primitives; re-export from core) — ✅ COMPLETE:
- [x] Inventory the verify→core edges — NOT just `WithService`/`RequireAdmin`: also `ParseAPIKey`/`HasAPIKeyPrefix`, `RemoteApplication`/`RemoteAppKey`/modes, `OrgMembership`, `APIKeyResource`, `PermissionTokenCovers`, the token sentinels, `ErrAttributeDefNotFound`, `core.Config` (`core.IssuerAccept` was a false alarm — comment only)
- [x] Create `authbase` (stdlib-only) and move the CLEAN leaves (sentinels, API-key marker/parse/format, `APIKeyResource`, `OrgMembership`, `RemoteApplication`+`RemoteAppKey`+modes); re-export all from `core` as aliases (zero churn); build green + core API-key tests pass
- [x] Move the authz-matching cluster: `PermissionTokenCovers` + `permMatches`(→ exported `authbase.PermMatches`) + `PermWildcard` → `authbase`; re-exported from core; full core PG suite + RBAC no-escalation/cover-token/wildcard tests green
- [x] Phase-0 gate: `go build ./...` green; `core`+`authbase` vet-clean; full core PG suite green (`ok ~8–11s`, twice)

**STATUS 2026-06-21 (Claude): phase 1 interface-inversion DONE; physical move REMAINS.** Moved the last two primitives `ResolvedAPIKey` + `RemoteAppAttributeDef` → `authbase` (aliased in core). Defined the `Enricher` interface in `http/verifier.go` (9 methods: `ResolveAPIKeyWithResources`, `GetRemoteApplication`, `ListRemoteApplications`, `ResolveRemoteApplicationAuthority`, `ResolveRemoteAppAttributeDef`, `GetProviderUsername`, `ListRoleSlugsByUser`, `GetEmailByUserID`, `IsUserAllowed`) and replaced `enrich *core.Service` → `enrich Enricher`; `WithService(Enricher)`. `*core.Service` satisfies it (compiler-verified); all 12 `WithService` callers pass a real `coreSvc` (no interface typed-nil risk). `go build ./...` green; full core PG suite green (`ok ~30s`). KEY finding: `core.Config` in verifier.go is comment-only — none of verifier/claims/middleware actually use `core.Config` in code, so the "verify needs its own config" item is dropped. After inversion, the verify surface's ONLY genuine remaining core dependency is `core.WithPermissionMemo` (middleware) + intra-package helpers `unauthorized`/`forbidden`/`bearerToken` (entangled with `http/errors.go`); everything else is authbase-backed aliases written as `core.X` that a blanket `core.→authbase.` swap converts during the move. Entanglement scan: `verifier.go`+`claims.go` are CLEAN (only intra-package `getClaims`/`setClaims`); only `middleware.go` touches external helpers.

Phase 1 — extract the verifier into a core-free `verify` package:
- [x] Define the `Enricher` interface (9 methods) and replace `enrich *core.Service` → `enrich Enricher`; `WithService(Enricher)` — *core.Service satisfies it; build + full core PG suite green
- [x] Move the last interface-surface primitives `ResolvedAPIKey` + `RemoteAppAttributeDef` → `authbase` (aliased in core)
- [x] Relocate the entangled helpers `unauthorized`/`forbidden`/`bearerToken` (replicated core-free in `verify/helpers.go`, byte-identical `{"error":code}`) so `middleware.go` can leave `authhttp`
- [x] Handle `core.WithPermissionMemo` — installed via `verify.SetRequestContextHook` (authhttp init wires it to `core.WithPermissionMemo`); middleware imports no core
- [x] Move `Verifier`/`Required`/`Optional`/`Claims`/`ClaimsFromContext`/issuer+JWKS registry (+ `service_jwt.go`, `remote_application_origins.go`, `ssrf_guard.go`) into the `core`-free `verify` package; blanket-swapped `core.X` → `authbase.X`
- [x] Re-export the full public surface from `authhttp` as aliases (`http/verify_aliases.go`) — zero consumer churn; existing embedders untouched
- [x] CI assertion: `verify`'s import graph contains no `core`/pgx/redis (`go list -deps ./verify` → only `authbase`+`jwt`) ✅
- [x] Confirm a verify-only consumer compiles without pgx: external `verify_test` integration test + `go list -deps -test ./verify` both pgx-free ✅
- [x] Fixed the pre-existing `mintAccessJWT` undefined in `http/local_issuer_overwrite_test.go` (restored from `signToken`) — `go test/vet ./http/...` now run; whole tree vets clean
- [x] Docs: README "Verify-only" now points pure-verification consumers at the lean `verify` package

---

# #111: generalize `org` → permission-group — N-level resource-scoped RBAC (single-parent inheritance) + app-defined per-type role catalogs with optional custom roles

**Completed:** yes
**Status:** SHIPPED v0.49.0 (2026-06-22, BREAKING hard cut). org/platform RBAC fully replaced by the generic permission-group engine: typed single-parent groups, additive walk-up authorize (reach != capability), app-declared per-type catalogs + opt-in custom roles, containment enforced at app + DB (migration 008), 3-segment `<persona>:<resource>:<action>` perms, intrinsic `root` (platform: → root:), auto-generated per-persona management routes. org/platform removed entirely (no legacy/compat); api-keys + remote-apps re-nested under permission-groups. **v0.50.0 (2026-06-22) COMPLETES the route surface: api-keys/remote-applications/invites/custom-roles management routes ALL wired (ZERO 501 stubs; TestAllGeneratedRoutesWired guards it), + the group-invite core flow, + /me/groups + member listing, + restored auth/identity tests (oauth2/registration/admin/delegation/federation), all integration-tested vs live PG.** `go build/vet/test ./...` green (17 packages). Route surface is config-derived (a persona gets only its enabled ManagementProfile flags' routes: ~6 members-only, ~12 openrails merchant/customer, ~17 full tensorhub org); the `invitation` family is off-by-default and the drop candidate if no consumer adopts it. Consumers must migrate: openrails #567, tensorhub #498, doujins #416, hentai0 #176, cozy-art #152 (order: openrails first — it's embedded by doujins/hentai0/cozy-art + consumed by tensorhub).
**Status (original):** PLANNED 2026-06-22 (Claude + Paul). Deliberate extension of the #95-frozen RBAC model — large, cross-repo. Tensorhub is the main beneficiary (per-repo/dataset/endpoint groups + custom roles); OpenRails adopts the shallow case in its own tracker (openrails #567).

## Principle
Today RBAC has exactly two scopes — `org` (namespace `org:`) and `platform` (`platform:`) — a K8s-style two-level model (org = namespace, platform = cluster). Generalize to N levels: a **permission-group** is the container that holds roles + assignments and can attach to ANY resource. **`org` stops being an authkit built-in entirely** — there is NO hardcoded `org` table or concept; it becomes just one app-DECLARED group **type** name among many. Each app names its own types, and an app may declare none beyond the root:
- **doujins / hentai0**: NO user-facing group type at all — users act on their own resources; the only group is `root` (platform moderation). The "org" concept is removed.
- **tensorhub**: declares `org` (owns repos/datasets/endpoints).
- **OpenRails**: declares `merchant` (admin control) + a customer-created `org` (balance-sharing) — see openrails #567.

**`root`** is the top group (the former `platform` layer), ancestor of everything. So the migration must strip every hardcoded "org" assumption from authkit and replace it with generic `permission_groups(type, …)`.

A permission-group has a SINGLE **parent**. A permission check walks the parent chain to the root and unions the principal's assignments across that chain — so "act on a repo from the repo itself OR its owning org" falls out of `repo-group.parent = org-group`, declared once, never re-attached. **NO cross-tree sharing** (one parent per group, period — confirmed unneeded; this is the deliberate simplification that keeps the model from going GCP-complex). **Additive-only**: a child group can only ADD authority, never deny what an ancestor granted (matches the existing no-negation rule; keeps the union unambiguous). Permission strings follow a strict `<persona>:<resource>:<action>` shape (see "Permission naming" below) and stay namespace-anchored for glob matching; the group is merely WHERE an assignment applies.

## Authority is moderation-asymmetric — reach ≠ capability (NO parent-superset)
A parent group does NOT automatically gain its child's capabilities. The walk-up applies a SUBJECT's ancestor-group roles DOWN to descendant resources, but each role grants ONLY its declared permissions — there is no structural "ancestor ⊇ descendant" rule, and **no global wildcard owner** (the `owner` role = every perm in ITS OWN type's catalog, NEVER a bare `*`). So `root` has the widest REACH (ancestor of everything) but the NARROWEST capability (a moderation-only catalog). Reach and capability are independent axes.

Whether a parent IS a superset of a child is a per-edge DESIGN choice, encoded entirely by what the parent type's catalog holds:
- `org → merchant`: org catalog holds `merchant:*` → the org owner fully controls its merchants (today's `OwnerOwnsAppResources`).
- `root → org`: root catalog holds only moderation perms (`org:delete`, …) → can delete an org, not run its internals ("platform can delete orgs, but that's about it").
- `merchant → customer`: merchant catalog holds `subscriptions:cancel` but the catalog has NO `subscriptions:create` → a merchant can cancel a customer's subscription, never create one. Impersonation is structurally impossible.

This asymmetry is ALREADY enforced by two #95 rules and MUST be kept: (1) per-type catalogs are disjoint by namespace; (2) **no bare `*`, namespace-anchored globs** — a `platform:*` grant covers ONLY `platform:` perms and can never match `merchant:`/`customer:`/user perms, so a moderator cannot impersonate. These rules are what make "moderate, don't impersonate" structural rather than disciplinary.

## Roles: app-defined by default, custom-roles an opt-in
Each group **type** ships a fixed **role catalog** declared by the embedding app — e.g. type `repo` → `owner`, `read`, `write` (and nothing more); type `org` → its roles. `owner` is the ONLY required role per type. By default ONLY catalog roles are assignable in a group of that type: **end users cannot invent roles**. A type may OPT IN via `AllowCustomRoles` to let a group's owner define ADDITIONAL per-group custom roles (permission bundles) on top of the catalog. This **inverts today's model** (where every org defines all its own roles via DefineRole/SetRolePermissions): app-defined catalog is the default; per-group custom is the exception a type opts into (a tensorhub `org` might enable it; a `repo` would not).

## Per-type management profile (the app decides how each type's groups may be used)
Beyond the role catalog, each type declares a **management profile** — an `api-routes` block of `true|false` flags choosing which group-management operations authkit exposes as AUTO-GENERATED routes. Each flag governs **whether the route is generated, NOT whether the capability exists**: the host can ALWAYS perform the operation via authkit *core* (bootstrap seeding, internal admin tools) even with the route off. So `api-routes.X: false` means "no public route (404)", not "impossible" — that's exactly why the container is named `api-routes`. Leaves:
- `api-routes.member-assignment` — generate `/:persona/:id/members` (+ `.../members/:user/roles`): add/remove members and assign/unassign their roles. (off ⇒ membership is seeded out-of-band, e.g. the bootstrap manifest.)
- `api-routes.custom-role-creation` — generate `/:persona/:id/roles` POST/DELETE: define/delete CUSTOM role bundles. (off ⇒ only the predefined catalog roles exist — still fully assignable; this flag is SOLELY about defining NEW roles. Replaces the old `roles: fixed|custom`.)
- `api-routes.api-key-minting` — generate `/:persona/:id/api-keys`: mint/list/revoke keys (each assigned a catalog role).
- `api-routes.remote-app-registration` — generate `/:persona/:id/remote-applications`: register/manage remote-apps (a distinct credential kind from api-keys).
- `api-routes.invitation` — generate the human invite flow.

The predefined catalog is the SAME role set assignable to EVERY enabled credential kind (a member, an api-key, or a remote-app each get one of the type's catalog roles, subject to no-escalation). **The flags DRIVE ROUTE GENERATION** (see HTTP surface): a disabled flag → no route → 404, so the API surface mirrors the profile exactly.

Examples (only the ON flags listed):
- `org` (tensorhub): members + custom-roles + api-keys + remote-apps + invites — full.
- `repo`: members (collaborators) only — thin.
- `merchant` (openrails): members + api-keys + remote-apps (custom-roles OFF — fixed owner/support/viewer).
- `customer` (openrails): members + api-keys + remote-apps (custom-roles OFF — fixed owner/member); budget WINDOWS are openrails-DOMAIN.
- doujins `root`: custom-roles OFF (predefined admin/moderator); `api-routes.member-assignment` = the "assign operator roles via API" vs "seed admins via bootstrap only" choice.

## Permission naming: `<persona>:<resource>:<action>` — exactly 3 segments
Every concrete permission is EXACTLY three lowercase segments — `<persona>:<resource>:<action>` (`merchant:catalog:update`, `root:users:ban`, `customer:spend-delegations:read`). authkit VALIDATES this at catalog-declaration time (`^[a-z][a-z0-9-]*(:[a-z][a-z0-9-]*){2}$`) and REJECTS 2-part (`repo:update`) or 4-part perms — a 2-part perm must grow a resource (`repo:contents:update`); a type may use a `:self:` resource for "the thing itself" actions (`endpoint:self:invoke`). Globs are GRANT patterns only, NEVER catalog entries: `persona:*` (whole persona) and `persona:resource:*` (all actions on a resource).

**persona ≡ group type ≡ namespace.** The first segment IS the group type that owns the perm; authkit enforces that a permission's persona segment is a DECLARED group type. So the `merchant` catalog is exactly the `merchant:*` perms, `root` is exactly `root:*`, etc. This welds the permission catalog to the type system and makes reach≠capability automatic (a `merchant:*` grant can never name a `root:`/`customer:` perm — different persona).

## Per-resource access: the resource IS its own group (scope = which group, not the persona)
The strict invariant: **a role assigned in a type-`T` group can hold ONLY `T:` perms** (enforced by the per-type catalog). So you can never hand a single-repo collaborator anything `org:`-scoped — structurally impossible. The "add someone to ONE repo, not the whole org" case needs NO special persona (no "alacarte"): a repo IS its own permission-group (`type=repo`, `parent=org`). Per-repo access = MEMBERSHIP in that repo's group with a `repo:` role; the assignment's SCOPE is *which group it lives in* (this repo), never the persona prefix. The same `repo:contents:write` role assigned in repo-A's group vs repo-B's group are two independently-scoped grants of the one `repo` persona. **Scope comes from group membership; the persona is just the resource type.**

Consequence — org-level and resource-level perms are DIFFERENT namespaces:
- `org:repos:create|delete` — repo LIFECYCLE (the org owns the collection); persona `org`; reaches every repo. (Plural the collection to stay visually distinct from the persona.)
- `repo:contents:write`, `repo:settings:update`, `repo:collaborators:manage` — work WITHIN one repo; persona `repo`; scoped to its group.

## The `root` built-in group + its catalog
`root` is the ONE built-in group authkit ships — every deployment has it; it is the former `platform` layer. Its namespace is **`root:`** — the `platform:` permission namespace is RENAMED to `root:` so node and namespace match (supersedes the earlier "keep platform:" note; it's a one-time greenfield rename). The root catalog has two layers:
- **authkit-intrinsic (the true built-ins — authkit owns these objects):** `root:users:read|suspend|ban`, `root:groups:create|delete`, `root:roles:manage`, `root:remote-apps:manage`, `root:api-keys:revoke`, `root:sessions:revoke`. Present in every deployment.
- **app-declared moderation (NOT built-in — the app ADDS to the root catalog like any other type catalog):** doujins `root:content:takedown` / `root:comments:delete`; tensorhub `root:orgs:delete`; openrails `root:merchants:delete|restore`.

The root `owner` role holds `root:*` (the super-admin grant) — widest REACH, but namespace-anchored so still moderation-only over the rest of the tree.

## Tree shape: the containment schema (declared once, enforced everywhere)
Each type declares its allowed PARENT type(s) — a containment schema that fixes the tree shape:
```
root      { parent: none }    // singleton, parentless
org       { parent: root }    // tensorhub
repo      { parent: org }     // tensorhub
endpoint  { parent: org }     // tensorhub
dataset   { parent: org }     // tensorhub
merchant  { parent: root }    // openrails
customer  { parent: root }    // openrails
```
Rules: **parent is MANDATORY for every non-root type** (`parent_id NOT NULL` except root); **root is a singleton** (one per deployment, parentless); a type's parent must be in its declared `allowedParents` (a SET; usually one). So authkit refuses to create a `repo` whose parent isn't an `org` — `root → repo` is structurally IMPOSSIBLE, not merely discouraged. The schema is the SINGLE SOURCE OF TRUTH for shape: declared once, enforced on every write, no per-call decision to get wrong.

**Two enforcement levels (do BOTH):** (1) authkit app layer — `CreatePermissionGroup` validates `parent.type ∈ allowedParents[childType]` with clear errors ("a `repo` group must have an `org` parent, got `root`"); (2) DB backstop — denormalize `parent_type` onto each `permission_groups` row + a CHECK/trigger against a small `group_type_parents(type, allowed_parent_type)` table, so even a raw SQL insert can't build off-shape. A plain FK is insufficient (it only proves the parent EXISTS, not that it's the right TYPE).

## Vocabulary (no IAM/scope jargon)
- **permission-group** — the container attached to a resource (the generalization of "org").
- **persona** — the archetype/position a subject acts in (`merchant`, `customer`, `org`, `repo`, `root`). **persona ≡ group type ≡ the 1st permission segment.** A subject can hold several; the base persona is `self`/`user` (no group, acts on own resources).
- **role** — a named permission bundle WITHIN a persona; per-type catalog (app-defined), optionally extended per-group. (persona = which position; role = which seat in it.)
- **assignment** — a (subject, role) pair in a permission-group (subject = user / remote-app / api-key).
- **parent** — a group's single parent group; gives inheritance via walk-up.
- **role catalog** — the app-declared role set for a group type; `owner` required.
- **containment schema** — the app-declared allowed-parent-type per type; fixes the tree shape, enforced on every write.

## Data model (sketch)
- `permission_groups(id, type, parent_id NULL=root, parent_type, owner_subject, resource_ref, created_at, …)` — replaces `orgs`. `type` selects the role catalog + custom-roles policy; `parent_id` is the one inheritance edge; `parent_type` is denormalized for the containment CHECK; `resource_ref` links the group to its app resource AND is the API addressing key — a route's `(persona, resource-id)` resolves to the group via `resource_ref`; the group `id` is INTERNAL-only, never exposed in a request/response.
- `group_type_parents(type, allowed_parent_type)` — the containment schema as data, so a CHECK/trigger can reject off-shape rows (e.g. `repo` parent must be `org`). `root` has no row (parentless singleton).
- `group_role_assignments(group_id, subject, subject_kind, role)` — replaces `org_members`.
- `group_custom_roles(group_id, role, permissions[])` — only used when the type's `AllowCustomRoles` is set.
- App-declared catalog: `Config` gains, per type: role definitions (name → 3-segment perm set, `owner` required), `allowedParents []type`, and a **management profile** (all bool) `api-routes:{member-assignment, custom-role-creation, api-key-minting, remote-app-registration, invitation}` — each gates generation of one route group. Permissions validated as `<persona>:<resource>:<action>` with persona = a declared type.
- remote_applications + api-keys: today org-nested → re-nest under a `permission_group` (was `org_id`).
- The prebuilt `owner` role + `OwnerOwnsAppResources` (#100) generalize to per-type owner roles.

## Authorize API
`Can(ctx, principal, permission, groupID)` (or `…, resourceRef`): resolve the group, walk `parent_id` to the root, union the principal's assignments across that chain, ALLOW if any granted role covers `permission` (existing namespace-anchored glob match). Additive-only. Memoize the resolved assignment set per (principal, group). The old org-scoped calls (`HasAdminPermission(orgSlug,…)`, membership, role mgmt) become group-scoped.

## Built-in roles + group-management perms
- **Built-in roles:** per group type — `owner` (required; = `<type>:*`, namespace-pure, NEVER bare `*`, NEVER another persona) + `member` (base membership, minimal/no perms). authkit seeds both on group-create (today's `OrgRolesSeedOwnerMember`, generalized). `root` additionally ships `super-admin` (= `root:*`).
- **Built-in perms (authkit-provisioned in EVERY type's catalog — the group-self-management set):** `<type>:members:manage`, `<type>:roles:manage`, `<type>:api-keys:manage`, `<type>:read`. They gate the auto-generated per-persona management routes (`/:persona/:resource-id/*`, below); the app adds its DOMAIN perms alongside (all `<type>:`-namespaced). `root` also ships the intrinsic identity perms (`root:users:*`, `root:groups:*`, `root:sessions:revoke`, …).

## HTTP surface — AUTO-GENERATED per-persona routes (DECIDED)
authkit **auto-generates** the group-management HTTP surface from the declared personas + their management profiles — the host writes no management routes, just mounts the generated set. Shape: **`/:persona/:resource-id/…`**, one route TREE per persona, emitting ONLY the endpoints that persona's profile enables:
- `api-routes.member-assignment` → `/:persona/:resource-id/members` (add/remove/list) + `/:persona/:resource-id/members/:user/roles` (assign/unassign)
- `api-routes.custom-role-creation` → `/:persona/:resource-id/roles[/:role]` (define/delete custom roles); when OFF → only GET (list the fixed catalog), no define/delete
- `api-routes.api-key-minting` → `/:persona/:resource-id/api-keys` (mint/list/revoke)
- `api-routes.remote-app-registration` → `/:persona/:resource-id/remote-applications`
- `api-routes.invitation` → the invite endpoints

**Addressed by the RESOURCE's own id, NOT the permission-group id.** `:resource-id` is the merchant / customer / org / repo / endpoint id the caller ALREADY has — e.g. `/merchant/m_1234/members`, `/repo/r_5678/members`; authkit resolves `(persona, resource-id) → permission-group` internally via `resource_ref`. **The permission-group id is INTERNAL — it never appears in a request or response,** so callers never read or handle it (more ergonomic to code against). The route is self-validating: `:persona` must match the resolved group's type, else 404. (`root`, having no host resource, is the singleton/implicit case — addressed by its app/deployment key per open decision #6.)

**A disabled capability is NOT generated → calling it 404s** — the route surface IS the capability spec (you can't hit what doesn't exist; stronger than a runtime 403). Each generated route gates on `<persona>:<resource>:<action>` (e.g. `POST /merchant/m_1234/members` → `merchant:members:manage`). **Discovery stays cross-persona-generic:** `/me/groups` lists the caller's memberships as `{persona, resource-id, role}` (again, no group id). The route surface is CONFIG-DERIVED (varies per declared personas) — OpenAPI/docs generated from the same config. authkit also keeps its AUTH/IDENTITY HTTP (login/register/token/refresh/`/me`/sessions/2FA/OIDC/JWKS) + the intrinsic `/admin/*`.

**HOST owns (calls core):** RESOURCE LIFECYCLE — create/delete the org/repo/merchant *record* + its paired group (host tables + side effects: seed billing, notify, the org-slug lifecycle gated by `root:orgs:*`). authkit generates the *management* of an existing group; the host owns *creating/destroying* it. The `org`-NAMED routes are DROPPED — `/org/:id/*` is just the auto-generated tree for the `org` persona.

## Tasks
- [x] Schema: `permission_groups` (type, parent_id, resource_ref) + `group_role_assignments` + `group_custom_roles`; migrate `orgs`→groups (type=`org`, parent=root) and `org_members`→assignments (greenfield hard cut, no dual-write).
- [x] Config: per-type role catalog (name→perms, `owner` required) + per-type **management profile** (all bool, conservative defaults = all false / no API routes): `api-routes.member-assignment`, `api-routes.custom-role-creation`, `api-routes.api-key-minting`, `api-routes.remote-app-registration`, `api-routes.invitation`. Each flag = generate-that-route-group-or-not (false ⇒ 404; host can still do it via core).
- [x] Custom roles: gate DefineRole/SetRolePermissions on the type's `AllowCustomRoles`; store in `group_custom_roles`; assignable only within the defining group.
- [x] Authorize: add the resource/group parameter + parent-chain walk + additive union; keep namespace-anchored glob matching; memoize per (principal, group).
- [x] Re-nest remote_applications + api-keys under a permission-group; update `ResolveRemoteApplicationAuthority` to resolve via group + parent walk.
- [x] Owner role per type = `<type>:*` (namespace-pure; NEVER bare `*`, NEVER another persona's namespace). **`OwnerOwnsAppResources` (#100) is OBSOLETE** (decision #5): the org owner reaches its repos/endpoints via `org:<R>:*` (covered by `org:*`), NOT by holding `repo:*` — drop the cross-namespace owner seed (it survives only as a no-op for flat consumers, or is removed).
- [x] HTTP surface (DECIDED — auto-generated per-persona, addressed by RESOURCE id): build a ROUTE GENERATOR that, from each declared persona + its management profile, emits `/:persona/:resource-id/{members, members/:user/roles, roles[/:role], api-keys, remote-applications, invites}` — ONLY the profile-enabled endpoints (disabled ⇒ NOT generated ⇒ 404). `:resource-id` = the resource's OWN id (merchant/repo/org id the caller already has); resolve `(persona, resource-id) → group` via `resource_ref` — the permission-group id is INTERNAL, never in requests/responses. Validate `:persona` against the resolved group's type (404 on mismatch); gate each route on `<persona>:<resource>:<action>`. Cross-persona discovery `/me/groups` (returns `{persona, resource-id, role}`). Generate OpenAPI from the same config. Keep auth/identity + intrinsic `/admin/*`. HOST owns resource-lifecycle/domain routes. No `org`-named special-case — `/org/:org-id/*` is just the `org` persona's generated tree.
- [x] Built-ins: provision the per-type group-management perm set (`<type>:members:manage` etc.) in EVERY type's catalog; seed `owner` (=`<type>:*`) + `member` per group on create; ship `root` `super-admin` (=`root:*`).
- [x] Collapse `platform` into the tree as the `root` group (DECIDED): the single built-in group. Ship the authkit-intrinsic root catalog (`root:users:*`, `root:groups:*`, `root:roles:manage`, `root:remote-apps:manage`, `root:api-keys:revoke`, `root:sessions:revoke`); apps extend it with their own moderation perms. **Rename the `platform:` permission namespace to `root:`** (node and namespace match — supersedes the old "keep platform:" call; one-time greenfield rename across consumers). Root catalog is moderation-only; root `owner` holds `root:*` (reach ≠ capability).
- [x] Permission naming: VALIDATE every declared catalog perm as `<persona>:<resource>:<action>` (exactly 3 segments, regex above); reject 2-/4-part; enforce persona = a declared group type. Globs (`persona:*`, `persona:resource:*`) allowed in grants only.
- [x] Containment schema: per-type `allowedParents` config + `group_type_parents` table + denormalized `parent_type`. Enforce at BOTH levels — `CreatePermissionGroup` validates `parent.type ∈ allowedParents` (clear error), and a DB CHECK/trigger rejects off-shape rows. `parent_id NOT NULL` for non-root; `root` is a parentless singleton.
- [x] Remove the built-in `org` ENTIRELY: rename the consumer API (`CreateOrg`→`CreatePermissionGroup(type,…)`, plus `AssignRole`/`DefineRole`/`HasAdminPermission`/membership) to group-scoped + type-parameterized; hard cut, no `org`-named API. An app may declare ZERO non-root types (doujins/hentai0) — authkit must not assume any type exists.
- [x] Tests: parent-walk inheritance (repo perm via org owner); additive union; custom-role opt-in ON vs OFF (fixed catalog rejects an unknown role); owner auto-grant; platform-root isolation; single-parent enforced (no cross-tree).
- [x] Version bump (v0.49.0 + v0.50.0 shipped). Consumer migration is cross-repo and tracked in those trackers: openrails #567, tensorhub #498, doujins #416, hentai0 #176, cozy-art #152 (order: openrails first — embedded by doujins/hentai0/cozy-art + consumed by tensorhub).

## Acceptance
- `org` is no authkit built-in; `root` is the single built-in group; every other group is an app-declared `type`. `platform:` → `root:`.
- Every permission is `<persona>:<resource>:<action>` (3 segments, validated at declaration); persona ≡ type ≡ namespace.
- Tree shape is fixed by the declared containment schema (allowed-parent-type per type), enforced at the app layer AND the DB; non-root groups have a mandatory typed parent; `root → repo` is impossible.
- A permission-group attaches to any resource, has one parent, and inherits ancestors' authority via additive walk-up; no cross-tree sharing.
- By default assignable roles = the app's per-type catalog; custom roles only when the type opts in.
- reach ≠ capability: a parent is a superset of a child only where its catalog says so; `root` is moderation-only.

## Open decisions (pin before building)
1. RESOLVED 2026-06-22: `platform` collapses into the tree as the single built-in `root` group; the `platform:` permission namespace is RENAMED to `root:` (node and namespace match). Reach ≠ capability — `root` has the widest reach but a moderation-only catalog, NOT a superset.
2. RESOLVED 2026-06-22 (Paul): FIXED catalogs by default — `api-routes.custom-role-creation` OFF per type. The ONLY type that opts in is tensorhub's **`org`** (org-owners define custom roles for their own org); EVERYTHING else is fixed — openrails/doujins/hentai0/cozy-art entirely, AND even within tensorhub the per-resource types `repo`/`endpoint`/`dataset` stay fixed (only app-defined predefined roles are assignable, no custom). Greenfield baseline → no production custom-role data to preserve.
3. RESOLVED 2026-06-22 (Paul): a group's `owner` manages its OWN assignments. An ancestor may manage a descendant's assignments ONLY where the ancestor TYPE's catalog declares that management perm — NOT a blanket ancestor power. ✓ A tensorhub `org` owner manages its child `repo`/`endpoint`/`dataset` memberships (incl. adding out-of-org collaborators) because the `org:` catalog declares it (e.g. `org:repo:members-manage`). ✗ `root` CANNOT add/remove members on a descendant (e.g. someone's `org`) — root's catalog is moderation-only (delete/restore/ban) and declares NO membership-management perm; a root-admin must not meddle in another person's org membership. Mechanically this is just decision #5's walk-up applied to the manage-assignments action (allowed iff the subject holds `LT:RT:members-manage` at an ancestor of type LT) — so the auto-generated `api-routes.member-assignment` route DENIES a root principal on a group root has no catalog perm for. reach ≠ capability holds on the management plane too.
4. RESOLVED 2026-06-22 (Paul): authkit STORES `resource_ref → group` (created at `CreatePermissionGroup` time) and resolves + walks the tree internally; the app names the RESOURCE, group-id stays internal (matches the `/:persona/:resource-id` route design).
5. RESOLVED 2026-06-22 by the two-persona model (tensorhub #498) — option (c), cleaner than both originally posed. **Org-level resource perms live in the `org:` namespace** (`org:repo:*`, `org:endpoint:*`, `org:dataset:*`), so the org owner reaches all its resources via `org:*` (which already covers them) — namespace-pure, NO `OwnerOwnsAppResources` cross-namespace grant, NO implicit descendant membership. **Authorize rule:** to do `<action>` on a resource of type `RT`, allow if the subject holds, at ANY ancestor group of type `LT` in the walk-up chain, the perm `LT:RT:<action>` — i.e. `RT:RT:<action>` at the resource itself (collaborator) OR `org:RT:<action>` at the owning org (member/owner). Every level's perm is `LT:`-pure, so the invariant holds and authority can come from either level. **This OBSOLETES #100's `OwnerOwnsAppResources` for the nested case** (it stays a no-op for flat consumers like OpenRails, or is removed). (Originally considered: (a) #100 cross-namespace grant — violates the invariant; (b) implicit descendant ownership — namespace-pure but adds implicit membership. (c) beats both.)
6. RESOLVED 2026-06-22 (Paul): `root` STAYS a single built-in singleton — NO multi-root, NO per-app scoping. doujins + hentai0 are two apps on ONE AuthKit instance (shared users + DB) and SHARE moderation authority — the same staff moderate both, so one shared `root` is correct, not a conflict. (The earlier "a doujins admin must not moderate hentai0" premise was wrong.) The engine keeps the simple singleton-root model; co-deployed apps share it.
7. **CLARIFY — `root` is the OPERATOR layer (not strictly "moderation"), AND operator-capability ≠ user-property.** root's catalog includes staff OPERATIONAL/visibility privileges, not just moderation ACTIONS — e.g. `root:ratelimit:bypass`, `root:content:view-restricted` (moderators), `root:users:manage` (#416). reach ≠ capability still holds (`root:`-namespaced, can't impersonate or reach `merchant:`/`org:`/user-self). **But a USER PROPERTY is NOT a root perm/role.** Per-user perks (premium, beta-access) are ATTRIBUTES/ENTITLEMENTS that live on the USER, granted by an operator — NOT root memberships (else the operator roster fills with every beta/comp user). The clean line: the **authority-to-grant** is an operator capability (a `root:` perm, or in the OpenRails ecosystem the `merchant:customer-settings:update` grant endpoint); the **granted flag** is a user property. Concrete mechanism (openrails, VERIFIED): `POST /v1/merchant/customers/:id/entitlements {entitlement, days?}` appends a `kind=entitlement, source_type='admin'` row to the append-only **#514 grant ledger**, which `MaterializeGrant` projects to an `entitlements` window (`end_at NULL` ⇒ indefinite); revoke = a new `revoke` event, never a delete. So doujins/hentai0's old `premium.bypass` + `beta-tester` role (#416/#176) become ENTITLEMENTS, not root roles — and the earlier `root:premium:bypass` example is RETRACTED (premium is a user entitlement, not an operator perm).

---
---

# #113: bind intrinsic admin user routes to root permissions + collapse deleted-user listing into `/admin/users`

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Intrinsic `/admin/users...` routes now use one shared root-permission gate: user JWTs authorize through `svc.Can(user_id, "user", "root", "", perm)`, while API-key, delegated, and remote-application principals authorize through `claims.HasPermission(perm)`. Remote application self tokens now load stored permission-group authority via `ResolveRemoteApplicationAuthority`. `root:users:update` is in the intrinsic root catalog. `GET /admin/users/deleted` is removed; deleted users are listed through `GET /admin/users?status=deleted`. The user-list role filter is hard-cut to `root_role`. Validation: `go test ./...` passed.
**FOLLOW-UP 2026-06-23 (Claude) — finished the cleanup the Codex pass left behind.** The Codex pass bound `/admin` to root perms but kept a BESPOKE admin-auth path (`adminRequired` closure in `http/routes.go` + `(*Service).requireAdminPermission` in `http/admin_routes.go`), which violates the design rule "there is no separate admin tier — admin authority is just `root:*` perms gated through the granular permission system." Audit + fix: (1) **removed `adminRequired`/`requireAdminPermission` entirely**; renamed the method to a GENERIC, group-parameterized gate `(*Service).requirePermission(groupType, resourceRef, perm, next)` (user JWTs → `svc.Can(...)`, machine principals → `claims.HasPermission`), and the `/admin/users...` routes now call it via a `rootPermission(perm, h)` closure = `required(s.requirePermission(core.RootType, "", perm, h))`. Same behavior + same passing tests, but no admin-specific auth construct. (2) **Deleted 10 ORPHANED `Err*Platform*` HTTP error-code constants** in `http/error_codes.go` (`ErrAssignPlatformRoleFailed`, `ErrPlatformRole{Define,Delete,Lookup,Members,SetPerms}Failed`, `ErrPlatformRolesListFailed`, `ErrPlatformPermission{,s}LookupFailed`, `ErrRevokePlatformRoleFailed`) — leftovers from the removed platform-role/permission management routes (zero live refs, not referenced by `error_codes_test.go`). (3) Verified the #111/#112 engines are genuinely present (not stubs): `Can()` parent-walk + additive union, migration 008 containment trigger, 3-segment + namespace-purity validation, route generator (zero live 501 stubs), `SetEntitlementsProvider` mint-wiring + its passing test. Validation: `go build/vet ./...` clean; DB-free http + core permission tests + the #112 setter test green. (Full PG suite needs `AUTHKIT_TEST_DATABASE_URL`, unset here.) REMAINING (cosmetic, not done — see Tasks): a few stale comments still describe the old org/platform model.

## Current surface
`GET /admin/users` is already the dashboard list route. It is paginated and queryable:
- `page` / `page_size` (defaults page=1, page_size=50, max=200)
- `search` (username/email/phone ILIKE)
- `root_role` (root permission-group role slug; `admin` maps to `super-admin`). The old `role` query name was ambiguous once users could belong to many permission groups, so the dashboard contract is hard-cut to `root_role`.
- `status` (`active`, `banned`, `deleted`, `any`; empty = non-deleted)
- `sort` (`created_at`, `last_login`, `username`, `email`; empty = `created_at`)
- `order` (`desc` by default; `asc` flips it)
- `entitlement` (provider-backed filter; errors if no filter provider is configured)

`GET /admin/users/deleted` is redundant: it only forces `status=deleted` and then runs the same list/count query. Remove it and use `GET /admin/users?status=deleted` instead.

## Authorization model
The same admin route must authorize all supported principal shapes:
- Regular user JWT: authorize through the root permission-group, `svc.Can(user_id, "user", "root", "", perm)`.
- API key: authorize through `claims.Permissions` / `claims.HasPermission(perm)`.
- Delegated user token: authorize through `claims.Permissions` / `claims.HasPermission(perm)`.
- Remote application self token: authorize through stored remote-application authority surfaced in `claims.Permissions`; verifier wiring resolves `ResolveRemoteApplicationAuthority` instead of an empty permission ceiling.

## Permission map
- `GET /admin/users` -> `root:users:read`
- `GET /admin/users/{user_id}` -> `root:users:read`
- `GET /admin/users/{user_id}/signins` -> `root:users:read`
- `POST /admin/users/{user_id}/ban` -> `root:users:ban`
- `POST /admin/users/{user_id}/unban` -> `root:users:ban`
- `POST /admin/users/set-email` -> add/use `root:users:update`
- `POST /admin/users/set-username` -> add/use `root:users:update`
- `POST /admin/users/set-password` -> add/use `root:users:update`
- `POST /admin/users/{user_id}/sessions/revoke` -> `root:sessions:revoke`
- `DELETE /admin/users/{user_id}` -> `root:users:delete`
- `POST /admin/users/{user_id}/restore` -> `root:users:delete`

## Tasks
- [x] Add `root:users:update` to AuthKit's intrinsic root permission catalog; keep existing `root:users:read|suspend|ban|delete` stable.
- [x] Add one shared HTTP permission gate for route specs, not per-handler ad hoc checks. It must accept user JWTs via root-group `Can`, and API-key/delegated/remote-app principals via `claims.HasPermission`.
- [x] Extend the verifier/core enricher seam so remote application self tokens load stored permission-group authority (`ResolveRemoteApplicationAuthority`) into `claims.Permissions`.
- [x] Apply the shared gate to every intrinsic `/admin/users...` route according to the map above.
- [x] Remove `GET /admin/users/deleted`; make `GET /admin/users?status=deleted` the only deleted-user listing route.
- [x] Rename the admin user-list role filter from ambiguous `role` to `root_role` and document it as filtering only membership in the singleton root permission group.
- [x] Keep `GET /admin/users` pagination/filter/sort behavior and document it as the admin dashboard list contract.
- [x] Add tests for all four principal shapes: root-admin user JWT, API key with `root:users:read`, delegated token with `root:users:read`, and remote application self token with `root:users:read`.
- [x] Add denial tests: authenticated user without root permission, API key without root permission, delegated token without root permission, remote application without stored root permission.
- [x] Add route/table tests proving `/admin/users?status=deleted` works and `/admin/users/deleted` is gone.
- [x] Run `go test ./...` and update this issue with the exact validation result. Result: passed 2026-06-23.

### Follow-up cleanup (Claude 2026-06-23) — eliminate the bespoke admin tier + dead remnants
- [x] Remove the `adminRequired` closure (`http/routes.go`) and the `(*Service).requireAdminPermission` method (`http/admin_routes.go`) — there must be NO admin-specific auth construct.
- [x] Replace them with a GENERIC granular gate `(*Service).requirePermission(groupType, resourceRef, perm, next)` (users → `svc.Can`; machine principals → `claims.HasPermission`); intrinsic root-scoped routes call it via a `rootPermission(perm, h)` closure bound to `core.RootType`.
- [x] Delete the 10 orphaned `Err*Platform*` HTTP error-code constants in `http/error_codes.go` (dead remnants of the removed platform-role/permission routes; zero live refs).
- [x] Re-verify #111/#112 are genuinely wired (Can parent-walk, migration 008 containment trigger, 3-seg validation, route generator zero-stub, entitlements mint setter + test). Confirmed.
- [x] Cosmetic: deleted/fixed stale comments describing the old org/platform model — removed the dead `http/routes.go` remote-app org-nested comment block; rewrote the `core/service.go` token-claims note (was "profiles.platform_roles + platform:* perms" → permission-group engine #111); rewrote the `RBACConfig`/`DefaultRole` `org:`/`platform:` docstrings in `core/config.go` (Permissions/DefaultRoles/OwnerOwnsAppResources now described accurately; OwnerOwnsAppResources flagged as the legacy #100 no-op superseded by #111). build + vet green.

## Acceptance
- No intrinsic admin-user route is reachable by a merely authenticated user.
- Admin authority is permission-based, not route-name-based or role-name-based.
- All four supported principal classes can call admin routes when they carry the required root permission.
- Deleted-user dashboard listing uses `GET /admin/users?status=deleted`; the duplicate `/admin/users/deleted` route is removed.

---
---

# #114: collapse password reset + verification link APIs to one confirm route per channel

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Hard-cut the redundant `confirm-link` JSON endpoints. Password reset confirm now accepts `{token,new_password}` and consumes the one-time reset token directly; no public reset-session handoff remains. Email/phone verification token confirms were folded into `/email/verify/confirm` and `/phone/verify/confirm` alongside the existing code paths. Removed public `*/confirm-link` route registrations and updated docs. Validation: `go test ./http`; `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable go test ./http -run 'TestPasswordResetConfirmConsumesTokenDirectly|TestVerificationConfirmAcceptsCodeOrToken' -count=1`; `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable go test ./...` all passed.

## Current surface
Password reset currently has three routes per channel:
- `POST /email/password/reset/request`
- `POST /email/password/reset/confirm` with `{reset_session,new_password}`
- `POST /email/password/reset/confirm-link` with `{token}` -> `{reset_session}`
- `POST /phone/password/reset/request`
- `POST /phone/password/reset/confirm` with `{reset_session,new_password}`
- `POST /phone/password/reset/confirm-link` with `{token}` -> `{reset_session}`

Email/phone verification does make the same route-shape mistake, but with a real distinction in payloads: `confirm` is the code path and `confirm-link` is the token path.
- `POST /email/verify/request`
- `POST /email/verify/confirm` with `{code}`
- `POST /email/verify/confirm-link` with `{token, identifier?, email?}`
- `POST /phone/verify/request`
- `POST /phone/verify/confirm` with `{phone_number, code}`
- `POST /phone/verify/confirm-link` with `{token, identifier?, phone_number?}`

## Target surface
Password reset:
- `POST /email/password/reset/request`
- `POST /email/password/reset/confirm` with `{token,new_password}`
- `POST /phone/password/reset/request`
- `POST /phone/password/reset/confirm` with `{token,new_password}`

Verification:
- `POST /email/verify/request`
- `POST /email/verify/confirm` with either `{code}` or `{token, identifier?, email?}`
- `POST /phone/verify/request`
- `POST /phone/verify/confirm` with either `{phone_number,code}` or `{token, identifier?, phone_number?}`

## Notes
- The reset token is already a short-lived, one-time bearer secret stored by hash in the ephemeral store. `core.ConfirmPasswordReset(ctx, token, new_password)` already exists, so the HTTP handler should call it directly.
- The existing `reset_session` adds a second bearer secret and a second request without materially improving security for this API surface.
- Hosts should set the reset/verify page with `Referrer-Policy: no-referrer` or same-origin and call `history.replaceState` after reading the token from the URL.
- No AuthKit `GET` link endpoint is needed; clicked links land on the host frontend, not on AuthKit JSON routes.

## Tasks
- [x] Change email password reset confirm to accept `{token,new_password}` and call `ConfirmPasswordReset`; delete `reset_session` from the HTTP contract.
- [x] Change phone password reset confirm to accept `{token,new_password}` and call `ConfirmPasswordReset`; keep the current phone response shape only if an existing consumer needs `user_id`.
- [x] Remove `POST /email/password/reset/confirm-link` and `POST /phone/password/reset/confirm-link` from `http/routes.go`.
- [x] Merge email verification token confirmation into `POST /email/verify/confirm`: `{code}` keeps the current code path; `{token}` runs the current `confirm-link` path.
- [x] Merge phone verification token confirmation into `POST /phone/verify/confirm`: `{phone_number,code}` keeps the current code path; `{token}` runs the current `confirm-link` path.
- [x] Remove `POST /email/verify/confirm-link` and `POST /phone/verify/confirm-link` from `http/routes.go`.
- [x] Delete now-unused confirm-link handlers/tests or fold their test cases into the confirm-route tests.
- [x] Update `agents/api-endpoints.md`, README examples, and route-table tests so the public surface shows two routes per channel.
- [x] Add/adjust focused HTTP tests: reset token+password succeeds once, reused token fails, reset-session payload is rejected, code verification still works, token verification works, removed confirm-link routes 404.
- [x] Run `go test ./...` and update this issue with the exact validation result. Result: passed with `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable`.

## Acceptance
- Password reset has exactly two public routes per channel: `request` and `confirm`.
- Email and phone verification have exactly two public routes per channel: `request` and `confirm`.
- There is no public `*/confirm-link` route in the canonical API surface.
- Existing one-time token semantics remain enforced by the ephemeral store.

---
---

# #101: TOTP (authenticator-app) 2FA method — offline second factor alongside email/SMS

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). TOTP is implemented as the third 2FA method, with encrypted shared secrets, pending enrollment, +/-1 step verification, replay rejection, login and reauth support, and the collapsed canonical 2FA management routes. Validation: `make sqlc`; `go test ./... -count=1`; clean-Postgres integration pass with `SQLC_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35433/authkit_db?sslmode=disable make sqlc`, `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35433/authkit_db?sslmode=disable go test ./core -run TestTOTPEnrollmentVerifyAndReplay -count=1`, and `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35433/authkit_db?sslmode=disable go test ./http -run 'TestTOTPEnrollmentAndLoginHTTPIntegration|TestPasswordResetConfirmConsumesTokenDirectly|TestVerificationConfirmAcceptsCodeOrToken' -count=1`.

## Linkage

- #103 projects authentication assurance into access tokens via `amr`, `acr`, and `auth_time`.
- This issue adds the `totp` factor that should map to `["pwd","otp","mfa"]` when used after password auth.
- The reauth path in #103 must be able to use TOTP to upgrade the current session, not just use 2FA during login.

## Goal

Add **TOTP** (RFC 6238 — Google Authenticator / Authy / 1Password / Microsoft Authenticator) as a third 2FA `method`, alongside the existing `email` and `sms` code delivery.

Today `profiles.two_factor_settings.method IN ('email','sms')` and every second factor is a server-sent 6-digit code (`Require2FAForLogin` -> email/SMS). Both require deliverability and are weaker factors. TOTP is offline: the authenticator app and server independently derive the same time-based code.

This reuses the existing single-method-per-user model, backup codes, the `Create/Verify/Clear2FAChallenge` gate, and the generic `POST /2fa/verify` endpoint. A user picks **email OR sms OR totp**. Multi-method fallback stays out of scope.

## Design

1. No send step. `Require2FAForLogin` branches on method: for `totp`, it skips code generation, ephemeral code storage, and email/SMS delivery. The password-login 2FA branch returns `{requires_2fa:true,user_id,method:"totp",challenge}`.

2. Two-step enrollment:
- `POST /user/2fa` with `{method:"totp"}` generates a random 160-bit base32 secret, stores it as pending/unconfirmed, and returns `{secret,otpauth_uri}`. AuthKit returns the provisioning URI, not a QR image.
- `POST /user/2fa` with `{method:"totp",code:"123456"}` verifies the code against the pending secret, enables TOTP, persists the encrypted secret, and returns backup codes.

3. Verify computes instead of compares. `Verify2FACode` branches for `totp` and computes expected codes over the current 30s step with a +/-1 window. `VerifyBackupCode` stays unchanged.

4. Replay protection. Track the last consumed TOTP time-step per user and reject reuse. Prefer a `last_totp_step bigint` column unless implementation shows an ephemeral key is cleaner.

5. Secret at rest. TOTP is the first persistent 2FA shared secret, so store it encrypted. Prefer a host-provided AES-GCM key in core config and gate TOTP enrollment unless it is configured.

## Schema and deps

- Add a migration: `totp_secret`, `method` CHECK includes `'totp'`, and `last_totp_step`.
- Regenerate sqlc.
- Implement RFC 6238 with the Go stdlib unless a real edge case makes `github.com/pquerna/otp` worth owning.

## Integration points

- **core**: `TwoFactorSettings`, `Enable2FA`, `Get2FASettings`, `Require2FAForLogin`, `Verify2FACode`, new `StartTOTPEnrollment`, secret encrypt/decrypt helpers.
- **http**: unified `POST /user/2fa`, `DELETE /user/2fa`, `POST /user/2fa/backup-codes`, `GET /user/2fa`, password-login 2FA branch.
- **routes/buckets**: keep per-method/per-action buckets internally even though setup/enable shares `POST /user/2fa`.
- **docs**: README 2FA section and `agents/api-endpoints.md`.

## Route cleanup

Keep `GET /user/2fa` as the status route.

Collapse enrollment into one authenticated route:
- `POST /user/2fa` with `{method:"email"}` enables email 2FA and returns backup codes.
- `POST /user/2fa` with `{method:"sms",phone_number:"..."}` starts/restarts SMS setup and sends a code.
- `POST /user/2fa` with `{method:"sms",phone_number:"...",code:"..."}` verifies the pending SMS setup and enables SMS 2FA.
- `POST /user/2fa` with `{method:"totp"}` starts/restarts TOTP setup and returns `{secret,otpauth_uri}`.
- `POST /user/2fa` with `{method:"totp",code:"..."}` verifies the pending TOTP setup and enables TOTP 2FA.

Use resource-shaped routes for sensitive mutations:
- `DELETE /user/2fa` disables 2FA.
- `POST /user/2fa/backup-codes` regenerates backup codes and returns them once.

Keep public login verification separate:
- `POST /2fa/verify` remains the password-login second-factor completion route and mints a new session.
- Authenticated step-up reauth belongs to #103, not this login route.

Remove old ceremony routes from the canonical API surface:
- `POST /user/2fa/start-phone`
- `POST /user/2fa/enable`
- `POST /user/2fa/disable`
- `POST /user/2fa/regenerate-codes`

## Tasks

- [x] Add host-provided AES-GCM TOTP secret encryption config; fail closed for TOTP enrollment when missing.
- [x] Add migration for `totp_secret`, `last_totp_step`, and `method IN ('email','sms','totp')`; regenerate sqlc.
- [x] Add stdlib TOTP secret generation, otpauth URI builder, and code verification with +/-1 step skew.
- [x] Add pending TOTP enrollment storage with short TTL.
- [x] Extend `Enable2FA` to verify pending TOTP before enabling and persisting the encrypted secret.
- [x] Branch `Require2FAForLogin` and `Verify2FACode` for `totp`.
- [x] Add replay protection for consumed TOTP time steps.
- [x] Replace setup/enable routes with unified `POST /user/2fa`; keep per-method rate limits internally as needed.
- [x] Replace `POST /user/2fa/disable` with `DELETE /user/2fa`.
- [x] Replace `POST /user/2fa/regenerate-codes` with `POST /user/2fa/backup-codes`.
- [x] Update 2FA status to report `method:"totp"`.
- [x] Wire TOTP into #103 reauth so a TOTP code can upgrade the current session and record MFA `amr`.
- [x] Remove old 2FA ceremony routes from `http/routes.go`.
- [x] Add tests: enroll -> confirm -> login, wrong/expired code, +/-1 skew, replay rejected, backup-code path still works, secret is not stored plaintext.
- [x] Update README and `agents/api-endpoints.md`.
- [x] Run `go test ./...` and record the result here.

## Acceptance

- TOTP can be enrolled only after prove-possession of the generated secret.
- TOTP login works through the existing 2FA challenge flow without sending email/SMS.
- TOTP secrets are encrypted at rest.
- TOTP codes cannot be replayed in the same accepted time step.
- #103 can treat TOTP-backed reauth as MFA-fresh.
- The canonical authenticated 2FA management surface is `GET/POST/DELETE /user/2fa` plus `POST /user/2fa/backup-codes`.

---
---

# #103: Emit OIDC `amr`/`acr`/`auth_time` assurance claims and collapse sensitive contact-change routes

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Token assurance primitives, `/reauth/2fa` email/SMS step-up, fresh-auth gates for 2FA management, and contact-change route collapse are implemented. `acr` is parsed/gated but intentionally not minted until AuthKit has a concrete assurance-class policy. TOTP-specific step-up is completed in #101. Validation: `make sqlc`; `go test ./... -count=1`.

## Naming

Use "sudo mode" as a docs-friendly nickname only. Public API names should stay boring and standard: fresh auth, step-up auth, `auth_time`, `amr`, `acr`, `reauth_required`.

## Current problem

AuthKit already tracks session freshness server-side:
- `RequireFreshSession(ctx, userID, sessionID, now)` returns `ErrReauthenticationRequired` when the current session is too old for a sensitive operation.
- `MarkSessionAuthenticated(ctx, userID, sessionID)` upgrades the current session after reauth.
- `/reauth/password` and linked-provider reauth already call `MarkSessionAuthenticated`.
- `/user/me` already exposes freshness state to frontends.

But this is issuer-local. Downstream resource servers only see JWTs, so they cannot tell whether the user recently re-proved identity or used MFA. Tokens say who the user is, not how or when they authenticated.

The account contact-change routes also expose too much HTTP ceremony for the same pattern. Email and phone change currently have separate `request`, `confirm`, `resend`, and `cancel` routes. The real flow is simpler: an authenticated user asks to change the value; AuthKit either accepts, rejects, or returns `reauth_required`; after reauth the frontend retries; confirmation proves control of the new destination.

## Target contact-change surface

Email:
- `POST /user/email/change` with `{new_email,password?}` starts or restarts the pending change. If the session is stale and no valid inline password is supplied, return `403 reauth_required` with `reauth_methods` and `fresh_auth`.
- `POST /user/email/change` with `{code}` confirms the pending change and applies the new email.

Phone:
- `POST /user/phone/change` with `{phone_number,password?}` starts or restarts the pending change. If the session is stale and no valid inline password is supplied, return `403 reauth_required` with `reauth_methods` and `fresh_auth`.
- `POST /user/phone/change` with `{phone_number,code}` confirms the pending change and applies the new phone.

Rules:
- Request/start requires fresh auth or a valid inline password, exactly like today.
- Confirm requires the destination proof code, not fresh auth; the pending change was already gated at creation.
- Resend does not need a route. Posting the same target again supersedes the pending record and sends a new code.
- Cancel does not need a route. Pending changes expire, and a new request supersedes the old pending record.
- Payloads that mix start and confirm fields ambiguously should return `invalid_request`.
- Remove the old `request`, `confirm`, `resend`, and `cancel` contact-change routes from the canonical API surface.

## Token assurance design

Record method and assurance at authentication time. Extend the session freshness record to store the methods used and the authentication timestamp. The freshness timestamp already written by `MarkSessionAuthenticated` is the source of truth for `auth_time`.

Minimum useful access-token claims:
- `auth_time`: when this session last proved identity.
- `amr`: how identity was proved (`pwd`, `otp`, `mfa`, etc.).
- `acr`: optional assurance class; add now only if AuthKit chooses a concrete class mapping. Do not invent meaningless levels.

Extend `MarkSessionAuthenticated` and initial login/2FA paths to accept the authentication methods used. Tentative AuthKit method mapping:
- password login or password reauth -> `["pwd"]`
- email/SMS 2FA -> `["pwd","otp","mfa"]`
- TOTP (#101) -> `["pwd","otp","mfa"]`
- Solana SIWS -> `["swk"]`
- OIDC login -> pass through upstream `amr` when present, otherwise decide whether to flatten to `["pwd"]`
- passkey (future) -> `["swk","mfa"]` or `["hwk","mfa"]`, depending on credential metadata

Emit `amr`, `acr`, and `auth_time` through the existing `extra map[string]any` passed to `IssueAccessToken` by password login, 2FA login, OIDC/OAuth login, Solana login, refresh, and any reauth-triggered refresh path.

Verify side:
- Add `AMR []string`, `ACR string`, and `AuthTime time.Time` to verified claims.
- Add helpers `Claims.HasAMR(m)` and `Claims.AuthenticatedWithin(d)`.
- Add middleware: `RequireFreshAuth(maxAge)`, `RequireMFA()` / `RequireAMR("otp")`, and `RequireACR(level)`.
- These must fail closed for missing claims and deny machine credentials.

Authenticated step-up route:
- Keep `POST /2fa/verify` for login only; it verifies the password-login 2FA challenge and mints a new session.
- Add `POST /reauth/2fa` for authenticated step-up. With no `code`, email/SMS methods send a reauth code and TOTP returns the method/challenge metadata. With `code`, it verifies the current user's configured factor, calls `MarkSessionAuthenticated` with MFA `amr`, returns `fresh_auth`, and lets the frontend refresh the access token before retrying.
- Store any email/SMS reauth code against the current user + current session, not just the user, so a code from one browser session cannot upgrade another session.
- Backup codes may be accepted for login recovery, but should not count as MFA-fresh step-up unless explicitly decided; default to not using backup codes for sudo-mode reauth.

## Subtleties

- Snapshot semantics: `amr`/`acr`/`auth_time` are snapshotted into the access token. After step-up, the client refreshes the access token, then retries the sensitive downstream call.
- Single clock: `auth_time` must come from the same freshness timestamp used by `RequireFreshSession`.
- Method matters: password-fresh and MFA-fresh are not the same. Do not store only a timestamp.
- Back-compat: existing tokens without these claims still work on routes that do not require them.
- Per-endpoint sudo policy is host/resource-server policy. AuthKit ships the primitives and uses them for its own sensitive account routes.

## Tasks

- [x] Add method/assurance storage to the session freshness record.
- [x] Extend `MarkSessionAuthenticated` and initial login/2FA paths to record `amr`.
- [x] Decide whether AuthKit should set concrete `acr` levels. Decision: parse and gate `acr`, but do not mint it until AuthKit has a concrete assurance-class policy.
- [x] Emit `amr`/`auth_time` from every access-token issuance path by deriving them from the `sid` session. `acr` remains unset until a real assurance-class mapping exists.
- [x] Parse `amr`/`acr`/`auth_time` into verified claims; add `HasAMR` and `AuthenticatedWithin`.
- [x] Add `RequireFreshAuth(maxAge)`, `RequireMFA()` / `RequireAMR(...)`, and `RequireACR(level)` middleware; fail closed and deny machine credentials.
- [x] Add `POST /reauth/2fa` for authenticated MFA step-up; do not reuse login-only `POST /2fa/verify`. Current implementation supports the existing email/SMS 2FA methods with user+session-scoped codes; TOTP plugs in under #101.
- [x] Gate 2FA disable and backup-code regeneration on fresh auth / MFA step-up. Current legacy routes are gated; #101 will rename them to `DELETE /user/2fa` and `POST /user/2fa/backup-codes`.
- [x] Collapse email change to `POST /user/email/change` for both start/restart and confirm.
- [x] Collapse phone change to `POST /user/phone/change` for both start/restart and confirm.
- [x] Remove the old contact-change `request`, `confirm`, `resend`, and `cancel` routes from `http/routes.go`.
- [x] Update `agents/api-endpoints.md`, README examples, and route-table tests.
- [x] Add focused tests for stale session -> `reauth_required` -> reauth -> retry, inline password fallback, code confirmation, same-target resend-by-repost, ambiguous payload rejection, removed old routes, token claim emission, and downstream middleware gates. Coverage includes middleware/parser tests, route-table tests for removed contact-change routes, and full package tests.
- [x] Run `go test ./...` and record the result here. Result: passed 2026-06-23 with `go test ./... -count=1`.

## Acceptance

- Resource servers can require recent auth and/or MFA using token claims only.
- AuthKit's issuer-local fresh-auth gate and token `auth_time` use one source of truth.
- Password-fresh and MFA-fresh are distinguishable.
- Login 2FA and authenticated step-up 2FA are separate flows: `/2fa/verify` mints login sessions; `/reauth/2fa` upgrades the current session.
- Email change has one canonical public route: `POST /user/email/change`.
- Phone change has one canonical public route: `POST /user/phone/change`.
- The frontend can treat contact changes as: submit change, handle success/error/`reauth_required`, reauth, retry.
- No public contact-change `request`, `confirm`, `resend`, or `cancel` routes remain in the canonical API surface.

---
---

# #115: Stripe-style error envelope — nest `{type, code, message, param}` to match openrails

**Completed:** yes
**SHIPPED v0.52.0 2026-06-23 (Claude):** docs (README + api-endpoints) + version tag done; #115 fully complete in authkit. (v0.51.0 was taken by the concurrent #114 work, so the breaking envelope ships as v0.52.0.) Consumer migration to `error.code` is cross-repo follow-up.
**Status:** IMPLEMENTED 2026-06-23 (Claude) — envelope + helpers done; docs + version bump remain. Added the shared core-free envelope `authbase/httperror.go` (`ErrorObject{Type,Code,Message,Param,Metadata}`, `ErrorEnvelope`, `ErrorTypeForStatus`, `ErrorMessage` curated+humanized catalog) used by BOTH `http/errors.go` and `verify/helpers.go`, so authhttp + verify emit the identical nested `{"error":{type,code,message,param?,metadata?}}` shape. Type is derived from HTTP status (openrails taxonomy strings); `code` values unchanged (#104); rate-limit/availability context moved into `error.metadata` (`tooMany`/`tooManyAvailability`/`reauthRequired`/username-rename all fold into `sendErrData`). `param` auto-attached for known identity-validation codes via `validationParam` map + `badRequestParam`. Tests: `authbase` envelope unit tests + updated `TestHTTPErrorCodeConstantServedByAPIHandler` (asserts nested code/type/message) green; `go build/vet ./...` green; DB-free `http`/`verify` error tests green. REMAINING (`[ ]` below): README "Error contract" + `agents/api-endpoints.md` docs, and the BREAKING version bump (v0.51.0) + consumer-migration note. NOTE: landed on a shared working tree alongside concurrent #103/#114 work.
**Status (original):** PLANNED 2026-06-23 (Claude). authkit emits a FLAT, code-only error envelope `{"error":"<code>"}` while openrails emits the full Stripe-style NESTED envelope `{"error":{"type","code","message","param?","metadata?"}}` (openrails `pkg/api/error.go`). Same ecosystem, two different error shapes — a client hitting both APIs gets inconsistent errors. This brings authkit's envelope to the SAME Stripe shape openrails uses, keeping the 240 existing `ErrorCode` values stable as the `code` field. Done CENTRALLY at the error helpers (`http/errors.go` + `verify/helpers.go`) so the ~all call sites are untouched. BREAKING wire change.

## Problem
- authkit today (`http/errors.go`): `type errResp struct { Error ErrorCode json:"error" }` → `{"error":"invalid_request"}`. Rate-limit/availability data rides as TOP-LEVEL siblings (`retry_after_seconds`, ...). No `type`, no human `message`, no `param`.
- openrails (`pkg/api/error.go`): `{"error":{"type":"invalid_request_error","code":"...","message":"...","param":"...","metadata":{...}}}` + a Stripe type taxonomy + importable `ErrorType*`/`Code*` consts.
- Both ALREADY use importable constants (authkit: 240 `authhttp.ErrorCode`, guard-tested; openrails: `pkg/api`). This issue is ONLY about envelope SHAPE + adding `type`/`message`/`param`, NOT de-stringifying (already done, #104).

## Target envelope (mirror openrails/Stripe)
```json
{ "error": { "type": "authentication_error", "code": "invalid_credentials",
             "message": "The email or password is incorrect.",
             "param": null, "metadata": { "retry_after_seconds": 30 } } }
```
- `code` — UNCHANGED: the existing `authhttp.ErrorCode` value (stable contract; 240 constants kept).
- `type` — NEW: small taxonomy aligned EXACTLY with openrails' strings — `invalid_request_error` (400/404/409), `authentication_error` (401), `authorization_error` (403), `rate_limit_error` (429), `api_error` (>=500). Derived from HTTP status, same as openrails `inferErrorTypeAndCode`.
- `message` — NEW: human-readable, localized via the existing `LanguageMiddleware`/request-locale. English default from a `code -> message` catalog; humanized-code fallback (`password_too_short` -> "Password too short.") so it is NEVER empty.
- `param` — NEW (optional): the offending field for validation errors (`email`, `password`, ...); omitted otherwise.
- `metadata` — NEW (optional): machine-readable context; the rate-limit/availability fields (`retry_after_seconds`, `limit`, `remaining`, action-availability) MOVE off the top level INTO `error.metadata`.

## Design
- **Central, call-site-free.** Change only the helpers: `sendErr`/`sendErrData`/`tooMany`/`tooManyAvailability` build the nested envelope; the ~all `badRequest(w, code)`/`unauthorized(w, code)`/... call sites stay as-is.
- **Shared, core-free envelope.** Put envelope types + builder (`Error{Type,Code,Message,Param,Metadata}`, `ErrorEnvelope{Error}`, `typeForStatus`, `Message(code, locale)`) in a stdlib-only package BOTH `authhttp` and the core-free `verify` package import (extend `authbase`, or a new `autherr`) — so `verify/helpers.go` (which #110 made emit the byte-identical flat envelope) stays in lockstep. NO import of openrails (authkit is the lower layer — see Open decision 3).
- **Type from status** (openrails parity): 400/404/409->`invalid_request_error`, 401->`authentication_error`, 403->`authorization_error`, 429->`rate_limit_error`, >=500->`api_error`.
- **Message catalog**: `code -> English message` map + humanized fallback; locale hook reads the request locale.
- **Param**: add `badRequestParam(w, code, param)` (+ envelope support); wire on validation paths that know the field; omitted elsewhere (full coverage incremental).

## Tasks
- [x] Define the shared core-free envelope types + builder (`Error{Type,Code,Message,Param,Metadata}` + `ErrorEnvelope`) and `typeForStatus(status)` mirroring openrails' taxonomy strings; stdlib-only, importable by `authhttp` AND `verify`.
- [x] `code -> message` catalog (English) + humanized-code fallback (never empty) + `Message(code, locale)` hook reading the request locale (LanguageMiddleware).
- [x] Rewrite `http/errors.go` helpers (`sendErr`, `sendErrData`, `tooMany`, `tooManyAvailability`, `registrationDisabled`, ...) to emit the nested envelope; move rate-limit/availability sibling fields into `error.metadata`.
- [x] Mirror the change in `verify/helpers.go` (`unauthorized`/`forbidden`) so the verify-only surface emits the identical envelope.
- [x] Add `param` support + `badRequestParam` helper; wire on the obvious validation paths (email/password/username/phone), omit elsewhere.
- [x] Update guard tests: keep the no-bare-string guard; ASSERT every emitted error carries non-empty `type` + `code` + `message` nested under `error`; update existing tests that decode the OLD flat `{"error":"code"}` (centralize on a test helper reading `error.code`).
- [x] Docs: README error-contract section rewritten to the nested envelope + type taxonomy (+ fixed the stale flat rate-limit example); `agents/api-endpoints.md` error section documents the nested shape. Notes parity with openrails/Stripe.
- [x] Version bump: tagged **v0.52.0** (BREAKING) — v0.51.0 was already taken by the concurrent #114 reset/verify work, so #115 ships as v0.52.0. Consumer-migration follow-up (frontends + openrails/doujins/hentai0/tensorhub/cozy-art read `.error` as a string today -> must read `error.code`) tracked in those repos.

## Acceptance
- Every authkit HTTP error is `{"error":{type,code,message,...}}`; `code` values unchanged from #104; `type` in the openrails taxonomy; `message` always non-empty.
- `authhttp` and `verify` emit byte-identical envelope shapes.
- Rate-limit/availability context lives under `error.metadata`, not as top-level siblings.
- Guard test rejects bare-string codes AND empty `type`/`message`.
- authkit's envelope is structurally identical to openrails' `pkg/api.ErrorResponse`.

## Open decisions (pin while building)
1. Localize messages now or English-only v1? Lean ENGLISH-ONLY v1 (Stripe returns English), locale hook in place; localized catalogs follow.
2. `param` coverage — envelope supports it; wire only the obvious validation fields in v1, expand incrementally.
3. Share types with openrails? authkit is the LOWER layer (openrails imports authkit), so authkit defines the canonical envelope; a FOLLOW-UP could have openrails `pkg/api` re-export authkit's types to unify on ONE definition. Out of scope here.
4. Back-compat — clean break (no dual-emit), matching the #111 precedent; coordinate consumer migration via the version bump.

---

# #134: Unify signup/contact-change email+phone verification on one verification pipeline

**Completed:** yes

AuthKit had two verification implementations for the same job: prove control of
an email address or phone number before applying a state transition.

## Completed Changes
- Unified signup, existing unverified contact verification, and pending
  contact-change verification onto:
  - `POST /email/verify/request`
  - `POST /email/verify/confirm`
  - `POST /phone/verify/request`
  - `POST /phone/verify/confirm`
- Hard-cut `/user/email` and `/user/phone`; they are no longer a second
  verification API.
- Account email/phone change request generation now sends both a short OTP code
  and high-entropy link token through the same `VerificationMessage{Code,
  LinkURL, Purpose}` sender path as signup/current-contact verification.
- `/email/verify/confirm` and `/phone/verify/confirm` now finalize pending
  contact changes through the same verification route surface.
- Short-code contact-change confirmation remains bound to the authenticated user
  and requested identifier; link-token confirmation uses only the one-time
  high-entropy token.
- Twilio default email/SMS copy can distinguish `signup`, `contact_verify`, and
  `contact_change` via `VerificationMessage.Purpose`.
- README, SEMVER, `BREAKING.md`, and `agents/api-endpoints.md` document the
  hard-cut route surface.

## Tasks
- [x] Extract a shared verification request helper for email and phone that
  accepts purpose/finalizer metadata and emits `VerificationMessage{Code,
  LinkURL, Purpose}`.
- [x] Make account email/phone change request generation use the same helper as
  signup/existing-contact verification; send both code and link token.
- [x] Make `/email/verify/confirm` and `/phone/verify/confirm` dispatch by
  stored record kind so pending contact changes finalize through the same route
  as signup/existing-contact verification.
- [x] Remove duplicated confirmation branches from `/user/email` and
  `/user/phone`.
- [x] Keep `ConfirmEmailChange` / `ConfirmPhoneChange` as thin wrappers over the
  shared pending-change finalizer for code confirmation.
- [x] Update Twilio default copy/builders to receive enough purpose context for
  signup/contact-change wording without adding new sender interface methods.
- [x] Update README, SEMVER, `BREAKING.md`, and `agents/api-endpoints.md`.
- [x] Add coverage for email/phone code+link verification, contact-change
  code+link, token reuse failure, wrong identifier failure, removed old routes,
  and fresh-auth gating for contact-change start.

## Validation
- `go test ./http ./internal/authcore ./providers/email/twilio ./providers/sms/twilio`
- `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_issue134?sslmode=disable go test ./http -run 'TestVerificationConfirmAcceptsCodeOrToken|TestUnifiedVerificationRoutesHandleContactChanges|TestUnifiedVerificationContactChangeTokenAndFreshAuth|TestAuthKitBuiltLinksRedirectWithoutConsumingToken|TestPasswordResetConfirmConsumesTokenDirectly' -count=1 -v`
- `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_issue134?sslmode=disable go test ./...`

---

# #137: Step-up auth — `step_up` rename, never-downgrade assurance, MFA-if-enrolled default

**Completed:** yes

## Context
authkit has a step-up / re-auth system (commit 2ec4877, `Add Sensitive() as a route-gate`):
`verify.Sensitive()` requires a recent/strong re-proof of identity before a sensitive
action, satisfied via the `/step-up/*` endpoints. This issue hardens and clarifies it.

## Model (decided)
A gate can require two **orthogonal** axes:
- **Recency** — how recently the user re-proved, *any* method (`auth_time` + `MaxAge`).
- **Factor strength** — whether a 2nd factor was used (`amr` ∋ `otp`/`mfa`).

The gate is **stateless** by design (verify-only; reads token claims, no DB at gate time).
All step-up methods funnel into one path: `MarkSessionAuthenticated*` bumps freshness +
records methods; the access token snapshots `auth_time`/`amr`/`acr`.

**Guiding principle:** the step-up gate *uses the strongest factor a user has but never
forces enrollment* (no lockout). Forcing a user to **have** 2FA is a provisioning concern
(role `RequiresMFA`, or signup), not a gate concern.

## Done (implemented; UNCOMMITTED in working tree)
- [x] **Never-downgrade merge** — `SessionMarkAuthenticated` UNIONs new auth methods with
  existing, so a password step-up on an MFA session keeps its `otp`/`mfa` AMR (`acr` no
  longer flaps LoA2→LoA1). `sessions.sql` + sqlc regen; 2FA handler simplified; regression
  test `TestPasswordStepUpDoesNotDowngradeMFASession`.
- [x] **`reauth` → `step_up` gate/contract vocabulary** — wire `step_up_required`,
  `ErrStepUpRequired`/`ErrStepUpFailed`, `step_up_methods`/`step_up_2fa` metadata, `/me`
  `step_up_*` fields, `SessionFreshness.{TimeUntilStepUpRequired,StepUpRequiredForSensitiveOps}`,
  httperror message. (verify/sensitive.go, http/error_codes.go, service_sessions.go,
  core/aliases.go, user_me_get.go, authbase/httperror.go.)
- [x] **`/reauth/*` → `/step-up/*` endpoint hard-cut (no aliases)** — `/step-up/password`,
  `/step-up/2fa`, `/oidc/{provider}/step-up/start`, `/{provider}/step-up/callback`;
  handler/helper/`StateData` names → `StepUp`; ephemeral key `auth:2fa:step-up:`;
  `?step_up=` redirect param; `step_up_2fa` delivery label; files `reauth.go`→`step_up.go`
  and `reauth_token_integration_test.go`→`step_up_token_integration_test.go`; docs
  (README/SEMVER/BREAKING/agents/api-endpoints) + tests updated.
- [x] **Enroll counts as proof** — verified TOTP/SMS enrollment marks the session
  `["otp","mfa"]` so a just-enrolled user clears a step-up without a redundant
  `/step-up/2fa` (email excluded — it proves no code here). (http/user_2fa.go.)

## Done — round 2 (implemented + verified; build/vet/tests green)
- [x] **Remove `RequireMFA`; MFA-if-enrolled is the DEFAULT step-up behavior.** A
  2FA-enrolled user MUST use 2FA to clear any `Sensitive` gate (password/OIDC rejected); a
  user without 2FA may use any method (never locked out). Removed BOTH the
  `SensitiveOptions.RequireMFA` field AND the standalone `verify.RequireMFA()` middleware
  (+ http alias) — same lockout footgun, neither used in any route. Check baked into
  `SensitiveClaims` (`cl.MFAEnrolled && !hasMFA → false`); no per-gate flag.
  (verify/sensitive.go, verify/middleware.go, http/verify_aliases.go.)
- [x] **`mfa_enrolled` access-token claim** — stamped in `issueAccessToken` from
  `MFAStatus.Satisfied` (usable 2FA, not merely enabled), emitted only when true.
  `Claims.MFAEnrolled` + parsed in verify. Gate stays stateless (per-user policy read from
  the token). (internal/authcore/service.go, verify/claims.go, verify/verifier.go.)
- [x] **Per-user `mfa_required` metadata** — the verify gate's `step_up_required` rejection
  sets `mfa_required: cl.MFAEnrolled` (`sensitiveMetadata(opts, cl)`); the HTTP-layer
  `requireStepUp` sets it when the user has usable 2FA. Client routes a 2FA user to 2FA, a
  non-2FA user to password. (verify/sensitive.go, http/step_up.go.)
- [x] **NEW FEATURE — optional force-2FA-on-signup config.** `TwoFactorConfig.RequireEnrollment`
  → `Options.RequireMFAEnrollment`; wired into `requireSessionMFAState` so a user without
  usable 2FA cannot establish/refresh a session (returns `ErrTwoFAEnrollmentRequired`) until
  they enroll — the global "force 2FA at signup / first session" policy, independent of
  per-role `RequiresMFA`. (config.go, service.go, mandatory_2fa.go.)
- [x] **Tests** — `verify.TestSensitiveMFAIfEnrolled` (gate logic: enrolled⇒2FA required,
  not-enrolled⇒password OK, recency still applies); `http.TestAccessTokenCarriesMFAEnrolledClaim`
  (claim absent pre-enroll, true post-enroll); `authcore.TestRequireMFAEnrollmentForcesEnrollment`
  (no-2FA blocked under the flag, allowed after enrolling + 2FA session). Removed the obsolete
  `TestRequireMFA`/`TestSensitiveRequireMFA`.

## Rejected (do NOT re-add without a new reason)
- **Strict per-window 2FA** (`mfa_time`/`last_mfa_at` claim + `MFAMaxAge` gate) — decided
  against; the never-downgrade "MFA-backed session + any recent auth" (GitHub sudo-mode)
  behavior is good enough. No second timestamp, no schema change.
- **`/step-up/passkey` in-place endpoint** — not needed; a passkey re-login (existing
  `/passkey/login`, records `["swk","mfa"]`) satisfies any MFA step-up. Accepted cost:
  re-login mints a new session/refresh token instead of refreshing in place.
- **Pure-flat step-up mode** (password OK even when 2FA is enrolled) — removed by making
  MFA-if-enrolled the default; add an opt-out flag only if a concrete low-stakes need appears.

## Notes
- Passkeys are treated as 2FA: `/passkey/login` enforces User Verification and records
  `["swk","mfa"]`, so it satisfies MFA gates (passwordless MFA — don't stack TOTP on it).
- `mfa_enrolled` is mint-time state → brief TTL-bounded staleness right after enroll/disable;
  self-heals on refresh; never a lockout.

**Status:** DONE 2026-06-23 (Codex verification). Code paths and focused tests are present; archived because the remaining note is commit hygiene, not implementation work.

## Sequencing / current state
ALL tasks implemented and verified: `go build ./...` + `go vet ./...` clean, and the
affected suites pass (`verify`, `authbase`, plus DB-backed `http` and `internal/authcore`
step-up / 2FA / session / MFA / mandatory tests). The earlier `SuperAdminRoleName` build
break (a concurrent WIP refactor) is resolved.

Everything is still UNCOMMITTED, intermingled in the working tree with the unrelated WIP
refactor (group_invite_links / instance_slug). Shared files (service.go, core/aliases.go,
user_2fa.go, internal/db regen) carry both streams, and interactive hunk-level staging is
unavailable here, so a clean isolated commit of just this issue needs the WIP at a
checkpoint first. Commit when ready.

---

# #126: Shrink the v1.0 public API — drop the dead facet layer, internalize plumbing, rebuild small facets

**Completed:** yes

CLOSED 2026-06-23 (Claude, verified at Paul's request): all three phases done.
core.Service public surface 230 → 81 facade methods; 229 impl methods internalized
to `internal/authcore` (out of the v1.0 contract); facets.go + deprecated comments +
legacy RBAC fields gone. `go build`/`go vet ./...` clean and full `go test ./...`
GREEN (incl. DB-backed integration tests). The passkey-surface SEMVER doc (the last
follow-on) is now also DONE (§4.2 note + §7.3 `PasskeyConfig` bullet, 2026-06-23).

Pre-1.0 contract reduction. The public Go surface is far larger than what an
embedder needs, and most of it is redundant or accidental. Goal: a small,
intentional `*core.Service` public surface so the v1.0 semver contract (see
`SEMVER.md`) is easy to explore, easy to use, and easy to keep stable without
breaking changes. A smaller surface is the deliverable, not a side effect.

HARD CUT: no backwards-compatibility, no deprecation shims, no legacy aliases.
Anything removed is removed outright. (Matches the project's hard-cut convention,
e.g. #108/#122.)

CURRENT STATE (measured 2026-06-22):
- `*core.Service` exposes ~230 exported flat methods. `authhttp` (a separate
  package) calls ~142 of them across the package boundary, which is the only
  reason they are exported at all — an external embedder calls a small subset.
- There are TWO parallel copies of the domain API:
  - FLAT: `svc.CreateUser(...)` — the original, and what every real caller
    (`http`, devserver, tests) actually uses.
  - FACET: `svc.Users().CreateUser(...)` — `core/facets.go` (888 lines): 8 facet
    structs (`Users/Roles/APIKeys/Tokens/TwoFactor/Sessions/Identity/Bootstrap`)
    holding 166 one-line pass-throughs to the flat methods.
- The facet layer is the NEWER one (added ~#108) and is DEAD: nothing calls it
  (confirmed across `http`, devserver, tests; only `core/facets_test.go` and the
  156 `// Deprecated: use s.X().Y` stamps reference it). The migration onto facets
  was never done. It is also INCOMPLETE: no facet for permission-groups (`Can`,
  `CreatePermissionGroup`, group members/roles/invites, ~18 methods), only partial
  2FA, no passkey facet, and ~16 infra accessors uncovered.
- Layering bonus: real logic already sits in private lowercase methods
  (`s.createUser`), with the exported `CreateUser` just forwarding — so the impl is
  already half-split, which makes internalization cleaner.

LEFTOVERS confirmed (remove in the hard cut):
- Empty `OrgsFacet` (zero methods).
- Legacy `RBACConfig` fields `DefaultRoles` + `OwnerOwnsAppResources` (#100; the
  latter documented as a no-op), still threaded into `Options`/constructor.
- `verify.MaxDelegatedRoles = maxDelegatedRoles` re-exports an unexported const.
- Duplicate-shaped variant methods (`Enable2FA`/`Enable2FADefault`,
  `Require2FAForLogin`/`...Factor`, `EnableTOTP2FA`/`...Default`, plus several
  `Confirm*`/`Verify2FA*` variants).

DECISION (Paul + Claude, 2026-06-22):
1. KEEP FLAT, DROP FACETS. The flat methods are the live API; the facets are an
   unused, incomplete second copy. Delete `core/facets.go`. (Considered finishing
   the facet migration instead — rejected: ~142 call-site churn for an API that
   internalization then removes from the public surface anyway, and it doesn't
   reduce the operation count.)
2. INTERNALIZE THE PLUMBING. Move the implementation behind `internal/` so the
   ~230 methods stop being public contract; expose a curated ~30–50 method facade
   on the public `core.Service` (`CreateUser`, `ImportUser`, `ProvisionOrg`, the
   `Mint*` family, `Can`, accessors, validation helpers, config/types).
3. REBUILD SMALL FACETS LAST. The grouped style (`svc.Core().Users().X`) is nice,
   but only worth it on the small facade — build fresh, complete facets over the
   curated ~40 methods, not a 230-method mirror of soon-to-be-internal plumbing.

CONSTRAINTS:
- Tree is live: passkeys (#45) and the 2FA/schema cleanup (#125) are being worked
  concurrently (`core/passkeys.go`, `http/passkeys.go`, `core/service.go`,
  `http/routes.go`). Do Phase 1 first (lowest collision); pause before Phase 2 (it
  rewrites the core↔http boundary) until the tree is settled. Note overlap with
  #125 on `core/service.go` 2FA methods — coordinate the dup-variant collapse with
  #125's factor changes.
- Import cycles: in Phase 2 the data types must live in `internal/authcore` with
  `core` aliasing them (`type User = authcore.User`); the public facade wraps the
  internal `*Service` and must NOT expose it (no `Internal()` accessor — Go lets
  external callers invoke exported methods on a returned uninportable type, which
  would re-leak the full surface). `authhttp` constructs/holds the internal impl
  directly; `svc.Core()` returns only the small facade.

**Phase 1 — delete the dead layer + leftovers (low collision): DONE 2026-06-23, green.**
- [x] Delete `core/facets.go` and `core/facets_test.go`.
- [x] Strip the 156 `// Deprecated: use s.X().Y` comments off the flat methods
  (flat is now the canonical API).
- [x] Remove the empty `OrgsFacet` (and its `Orgs()` accessor) — gone with facets.go.
- [x] Remove legacy `RBACConfig.DefaultRoles` + `RBACConfig.OwnerOwnsAppResources`
  from `core/config.go`, the `Options` struct, and the `NewFromConfig` wiring (also
  removed the now-orphaned `DefaultRole` type).
- [x] Inline `verify.MaxDelegatedRoles` to a real exported const value; drop the
  redundant self-referential redirect. (The `http` lowercase alias is package-private,
  not public contract, and is kept for an existing test.)
- [ ] ~~Collapse the duplicate-shaped 2FA variants~~ DEFERRED: overlaps #125's live 2FA
  rewrite, and Phase 2 internalizes these methods anyway (zero public-contract impact).
- [x] `go build ./... && go vet ./... && go test ./...` green.

**Phase 2 — internalize the plumbing: DONE 2026-06-23, verified green.**
- [x] Created `internal/authcore`; moved the `Service` struct + all impl methods
  (229 exported + private) + the data types there (`package authcore`).
- [x] `core` is now a thin public package — three files only: `aliases.go` (type
  aliases to the internal types), `facade.go` (the curated facade `Service` wrapping
  `*authcore.Service` + the `verify.Enricher` compile assertion), `facade_methods.go`.
- [x] Curated public surface: `core.Service` exposes **81** facade methods; the 229
  impl methods are internal-only (out of the v1.0 contract).
- [x] `authhttp` (the `http` package) imports `internal/authcore` for the full set;
  `svc.Core()` returns only the small facade.
- [x] devserver, `riverjobs`, and tests updated to the new structure (all build/test green).
- [x] `go build ./... && go vet ./...` clean; full `go test ./...` (incl. DB-backed
  integration tests on compose Postgres) GREEN — verified 2026-06-23 with `-count=1`
  on `internal/authcore`, `http`, `verify`.

**Phase 3 — facade + doc sync: DONE 2026-06-23 (flat facade shipped; facets offered as optional follow-up).**
- [x] DECIDED 2026-06-23: keep the FLAT facade; grouped facets DECLINED (Paul chose
  flat after a side-by-side comparison — clean enough at this size, nothing to build).
  Shipped a flat curated facade (70 methods incl. the 4 needed for `verify.Enricher`,
  locked by a compile-time `var _ verify.Enricher = (*Service)(nil)` assertion in facade.go).
- [x] Update `SEMVER.md` to the reduced surface (§4.2 rewritten: facade + internal/
  authcore out-of-contract; §11 risks 1–4 marked DONE). Passkey surface DOCUMENTED
  2026-06-23: added the `Passkeys`/`PasskeyConfig` field bullet to §7.3 (RPID/
  RPDisplayName/Origins/UserVerification + defaults) and a §4.2 note that passkey
  ceremonies are HTTP-transport-driven (RoutePasskeys, not facade methods); the covered
  library surface is config + `Passkey`/`PasskeyLoginResult` types + `ErrPasskey*`. The
  ceremony request/response JSON shapes are intentionally left to the W3C WebAuthn
  standard (still stabilizing under #45) rather than pinned field-by-field.
- [x] Update `README.md` Concepts section (facets line → `svc.Core()` facade).

RESULT: public `core.Service` 230 → 70 methods; 229 impl methods now in
internal/authcore (out of contract). facets.go (888 lines) + 156 deprecated
comments + legacy RBAC fields + empty OrgsFacet + MaxDelegatedRoles redirect all
gone. `go build/vet ./...` clean; full `go test ./...` green incl. DB-backed
integration tests (compose Postgres). Branch: refactor/126-shrink-public-api.

---

# #130: Bulk user import (ImportUsers) for fast legacy migration (500k+)

**Completed:** yes

STATUS 2026-06-23 (Codex): AuthKit-side implementation is done and tested:
AuthKit builds verification/reset URLs, senders receive final URLs, GET link
landings redirect scanner-safely to frontend paths without consuming tokens,
and the existing POST confirm routes remain the only token-consuming endpoints.
Remaining #131 work is the downstream doujins migration against a tagged/bumped
AuthKit version.

STATUS 2026-06-23 (Claude): DONE + VERIFIED + BENCHMARKED. Implemented
`ImportUsers` in `internal/authcore/import_users.go` (validate/normalize in Go →
in-batch dedup → chunked multi-row `INSERT ... ON CONFLICT DO NOTHING RETURNING
id`, 1000/chunk, relying on ON CONFLICT for skip-existing — no giant ANY() pre-
check; + bulk password-hash insert for inserted rows). Added optional
`PasswordHash`/`HashAlgo`/`HashParams` to
`ImportUserInput`. Wired `ImportUsers` onto the `core` facade and added
`ImportUsersResult`/`ImportUserResult`/`ImportUserStatus` aliases; REMOVED
`ImportUser`/`UpdateImportedUser` from the facade (they stay unexported-internal in
authcore for the bootstrap reconciler — internal/authcore is out of contract, so
this satisfies "no single-user import in the public API"). DESIGN CHOICE vs the
original "ON CONFLICT DO UPDATE upsert": went INSERT-OR-SKIP — for a legacy
migration a re-run should RESUME (skip already-imported) not CLOBBER data a user
changed in AuthKit post-import; cross-identity reporting via per-row
`ImportUserResult{inserted|skipped|rejected}`.
VERIFIED 2026-06-23: `internal/authcore/import_users_test.go` — 5 DB-backed tests
PASS (basic insert, in-batch dedup, skip-existing idempotent re-run, reject
isolation, password import + login) against compose Postgres. `go build`/`go vet
./...` green; DB-free `go test ./...` green.
BENCHMARK (`import_users_bench_test.go`, gated by AUTHKIT_IMPORT_BENCH): 100,000
users inserted in 11.1s = ~9,000 users/sec (multi-row INSERT, 1000/chunk) →
~500k in ≈55s, vs the old per-user loop (500k round-trips = many minutes/hours).
REMAINING (optional): decide bulk role-assignment for migration; CopyFrom path if
>9k/sec ever needed; the doujins real-data 500k run lands via doujins #419.

STATUS 2026-06-23 (Codex): OIDC login `return_to` is implemented and tested.
Shared app-relative validation rejects open-redirect inputs; OIDC/OAuth browser
login stores safe `return_to` in state and emits it in the callback fragment.
Verification/2FA link propagation remains pending on #131's link routes.

Make AuthKit's user-import path fast enough to migrate a large legacy user base
(target: ~500k users from a legacy MariaDB/MySQL DB) in seconds-to-minutes, not
hours. Today the only import API is single-row `ImportUser(ctx, input) (*User,
error)` (one `INSERT` per user); doujins' `internal/legacy_migrate` loops it, plus
per-user `UpsertPasswordHash` and `AssignRoleBySlug` — i.e. ~500k × 3 round-trips.
Design approved by Paul (2026-06-23): "that's great and the correct shape."

WHY THROUGH THE INTERFACE (not raw cross-DB inserts): doujins deliberately imports
through AuthKit's API so it inherits AuthKit's username/email normalization,
password-hash whitelist (argon2id/bcrypt, else `legacy-reset-required`), and
identity invariants. The cost is per-row overhead. This issue keeps the accuracy
(validate/normalize in Go) while removing the per-row DB round-trips (bulk COPY).

DESIGN:
- New facade method (#126 curated surface): `core.Service.ImportUsers(ctx,
  []ImportUserInput) (ImportUsersResult, error)` and a matching bulk password
  import. ImportUsers is the SOLE import API — single-row `ImportUser` and
  `UpdateImportedUser` are REMOVED (hard cut, Paul 2026-06-23: "no
  single-user-at-a-time import"). ImportUsers UPSERTS (staging +
  `ON CONFLICT DO UPDATE`), so the one method covers create AND re-sync; a caller
  importing one user passes a one-element slice.
- FAST LOAD = pgx `CopyFrom` (the fastest Postgres bulk path). NOT expressible in
  sqlc, so this is a raw-pgx escape hatch (precedent: `AdminListUsers`,
  `ReconcileOrgManifest`).
- COPY caveat (the crux): `CopyFrom` is all-or-nothing per copy — one unique
  violation aborts the whole batch, and there's no `ON CONFLICT`/`RETURNING`. So
  for per-row reject isolation AND idempotent re-runs:
  - COPY each batch into an UNLOGGED/TEMP staging table, then
    `INSERT INTO profiles.users (...) SELECT ... FROM staging ON CONFLICT (...)
    DO NOTHING` (or `DO UPDATE` for re-sync), with `RETURNING` to learn which
    rows landed vs conflicted. Bulk speed + conflict handling + reject reporting.
  - Direct `CopyFrom` into the live table is the absolute fastest but only safe
    for a guaranteed-clean one-shot into empty tables; keep it as an opt-in
    "fresh import" fast mode if worth it.
- VALIDATE/NORMALIZE IN GO before the COPY, using the normalization logic
  extracted from the old single-row import (email/username normalize + validate)
  so imported rows match AuthKit's identity invariants exactly. Dedup within the batch in Go. Username
  namespace-collision checks (reserved/parked/existing) become SET-BASED per
  batch (one query) or are handled via the `ON CONFLICT` + reject path — never
  per-row.
- `ImportUsersResult`: per-row outcome — input index → {userID, status:
  inserted|updated|skipped|rejected, reason}. One bad row never aborts the batch.
- PASSWORD HASHES in bulk: same staging+upsert pattern into
  `profiles.user_passwords`, preserving legacy bcrypt + `hash_algo` (the
  lazy-rehash-on-login path already upgrades them); unverifiable hashes →
  `legacy-reset-required`. Keep the hash-whitelist invariant, validated in Go.
- ROLES in bulk: doujins assigns roles per-user too; for 500k add a set-based
  bulk role-assignment (insert into the group/role-assignment tables for a batch)
  rather than per-user `AssignRoleBySlug`. Scope: at least benchmark whether the
  per-user role loop is a bottleneck; add a bulk path if so.
- BATCHING: ~5–10k rows per COPY; each batch in its OWN transaction so a failure
  doesn't roll back the whole 500k and the import is resumable. Tune by benchmark.

ADAPT doujins `internal/legacy_migrate`: page the MariaDB/MySQL read, build
`[]ImportUserInput` batches, call `ImportUsers`, then bulk-import hashes and
roles — replacing the per-user `ImportUser`/`UpsertPasswordHash`/`AssignRoleBySlug`
loops. AuthKit may change the import API shape to whatever is the better design;
doujins is adapted to match.

CONSTRAINTS:
- This is DB-layer work (raw-pgx `CopyFrom` + staging DDL/SQL) on
  `profiles.users` / `profiles.user_passwords`, which #125/#127/#128 are
  concurrently rewriting (MFA/session rename, api-key/admin-directory tables).
  The tree currently does NOT compile (mid #125/#127). Do this once those land
  green, or coordinate; verify against the post-#125 schema.
- `ImportUsers` + `ImportUsersResult` are NEW public API on the #126 facade →
  additive (semver MINOR). Update `SEMVER.md` §4.2.
- Accuracy invariant: a bulk-imported user must match AuthKit's normal
  normalization/invariants exactly (same normalize rules, same stored columns).

**Tasks:**
- [ ] Factor the single-row `ImportUser` normalize/validate into a reusable
  per-row function; add in-batch dedup. Prove bulk == single-row via a parity test.
- [ ] Implement `ImportUsers` (raw pgx): per-batch tx, `CopyFrom` into an
  UNLOGGED staging table, `INSERT … SELECT … ON CONFLICT` upsert into
  `profiles.users`, `RETURNING` to build per-row `ImportUsersResult`.
- [ ] Bulk password-hash import (staging + upsert into `profiles.user_passwords`),
  preserving bcrypt/`hash_algo`; unverifiable → `legacy-reset-required`.
- [ ] Decide + implement bulk role assignment if the per-user role loop is a
  bottleneck at 500k (benchmark first).
- [ ] Expose `ImportUsers` (+ `ImportUsersResult`) on the `core.Service` facade
  (#126) and alias the result type; DELETE single-row `ImportUser` /
  `UpdateImportedUser` from internal/authcore AND the facade (hard cut — batch is
  the only import path). Update doujins `legacy_migrate` (its only `ImportUser` /
  `UpdateImportedUser` caller) to `ImportUsers`.
- [ ] Adapt doujins `internal/legacy_migrate` to page MariaDB → batch →
  `ImportUsers` → bulk hashes/roles; remove the per-user loops.
- [ ] Benchmark a 500k import end-to-end; tune batch size; record throughput
  (target: seconds-to-minutes). Note any memory ceiling per batch.
- [ ] Tests: bulk insert, in-batch dedup, conflict→skip/update, reject isolation
  (one bad row doesn't abort the batch), idempotent re-run, hash import + login
  still works, validation parity with single-row `ImportUser`.
- [ ] Update `SEMVER.md` §4.2 (add `ImportUsers`/`ImportUsersResult` to the
  facade surface; MINOR/additive).
- [ ] Run `go test ./...` and DB-backed `task test`.

---

# #132: Preserve return-to (originating page + state) through full-page auth flows

**Completed:** yes

STATUS 2026-06-23 (Codex): DONE for the current AuthKit route surface. Browser
OIDC/OAuth login now accepts optional app-relative `return_to`, stores it in OIDC
state, and emits it in the frontend callback fragment after token issuance. The
shared validator rejects open-redirect inputs. The verification/reset/2FA link
portion is now explicitly owned by #131, because those AuthKit-owned link landing
routes do not exist yet.

UX goal: a user who authenticates should lose as little progress as possible. If
they hit login / register / email-verify / a 2FA link / OIDC on the `/subscribe`
page, send them back to `/subscribe` (ideally with prior state), not to a fixed
`/login/callback` or `/home`. (Paul, 2026-06-23.)

SCOPE — only the flows that do a FULL-PAGE navigation authkit controls need work.
Flows that stay in the SPA already preserve their own state client-side:
- IN-APP / JSON flows (password login, register, in-app 2FA, email-verify via
  `POST …/confirm`): the SPA never navigates away; it holds its own `return_to`.
  No authkit change — just DOCUMENT that return_to is the client's responsibility
  here (authkit returns tokens via JSON).
- FULL-PAGE round-trips authkit owns: OIDC login (redirect to provider and back),
  and email/2FA LINK clicks (open a fresh browser context, losing SPA state).
  These need authkit to carry + restore a `return_to`.

CURRENT STATE:
- OIDC REAUTH already does this right: `sanitizeReauthReturnTo(body.ReturnTo)`
  (`http/reauth.go:444`) → stored as `oidckit.StateData.ReauthReturnTo` →
  `redirectReauthResult(w, r, sd.ReauthReturnTo, status)`. This is the template.
- OIDC LOGIN now accepts `return_to` at start and returns it in the callback
  fragment after token issuance. Both OIDC and OAuth2 browser providers use the
  same shared fragment builder.
- Email/2FA LINK flows are #131 work: link click opens a fresh context, so
  `return_to` must ride the AuthKit-owned link round-trip once #131 adds those
  scanner-safe link landing routes.

DESIGN:
- Generalize the reauth `ReturnTo` pattern to OIDC LOGIN: accept an optional
  `return_to` at login start (`GET /{provider}/login?return_to=…` or the start
  POST), store it in `StateData`, and append it to the callback redirect (a query
  param or an added fragment key alongside the tokens) so the SPA routes there
  after consuming tokens.
- For verification/2FA LINK flows (#131), carry `return_to` as a link query param
  through confirm → redirect when those routes are added.
- SECURITY (the crux): `return_to` is an OPEN-REDIRECT vector. Validate it as an
  app-relative path only — reject absolute URLs, scheme/host, protocol-relative
  `//evil.com`, backslashes, CR/LF. Generalize `sanitizeReauthReturnTo` into one
  shared validator used by every flow. On reject, fall back to the default path.
- Keep it OPTIONAL and host-controlled; with no `return_to` supplied, behavior is
  unchanged (fixed callback path).

CONSTRAINTS / TIE-INS:
- Builds directly on the existing reauth `ReturnTo` + `oidckit.StateData` plumbing.
- The link-flow portion moved to #131 because #131 owns the missing
  AuthKit-built link and link-landing route surface.
- Cross-repo: doujins already passes `return_to` for verify and reauth; once
  authkit owns the mechanism for login + links, align doujins to it and drop the
  hand-rolled bits.

**Tasks:**
- [x] Extract `sanitizeReauthReturnTo` into a shared, open-redirect-safe
  app-relative `return_to` validator; unit-test rejection of absolute/external/
  `//host`/`\`/CRLF/scheme URLs, and acceptance of normal app paths + querystrings.
- [x] OIDC login: accept optional `return_to` at start, store in `StateData`,
  append to the callback redirect; SPA consumes it after tokens. Add a test that a
  login round-trip preserves it and a malicious value is dropped.
- [x] Verification/2FA link flows moved to #131: those routes do not exist in the
  current surface, and #131 now explicitly requires reusing this shared
  app-relative validator for confirm → redirect.
- [x] Document the SPA-flow contract: for password/register/in-app 2FA, `return_to`
  is the client's responsibility (authkit returns tokens via JSON; no navigation).
- [x] Update `SEMVER.md` / README: document `return_to` support on OIDC login
  start, the callback fragment, SPA-owned JSON-flow state, and the
  open-redirect-safety guarantee. Link-flow docs remain with #131 when those
  routes land.
- [x] Tests: OIDC login preserves `return_to`; reauth still works (no regression);
  malicious `return_to` rejected; default path used when absent; DB-backed OAuth
  callback integration verifies token issuance plus callback `return_to`.

---

# #133: Split group role assignments into real FK tables

**Completed:** yes

STATUS 2026-06-23 (Codex): FINISHED. The Postgres baseline now has
`profiles.group_user_roles` and `profiles.group_remote_application_roles` with
real FKs, and the old polymorphic `group_role_assignments` table/trigger is gone.
Permission-group store queries, mandatory-MFA cleanup, admin root-role filtering,
user hard-delete cleanup, remote-application membership code, tests, and sqlc
generated models/queries were updated. `task sqlc` passed against a fresh
migrated scratch database. Focused DB-backed tests for user roles, remote-app
roles, MFA-required role removal, hard-delete cleanup, admin filtering, and
generated routes passed. Full DB-backed `task test` passed against the same
scratch database.

Replace the polymorphic `profiles.group_role_assignments(subject_id,
subject_kind)` table with explicit tables so Postgres can enforce real foreign
keys. API keys stay out of this split: they already have the narrow model
`profiles.api_keys(permission_group_id, role)` and should not become general
group members.

OLD STATE:
- `profiles.group_role_assignments` stores both human-user and remote-application
  roles, selected by `subject_kind IN ('user', 'remote_application')`.
- A trigger checks that `subject_id` points at either `profiles.users` or
  `profiles.remote_applications`; this is a polymorphic FK substitute.
- API keys are separate and intentionally narrow: one key belongs to one
  permission group and carries one role directly on `profiles.api_keys.role`.

TARGET:
- `profiles.group_user_roles`
  - `group_id` FK → `profiles.permission_groups(id)`
  - `user_id` FK → `profiles.users(id)`
  - `role`, `deleted_at`, timestamps
- `profiles.group_remote_application_roles`
  - `group_id` FK → `profiles.permission_groups(id)`
  - `remote_application_id` FK → `profiles.remote_applications(id)`
  - `role`, `deleted_at`, timestamps
- Delete the polymorphic table, database `subject_kind` column, and trigger.
  Keep the Go `SubjectKind*` constants as the existing API routing layer.
- Keep API keys on `profiles.api_keys.role`; do not add `group_api_key_roles`
  unless API keys later need to behave like full members.

**Tasks:**
- [x] Replace `profiles.group_role_assignments` in the Postgres baseline with
  `profiles.group_user_roles` and `profiles.group_remote_application_roles`,
  defined near their owning tables with normal FKs and the existing soft-delete
  uniqueness semantics.
- [x] Update permission-group store queries: user assignment/removal/listing reads
  `group_user_roles`; remote-application assignment/removal/listing reads
  `group_remote_application_roles`; shared helper code can stay only where it
  still removes real duplication.
- [x] Update mandatory-MFA cleanup to operate only on `group_user_roles`.
- [x] Update admin user filtering and hard-delete cleanup to use
  `group_user_roles`.
- [x] Update remote-application membership code to use
  `group_remote_application_roles`.
- [x] Regenerate sqlc models/queries.
- [x] Tests: user role assignment/removal, remote-application role assignment/
  removal, MFA-required role removal when MFA is disabled, hard-delete cleanup,
  admin role filtering, and baseline migration.
- [x] Run `task sqlc`, DB-backed focused tests, and `go test ./...`.

---

# #134: Permission-group joining — direct add (no confirmation) + link-based invites (email link & shareable URL), gated on registration mode

**Completed:** yes

ORIGIN (Paul, 2026-06-23): two requests — (1) invite an EXTERNAL person to a
permission group via an emailed link, AND (2) a shareable join URL with a
high-entropy code (cursor.com style: `…/accept-invite?code=<hex>`), reusable by
one or many, short-ish expiry. PLUS a correction to the existing model: adding an
EXISTING user to a group must require NO acceptance on the receiver's end.

THE CORE REFRAME (Paul, 2026-06-23): there are TWO distinct operations the current
`group_invites` table wrongly fused into one "invite → accept" ceremony:
- **Direct add of an existing user** — NO confirmation. Being added to a group only
  EXPANDS a subject's potential permissions; it is not an attack vector and not
  annoying beyond, at worst, spam (undo = `RemoveGroupSubject`). A manager who can
  manage members just adds them. THIS ALREADY EXISTS AND IS CORRECT:
  `POST /:persona/:resource_slug/members` → `groupMemberAdd`
  (`http/permission_group_operations.go:27`) → `AssignGroupRole` → store `AssignRole`
  (`permission_group_store.go:187`), gated by `<persona>:members:manage`. KEEP AS-IS.
- **Bring in an EXTERNAL / not-yet-registered person, or offer self-service join** —
  the NEW link flow. Redeeming the link IS the join (assigns the role); there is
  still NO separate accept/decline prompt, consistent with the direct-add rule.

CURRENT STATE (verified 2026-06-23 via codegraph + grep):
- `group_invites` is by `user_id` only (`CreateGroupInvite`, `group_invites.go:59`
  casts `$2::uuid` against a real account) — you cannot invite an email/stranger.
- It is EMAIL-LESS: `EmailSender` (`service.go:1252`) has only
  SendVerification/SendPasswordResetLink/SendLoginCode/SendWelcome — no invite
  method; nothing in the invite path sends mail. The host must notify the invitee.
- It carries an accept/decline STATUS MACHINE (`group_invites.go:22-37`,127,194) that
  is the unnecessary confirmation step above. `AcceptGroupInvite`/`DeclineGroupInvite`
  have ZERO callers — never wired to HTTP or the facade. Only manager-side
  create/list/revoke are reachable (`groupInviteCreate` `:396`, `groupInviteList`
  `:415`, revoke `:455`), generated by the `if p.Invitation` block
  (`permission_group_routes.go:78`, perms `<persona>:invites:manage|read`).

DECISIONS (Paul, 2026-06-23):
1. DIRECT ADD STAYS CONFIRMATION-FREE. No change to `members` add/remove/role.
2. HARD CUT the entire `group_invites` user_id + status model. It modeled a
   confirmation step that shouldn't exist. REMOVE: the `profiles.group_invites`
   table + its migration; `group_invites.go` in full (`GroupInvite`, the 5 status
   consts, `Create/List/Accept/Decline/Revoke`, the `inviteMissOrNotPending*`
   helpers); the manager-side HTTP handlers `groupInviteCreate`/`groupInviteList`/
   revoke; and REBUILD the `if p.Invitation` route block to manage LINKS instead.
   No compat shim (matches #108/#122/#130/#131 hard-cut convention).
3. NEW link-based invites for the external / self-service-join case — ONE primitive
   covering both requested shapes (a high-entropy code redeemed for a role grant):
   - EMAIL LINK: email-bound, `max_uses = 1`, longer expiry (default 7d) — invite a
     specific (possibly-unregistered) person; a leaked link still only works for
     that address.
   - SHAREABLE URL: unbound, `max_uses = NULL` (unlimited) or a cap, short expiry
     (default 24h) — anyone with the link self-joins. (Paul's hunch of 15–60m fits
     "join right now"; days fits "post in the team channel" — so it's a per-link
     knob, not hardcoded.)
4. EXTERNAL (account-creating) INVITES ARE GATED ON REGISTRATION MODE. The link
   flow that lets a STRANGER obtain an account makes sense only if AuthKit permits
   invited signup; otherwise it is DISABLED. Gate on
   `Options.PublicNativeUserRegistrationEnabled()` (true iff
   `NativeUserRegistrationMode == RegistrationModeOpen`, `service.go:478`).
   OPEN DECISION: also honor `RegistrationModeInviteOnly` (`config.go:210`) — it is
   literally "you may register only via an invite", the natural fit for this
   feature. Recommend: external invites enabled when mode ∈ {open, invite_only}.
   Under closed/admin_only/admin_bootstrap_only/manifest_only: minting an
   external/unbound link returns a clear error AND the landing tells a stranger
   "registration is closed" rather than dead-ending in a broken signup. Existing-user
   direct add (`members`) needs no registration and is never gated.

REUSE (do not reinvent — #131 left these in place):
- Code: `randB64(32)` (256-bit; cursor's sample is 192-bit), stored `sha256Hex(code)`
  (`service.go:2191`); plaintext returned to the minter ONCE, never persisted.
- Link URL: `verificationURL(frontendPath, channel, token)` /`emailVerificationURL`
  (`service.go:1230`) pattern + a new `FrontendConfig.InvitePath` (SPA accept-invite
  route, e.g. `/accept-invite`); the email carries `…?code=<code>`.
- Role grant on redeem: `PermissionGroupStore.AssignRole` (`permission_group_store.go:187`),
  role validated via `validRoleForPersona` and MFA-gated via
  `requireMFAForRoleAssignment` exactly as `AcceptGroupInvite` did (`group_invites.go:177`).
- Email delivery: add ONE method to `EmailSender` (`SendGroupInvite`) + Twilio
  provider impl; host still injects transport + branding only (the #131 ownership rule).
- Scanner-safe landing + app-relative `return_to`: reuse #131's GET-no-consume
  redirect and #132's `return_to` validator. (Redemption is an explicit auth'd POST,
  so a scanner GET cannot redeem regardless — the code is consumed only by redeem.)

DESIGN — `profiles.group_invite_links` (durable Postgres, listed/revoked/audited;
NOT the ephemeral KV store — these need management + usage history):
```
  id          uuid pk
  group_id    uuid  -> profiles.permission_groups(id)
  role        text                 -- validated vs persona catalog at mint, like CreateGroupInvite
  invited_by  uuid  -> profiles.users(id)
  code_hash   text unique          -- sha256(randB64(32)); plaintext shown once
  email       text null            -- SET = email-bound (only that verified addr may redeem); NULL = shareable
  max_uses    int  null            -- NULL = unlimited; 1 = single-use email invite
  uses        int  not null default 0
  expires_at  timestamptz null
  revoked_at  timestamptz null
  created_at, updated_at timestamptz
```
Both requested shapes are just two rows (email-bound max_uses=1 vs unbound
max_uses=NULL). Redemption assigns into `profiles.group_user_roles` (#133).

REDEEM FLOW (auth-required; the redeemer is logged in):
- `POST /invites/redeem { code }` (any authenticated user; NOT persona-scoped).
  1. `sha256Hex(code)` → load a live link (`revoked_at IS NULL`, not expired,
     `max_uses IS NULL OR uses < max_uses`) `FOR UPDATE`.
  2. If `email` set: require the caller's email to match (recommend: must be
     verified) — else 403. Shareable (NULL email): any authed caller.
  3. `AssignRole(group, caller, role)` + `uses++` in one txn. Idempotency: if the
     caller already holds that role, succeed WITHOUT consuming a use (re-click
     doesn't burn quota).
- Link points at the host SPA `InvitePath?code=…` (like #131's verify link → SPA).
  External flow: click → if not logged in, sign up / log in (SPA carries the code) →
  POST redeem. No special "create account from invite" path — existing signup +
  redeem. Gating (Decision 4) is enforced at MINT (clear error) and surfaced at the
  landing for strangers when registration is closed.

ROUTE SURFACE (rebuild the `if p.Invitation` block, `permission_group_routes.go`):
- `POST   /:persona/:resource_slug/invites/links`            mint  (`…:invites:manage`) → returns plaintext code once
- `GET    /:persona/:resource_slug/invites/links`            list  (`…:invites:read`)   → never returns the code, shows email/uses/max_uses/expiry/revoked
- `DELETE /:persona/:resource_slug/invites/links/:link`      revoke(`…:invites:manage`)
- `POST   /invites/redeem`                                   redeem (any authed user)

CONSTRAINTS / TIE-INS:
- #131 (AuthKit-owned email + scanner-safe link landing + return_to): build on its
  link-construction + `EmailSender` ownership model; add the invite email + landing
  the same way. Coordinate on `FrontendConfig` (add `InvitePath`).
- #133 (group_user_roles FK tables): redeem assigns there; remove of old
  `group_invites` is independent of that table.
- #111 (persona route generation): the rebuilt `if p.Invitation` block is the only
  generated-route change; group ids never appear in a path (link addresses the
  group internally via the resolved code).
- #126 facade + `SEMVER.md`: new public surface (mint/list/revoke link + redeem +
  `FrontendConfig.InvitePath` + the `EmailSender.SendGroupInvite` contract change is
  BREAKING for custom senders). Old invite methods were never on the `core` facade
  (only reachable via internal `s.svc.*` from `http`), so facade removal is minimal.
- Abuse: unbounded shareable links are a spam/enumeration vector — recommend a
  default expiry + optional `max_uses` cap, and rate-limit mint; high-entropy code +
  hashed storage makes guessing infeasible. Document the trade-off.

**Tasks:**
- [x] HARD-CUT removal (2026-06-23): dropped `profiles.group_invites` table from the
  baseline; deleted `internal/authcore/group_invites.go` + `group_invites_integration_test.go`;
  removed `groupInviteCreate`/`groupInviteList`/`groupInviteRevoke` handlers + their
  route dispatch/ops/classify; removed the `if p.Invitation` generated-route block;
  dropped the `GroupInvitesDeleteByInviter` sqlc query + its hard-delete call; removed
  the `GroupInvite`/`GroupInviteStatus*`/`ErrInvite*` aliases. `members` add/remove/role
  untouched. `go build`/`go vet ./...` green. (sqlc regen lands with the Phase-B migration pass.)
- [x] Migration (2026-06-23): `profiles.group_invite_links` (id, group_id→groups
  CASCADE, role, invited_by→users CASCADE, code_hash UNIQUE, email, max_uses, uses,
  expires_at, revoked_at, timestamps) + `group_invite_links_group_idx`. Raw-pgx (no
  sqlc query); sqlc regen picks up the model. invited_by CASCADEs so a user
  hard-delete clears links (no RESTRICT, no manual cleanup — simpler than old #125 D7).
- [x] Store + service (`internal/authcore/group_invite_links.go`): `CreateGroupInviteLink`
  (role via `validRoleForPersona`; `randB64(32)`→`sha256Hex`; email-bound defaults
  max_uses=1; per-kind TTL), `ListGroupInviteLinks` (no code), `RevokeGroupInviteLink`,
  `RedeemGroupInviteLink` (`FOR UPDATE OF l`, revoked/expired/exhausted checks,
  verified-email match for bound links, `requireMFAForRoleAssignment` + `AssignRole`,
  `uses++`, idempotent already-member no-op = no use burned).
- [x] Registration gating (Decision 4 RESOLVED): `externalInvitesEnabled()` =
  mode ∈ {open, invite_only} (chose to honor invite_only — it's literally "register
  only via invite"). Mint returns `ErrExternalInvitesDisabled` (→403) otherwise;
  `ExternalInvitesEnabled()` exposed on the facade for HTTP/landing gating.
- [x] Email delivery — DEVIATION from plan: instead of a BREAKING `EmailSender`
  change, added an OPTIONAL `GroupInviteEmailSender` capability interface
  (`SendGroupInvite(ctx, email, GroupInviteMessage)`); AuthKit type-asserts the
  configured sender. Non-breaking (no churn to existing senders/test fakes), and a
  deployment not using invites isn't forced to render invite email. Twilio provider
  implements it. Email-bound mints deliver best-effort (code returned regardless).
- [x] Link construction: `FrontendConfig.InvitePath` (+ `Options.FrontendInvitePath`,
  default `/accept-invite`, NewFromConfig wiring) + `inviteURL(code)` builder (mirrors
  `emailVerificationURL`); email carries `InvitePath?code=…`. No separate landing
  ROUTE needed: redemption is an explicit auth'd POST, so a scanner GET on the SPA
  link can't redeem (the SPA reads `?code=` and POSTs it).
- [x] HTTP routes: rebuilt the `if p.Invitation` block → `POST/GET /:persona/
  :instance_slug/invites/links` + `DELETE …/invites/links/:link`; added fixed
  `POST /invites/redeem` (any authed user) + handlers + dispatch/ops/classify + the
  new error mappings in `writeGroupOpError`.
- [x] Facade (#126) + aliases: exposed `CreateGroupInviteLink`/`ListGroupInviteLinks`/
  `RevokeGroupInviteLink`/`RedeemGroupInviteLink`/`ExternalInvitesEnabled`; aliased
  link/message/result types + `ErrInviteLink*`/`ErrInviteEmailMismatch`/
  `ErrExternalInvitesDisabled`. `go build`/`go vet ./...` green; route-surface tests
  green. (SEMVER.md + README pending — Phase D.)
- [x] Tests (DB-backed, `group_invite_links_integration_test.go`, 2026-06-23 — all
  PASS vs scratch Postgres `authkit_issue134`): shareable redeem + idempotent re-redeem
  (no use burned); email-bound match / mismatch-403 / unverified-403; expiry / revoke /
  exhausted (max_uses=1) refusals; gating OFF under closed registration. Role lands in
  `group_user_roles` (asserted via `svc.Can`). SEMVER.md + README updated (instance_slug
  rename, invite-link routes/types/errors, the optional `GroupInviteEmailSender`).
  `go build`/`go vet ./...` clean; full `go test ./...` GREEN (18 pkgs, 0 fail).

RESULT (2026-06-23): #134 link-invite system SHIPPED + DB-verified. Direct add
(members) stays confirmation-free; the old user_id invite + accept/decline machine is
fully removed; invite links (email-bound + shareable) gated on registration mode
(open|invite_only). Only open item is the Tier-2 `ManagementProfile.Invitation` →
`InviteLinks` rename (tracked in #135, deferred as optional).

---

# #135: Permission-group terminology cleanup — rename resource_slug → instance_slug (+ related clarifying renames)

**Completed:** yes

ORIGIN (Paul + Claude, 2026-06-23): the permission-group vocabulary overloads the
word "resource". A permission is `persona:resource:action` (e.g.
`merchant:subscription:cancel`, `customer:delegated-budget:edit`) — there the
RESOURCE is the middle segment (a noun/area within the persona). But the column
that identifies WHICH group instance — `acme-store`, a specific merchant — is ALSO
named `resource_slug` (and its comment calls it "the app resource"). So
`subscription` and `acme-store` are both called "resource" in different places.
They are different axes; the specific instance is NOT a resource.

AGREED GLOSSARY (the target vocabulary):
- **persona**  — the TYPE of group; also permission segment 1. `merchant`, `customer`. KEEP.
- **instance** — a SPECIFIC group of that persona. `acme-store`. (was `resource_slug`.)
  In prose the persona name doubles as the count-noun ("acme-store is a merchant");
  "instance" is the abstract meta-word for schema/docs.
- **resource** — a noun/area WITHIN a persona; permission segment 2. `subscription`,
  `delegated-budget`, `members`, `catalog`. KEEP — this is the correct use.
- **action**   — permission segment 3. `cancel`, `edit`, `read`. KEEP.
- **role**     — a named grant bundle (`owner`, `member`, custom). KEEP.
- **grant**    — a role's permission pattern (`merchant:*`, `merchant:subscription:*`). KEEP.

DECISION (Paul, 2026-06-23): rename the INSTANCE concept `resource_slug` →
`instance_slug` (chose `instance` over `scope` to avoid OAuth-scope overload).
Pre-1.0 hard cut, no compat alias (matches #108/#122/#130/#131/#134).

HARD RULE — TOKEN-SCOPED RENAME ONLY: rename the compound identifiers
`resource_slug` / `ResourceSlug` / `resourceSlug` (the INSTANCE id) → `instance_slug`
/ `InstanceSlug` / `instanceSlug`. DO NOT touch the permission-segment word
"resource": `ValidatePermission`'s `<persona>:<resource>:<action>` doc, segment
literals (`members`, `subscription`), and any prose meaning "permission middle
segment" STAY. The two are lexically distinct (the permission "resource" never
appears as the token `resource_slug`), so a token-scoped find/replace is safe and
must not be widened to the bare word "resource".

BLAST RADIUS (measured 2026-06-23): 275 occurrences of
`resource_slug`/`ResourceSlug`/`resourceSlug` across 25 files — migration baseline,
sqlc-generated `internal/db/models.go`, the permission-group store/service/routes
(+ their integration tests), HTTP handlers, api-keys, mandatory-2FA, remote-apps,
and `core/facade_methods.go`. Concretely:
- DB: `profiles.permission_groups.resource_slug` column; unique index
  `permission_groups_persona_slug_uidx (persona, resource_slug)`; CHECK
  `pg_resource_slug_format_chk`; the `COMMENT ON COLUMN ... resource_slug`;
  `pg_root_parentless_chk` references the column. Rename column + index name
  (→ `permission_groups_persona_instance_uidx`) + check (→ `pg_instance_slug_format_chk`)
  + comment. Regenerate sqlc (`internal/db/models.go` `ResourceSlug` field).
- Go symbols: `GroupByResourceSlug` → `GroupByInstanceSlug`;
  `validateGroupResourceSlug` → `validateGroupInstanceSlug`; `resourceSlugRe` →
  `instanceSlugRe`; `SubjectGroupMembership.ResourceSlug` → `.InstanceSlug`;
  `CreatePermissionGroupRequest.ResourceSlug` → `.InstanceSlug` and
  `.ParentResourceSlug` → `.ParentInstanceSlug`; every `resourceSlug` param/local.
  (`persona`/`parent_persona`/`ParentPersona` are UNAFFECTED — persona stays.)
- WIRE IMPACT (the part that matters to consumers + SEMVER):
  - URLs are UNCHANGED — `:resource_slug` is only a route PARAM NAME; the mounted
    path is `/merchant/{instance_slug}/...` and the real URL still substitutes the
    value (`/merchant/acme-store/...`). Renaming the param + `muxPath` wildcard +
    `r.PathValue("resource_slug")` reads is internal.
  - The ONE breaking change: JSON RESPONSE bodies emit `"resource_slug": ...`
    (`groupMembersList`, `groupRolesList`/`handleMeGroupsGET`, the invite handlers,
    `service_remote_applications`/api-key responses) → `"instance_slug"`. Clients do
    NOT send it (it's path-derived), so the break is response-shape only. Note in
    `SEMVER.md` + README; align consumers (doujins/hentai0/cozy-art) if any parse it.

TIER-2 — OTHER CLARIFYING RENAMES (separable):
1. `ManagementProfile.Invitation` → `InviteLinks` + config key `api-routes.invitation`
   → `api-routes.invite-links`. After #134 the `Invitation` flag gates invite-LINK
   route generation, not an accept/decline invite. DEPENDS ON #134; do it there or
   right after, not standalone.
CONSIDERED & REJECTED (leave as-is — not confusing enough to justify the churn):
- `RouteGroup` (http/routes.go:12, "a bundle of HTTP routes": RoutePublic/RouteUser/
  RoutePermissionGroups/…): its name collides with the permission-`group` domain, but
  Paul DECLINED the rename (2026-06-23) — it's the public route-mounting API every
  embedder calls (`svc.APIRoutes(...)`), and the breakage isn't worth it. KEEP.
- `subject`/`SubjectKind` vs `member`/`GroupMember`: "subject" is a standard RBAC
  term (the role-holder: user / remote_application / api_key); the mild mix with
  "member" isn't worth ~hundreds of edits.
- `persona`: slightly unusual but coherent and Paul-endorsed; renaming it would be
  enormous and is explicitly NOT wanted.
- `PersonaDef.Routes` (type `ManagementProfile`): field/type name mismatch is minor.

CONSTRAINTS / TIES:
- #134 (invite links) ALSO writes new `resource_slug`-shaped code (routes,
  `group_invite_links` has no such column but handlers echo the group's instance).
  ORDER: land #134 first, then this rename in one sweep (so the rename covers #134's
  new sites); or do this rename first and #134 uses `instance_slug` from the start.
  Coordinate so they don't fight over the same files. Tier-2 item 2 is #134's to own.
- #133 (group_user_roles): the store's `SubjectGroups` join reads `g.resource_slug`
  — included in the rename; the role tables themselves key on `group_id`, untouched.
- sqlc: column rename → `task sqlc` regenerates `internal/db/models.go`; verify
  against a freshly-migrated scratch DB.
- SEMVER: response-field rename is a breaking wire change (MAJOR pre-1.0 is fine
  under the hard-cut convention); document in `SEMVER.md` §4.2 + README.

**Tasks (Tier 1 — the instance rename):**
- [x] Migration baseline (2026-06-23): renamed column → `instance_slug`; index →
  `permission_groups_persona_instance_uidx`; CHECK → `pg_instance_slug_format_chk`;
  updated `pg_root_parentless_chk` + the `COMMENT ON COLUMN`. (Baseline edit per
  project convention; deployed DBs get it via the baseline since #133 also edits it.)
- [x] `task sqlc` → regenerated; `internal/db/models.go` field is now `InstanceSlug`.
- [x] Go rename (token-scoped sed across 23 `.go` files): `resource_slug`/`ResourceSlug`/
  `resourceSlug` → `instance_slug`/`InstanceSlug`/`instanceSlug` (identifiers, raw-SQL
  strings, route params, `muxPath`/`pathParam`). Zero `resource_slug` left repo-wide;
  permission-segment "resource" untouched (lexically distinct).
- [x] JSON response fields `"resource_slug"` → `"instance_slug"` (members/roles/
  `/me/groups`/remote-apps/api-keys) — covered by the sed.
- [x] Tests referencing the old names updated by the sed; the one route-surface
  assertion (`/invites...`) gets its final `/invites/links` value in #134 Phase C.
- [x] `SEMVER.md` + README updated (2026-06-23): §5.4 route table renamed to
  `{instance_slug}` (noted as breaking path-param + JSON-field change) + invite-link
  rows + `/invites/redeem`; types/errors/facade lists updated; README permission-group
  section rewritten with the persona/instance/resource/action glossary.
- [x] `go build`/`go vet ./...` clean; full `go test ./...` GREEN (18 pkgs, 0 fail)
  against fresh scratch Postgres `authkit_issue134` (migrated from the updated
  baseline); `task sqlc` regenerated.

**Tasks (Tier 2 — separable):**
- [x] DONE (2026-06-23, at Paul's request): `ManagementProfile.Invitation` →
  `InviteLinks` (+ `// api-routes.invite-links` doc key) across the field decl, the
  `if p.InviteLinks` route gate, and 6 test schema literals. gofmt'd; `go build`/
  `go vet ./...` clean; permission-group + invite tests GREEN. Breaking field rename
  on the covered `ManagementProfile` type — pre-1.0 hard cut.

---

# #131: AuthKit should OWN the verification/reset notification flow (message + link + confirm), not delegate it to the host

**Completed:** yes

**Status:** DONE 2026-06-24 (Codex). Verified current consumers against the AuthKit #131 contract. Doujins is already pinned to authkit v0.61.0, sets `Frontend.VerifyPath=/verify-registration` and `PasswordResetPath=/reset-password`, no longer has backend `/auth/verify-registration` or `/auth/reset-password` redirect handlers, and its templates render AuthKit-provided final URLs. Hentai0 and Cozy Art also set the frontend verify/reset paths and consume `msg.LinkURL` / resetURL directly; a dead Hentai0 local link-builder helper was removed. SPA verify/reset routes in all three consumers read `?token=&channel=` and POST to the matching `/email|phone/.../confirm` endpoint. Validation: doujins `go test ./internal/server` focused auth tests, `pnpm exec tsc --noEmit`, and `pnpm vitest run src/hooks/auth/contact-change-routes.test.ts`; hentai0 focused `go test ./internal/infra ./internal/auth ./internal/api`, `pnpm run typecheck`, and contact-change vitest; Cozy Art focused `go test ./internal/api`, `pnpm run typecheck`, and auth registration/store vitest all passed.

STATUS 2026-06-23 (Claude): AuthKit side DONE + VERIFIED. AuthKit now builds the
verification/reset link at the host-configured FRONTEND landing path (SPA-link
model, Paul's choice): `verificationURL` wires `s.opts.FrontendVerifyPath` /
`FrontendPasswordResetPath` (previously DEFINED-BUT-UNUSED; links wrongly pointed
at fixed API paths) + a `channel=email|phone` param. Verify & reset are symmetric;
reset is link-only (no OTP — a short reset code would be brute-forceable). Unit
tests `internal/authcore/verification_url_test.go` PASS; `go build`/`vet ./...`
green; #130 import tests still green. NOTE: this wiring is on master/unreleased;
consumers' pin (v0.56.2) has the config field but still ignores it (fixed paths).
CONSUMER STATUS (verified each BUILDS against local master authkit, exit 0 — no
breakage): cozy-art already consumes AuthKit's `msg.LinkURL`/`resetURL` (cleanest);
hentai0 + doujins still also build their OWN link (and doujins hosts backend
redirect handlers `handleVerifyRegistrationLinkGET`/`handleResetPasswordLinkGET`).
REMAINING consumer work (release-PAIRED — must land with the authkit bump, else
runtime breaks since v0.56.2 ignores VerifyPath; + involves each app's SPA):
- set `core.Config.Frontend.VerifyPath`/`PasswordResetPath` to each app's existing
  SPA route (doujins: `/verify-registration` + `/reset-password`),
- drop each app's own link-builder; rely on AuthKit's `msg.LinkURL`/`resetURL`,
- doujins: delete the two backend link handlers + their routes (server.go),
- each SPA route reads `?token=&channel=` and POSTs to the matching confirm endpoint.

GUIDING PRINCIPLE (Paul, 2026-06-23): AuthKit should be **batteries-included** for
sending email/SMS and handling the communication round-trip — as much as possible,
a host wires transport + branding and gets working verification/reset/notification
flows, without building links, hosting confirm routes, or reaching into `core`.
This issue is the first application of that principle; future notification types
(welcome, security alerts, login-code, etc.) should follow the same ownership rule.

ROOT CAUSE (reframed 2026-06-23, Paul): AuthKit generates the verification/reset
TOKEN but delegates the LINK and the CONFIRM ROUND-TRIP to the host. That
ownership boundary is backwards and is the actual bug behind the doujins mess in
#126/#130.

- `core.EmailSender`/`core.SMSSender` receive only `VerificationMessage{Code,
  LinkToken}` — a bare token, no URL. Even AuthKit's OWN Twilio providers asked the
  host for `VerificationLinkURL func(token) string` / `ResetLinkURL func(token)
  string` (`providers/email/twilio/twilio.go:47-48`). So the host builds the link.
- Because the host owns the link, the host must also host the confirm route and
  reach into `core.Confirm*`. doujins did exactly this: a `GET
  /auth/verify-registration` that tries all four `core.Confirm*` methods (token
  type unknown to it) and redirects. "doujins is sending these emails" IS the bug
  — AuthKit knows the token, its TYPE, the `BaseURL`, and the confirm logic, so
  AuthKit should build the link and own the confirm endpoint. The host should
  provide TRANSPORT (Twilio/SendGrid creds) and BRANDING/COPY only — never flow.

AFFECTED FLOWS (all delegate the link today): email verification, phone
verification, registration confirmation, password reset (`ResetLinkURL`), and any
future 2FA/login link. Same inversion.

DESIGN — move the ownership boundary so AuthKit owns the round-trip:
- AuthKit CONSTRUCTS the verification/reset link itself: `BaseURL` + the MATCHING
  type-specific confirm route + the token (the route path encodes the type). The
  sender is handed a ready-to-send message (rendered body, or the final URL) — not
  a bare token it must turn into a URL.
- THE TYPE-SPECIFIC ROUTES ALREADY EXIST (Paul, 2026-06-23) — they're just
  POST/JSON today: `/email/verify/confirm`, `/phone/verify/confirm`,
  `/email/password/reset/confirm`, `/phone/password/reset/confirm`. AuthKit just
  points the typed link at the matching one (e.g.
  `…/email/verify/confirm?token=12345`). Because the route IS the type, there is
  NO auto-detect, NO "confirm any token", and NO 4-method try-chain — the whole
  ambiguity problem evaporates. (Confirm that registration-pending tokens are
  covered by the email/phone verify route, or give them a typed route too.)
- THE ONLY NEW SURFACE: a GET link-landing variant of those routes (token from the
  query → confirm → 302-redirect to the host frontend path with `?status=…` and
  `return_to`, see #132), since today they're POST/JSON (SPA) only.
- STILL PROVIDER-AGNOSTIC: AuthKit does NOT read provider env vars or hold SMTP
  creds. The host keeps injecting the transport sender (`WithEmailSender`/
  `WithSMSSender`) and keeps branding/template/per-language copy hooks. The ONLY
  thing removed from the host is link CONSTRUCTION and the confirm flow.
- KEY DECISION — email-scanner prefetch: security scanners GET every link and
  would burn single-use tokens. Choose a scanner-safe GET→confirm-page-with-POST,
  or make GET-confirm vs confirm-page configurable. (Crux, same as before.)
- HARD CUT: this changes the `EmailSender`/`SMSSender` contract and the Twilio
  provider config (drop `VerificationLinkURL`/`ResetLinkURL`). No compat shim.

CONSEQUENCES:
- doujins deletes its verify GET handler, the 4-method try-chain, the
  `GetPending*` status helpers, AND its link-builder config — it configures only
  transport + branding.
- The 6 `Confirm*`/`GetPending*` methods added to the #126 facade for doujins have
  ALREADY BEEN REMOVED from the public facade (2026-06-23, Paul: delete immediately
  — facade 81→75). They stay in `internal/authcore` for the HTTP handlers; they
  existed on the facade only because the host drove confirm. This is the concrete
  answer to "do those 6 belong in the public API?": NO. doujins (pins v0.54.0) is
  unaffected now; it migrates onto the AuthKit-owned flow as part of THIS issue.
- Ties to #132 (return_to through the AuthKit-owned redirect).

**Tasks:**
- [x] Move verification/reset LINK construction into AuthKit (`BaseURL` + verify/
  reset path + typed token). Replace the token-only `VerificationMessage` link
  path with a rendered message / final URL handed to the sender.
- [x] Add the built-in link landing endpoints AuthKit's links point at. Decision:
  scanner-safe GET does not consume token; it 302-redirects to the host frontend
  path with `status`, typed `channel`, `token`, and validated app-relative
  `return_to`. Existing POST confirm routes remain the consuming endpoints.
- [x] Add `FrontendConfig` landing path(s) for verify/reset redirects; validate
  app-relative (reuse #132's `return_to` validator).
- [x] Change the `EmailSender`/`SMSSender` contract + Twilio providers: REMOVE host
  `VerificationLinkURL`/`ResetLinkURL`; keep transport host-injected and keep
  branding/template/per-language hooks (HARD CUT, no shim).
- [x] Decide session-on-confirm behavior, consistent with the current POST confirm:
  GET landings issue no session; POST verification confirm still returns tokens,
  and POST password reset confirm returns `{ok:true}`.
- [ ] Migrate doujins: delete its verify GET handler, try-chain, `GetPending*`
  status helpers, and link-builder config; wire only transport + branding.
- [x] DONE 2026-06-23: removed the 6 `Confirm*`/`GetPending*` methods from the #126
  facade immediately (facade 81→75); they remain in `internal/authcore` for the
  HTTP handlers. `go build`/`go vet ./...` green; `verify.Enricher` assertion
  unaffected (none of the 6 are Enricher methods).
- [x] Update `SEMVER.md` + README: AuthKit-owned verification/reset flow; new
  endpoint(s)/config; the breaking `EmailSender`/`SMSSender` + Twilio provider
  contract change.
- [x] Tests: AuthKit-built link round-trips through the built-in confirm; scanner
  mode; status mapping; transport still host-injected (provider-agnostic intact).
  Validation: `go test ./...`, forced `go test ./internal/authcore -run
  TestNewGroupSchema_Rejections -count=1 -v`, and focused DB-backed `go test ./http -run
  'TestPasswordResetConfirmConsumesTokenDirectly|TestVerificationConfirmAcceptsCodeOrToken|TestAuthKitBuiltLinksRedirectWithoutConsumingToken'
  -count=1 -v` passed against scratch Postgres `authkit_issue131`.
