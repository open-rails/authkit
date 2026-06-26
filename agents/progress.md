<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 143

---

# #142: Standalone self-hostable server + remote SDK (authkit Phase 2)

**Completed:** no

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

## Tasks
- [ ] **Interface portability audit.** Some `authkit.Client` methods are awkward over
      the wire — `ApplyBootstrapManifestFile(path)` reads a LOCAL file (whose fs? the
      server's), `CleanupExpiredAuthState` is a maintenance op, raw `Keyfunc`/`JWKS`
      aren't on the interface but check the rest. Decide per method: keep / drop from
      the remote surface / reshape (e.g. `ApplyBootstrapManifest(bytes)` only).
- [ ] **Management HTTP API contract** — versioned REST/JSON covering the portable
      Client methods (CreateUser, MintServiceJWT, Can, UsersByIDs, BanUser, API-key
      mgmt, …). The frozen wire contract for non-Go clients + the remote SDK.
- [ ] **App→server auth** — how a calling app authenticates to the management API
      (service credential / signed service JWT / mTLS); least-privilege scoping.
- [ ] **`authkit/server`** — standalone binary logic (engine + authhttp routes + mgmt
      API + own config/DB/Redis); thin `main` in `cmd/authkit-server`.
- [ ] **`authkit/remote`** — HTTP-transport SDK; `remote.New` returns a client
      satisfying `authkit.Client`; per-method marshal + error mapping that preserves
      `errors.Is(err, authkit.ErrX)` (shared identity #138 already provides).
- [ ] **Transport seam** — embedded uses an in-process direct-call adapter over the
      SAME management handlers (not a parallel impl), per etcd `v3client`.
- [ ] **Config unification** — one server config struct, mutated by the library and
      filled-from-flags/file by the binary (etcd `embed.Config`/`etcdmain`).
- [ ] **Tests** — `remote.Client` against an in-process `httptest` server; assert
      parity with `embedded.Client` over the shared `authkit.Client` interface.
- [ ] **Docs** — deploy guide; the embedded↔remote one-line swap; non-Go REST examples.

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

**Completed:** no

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

**Completed:** no

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
- [x] Add safe `return_to` handling or explicitly return tokens only to the caller and let the host own navigation.
- [x] Add DB-backed tests for email OTP login, email magic-link login, SMS OTP login, SMS magic-link login, create-if-missing, existing-user resume, generated username collision, no password row, disabled feature, duplicate/expired token, invalid code attempt caps, and anti-enumeration responses.
- [x] Update README, `agents/api-endpoints.md`, and SEMVER notes with the new flow and host integration guidance.

## Validation

- [x] Real-server passwordless integration pass against a fresh migrated Postgres: `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_issue49_1782336194?sslmode=disable' go test ./http -run 'TestPasswordless' -count=1 -v`. This includes `TestPasswordlessRealHTTPServerEmailOTP`, which uses `httptest.NewServer(srv.APIHandler())` over actual HTTP plus the real DB.
- [ ] Full DB-backed `go test ./... -count=1` is blocked by unrelated existing permission-group/admin failures in `http` and `internal/authcore`; issue-49 focused DB-backed tests pass.

## Cross-repo

- OpenRails SaaS #19 will use this for customer wallet login/account creation at checkout while keeping merchant-app authentication separate.
