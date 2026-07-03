<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 238

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
#206 REALITY CHECK (2026-07-02): the audit spec was partly inaccurate. DONE: collapsed the Service/Server
  alias → single canonical `Service` type (kept Service; NewServer returns *Service). NOT REAL / skip: there is
  NO free-func `authhttp.MintDelegatedAccessToken` dupe (only the Client method); no obvious legacy "code-as-token"
  field in reset/verify confirm (only legitimate verification `code`). REMAINING #206: (a) drop the dead `email`
  param on IssueAccessToken/issueAccessToken (breaking Tokens-iface signature + regen mirrors); (b) remove the ~35
  EXPORTED verify re-export aliases from authhttp/verify_aliases.go — HIGH churn (every unqualified Verifier/Claims/
  Required in the http package must become verify.X) + debatable (it's an embedder convenience), and the file's
  UNEXPORTED helpers setClaims/getClaims/maxDelegatedRoles are load-bearing and MUST stay. Recommend deciding (b)
  with Paul (convenience vs surface purity) rather than grinding it blind.
PLAN (Paul, 2026-07-02): finish authkit breaking changes, then COMMIT+PUSH+TAG a new version (push now
  authorized). Then migrate consumers one at a time starting with ~/openrails. STRATEGY QUESTION ASKED (tag-now-
  phase2 vs finish-all-then-tag vs pause-before-batch-native) — awaiting Paul. HOLDING: push+tag (irreversible,
  needs version/scope confirmation) and the batch-native redesign #219–#222 (design-sensitive) until he answers.
NEXT (remaining, serial — shared files client.go/interfaces.go/SEMVER/generated, do in-tree not via worktree
  agents which branch from master): #206 (strip aliasing: delete authhttp/verify_aliases.go, collapse Service/Server,
  dedupe MintDelegatedAccessToken, drop dead email param, legacy code-as-token), #202 (move storage/ratelimit/siws
  under internal/), #205 (dir renames http→authhttp/oidc→oidckit/jwt→jwtkit), #209 (gin-native Optional/Required),
  #211 (one construction entrypoint + RegisterAll), #213 (consolidate error registries + HTTPStatus), #214 (Mint*
  verbs + Principal classifier), #219–#222 (batch-native reads/entitlements/mutations). Then push+tag.
RULES: reduce API/SEMVER surface + total LOC; keep build+vet green after each change; integration-test new
  behavior; push+tag ONLY after all authkit breaking changes land. Tick each issue's tasks as done.
-->

---

# #196: [BUG] SIWS in-memory challenge cache re-created per request (Solana login broken without Redis)

**Completed:** no

Proposed 2026-07-02 (Paul + Claude audit). `authhttp/siws_cache.go:11-16` returns a **fresh**
`memorystore.NewSIWSCache(...)` on every call in the no-Redis branch. `GenerateSIWSChallenge`
does `Put` on instance A; the follow-up login/link does `Consume` on a **new empty** instance B
→ always `ErrSIWSChallengeNotFound` → 401. Its sibling `stateCache()` (`authhttp/service.go:195`)
memoizes into `s.memStateCache`; `siwsCache()` has no equivalent field. Secondary defect: each
`NewSIWSCache` starts an unstoppable `cleanupLoop` goroutine (`storage/memory/siws_cache.go:33`),
so every Solana request permanently leaks one goroutine + map.

Blast radius: no-Redis / single-instance deploys (prod requires Redis; no current consumer uses
SIWS) — but it's a shipped feature that is 100% broken in a supported config. Root-cause fix, not
per-caller.

## Tasks
- [ ] Add a `memSIWSCache siws.ChallengeCache` field to `authhttp.Service`; create once in `NewServer` (mirror `memStateCache` at `authhttp/server.go:90`).
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
  fails closed). `authhttp/oidc_browser.go:149,201`.
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

**Completed:** yes — EXECUTED 2026-07-03 per `plans/030-package-path-rename.md` (quiet window confirmed:
origin had no in-flight work under the dirs). `git mv` http→authhttp, oidc→oidckit, jwt→jwtkit; all 65
in-repo imports rewritten to the new paths with the now-redundant aliases dropped (all had aliased to
the exact target basename ⇒ pure sed); SEMVER §4.1 rows + inline mention, README import line, and
open-issue file refs in this tracker updated (net/http + /oidc route paths protected). Full
`go test ./...` green at the new paths; both env-doctrine guards pass; zero old-path Go references.
Direction rationale: the reverse (rename packages) would create `package http` shadowing stdlib and
`package jwt` colliding with golang-jwt. Consumer migration rides the #143 bump — sed one-liner in the
commit message (BREAKING note in commit body). #206 unaffected (its file refs updated here).

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
  - `authhttp/verify_aliases.go` — re-exports the public `verify.*` (Verifier/Claims/Required/Optional, ~40
    symbols) under `authhttp` "so existing embedders keep compiling" after the #110 split. A second public
    path for symbols that already live in `verify`. Delete; consumers import `verify.X`.
  - `Service` ≡ `Server` type alias (`authhttp/server.go:22`, #109 collision) — pick one name.
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
- [ ] Delete `authhttp/verify_aliases.go`; migrate the three consumers `authhttp.X` → `verify.X`.
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
`authhttp/oauth2_provider.go:43` when set. Refactor so OIDC providers (Google/Apple) read standard ID-token
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
  `authhttp/providers_get.go`, a JSON response shape living in the root package.
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
three apps wire both and each left a warning comment. The prod validation (`authhttp/server.go:106`) only checks
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
types: `authkit.ErrX` sentinels (`errors.go`, ~60) and `authhttp.ErrorCode` (`authhttp/error_codes.go`, ~210
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

Proposed 2026-07-02 (Paul + Claude audit). `jwtkit/jwt.go:26` — exported interface with **zero** references
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

Proposed 2026-07-02 (Paul + Claude audit). `authhttp/service.go:133` (`allowResult`) derives
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
- **Password login** (`authhttp/password_login_post.go`) and **2FA verify** (`authhttp/user_2fa_verify_post.go:69-91`):
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

Proposed 2026-07-02 (handler over-fetch audit). `authhttp/user_me_get.go:40-173` (very hot — app boot / page loads)
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

Proposed 2026-07-02 (handler over-fetch audit). `authhttp/register_availability.go:52-78` calls
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

---

# #231: [BUG][SECURITY] JWT prod-detection reads the wrong env vars — and libraries must not read env at all

**Status:** IMPLEMENTED 2026-07-02 (Claude) — COMMITTED in 8bb630c (design-lock batch, on origin). FULL AUDIT 2026-07-03 (Claude): every status claim verified against code (guard test passes; env sweep clean — only internal/testdb allowlist; KeysConfig shape + Source→VerifyOnly→keys.json→opt-in precedence exact; cmd env boundary + NewStaticKeySourceFromPEM wiring exact; embedded.IsDevEnvironment exported; ResolveStatic plain-string; SEMVER §7.2/§7.3 + KEY_ROTATION.md + cmd README updated; binary builds; note BREAKING.md claim is moot — 0420aba later deleted BREAKING.md in favor of commit messages). ONE GAP FOUND + FIXED 2026-07-03: `authhttp/server.go` validate() still had its own inline `env == "prod"|"production"` classifier, so STAGING ESCAPED the production Redis-ephemeral requirement (contradicting the staging-flips-to-prod-like claim below) — now routed through `embedded.IsDevEnvironment` (the genuinely last inline env comparison; sweep confirms all other sites use the single classifier). ENFORCEMENT CLOSED 2026-07-03: added `TestSingleDevProdClassifier` to env_doctrine_test.go — AST guard failing on any ==/!=/switch-case comparison against the dev/prod vocabulary ("prod"/"production"/"staging"/"dev"/"development"/"local") outside internal/authcore/accessors.go (+cmd/, tests) — so an inline classifier can never silently reappear (the env-READ guard alone had let the authhttp/server.go one survive). Zero env reads in library code, enforced by guard
test `env_doctrine_test.go` (AST scan for os.Getenv/LookupEnv/Environ/ExpandEnv outside cmd/ + *_test.go;
allowlist: internal/testdb only). Config shape: `KeysConfig.AllowEphemeralDevKeys bool` (default false ⇒
no keys = hard construction error); resolution is Source → VerifyOnly → <Keys.Path>/keys.json → opt-in
dev-gen. `jwtkit.NewAutoKeySourceWithPath` → `jwtkit.ResolveKeySource(path, allowEphemeralDevKeys)`; new
`jwtkit.NewStaticKeySourceFromPEM(kid, pem, extraPubs)` for explicit material. cmd/authkit-server reads env
once (incl. ACTIVE_KEY_ID/ACTIVE_PRIVATE_KEY_PEM/PUBLIC_KEYS + AUTHKIT_KEYS_PATH, moved out of the library)
and maps AUTHKIT_ENV through THE single classifier `authcore.IsDevEnvironment` (exported via embedded):
dev = ""/dev/development/local/test; EVERYTHING else incl. staging is prod-like/fail-closed (divergent
accessors.go + main.go classifiers killed). authprovider `ClientSecret.Env` + `AppleJWTSecret.PrivateKeyEnv`
removed (env indirection; ResolveStatic returns plain string). BREAKING for hosts: staging flips to
prod-like (dev leniency closes, Redis-ephemeral prod requirement applies); dev boots without keys must set
AllowEphemeralDevKeys (hosts already passing Source/keys.json unaffected). Docs: SEMVER §7.2/§7.3,
BREAKING.md, cmd README, jwtkit/KEY_ROTATION.md. Verified: full `go test ./...` green; binary smoke-tested
(AUTHKIT_ENV unset → boots with ephemeral keys; production/staging with no keys → refuses, loud error).

`jwtkit/keys.go` `isProdEnv()` reads `ENV` → `APP_ENV` → `ENVIRONMENT`, but the system uses `AUTHKIT_ENV`
(`cmd/authkit-server/main.go`). A server run with only `AUTHKIT_ENV=production` is classified non-prod and
SILENTLY AUTO-GENERATES dev signing keys instead of hard-failing (contradicts config.go docs). Three
divergent dev/prod classifiers exist ('staging' is dev in one, prod-like in another).

Fix shape (decided with Paul 2026-07-02 — doctrine, not just a rename):
- NO env reads in library code, period. Libraries must not read ambient env behind the host application's
  back; in embedded mode the HOST owns the process env. Env is read once, at the binary boundary, by
  cmd/authkit-server's config pipeline.
- The dangerous behavior becomes an explicit opt-in: e.g. `AllowEphemeralDevKeys bool` on config (or an
  explicit dev constructor). Default fail-closed: no keys + no flag → refuse to boot. Forgetting
  configuration then fails loudly instead of minting dev keys in prod.
- cmd/authkit-server reads `AUTHKIT_ENV` once, through ONE classifier, and sets the flag. Dev ergonomics
  preserved (unset/dev → binary opts in; `go run ./cmd/authkit-server` still just works).
- Enforcement: guard test failing on os.Getenv/LookupEnv outside cmd/ and *_test.go.
Mirror issue: openrails #712.

---

# #232: [BUG] TOTP file-key loading path is entirely dead — standalone can never enable TOTP

**Status:** IMPLEMENTED 2026-07-02 (Claude; uncommitted) — WIRED, not deleted: `NewFromConfig` now calls
**Addendum (Paul 2026-07-02):** missing key stays a graceful degradation (boots fine, TOTP reported unavailable, enrollment fails closed) — now ALSO logs a boot warning when 2FA policy offers TOTP but no key material exists. Boot error remains ONLY for configured-but-invalid key material.
`resolveTOTPSecretKey` (explicit override validated 16/24/32 raw bytes → `<Keys.Path>/totp.key` → nil, TOTP
fails closed at enrollment), so standalone/file-key deployments can enable TOTP. `totpKeysDir` env fallback
removed per #231 (Path → /vault/auth). Construction tests added (`constructor_keys_test.go`:
TestNewFromConfigWiresTOTPFileKey). NOTE for hosts: an invalid-length explicit TOTPSecretKey override is now
a boot-time error (was silently broken at runtime — check doujins/hentai0 configured key lengths).
Original finding: `totp_key.go` `resolveTOTPSecretKey`/`totpKeysDir` and the decode
branches had zero non-test callers; `constructor.go` copies only the `TwoFactor.TOTPSecretKey` override into
Options. The documented production mechanism (`<Keys.Path>/totp.key`, config.go) never runs. Wire the file
path into the constructor or delete the file-path code + doc. (Coordinate the config-field shape with #231's
no-env doctrine.)

---

# #233: [DB] drop owner_reserved_names + 4 dead sqlc queries

**Status:** IMPLEMENTED 2026-07-02 (Claude; uncommitted) — owner_reserved_names table + seed + 3 queries dropped; IdentityForwardUsername (+ user_renames_from_renamed_idx), UserBySlug, IdentityUserByID, IdentityUpdateUserUsername deleted; identity.sql reheaded (only IdentityUsersByIDs remains); querytest/schema_test callers retargeted to live queries (UserSetUsername/UserSlugAliases); perf-gate case + user_renames seed removed. sqlc regenerated; baseline + full internal/db suite green.

- `profiles.owner_reserved_names` — seeded 4 rows, never consulted at runtime; all three queries
  (`OwnerReservedNameExists/Upsert/Delete`) are caller-less; the real reserved guard is
  `users.metadata->>'reserved'` (`UserIsReserved`) — a different mechanism. Drop table + seed + queries.
- Dead queries: `IdentityForwardUsername` (rename-forwarding read path dead; its dedicated index
  `user_renames_from_renamed_idx` goes with it), `UserBySlug`, `IdentityUserByID`,
  `IdentityUpdateUserUsername`. The identity.sql header references a retired `identity` package.
- NOTE `user_renames` itself is LIVE (rename cooldown + slug aliases) — only the forwarding query dies.

---

# #234: [DB] soft-delete fiction + dead denorm/metadata columns

**Status:** IMPLEMENTED 2026-07-02 (Claude; uncommitted) — groups are PERMANENT: permission_groups.deleted_at dropped + every `deleted_at IS NULL` filter and index predicate removed (persona_instance/singleton_root uidx stay partial for their other predicates); remote_applications.deleted_at dropped (delete stays hard; bootstrap emptiness count updated); both dead metadata jsonb columns dropped (verified zero readers/writers); parent_persona denorm dropped — trigger now validates (NEW.persona, actual parent persona fetched by parent_id) against group_persona_parents; CreateGroup signature lost parentPersona. group_persona_parents mirror + trigger kept (DB enforcement). updated_at left in place (cheap).

- `permission_groups.deleted_at` — never written; NO group-deletion surface exists, yet every read filters
  `deleted_at IS NULL` and two partial indexes predicate on it. Decide: groups are permanent (drop column +
  predicates) or build deletion. (`updated_at` is also never updated.)
- `remote_applications.deleted_at` — never set; delete is a HARD delete while reads filter on deleted_at and
  the bootstrap emptiness check counts on it. Worst of both — drop it or make delete soft.
- `remote_applications.metadata`, `permission_groups.metadata` — pure dead jsonb (no query reads or writes).
- `permission_groups.parent_persona` — write-only denorm; only the containment trigger reads it, to
  cross-check against the parent persona it ALREADY fetches by parent_id. Drop the column, have the trigger
  use the fetched value. (Containment enforcement is otherwise 4 mechanisms for 1 invariant — Go validation +
  group_persona_parents mirror + denorm + trigger; keep trigger + mirror if DB enforcement is wanted, cut the
  denorm either way.)

---

# #235: [DB] schema hygiene pre-lock: passkey-handles PK, role CHECK unification, redundant indexes, invite retention

**Status:** IMPLEMENTED 2026-07-02 (Claude; uncommitted) — DECISION passkey handles: rpid DROPPED (single-valued config; PK stays user_id, both rpid uniques replaced by UNIQUE(user_handle) — discoverable login looks up by handle alone, ON CONFLICT retargeted to (user_id)); user_passkeys.user_present/user_verified dropped (scan derives from flags). CHECKs: ari_role_format_chk + ari_group_role_pairing_chk on account_registration_invites, gmi_role_format_chk on group_membership_invites; api_keys regex KEPT divergent + comment (catalog role names from host Go config are not slug-constrained). Indexes: idx_mfa_factors_user + remote_applications_enabled_idx dropped; DECISION users_admin_email_idx KEPT (serves admin-directory (email,id) sort over live users; users_email_uidx is uniqueness-only) — documented in schema. group_invite_links.uses → redeemed_at timestamptz (contract GroupInviteLink.Uses → RedeemedAt; HTTP list emits redeemed_at when set). Retention: CleanupExpiredAuthState now purges all three invite tables past inviteRetention = 90d after expiry/consumption/revocation. Hygiene: dead auth_methods COALESCEs removed from sessions.sql, stale group_invites comment fixed, mfa test's phantom-table DELETE fixed, password_updated_at keep documented. FK-cascade indexes (invited_by/consumed_by/created_by/banned_by) SKIPPED deliberately: tiny tables, rare user hard-deletes; per-insert index cost not worth it.

- `user_passkey_handles` PK is `user_id` alone while `rpid` + the (rpid,user_id)/(rpid,user_handle) uniques
  imply per-rpid handles; PasskeyRPID is single-valued config. Drop `rpid` from the table or make PK
  `(user_id, rpid)` — pick one story.
- Role-format CHECKs inconsistent: `account_registration_invites.role` and `group_membership_invites.role`
  have NO format check (siblings check `^[a-z][a-z0-9-]*$`); `account_registration_invites` lacks the
  `(permission_group_id IS NULL) = (role IS NULL)` pairing check (app-enforced only); `api_keys.role` uses a
  different regex for the same domain. Unify or document.
- Redundant indexes: `idx_mfa_factors_user` (covered by uniq_mfa_factors_user_method),
  `uniq_user_passkey_handles_rpid_user` (PK makes it unique already — retarget the ON CONFLICT and drop),
  `remote_applications_enabled_idx` (boolean partial on a tiny catalog), `users_admin_email_idx` vs
  `users_email_uidx` (keep only if keyset pagination needs it).
- Dead-ish columns: `user_passkeys.user_present`/`user_verified` always overridden from `flags` on scan —
  drop; `user_passwords.password_updated_at` write-only — keep only as deliberate forensics.
- `group_invite_links.uses integer CHECK (uses IN (0,1))` — an int constrained to a boolean; `redeemed_at
  timestamptz` carries more in one column.
- No retention sweep for the three invite tables (CleanupExpiredAuthState only sweeps refresh_sessions);
  expired/consumed rows accumulate until user hard-delete.
- Hygiene: dead `COALESCE(auth_methods, ...)` in sessions.sql (column NOT NULL); stale comment in users.sql
  about a nonexistent `group_invites` table; `mfa_required_roles_integration_test.go` deletes from
  nonexistent `profiles.group_invites` (error silently swallowed).
- Low-priority: unindexed FK cascade paths from users (invited_by/consumed_by/created_by/banned_by) — user
  hard-delete seq-scans small tables.

---

# #236: [CONFIG] config seam cleanup: Config↔Options double declaration, contradictory defaults, standalone reachability

**Status:** IMPLEMENTED 2026-07-02 (Claude; uncommitted) — pragmatic seam fix, defaults reconciled, standalone gaps closed.
Decisions:
- Config↔Options: audited all ~30 mappings; the ONLY unsettable field was `VerificationSendTimeout` — now on
  `Registration.VerificationSendTimeout` (0 ⇒ 15s) and mapped through. Name divergences (e.g.
  `Registration.NativeUserMode` → `NativeUserRegistrationMode`) are deliberate: nested Config fields carry
  context from the group, flat Options carry it in the name — no renames. Full structural collapse NOT
  attempted (not mechanical): `Options` is also the low-level `NewService` entry used by ~40 tests and
  re-exported as `embedded.Options`; a collapse means either making Config the single struct (breaking the
  flat-Options constructor) or code-generating the mapping — punt until `NewService` itself is on the block.
- `Registration.Verification` empty ⇒ **none** now (was: silently required, which broke zero-config
  NewServer without a sender); doc/code/server-env-default all agree. BREAKING.md noted.
- `SessionMaxPerUser`: code wins, doc fixed — 0 (unset) ⇒ default 3, negative (-1) ⇒ unlimited. No behavior
  change; the old "0 = unlimited" doc was never true and 0-means-default is the least surprising Go-config
  contract (no unset representation on an int).
- `RLAdminUserSessionsRevoke` DELETED — there is no single-session admin revoke handler at all (the admin
  route revokes ALL of a user's sessions and uses ...RevokeAll); nothing referenced the constant.
- Standalone env (cmd/authkit-server, binary boundary only; README table updated): AUTHKIT_TRUSTED_PROXIES,
  AUTHKIT_ACCESS_TOKEN_TTL, AUTHKIT_REFRESH_TOKEN_TTL, AUTHKIT_SESSION_MAX_PER_USER,
  AUTHKIT_VERIFICATION_SEND_TIMEOUT, AUTHKIT_2FA_MODE, AUTHKIT_2FA_METHODS, AUTHKIT_PASSKEY_RPID,
  AUTHKIT_PASSKEY_RP_DISPLAY_NAME, AUTHKIT_PASSKEY_ORIGINS, AUTHKIT_LANGUAGES, AUTHKIT_DEFAULT_LANGUAGE,
  AUTHKIT_BOOTSTRAP_PATH (startup-once manifest apply; genesis-seed semantics — non-empty unmarked DB
  refuses boot, live-verified apply + already-applied restart). Bad values fail boot loudly. README also
  documents the env→KeySource mapping (#231 vars were already in the table). WithClickHouse env wiring
  SKIPPED deliberately (needs DSN+TLS surface; ClickHouse is an embedded-host dependency today).
- i18n: negotiation trimmed 5→3 tiers — kept `?lang` (test-covered, frontends use it) > Accept-Language >
  default; DELETED path-prefix (routes are never mounted under /:lang/) and cookie (authkit never sets one)
  tiers. Made configurable from the binary (AUTHKIT_LANGUAGES/AUTHKIT_DEFAULT_LANGUAGE).
- `EphemeralMode` string REMOVED (type, consts, facade method, mode param on WithEphemeralStore); the
  `EphemeralRedisClient()` type assertion is the single redis-vs-memory truth. Not on authkit.Client; no
  consumer repo referenced it.
- `users.metadata` jsonb stays AS-IS deliberately (import passthrough; a `reserved` column would collide
  with the just-finished #233-#235 schema baseline).
- Also fixed forward: internal/authcore passkey integration test missing the #231 AllowEphemeralDevKeys
  opt-in. Full suite green incl. DB-backed tests against a freshly-migrated scratch DB (the persistent
  compose authkit_db still carries the pre-#233 schema — re-migrate it before trusting DB tests there).

- ~30 fields double-declared across `authcore.Config` and flat `Options`, hand-mapped in constructor.go with
  renames en route; `Options.VerificationSendTimeout` is UNSETTABLE by any host (not on Config, never
  populated — frozen at 15s). Collapse the seam or generate the mapping.
- `Registration.Verification` empty default: doc says none, code makes it required (then NewServer fails
  without a sender); three different defaults across layers. Make doc and code agree.
- `SessionMaxPerUser: 0` — doc says unlimited, code forces 3; unlimited only via negative. Fix one.
- `RLAdminUserSessionsRevoke` rate bucket wired to no handler and no DefaultRateLimits entry.
- Standalone reachability gaps: no env vars for WithTrustedProxies/WithClientIPFunc (behind a CDN, rate
  limiting can't see real client IPs), token TTLs, 2FA modes, passkey knobs, WithLanguageConfig,
  WithClickHouse; `bootstrap.example.yaml` is never loaded by the server (default path
  /etc/authkit/bootstrap.yaml doesn't match); JWT env vars missing from the cmd README table.
- Overengineered: 5-tier language negotiation with no message catalogs (header-only would do);
  `EphemeralMode` string beside the store (Redis client recovered by type assertion anyway);
  `users.metadata` jsonb whose production use is one boolean ('reserved') — a real column would delete the
  jsonb gymnastics.

---

# #237: [DESIGN] single config type — collapse authcore Options into Config

**Status:** IMPLEMENTED 2026-07-02 (Claude; uncommitted) — Paul's mandate: one config type; breaking change approved (pre-1.0 hard cut, no aliases/shims).
Decisions:
- Flat `authcore.Options` DELETED. The Service reads a NORMALIZED `Config` directly (`Service.cfg`); the
  #236 bug class (knob settable internally but not on Config) is now structurally impossible — no guard
  test needed, there is no second struct to drift. `Service.Config()` returns the normalized Config
  (paths/TTLs/session-cap defaulted, enums canonical, resolved TOTP key written back).
- ONE normalization pass: `normalizeConfig(Config) (Config, error)` in constructor.go (trim, BaseURL-from-
  issuer, frontend-path defaults+validation, 0⇒3 session cap, 0⇒15m access TTL, enum normalization,
  api-key-prefix + schema validation, passkey RP derivation when a base origin exists). `NewFromConfig`
  keeps ONLY host-required checks (Issuer/audiences present, BaseURL when issuer non-URL) + key/TOTP
  resolution + RBAC BuildSchema. Low-level `NewService(Config, Keyset, ...Option)` stays exported in
  internal/authcore (module-internal: ~110 test call sites; hosts can't reach internal/) and panics where
  NewFromConfig errors.
- Config(values) vs dependencies split unchanged and confirmed correct: deps are functional `Option`s
  (WithPostgres/WithRedis/WithEmailSender/WithSMSSender/WithClickHouse/WithEntitlements/WithEphemeralStore);
  no dependency ever lived on the flat struct, so nothing moved there.
- Public surface: `embedded.Options` + `embedded.Keyset` aliases REMOVED (never host-usable — no
  embedded.NewService existed; doujins/hentai0/cozy-art verified clean: all construct via embedded.New
  with nested Config, zero `.Options()` calls). `Client.Options()` → `Client.Config()`. Options policy
  methods moved to the engine: `RegistrationVerificationPolicy/Required/Enabled()`,
  `PublicNativeUserRegistrationEnabled()` are now *Service methods; derived `RequireMFAEnrollment` field
  gone (≡ TwoFactor.Mode == required, method `requireMFAEnrollment`); `solanaChainIDForOptions` →
  `solanaChainIDForConfig`.
- Deliberate behavior unification (host semantics won; the low-level path inherits them): NewService-built
  services now also get BaseURL-from-issuer + passkey RPID derivation + 0⇒3 session cap + 0⇒15m TTL.
  Two http tests that relied on the old skipped normalization ("no BaseURL" fallback, passkey route
  gating) now construct via a non-URL issuer (`newTestServiceNoBaseOrigin`) — for NewFromConfig hosts,
  passkey RP identity was ALWAYS derived, so PasskeysEnabled() was already effectively always-on there.
- Docs: BREAKING.md #237 entry (field-by-field reader migration map), SEMVER.md alias list updated.
  Verified: go build/vet clean; full `go test ./...` green incl. DB-backed (fresh scratch DB
  authkit_237_scratch on compose PG :35432 with the current 0001 baseline).
