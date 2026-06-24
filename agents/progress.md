<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 137

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

# #131: AuthKit should OWN the verification/reset notification flow (message + link + confirm), not delegate it to the host

**Completed:** no

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
- [ ] DEFERRED (optional): `ManagementProfile.Invitation` → `InviteLinks`
  (+ `api-routes.invitation` doc key). It's a breaking field rename on a covered public
  type for a cosmetic gain (the flag now gates invite-LINK routes); left out of the
  #134/#135 ship to avoid breaking churn. Pick up if/when the naming bites.

---

---

# #136: Root RBAC redesign — owner/admin tiers, core-enforced no-escalation, bootstrap seed-if-absent

**Completed:** no

Proposed 2026-06-23 (Paul + Claude design session). Rework the `root` persona's
operator model into a clean two-tier scheme with escalation safety enforced in
CORE, not left to callers. Land this BEFORE consumers adopt (doujins #420) so they
migrate to the final shape once. doujins + hentai0 share ONE root group.

## Motivation
1. The root persona ships TWO equivalent `root:*` roles — `owner`
   (reserved/unassignable) and `super-admin` (assignable) — redundant and
   confusing ("why two god-mode roles?").
2. Role ASSIGNMENT is actor-less and does NOT enforce no-privilege-escalation:
   `assignRoleBySlug`/`AssignGroupRole` take (target, role) with no actor; the only
   guard is the blunt "owner slug is reserved"; `api_keys.go` literally says
   "No-escalation is the caller's responsibility." So a weak role able to call the
   grant path could mint a STRONGER role (e.g. super-admin) — a privilege-
   amplification hole left to each HTTP handler to remember to close.

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
special-case reserved check. Generalizes to org personas + api-key grants (fold in
the api_keys "caller's responsibility" TODO). Requires making the assignment path
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
- [ ] Make role assignment ACTOR-AWARE (root + org + api-key paths).
- [ ] Enforce capability + no-escalation (subset, wildcard-correct) in authcore.
- [ ] Drop `super-admin` from intrinsic root; keep `owner` as apex; delete the
      owner-reserved special case (subsumed by no-escalation).
- [ ] Bootstrap: seed `owner` (not super-admin), seed-if-absent; NO last-owner guard.
- [ ] Add an ERROR-RETURNING role/permission read (e.g. `ListRoleSlugsByUserErr`)
      so consumers can surface role-resolution failures instead of swallowing
      (today `ListRoleSlugsByUser` returns `[]string`, no error). Needed by doujins #420.
- [ ] Tests: escalation attempts rejected (weak role can't grant stronger/owner);
      owner grants owner+admin; admin (no roles:manage) can't grant; bootstrap
      genesis bypasses; zero-owner recoverable via bootstrap.
- [ ] Release (v0.60.0) + update SEMVER.md (root role model + assignment rules).

## Cross-repo
Consumers adopt via doujins #420 (doujins + hentai0 share ONE root group).
