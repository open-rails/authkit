<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 134

---

# #126: Shrink the v1.0 public API — drop the dead facet layer, internalize plumbing, rebuild small facets

**Completed:** yes

CLOSED 2026-06-23 (Claude, verified at Paul's request): all three phases done.
core.Service public surface 230 → 81 facade methods; 229 impl methods internalized
to `internal/authcore` (out of the v1.0 contract); facets.go + deprecated comments +
legacy RBAC fields gone. `go build`/`go vet ./...` clean and full `go test ./...`
GREEN (incl. DB-backed integration tests). Only follow-on left is the passkey-surface
SEMVER doc, intentionally gated on #45 landing (not a #126 deliverable).

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
  authcore out-of-contract; §11 risks 1–4 marked DONE). Passkey-surface addition
  still PENDING — deferred until #45 lands so we don't document a moving target.
- [x] Update `README.md` Concepts section (facets line → `svc.Core()` facade).

RESULT: public `core.Service` 230 → 70 methods; 229 impl methods now in
internal/authcore (out of contract). facets.go (888 lines) + 156 deprecated
comments + legacy RBAC fields + empty OrgsFacet + MaxDelegatedRoles redirect all
gone. `go build/vet ./...` clean; full `go test ./...` green incl. DB-backed
integration tests (compose Postgres). Branch: refactor/126-shrink-public-api.

---

# #130: Bulk user import (ImportUsers) for fast legacy migration (500k+)

**Completed:** no

STATUS 2026-06-23 (Claude, overnight): CODE-COMPLETE, UNVERIFIED. Implemented
`ImportUsers` in `internal/authcore/import_users.go` (validate/normalize in Go →
in-batch dedup → set-based existing-check → chunked multi-row `INSERT ... ON
CONFLICT DO NOTHING RETURNING id`, 1000/chunk; + bulk password-hash insert for
inserted rows). Added optional `PasswordHash`/`HashAlgo`/`HashParams` to
`ImportUserInput`. Wired `ImportUsers` onto the `core` facade and added
`ImportUsersResult`/`ImportUserResult`/`ImportUserStatus` aliases; REMOVED
`ImportUser`/`UpdateImportedUser` from the facade (they stay unexported-internal in
authcore for the bootstrap reconciler — internal/authcore is out of contract, so
this satisfies "no single-user import in the public API"). DESIGN CHOICE vs the
original "ON CONFLICT DO UPDATE upsert": went INSERT-OR-SKIP — for a legacy
migration a re-run should RESUME (skip already-imported) not CLOBBER data a user
changed in AuthKit post-import; cross-identity reporting via per-row
`ImportUserResult{inserted|skipped|rejected}`.
COULD NOT VERIFY (`go build/test`): the shared tree is mid-rewrite by the
concurrent #125/#127/#129/#45 agents (MFA + org→persona renames) and does not
compile (e.g. `core.RootType`/`GroupTypeDef`/`Mandatory2FAPolicy`/aliases.go all
broken by their in-flight edits — NOT this issue). `import_users.go` itself has
zero diagnostics (all its references resolve). REMAINING: build+vet+test once the
tree is green; benchmark 500k; tests (dedup, skip-existing, reject isolation,
idempotent re-run, password import + login); decide bulk role-assignment.

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
  LinkToken}` — a bare token, no URL. Even AuthKit's OWN Twilio providers ask the
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
- [ ] Move verification/reset LINK construction into AuthKit (`BaseURL` + verify/
  reset path + typed token). Replace the token-only `VerificationMessage` link
  path with a rendered message / final URL handed to the sender.
- [ ] Add the built-in confirm endpoint(s) AuthKit's links point at: consume token
  (type known), confirm, 302-redirect to the host frontend path with `?status=…`
  and a validated app-relative `return_to` (reuse #132's shared validator).
  Decide + implement the scanner-safe GET/POST mode.
- [ ] Add `FrontendConfig` landing path(s) for verify/reset redirects; validate
  app-relative (reuse #132's `return_to` validator).
- [ ] Change the `EmailSender`/`SMSSender` contract + Twilio providers: REMOVE host
  `VerificationLinkURL`/`ResetLinkURL`; keep transport host-injected and keep
  branding/template/per-language hooks (HARD CUT, no shim).
- [ ] Decide session-on-confirm behavior, consistent with the current POST confirm.
- [ ] Migrate doujins: delete its verify GET handler, try-chain, `GetPending*`
  status helpers, and link-builder config; wire only transport + branding.
- [x] DONE 2026-06-23: removed the 6 `Confirm*`/`GetPending*` methods from the #126
  facade immediately (facade 81→75); they remain in `internal/authcore` for the
  HTTP handlers. `go build`/`go vet ./...` green; `verify.Enricher` assertion
  unaffected (none of the 6 are Enricher methods).
- [ ] Update `SEMVER.md` + README: AuthKit-owned verification/reset flow; new
  endpoint(s)/config; the breaking `EmailSender`/`SMSSender` + Twilio provider
  contract change.
- [ ] Tests: AuthKit-built link round-trips through the built-in confirm; scanner
  mode; status mapping; transport still host-injected (provider-agnostic intact).

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
