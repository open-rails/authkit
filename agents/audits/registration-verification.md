# Audit — Registration & Verification (correctness / integrity / structure)

Focused pass requested 2026-06-26, grounded at commit `d97a0c8`. Scope: the `register`/`verify`
route groups and their service layer — `http/{register,email_verify,phone_verify,*_confirm_link_post,
verify_aliases}.go` → `internal/authcore/{service,pending_change,pending_change_finalizers}.go` →
ephemeral store + `internal/db` (postgres). Covers correctness (non-atomic writes/races, silent
partial failures, resource scoping, error-handling, state/visibility, schema integrity, dead code)
and the forward-only structural / config / API cleanups the operator asked for (backward compat is
explicitly waived).

Every finding was re-opened and read against live code before recording; subagent over-reports are in
"Rejected / by-design".

## Surface & reachability (this is a library other projects import)

"Not called in this repo" only proves dead code for symbols external consumers cannot reach. The
boundary used throughout this audit:
- `internal/authcore/*` is import-forbidden to external projects, and the public `embedded.Client`
  holds `impl *authcore.Service` as an **unexported field**, re-exposing only a small curated facade
  (`embedded/facade_methods.go`). The registration service methods below are **not** re-exported there
  (verified `grep`-clean), so their in-repo callers (the `http` package + tests) are the complete set.
- The genuinely consumer-facing surface — and what these plans deliberately break — is: the **HTTP
  wire contract** (route JSON + status codes), the `embedded` facade and its **aliased types/constants**
  (`embedded/aliases.go`), and exported **sentinel errors** (`errors.go`). Each plan that touches one
  flags it for `BREAKING.md`/`SEMVER.md`; plan 012 re-verifies the facade boundary before deleting
  anything (in case the facade changed after this audit).

## Reconciliation with the issue tracker (`agents/progress.md`)

This pass was checked against the active issues so it doesn't open a parallel track:
- **REG-6 (RegistrationMode) is already owned by #147** ("Registration modes + first-class invites"),
  which has *already decided* to collapse to `Open`/`InviteOnly`/`Closed` and delete `AdminOnly` /
  `AdminBootstrapOnly` / `ManifestOnly`. So there is **no plan 013** — it was retracted as a duplicate;
  REG-6 below is folded into #147 (the only reg/verify-specific residue, the stale error message at
  `service.go:363`, disappears when those constants are deleted).
- **REG-5 (entry-point redesign) overlaps the #143/#146/#147 release train** — #147 re-touches the
  `CreatePendingRegistration*` / `ConfirmPendingRegistration*` call sites for invite-gating, #146
  re-groups the `/register` + `/*/verify/*` routes (folding verification into Registration/Account),
  and #143 owns `embedded`/contract hygiene. Plan 012 must land **with** that train (same hotspot
  files), not as an independent refactor — see its coordination note.
- **REG-1…REG-4 are correctness bugs not tracked by any issue.** They edit the #146/#147 hotspot files
  (`http/register.go`, `email_verify.go`, `phone_verify.go`), so they need sequencing against the
  train, but they are net-new findings. Open question for the operator: file them as issues #150+ in
  `progress.md` for consistency, or keep them as plans 008–011? (Recommended: file them — this repo
  tracks work in `progress.md`.)

## Findings → plans

### REG-1 — Verification send swallows the token-store error (silent no-send)
- **Evidence**: `internal/authcore/service.go:1669-1674` — `sendEmailVerificationToUser`: when
  `storeEmailVerificationTokens` returns an error it executes `return nil`, reporting success and
  skipping the send entirely. `SendPhoneVerificationToUser` has the identical `return nil` on the
  `storePhoneVerificationTokens` error.
- **Impact**: If the ephemeral store is unavailable (Redis outage) the HTTP layer returns `202 ok`
  while no message is sent and no token is stored. The user believes a code/link is on the way and
  can never verify; an infra failure is fully masked. Silent partial failure + swallowed error.
- **Class**: 2 (silent failure), 4 (swallowed error). **Effort** S · **Risk** LOW · **Confidence** HIGH.
- **Fix**: `return err` instead of `nil`; callers already map send/store errors
  (`handleDeliveryError` / `serverErr`). → Plan **008**.
- **Status**: ✅ EXECUTED + REVIEW-APPROVED (worktree `worktree-agent-aa5201adeb1ab7b06`, commit
  `1d6f4a9`) — both sites fixed (`service.go:1673`, `:2181`) + 2 regression tests that fail on pre-fix
  code; build/vet/full `internal/authcore` suite green. Awaiting operator merge to `master`.

### REG-2 — Verify-confirm handlers collapse every error to `400 invalid_or_expired_code`
- **Evidence**: `http/email_verify.go:142-179` and `http/phone_verify.go:119-150` — the return values
  of `ConfirmPendingRegistration`, `ConfirmEmailVerification`/`ConfirmPhoneVerificationUserID`, and
  `ConfirmEmailChange`/`ConfirmPhoneChange` are matched only as `err == nil && userID != ""`; any
  non-nil error is discarded. The handler then calls `RecordFailed*VerifyCode` (counts toward the
  per-identifier cap and, at the cap, invalidates the outstanding code) and returns
  `ErrInvalidOrExpiredCode`.
- **Impact**: Two wrong behaviours. (1) A transient DB error during user creation at confirm time is
  reported to the client as "invalid or expired code", masking the outage **and** burning the
  brute-force attempt budget against a code that is actually valid. (2) The finalizer's
  "first-to-verify-wins" conflict (`pending_change_finalizers.go:23-27,52-55` — email/username taken
  since the pending record was created) is likewise reported as a bad code instead of a `409`
  conflict. The conflict path is also where REG-3's unique-constraint violation surfaces.
- **Surface**: changes HTTP status codes (new `409`/`500` where clients saw `400`) — wire-breaking.
- **Class**: 2 (silent), 4 (mapping). **Effort** M · **Risk** MED · **Confidence** HIGH.
- **Fix**: have the confirm service methods return typed errors that distinguish *code not
  found / address mismatch* (→ keep trying other flows, then `400` + RecordFailed) from
  *found-but-finalize-failed* (conflict → `409`; infra error → `500`, no RecordFailed). → Plan **009**.

### REG-3 — Non-atomic user creation (insert user + password + verified flag are separate writes)
- **Evidence**: `internal/authcore/service.go:2657-2719` — `createEmailRegistrationUser` /
  `createPhoneRegistrationUser` call `createUser` (`service.go:2518`, `UserInsert`), then
  `UserPasswordInsert`, then `setEmailVerified` / `UserSetPhoneAndVerified` as independent
  pool writes with no surrounding transaction.
- **Impact**: If any write after `UserInsert` fails (constraint, network blip, context cancel) the
  user row persists with no password, holding the **unique** `username` (and `email`/`phone_number`)
  slot. The caller returns an error, but the orphan row now makes every retry fail the conflict
  check with "username/email in use" — a permanent wedge until a hard purge, and the account can
  never log in. This is also the path the `finalizeRegister*` check-then-insert depends on.
- **Class**: 1 (non-atomic multi-step write). **Effort** M · **Risk** MED · **Confidence** HIGH.
- **Fix**: wrap the create sequence in `s.pg.Begin(ctx)` + `s.qtx(tx)` + `Commit`, matching the
  repo's existing transaction pattern (`service.go:787` `qtx`; `Begin` at `service.go:2827, 3589,
  3879, 4168`, `api_keys.go:286`, `group_invite_links.go:300`). On any step error, rollback so no
  partial user exists. → Plan **010**.
- **Status**: ✅ EXECUTED + REVIEW-APPROVED (worktree `worktree-agent-a609db545eb90fdb3`) — both
  `createEmail/PhoneRegistrationUser` now wrap UserInsert+password+verified in one `pgx.Tx`
  (`service.go:2670,2709`); `createUser` left intact for its other callers; build/vet/`-race` green.
  CAVEAT: DB happy-path tests skip without `AUTHKIT_TEST_DATABASE_URL`; rollback manually-reasoned.
  Awaiting operator merge.

### REG-4 — Dead / fragile string-matched error guards in change-request handlers
- **Evidence**: `http/email_verify.go:64-72` and `http/phone_verify.go:54-62` map errors from
  `RequestEmailChange` / `RequestPhoneChange` with `strings.Contains(err.Error(), "same as current")`
  and `"already in use"`. But `RequestEmailChange` (`service.go:2914-2925`) and `RequestPhoneChange`
  (`service.go:843-854`) **never** return a "same as current" string: for the same-and-verified
  address they return the sentinel `ErrEmailAlreadyVerified` / `ErrPhoneAlreadyVerified`, for
  same-and-unverified they resend (return `nil`), and for a foreign owner they return
  `fmt.Errorf("email already in use")` / `"phone already in use"`.
- **Impact**: The `"same as current"` branch is dead — it never fires. Changing to your own
  already-verified address returns the sentinel, which is not matched by `errors.Is`, so it falls to
  the generic default `ErrFailedToRequestEmailChange` / `ErrFailedToRequestPhoneChange` instead of
  the intended `email_already_verified` / `email_unchanged` code. The `"already in use"` branch works
  only by literal-string coincidence and breaks silently on any reword. The repo already has the
  correct pattern: `http/internal_errors.go:78-81` maps these sentinels to `409` via the typed
  `handleVerificationRequestError`.
- **Surface**: changes which sentinel `RequestEmailChange`/`RequestPhoneChange` return and the wire
  status for self-change-to-already-verified — wire-breaking.
- **Class**: 4 (guard never fires / string comparison). **Effort** S · **Risk** LOW · **Confidence** HIGH.
- **Fix**: replace the string blocks with `errors.Is` on `ErrEmailAlreadyVerified` (→ `409`) and the
  existing `ErrEmailInUse`/`ErrPhoneInUse` sentinels (returned by the request methods); drop the dead
  "same as current" branch. → Plan **011**.

### REG-5 — Redesign the registration entry point (one coherent method + result) — forward-only
- **Evidence**:
  - `internal/authcore/service.go:1766` `CreatePendingRegistration` (base) and `:1952`
    `CreatePendingPhoneRegistration` (base) have no non-test caller in the module and are not
    re-exported by the `embedded` facade (so unreachable externally — see "Surface & reachability").
    Callers are tests only (`ephemeral_test.go`, `policy_switches_test.go`,
    `registration_optional_no_sender_test.go`, `phone_verify_cap_test.go`, `pending_change_cancel_test.go`,
    `email_verify_scope_test.go`, `pending_abandon_test.go`, `verification_tokens_test.go`,
    `register_response_test.go`).
  - The production methods `CreatePendingRegistrationWithLanguage` (`:1770`) and
    `CreatePendingPhoneRegistrationWithLanguage` (`:1956`) are `*WithLanguage` shims; the email one
    carries a `ttl time.Duration` param that **every HTTP caller passes as `0`**
    (`http/register.go:211,287`, `http/password_login_post.go:268`); the phone one has no `ttl` param
    at all — gratuitous email/phone asymmetry.
  - Overloaded contract: under `none`/`optional` policy `CreatePendingRegistrationWithLanguage`
    **creates a real verified user and returns `("", nil)`** (`service.go:1780-1804`); under `required`
    it stores a pending change and returns the code. The HTTP handler ignores the return value
    (`_, err = ...`) and, for the non-verification path, **re-fetches the just-created user** via
    `GetUserByEmail`/`GetUserByPhone` to issue tokens (`http/register.go:171-176, 229-234`) — an
    extra round-trip and a spurious failure mode (`u == nil` → `ErrRegistrationFailed` even though the
    user was created). The name ("CreatePendingRegistration") describes only one of the two behaviours.
  - The handler `handleRegisterUnifiedPOST` (`http/register.go:64-247`) is ~180 lines of
    near-duplicated email/phone branches because the service surface pushes policy/identifier branching
    up into HTTP. `registrationResponse.DiscordUsername` (`http/register.go:27,41`) is always `nil` —
    a dead, consumer-specific field in the wire contract.
- **Impact**: Confusing, redundant API surface; dead params; an avoidable DB round-trip and failure
  path on every non-verified signup; duplicated handler logic that the bug plans (009/010) otherwise
  patch in two places.
- **Surface**: collapses the registration `/register` wire response (drops `discord_username`) and
  the authcore method surface — wire-breaking + internal-API-breaking (not externally reachable).
- **Class**: 7 (dead/duplicate), architecture. **Effort** M · **Risk** MED · **Confidence** HIGH.
- **Fix**: collapse the four methods into one identifier-agnostic entry point taking a request struct
  and returning a result struct, e.g.
  `Register(ctx, RegisterParams{Identifier, Username, PasswordHash, PreferredLanguage}) (RegisterResult{UserID, NextAction, Code}, error)`
  — the result tells the handler whether a user exists (issue tokens, no re-fetch) or verification is
  pending. Delete the base + `WithLanguage` methods and the dead `ttl` param (if a tunable
  verification TTL is wanted, add it to `RegistrationConfig`, not a per-call arg); remove the
  always-nil `discord_username` field (the broader discord cleanup is #143's contract work). → Plan
  **012** (depends on 009, 010).
- **Coordination**: this edits the exact methods #147 re-touches for invite-gating
  (`CreatePendingRegistration*`/`ConfirmPendingRegistration*`) and the handler #146 re-groups, so it
  must land **with** the #143/#146/#147 release train, not as an independent refactor — otherwise those
  methods get migrated twice. Plan 012 carries this as a hard sequencing note.

### REG-6 — Over-modeled `RegistrationMode` config — OWNED BY #147 (no separate plan)
- **Evidence**: `internal/authcore/config.go:232-237` defines 6 modes. `normalizeRegistrationMode`
  (`service.go`) accepts all 6, but `PublicNativeUserRegistrationEnabled()` (`service.go:464-521`)
  treats **all five non-open modes identically** (public disabled). Only `invite_only` carries any
  distinct meaning (`group_invite_links.go:103`). So `admin_only`, `admin_bootstrap_only`,
  `manifest_only`, `closed` are behaviorally indistinguishable; separately the construction-time error
  (`service.go:363`) silently omits `manifest_only` from the accepted set.
- **Status**: this is **already #147's decision** — "simplify `RegistrationMode` to keep `Open`,
  `InviteOnly`, `Closed`; delete `AdminOnly`, `AdminBootstrapOnly`, `ManifestOnly`" (`progress.md`
  #147). This audit only **confirms the finding** and adds one detail for #147's executor: deleting
  those three constants also resolves the stale `service.go:363` error message (no separate fix
  needed). The constants are aliased in `embedded/aliases.go:107-112` (public-breaking — already
  acknowledged in #147's hard-cut). **No plan 013** — retracted as a duplicate of #147.

## Cross-references (no separate plan)
- **Soft-delete identifier reuse** is part of the existing identifier-uniqueness fork — recorded in
  `plans/007-identifier-uniqueness-model-spike.md` (its "The fork" section), not duplicated here. In
  short: `users.email`/`username`/`phone_number` uniqueness is not `deleted_at`-aware and the conflict
  queries don't filter soft-deleted rows, so a soft-deleted account reserves its identifiers until
  `HardDeleteUser` purges it — and whether to make them reclaimable is the security-loaded call 007
  already owns.
- **`discord` hardwired in a generic auth library** (broader than registration, not planned here): a
  `discord_username` claim is read by the verifier (`verify/verifier.go:988`), enriched in middleware
  (`verify/middleware.go:62`), allow-listed in custom claims (`service.go:637`), and surfaced on `/me`
  (`http/user_me_get.go:16,150`) and the user DTO (`contract.go:333`, `user.go:14`). This belongs
  behind a generic provider-username mechanism. The registration-scoped slice (the always-nil
  `registrationResponse.DiscordUsername`) is handled in plan 012; the claims/contract cleanup is a
  separate effort for the verify/identity owner.

## Rejected / by-design (do not re-audit)
- **"Account takeover via concurrent change-confirm"** (subagent CORRECTNESS-1): the unique
  constraints on `email`/`phone_number` prevent the second writer from overwriting; the race surfaces
  as a constraint error, i.e. REG-2/REG-3, not a takeover. Downgraded.
- **Best-effort `_ =` ephemeral index writes/deletes** (`pending_change.go:121-127, 185-201`):
  intentional on a TTL-expiring disposable store with supersede-on-re-request semantics; failure is
  self-healing via resend/TTL. Not worth a transaction over Redis.
- **`consumePendingChangeByToken` load→finalize→delete "race"** (`pending_change.go:243-257`): the
  finalizer's existence check plus the DB unique constraint bound double-finalize; low value.
- **`ConfirmEmailChange` optional `email` scoping** (`service.go:2989`): the code is already bound by
  its hash and `rec.UserID == userID`; the HTTP handler always supplies a validated email. Defense
  in depth only.
- **Anti-enumeration handlers that always return `ok`** (`handlePendingRegistrationAbandonPOST`,
  resend): by design (documented at `register.go:299-304`).
- **Optional DB CHECK** (`NOT email_verified OR email IS NOT NULL`, phone analog): reasonable
  hardening but low priority and edits the shared `001` schema file; left as a note.
