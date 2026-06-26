# Sessions & Tokens — Correctness & Integrity Audit

Focused audit of AuthKit's **session and token subsystem**: refresh-session lifecycle
(issue / rotate / reuse-detect / revoke / evict), the access-token mint and its claim
contract, and the other token-mint paths (service / custom / delegated / remote-app JWT).

**Grounded at commit `68f437a`.** Every verdict was re-read against the actual code
(`service_sessions.go`, `service.go` `issueAccessToken`, `internal/db/queries/sessions.sql`,
the `refresh_sessions` DDL, `http/auth_token_post.go`, and the mint files), not a summary.
Evidence is `file:line`.

Verify gates: `go build ./...`, `go vet ./...`, `task test-fast` (race, DB-free),
`task test` (DB-backed), `task sqlc` / `task sqlc-check` (after any query edit).

Markers: **[confirmed]** = read end-to-end · **[decision]** = needs a policy call · **[by-design]** = intentional.

## Surface & reachability (this is a library other projects import)

Same boundary the identity and auth-login audits use: the consumer-facing surface is the **HTTP
wire contract**, the `embedded` facade + aliases, exported **sentinel errors** (`errors.go`), and
the `authkit.Client` contract + generated RPC. `internal/authcore/*` is import-forbidden externally.
`IssueRefreshSession*`, `ExchangeRefreshToken`, `IssueAccessToken`, `RevokeAllSessions` are all on
the facade/contract — behavior changes to them are consumer-visible (none of the two findings below
change the wire contract; both are internal correctness fixes).

## Confirmed findings → plans

| ID | Finding | Plan |
|----|---------|------|
| ST-1 | **Non-atomic session-limit enforcement.** `enforceSessionLimit` runs `SessionsCountActive` (`service_sessions.go:388`) then `SessionsEvictOldest` (`:398`), and `IssueRefreshSessionWithAuthMethods` then runs `SessionInsert` (`:93`) — three separate statements, no transaction, no row lock. Under N concurrent logins for the same user at the cap, all read `count == max`, each evicts the same 1 oldest (deduped by the DB to one real revoke), and all insert → the user ends with **more than `SessionMaxPerUser` active sessions**. Check-then-act on a limit (defect class 1). Only bites when `SessionMaxPerUser > 0`. | 028 |
| ST-2 | **Refresh rotation commits before the dependent access-token mint.** In `ExchangeRefreshToken` the `SessionRotate` CAS commits at `service_sessions.go:157` (`current=new`, `previous=old`), *then* `IssueAccessToken` runs at `:173`. If the mint fails after the rotate committed (e.g. a transient `getUserByID` DB error inside `issueAccessToken`, `service.go:674`), the caller gets an error and **never receives `newTok`** — the client retries with its old token, which now matches `previous_token_hash` (`:124`) → `revokeFamilyEnsured` → the **entire session family is revoked** and the user is silently logged out everywhere. Non-atomic multi-step: a DB write committed before its dependent step, with no compensation (defect class 1). | 029 |

## Forward-only / structural

None for this subsystem. Both fixes are internal and forward-only-neutral (no API/config/schema/SDK
break). ST-1's fix edits one query file (`sessions.sql`) + regenerates sqlc; ST-2's fix is a pure
statement reorder. Nothing to flag for `BREAKING.md`/`SEMVER.md`.

## Active-issue coordination (`agents/progress.md`)

- **Shared hotspot `internal/authcore/service_sessions.go`**: plans **017** (`MarkSessionAuthenticated`
  pwd-default), **020** (atomic password rotation reuses `RevokeAllSessions`), and these new **028/029**
  all edit this file. Sequence to avoid collisions; 028/029 touch only `IssueRefreshSession*` /
  `ExchangeRefreshToken` / `enforceSessionLimit`, disjoint from 017's `MarkSessionAuthenticated` and
  020's password functions.
- **#148 (2FA policy → `TwoFactor.Mode`)** re-touches `requireSessionMFAState`, which both
  `IssueRefreshSessionWithAuthMethods` and `ExchangeRefreshToken` call. 028/029 do **not** change that
  gate's logic; keep the call sites intact when #148 lands.
- **#143 (AK2-AUTH-01 token claims)** already shipped `reservedAccessTokenClaims` — confirmed sound
  below; 029 does not touch claim assembly.
- No consumer-bump needed (no public-surface break), so these do **not** need to ride #143's coordinated bump.

## Considered and rejected / downgraded (do not re-audit)

- **Eviction orders by `last_used_at` with possible NULLs** → **rejected**: `refresh_sessions.last_used_at`
  is `NOT NULL DEFAULT now()` (DDL), so `SessionsEvictOldest`'s `ORDER BY last_used_at ASC` is
  well-defined (least-recently-active first; brand-new sessions sort last). No NULL hazard.
- **Refresh errors are bare `errors.New("invalid refresh token" / "refresh token reuse detected" /
  "user_disabled")`** (`service_sessions.go:116,126,147,168`) → **not a defect-class-4 finding**:
  `http/auth_token_post.go:27-37` maps via `errors.Is` (2FA/banned) then a clean default `401`; it does
  **not** `strings.Contains`-match these, and collapsing reuse/invalid to one opaque 401 is the correct
  anti-enumeration behavior (don't tell a client "reuse detected"). Minor library nit only: external
  callers of `ExchangeRefreshToken` can't `errors.Is` the disabled/reuse cases — not worth a contract change.
- **Access tokens stay valid until `exp` after a session is revoked** (`service_sessions.go:145` comment)
  → **by-design**: stateless JWTs, bounded by `AccessTokenDuration`; revocation propagates at next refresh.
  Standard tradeoff, documented in-code.
- **`RevokeAllSessions` logs per-session after the bulk `UPDATE ... RETURNING`, outside any tx**
  (`service_sessions.go:368-379`) → **by-design** best-effort audit logging; the revoke itself is one
  atomic statement. (Same verdict the auth-login audit reached for logout scoping.)
- **Other mint paths** (`service_jwt.go`, `delegated.go`, `remote_application_token.go`) → **confirmed
  sound**: stateless, no multi-write/`go func`. `custom_jwt.go` has full `reservedCustomClaims` +
  `reservedCustomJWTTypes` guards (`:79,:52`) — host can't inject owned registered claims or first-party `typ`.
- **`IssueAccessToken` claim assembly** (`service.go:686-731`) → **confirmed sound**: owned-claim check +
  `reservedAccessTokenClaims` denylist (AK2-AUTH-01) drop any caller `extra` that collides with
  authority/identity/assurance claims; reuse-detection unique partial indexes
  (`refresh_sessions_current_hash_active` / `_prev_hash_active`) back the rotate CAS.

## Confirmed sound (spot-checked, not findings)

Refresh-rotation CAS (`SessionRotate` conditioned on the read hash; 0 rows ⇒ lost race, not reuse),
reuse-detection → family revoke with retry + CRITICAL log (`revokeFamilyEnsured`), per-user ownership
scoping on `RevokeSessionByIDForUser` / `MarkSessionAuthenticated` / `SessionFreshness`,
`ON DELETE CASCADE` from `users`, all session-creation paths route through `enforceSessionLimit`
(no cap-bypass entry point), assurance-claim derivation (`amr`/`acr`/`auth_time`) gated on a
server-read `SessionFreshness`, `mfa_enrolled` emitted only when true.

## Provenance
Grounded at `68f437a`; all evidence re-read against the code. Two findings → plans 028, 029.
