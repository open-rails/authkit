<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 130

---

# #129: Hard-cut remaining org terminology to persona / permission groups

**Completed:** no

Finish the #111/#125 terminology cut. AuthKit no longer owns a first-class
"org" model; the durable model is permission groups, addressed by persona
(`Persona`) + URL-safe resource slug, with `org` allowed only as a host-defined
persona value in examples/tests.

Do this as a hard cut: no legacy aliases, no compatibility views, no dual field
names, no old `/orgs` route docs. If a downstream consumer breaks, bump it.
AuthKit-owned `org` nouns become `group` / `permission group`; AuthKit-owned
`type` / `GroupType` nouns become `persona`.

Known real leftovers from the 2026-06-23 audit:
- `verify.IssuerOptions.OrgSlug` and internal `issuerEntry.orgSlug`.
- `verify.ServiceJWTPrincipal.Org`.
- exported but apparently unused `authbase.OrgMembership`.
- stale public org error constants in `http/error_codes.go`
  (`ErrOrg*`, `ErrPersonalOrg*`, `ErrNotOrgMember`, etc.).
- stale devserver E2E in `testing/devserver_rbac_e2e_test.go` using
  `DEVSERVER_ORG_MODE`, `/orgs/...`, and `profiles.org*` tables.
- stale README / DEVSERVER / SEMVER / agents docs that still describe org
  bootstrap, org-owned API keys, org route groups, or org manifests.
- stale comments/tests that say "org" when they mean permission group,
  persona, group assignment, remote application, or root role.

Rules:
- Keep the schema names already cut to `permission_groups`,
  `group_role_assignments`, `group_custom_roles`, and `group_invites`.
- Keep `org` as a valid host-defined persona value where a schema/test is
  explicitly proving arbitrary personas. Do not reserve or special-case it.
- Rename AuthKit-owned API fields to the narrowest true noun:
  `PermissionGroupID` for ids, `Persona` for group kind/category names,
  `ResourceSlug` for route/resource slugs, and `RemoteApplicationSlug` (or
  equivalent) for remote-application identity. Do not call a remote application,
  permission group, or persona an org.
- Hard-cut `type` / `GroupType` to `persona` / `Persona` for permission-group
  public API, route generation, service requests, store methods, docs, and
  tests. Keep database column `permission_groups.type` only if renaming it is
  judged too noisy; otherwise rename it to `persona` in the baseline too.
- Hard-cut `resource_ref` / `ResourceRef` to `resource_slug` / `ResourceSlug`.
  Slugs are public API route identifiers, so enforce lowercase URL-safe values
  (`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$` or the existing closest helper)
  everywhere groups are created or resolved. The root group remains singleton
  and has no resource slug.
- Remove dead constants/types instead of renaming them if nothing references
  them.
- Do not change the API-key bearer token format or permission string grammar.

**Tasks:**
- [ ] Rename `verify.IssuerOptions.OrgSlug` and `issuerEntry.orgSlug` to the
  actual identity being stored; update `remoteAppOptions`, verifier tests, and
  service-JWT tests.
- [ ] Rename `verify.ServiceJWTPrincipal.Org` to the same non-org identity field,
  or delete it if consumers should use issuer/subject/resources instead.
- [ ] Rename AuthKit-owned permission-group `GroupType` / `type` public fields,
  request fields, response fields, route structs, store args, and docs to
  `Persona`; update tests and generated-route names accordingly.
- [ ] Rename permission-group public/API fields and DB column from
  `resource_ref` / `ResourceRef` to `resource_slug` / `ResourceSlug`; update
  routes, store methods, request/response DTOs, sqlc/raw SQL, docs, and tests.
- [ ] Enforce lowercase URL-safe `ResourceSlug` validation on create and lookup;
  add one focused test that rejects uppercase, spaces, slashes, empty non-root
  slugs, and trailing hyphens.
- [ ] Delete `authbase.OrgMembership` if it is still unused; otherwise rename it
  to a permission-group membership type and update callers.
- [ ] Delete stale `http/error_codes.go` org-specific constants that no runtime
  path emits; rename only the ones that are still genuinely live.
- [ ] Replace or delete `testing/devserver_rbac_e2e_test.go`; it must use
  permission-group routes/tables or be removed as obsolete.
- [ ] Update README / DEVSERVER / SEMVER / agents API docs to describe
  permission groups/personas, not org bootstrap/routes/storage.
- [ ] Clean comments and test names where `org` is historical AuthKit language;
  leave `org` only where it is deliberately a sample host persona.
- [ ] Add a small guard test or grep-style test that fails if AuthKit reintroduces
  `/orgs`, `profiles.orgs`, `profiles.org_roles`, `OrgID`, `OrgSlug`,
  `GroupType`, `ResourceRef`, or `resource_ref` as live code/API surface.
- [ ] Run `rg` audits for
  `OrgID|OrgSlug|OrgMembership|GroupType|ResourceRef|resource_ref|/orgs|profiles\.org|org_`
  and classify any remaining hits as either host-defined persona examples or
  historical tracker/docs.
- [ ] Run `go test ./...` and the DB-backed `task test` if this touches generated
  routes, verifier behavior, or devserver integration.

---

# #122: Make sensitive-action reauth support 2FA refresh without full password login

**Completed:** yes

Change the sensitive-action model from "old MFA can stand in for freshness" to "sensitive actions need a recent step-up, and the step-up method can be password, 2FA, or linked-provider reauth." This keeps the GitHub-style UX: a user who logged in with password + 2FA should be able to refresh with just 2FA after the sensitive-action window expires.

HARD CUT: no backwards compatibility for the old reauth `factor_id` request/response contract. Reauth uses method names as the public selector; factor UUIDs remain internal implementation details.

CURRENT STATE:
- `POST /reauth/2fa` already exists and returns a fresh access token after TOTP/SMS/email/backup-code verification.
- `/user/me` and `reauth_required` responses already expose coarse `reauth_methods`, but not the available 2FA method choices the frontend should render.
- `SensitiveClaims` currently treats any MFA claim as sufficient even when `auth_time` is stale, so stale MFA tokens may skip the reauth prompt entirely.

TARGET BEHAVIOR:
- Single-factor session, stale `auth_time`: sensitive action returns `reauth_required`; `POST /reauth/password` refreshes the window.
- MFA-capable session, stale `auth_time`: sensitive action returns `reauth_required` with `"2fa"` in `reauth_methods`; `POST /reauth/2fa` refreshes the window without requiring the password again.
- `POST /reauth/2fa` with no factor choice uses the user's default factor; clients choose a non-default factor by `method` (`"totp"`, `"email"`, or `"sms"`). Reauth-facing request/response shapes should not expose `factor_id`/`factor.id`; the DB UUID can remain internal.
- `/user/me` and `reauth_required` responses include available 2FA reauth options so frontends know which choices to show before calling `POST /reauth/2fa`.
- Fresh password-only, fresh 2FA, and fresh provider reauth continue to work.
- Operations that explicitly require MFA should require both recent freshness and MFA assurance, not stale MFA alone.

**Tasks:**
- [x] Update `SensitiveClaims`/`SensitiveOptions` semantics so default sensitive checks require recent `auth_time`; MFA no longer bypasses `MaxAge`.
- [x] Keep `RequireMFA` as an additional assurance requirement: require recent freshness plus MFA AMR/ACR when requested.
- [x] Extend `/user/me` and `reauth_required` metadata with available 2FA reauth options: enabled methods, default method, and enough display-safe factor data for the frontend to render choices.
- [x] Replace `POST /reauth/2fa` `factor_id` request handling with optional `method` as the public selector; remove `factor_id` from the reauth-facing contract with no compatibility shim.
- [x] Keep 2FA option metadata display-safe: include method/default/obfuscated destination where useful, never TOTP secrets or raw backup codes.
- [x] Add regression tests for stale MFA token rejection, fresh MFA acceptance, stale password token rejection, and password reauth refresh.
- [x] Add tests for `POST /reauth/2fa` factor selection: omitted choice uses default, `method` selects the enabled factor of that method, invalid/missing method fails cleanly, and reauth responses do not expose `factor.id`.
- [x] Add tests that `/user/me` and `reauth_required` expose the same available 2FA methods for users with email, SMS, TOTP, and multiple factors.
- [x] Add integration test for stale MFA session -> `reauth_required` with `"2fa"` -> `POST /reauth/2fa` -> retry sensitive action succeeds with returned access token.
- [x] Update endpoint docs/client guidance for the retry loop: call sensitive endpoint, handle `reauth_required`, perform one listed reauth method, retry with the returned access token.
- [x] Run focused verify/http tests plus full `go test ./...`.

---

# #123: Harden against security-audit findings (email-code brute force, OAuth redirect_uri header injection, OAuth state binding, + hardening)

**Completed:** no

Security audit (2026-06-22, Paul + Claude) of the live authkit code. Findings are listed worst-first. F1 is a default-reachable account-takeover vector and should be fixed first. F2/F3 are real OAuth/social-login weaknesses. F4–F7 are hardening. Related: #121 (auth-bypass/destructive-action gaps), #122 (reauth model) — distinct from these.

---

## F1 (HIGH; CRITICAL under load) — Email-verification / pending-registration codes are brute-forceable → account takeover

**Where:** `http/email_verify.go:60-112` (`handleEmailVerifyConfirmPOST`) → `core/service.go:1512` (`ConfirmEmailVerification`) and `core/service.go:1649` (`ConfirmPendingRegistration`) → `core/ephemeral_data.go` (`consumeEmailVerification` / `useEmailVerifyToken`) + `consumePendingChangeByToken`.

**Bug — three weaknesses that compound:**
1. The typed code is **6 numeric digits** (`randAlphanumeric(6)`, generated at `core/service.go:1480,1585,1609`), valid for **1 hour** (`defaultEmailVerificationTTL`).
2. **Global lookup, not scoped to an email.** The confirm endpoint accepts a bare `code` and calls `ConfirmPendingRegistration(ctx, code)` / `ConfirmEmailVerification(ctx, code)`, which look the code up **by `sha256Hex(code)` across the whole store** — no email/identifier is supplied or checked at lookup time. A guessed code matches *whichever* pending verification holds it.
3. **Rate-limited per-IP only.** `handleEmailVerifyConfirmPOST` calls `s.rateLimited(w, r, RLEmailVerifyConfirm)` (10/10min per IP) but **never** `rateLimitedByIdentifier`. (The per-identifier call in `email_verify.go` is on the *request* handler, mail-bomb protection — not confirm.) The code is **not invalidated on a wrong guess** (`consume*` deletes only on success); no per-account/global attempt counter.

On success the handler issues **full access + refresh tokens for the matched user** (`issueTokensForUser`, lines 88/104) — so a hit on an existing user mid email-(re)verification is direct account takeover, not just a new-signup.

**Exploit:** spray 6-digit codes at the confirm route. `P(hit) ≈ N/10⁶` per guess where `N` = concurrent active codes; the only throttle is per-IP, defeated by IP rotation (or X-Forwarded-For spoofing — see F6). Reward: a live session for someone else's account.

**Intended design is visible next door** (this is an inconsistency, not a design choice): phone confirm requires `(phone, code)` + caps per-phone (`http/phone_verify.go:83`, `ConfirmPhoneVerificationUserID(ctx, phone, code)`); email-*change* confirm is scoped to `claims.UserID` (`http/user_routes.go:146`). Only the unauthenticated email-verify / pending-registration confirm was left global + per-IP-only. The 256-bit link-token path (`randB64(32)`) is fine.

**Fix (do at least scoping + attempt cap):**
- Require an `email` (identifier) on the typed-code path and bind the lookup to `(email, code)` like phone; then add `rateLimitedByIdentifier(RLEmailVerifyConfirm, email)`.
- Invalidate the code after N (e.g. 5) failed attempts (per-code attempt counter in the ephemeral record), and/or add a per-account/global attempt cap.
- Optionally lengthen the typed code (8+ alphanumeric); keep the 256-bit link token as the primary confirm path.

---

## F2 (MEDIUM–HIGH) — OAuth `redirect_uri` built from attacker-controlled headers

**Where:** `http/oidc_util.go:17-51` (`buildRedirectURI`) — uses `X-Forwarded-Proto` / `X-Forwarded-Host` verbatim with no allowlist / trusted-proxy gate. Consumed by `http/oauth2_browser.go:93,139,302`, `http/oidc_browser.go`, `http/oidc_link_start_post.go`, `http/reauth.go`. The value is sent to the IdP as `redirect_uri` and replayed at token exchange.

**Exploit / severity:** if the IdP registration is permissive (wildcard / multiple redirect URIs — common in multi-domain/multi-tenant setups), an attacker steers the authorization `code` to a host they control → auth-code theft → account takeover. With a single exact registered URI the IdP rejects the mismatch (impact drops to cache-poisoning / broken flow). The codebase already has the right pattern for forwarded headers in `http/client_ip.go:50-88` (only honor behind a trusted-proxy CIDR) — `buildRedirectURI` just doesn't use it.

**Fix:** derive the redirect base from trusted config (`Options().BaseURL`), or only honor `X-Forwarded-*` when `RemoteAddr` is a trusted proxy (reuse the `client_ip.go` pattern), or validate the resulting host against an allowlist.

---

## F3 (MEDIUM) — OAuth/OIDC `state` not bound to the browser → login CSRF

**Where:** `http/oauth2_browser.go:117-130` (start) / `:175-180` (callback); same in `http/oidc_browser.go`. `state` is `randB64(32)` (good entropy) but stored only in a shared server-side cache and validated by existence; **no cookie ties it to the initiating browser**. The login flow (unlike the reauth/link flows, which bind to `ReauthUserID`/`LinkUserID`) accepts any valid `state`+`code`.

**Exploit (login CSRF / session fixation):** attacker starts a login as themselves, captures their valid `state`+`code`, lures the victim to `…/callback?state=…&code=…`; the victim's browser is silently logged into the **attacker's** account.

**Fix:** at start set an `HttpOnly; Secure; SameSite=Lax` cookie holding the state (or its hash); at callback require the cookie present and equal to the `state` param before consuming it.

---

## F4 (LOW–MEDIUM) — GitHub provider hardcodes `email_verified = true`

**Where:** `authprovider/builtins.go:61,74` (`EmailVerified: FieldMapping{Value: true}` on both the primary mapping and the email fallback). The C-2 protection (`http/oauth2_browser.go:386-396`) blocks silent merge-by-email, but on **new-account creation** (`resolveOAuthUser` → `SetEmailVerified`, `oauth2_browser.go:417`) it marks an unverified address as verified.

**Fix:** map GitHub's real per-address `verified` flag — use `EmailVerified: FieldMapping{Path: "verified"}` on the `/user/emails` fallback and stop hardcoding `Value: true` on the primary mapping.

---

## F5 (LOW) — SIWS link path uses non-atomic `Get`+`Del` for the nonce

**Where:** `core/service_solana.go:202-211` (`LinkSolanaWallet`) does `cache.Get(...)` then a best-effort `cache.Del(...)` (error ignored) instead of the atomic `Consume` (GETDEL) the login path uses (`service_solana.go:112`). TOCTOU replay window; a swallowed `Del` error can also leave the nonce live for its full TTL. Bounded (link requires an authed session and dedups at `LinkProviderByIssuer`).

**Fix:** use `cache.Consume(ctx, parsedInput.Nonce)` in `LinkSolanaWallet`, matching the login path.

---

## F6 (LOW, conditional) — `ClientIPFromForwardedHeaders` trusts the left-most `X-Forwarded-For`

**Where:** `http/client_ip.go:73-82` — takes the left-most XFF entry (the client-claimed value), so when a host opts into this helper an attacker can rotate their per-IP rate-limit key at will. Default `DefaultClientIP` uses `RemoteAddr` and is safe, so this is conditional — but it directly amplifies F1 (email-verify confirm has no per-identifier cap).

**Fix:** take the right-most untrusted hop (the address appended by the trusted proxy), not the left-most client-supplied value.

---

## F7 (LOW) — `decodeJSON` has no `http.MaxBytesReader` cap

**Where:** `http/util.go` (`decodeJSON`) — unbounded request bodies on public endpoints → memory DoS.

**Fix:** wrap the body with `http.MaxBytesReader` at a sane limit (e.g. 1 MiB) before decoding.

---

**Tasks:**
- [x] **F1:** scope the typed email-verify / pending-registration confirm to `(email, code)` (mirror the phone path); email passed through `handleEmailVerifyConfirmPOST` → `ConfirmEmailVerification` / `ConfirmPendingRegistration`. Link path split into `…ByToken` (256-bit) variants. (`core/service.go`, `core/ephemeral_data.go`, `core/facets.go`, `http/email_verify*.go`)
- [x] **F1:** add `rateLimitedByIdentifier(RLEmailVerifyConfirm, email)` to the confirm handler.
- [x] **F1:** add a per-email failed-attempt counter (`RecordFailedEmailVerifyCode`/`ClearEmailVerifyCodeAttempts`, cap=5) that invalidates the outstanding code(s) once the cap is hit.
- [x] **F1:** tests — `core/email_verify_scope_test.go` (mismatched email rejected & not consumed, attempt-cap invalidation, counter reset; no-DB) + `http/email_verify_scope_integration_test.go` (HTTP scoping; DB-gated/CI). Updated existing `password_reset_verify_confirm_integration_test.go` to send `email`.
- [x] **F2:** `buildRedirectURI` is now a `*Service` method deriving scheme+host from `Options().BaseURL` (or the connection), never `X-Forwarded-*`. Tests in `http/security_audit_test.go` (BaseURL used, spoofed `X-Forwarded-Host` ignored).
- [x] **F3:** bind OAuth/OIDC `state` via an `HttpOnly; Secure; SameSite=Lax` cookie (`oidc_util.go`), set at all 4 start sites, verified+cleared at both callbacks. Tests: `stateCookieMatches` + callback-rejects-without-cookie + cookie-passes-gate.
- [x] **F4:** GitHub primary mapping no longer hardcodes `email_verified=true`; `/user/emails` fallback maps the real `verified` flag. Test: `authprovider/builtins_security_test.go`.
- [x] **F5:** `LinkSolanaWallet` switched to atomic `cache.Consume` (matches the proven login path). A replay/concurrency assertion would need SIWS signing fixtures + a DB harness (none exist yet); the change is mechanically identical to the already-correct login path.
- [x] **F6:** `ClientIPFromForwardedHeaders` walks `X-Forwarded-For` right-to-left to the first non-trusted hop (added `inPrefixes`). Test: spoofed left-most can't rotate the key; chained trusted proxies skipped; untrusted peer ignores XFF.
- [x] **F7:** `decodeJSON` wraps the body in `http.MaxBytesReader` (1 MiB). Tests: oversized rejected, small accepted.
- [x] Run focused package tests + full `go test ./...` — **green** (all packages pass; DB-gated integration tests skip without `AUTHKIT_TEST_DATABASE_URL`). `go build ./...` and `go vet ./...` clean.

---

# #124: Clarify DB-backed test setup and prune low-value test coverage

**Completed:** yes

STATUS 2026-06-23 (Codex): FINISHED. The DB-backed test path is documented in
`README.md`/`DEVSERVER.md`, CI now starts the compose `issuer` and runs
`task test`, and low-value route/source/private-helper tests were pruned. Final
validation passed with `go test ./...` and
`SQLC_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35433/authkit_db?sslmode=disable task test`
against a fresh temporary compose project. Pruning-only delta from the audit
baseline was 104 test files / 389 tests / 14,405 test LOC to 103 test files /
369 tests / 13,838 test LOC (-1 file, -20 tests, -567 LOC). The current full
tree after concurrent passkey/security additions is 109 test files / 387 tests /
14,787 test LOC.

Tighten the test suite around real AuthKit behavior. The goal is not "more tests";
it is fewer tests that prove the important paths: HTTP + service + Postgres for
auth/security workflows, and small unit tests only where they are the right tool
(crypto, JWT parsing, SSRF validators, TOTP math, schema rewriting).

CURRENT STATE:
- `go test ./...` passes without `AUTHKIT_TEST_DATABASE_URL`, but many important
  integration tests silently skip without a real Postgres.
- `Taskfile.yml` has `task test`, which exports
  `AUTHKIT_TEST_DATABASE_URL=$SQLC_DATABASE_URL`, defaulting to the devserver
  compose Postgres at `127.0.0.1:35432/authkit_db`.
- `docker-compose.yaml` starts Postgres and the devserver. The
  devserver applies AuthKit migrations on boot by default.
- This means `task test` only works as a full DB-backed suite if the compose
  stack has been started far enough for the `issuer` service to run migrations.
  Starting only `postgres` is not enough.

DESIGN:
- Keep plain `go test ./...` fast and DB-free by default.
- Treat `task test` as the full-suite command once the local compose `issuer`
  is running. `issuer` runs migrations on startup, so a healthy issuer means the
  DB is ready for the DB-backed tests.
- Treat devserver migration-on-start as the local migration runner. Do not add a
  separate migration CLI unless a postgres-only test path becomes necessary.

RECOMMENDED SHAPE:
- Document the required local full-suite flow:
  `docker compose up -d --build issuer && task test`.
- CI should start the compose `issuer` (or an equivalent migrated Postgres) and
  run `task test`, not rely only on plain `go test ./...`, for the required
  security/integration gate.
- Optional convenience only: add `task test-db-up` / `task test-db-reset` if the
  repeated local command becomes annoying. Do not add this unless it actually
  simplifies day-to-day use.

TEST AUDIT / CUT PLAN:
- DB-backed tests gated on `AUTHKIT_TEST_DATABASE_URL` are required full-suite
  coverage, not optional smoke: core/http password reset, registration,
  mandatory 2FA, reauth, OIDC linking, permission groups/API keys, remote apps,
  admin directory, bootstrap password seed, and purge-deleted-users. Optional
  skips are the docker-compose devserver E2E tests in `testing/` and the public
  outbound SSRF reachability probe.
- Delete or replace source-text contract tests. `TestFreshReauthRouteContract`
  reads `.go` files and checks string markers; this should be covered by real
  reauth integration behavior instead.
- Shrink route-shape smoke tests. Keep one small route-group sanity test, but
  remove broad unauthenticated `401/404` route tables that mostly pin routing
  layout instead of behavior.
- Replace private-helper branch tests with HTTP-level flows where the behavior
  matters. `http/password_login_post_test.go` mostly tests callback plumbing in
  `recoverPendingEmailLogin` / `recoverPendingPhoneLogin`; keep one end-to-end
  pending-login behavior test if still product-relevant.
- Collapse duplicated generated permission-group route coverage. Keep core
  schema generation tests plus DB-backed generated-handler lifecycle tests
  (API key, remote app, invite); trim HTTP route-table mirror assertions.
- Rename/merge `*_restored_test.go` files into normal feature test files where
  the behavior still matters. Delete migration-era comments and duplicate cases.
- Delete private response-builder tests such as `TestRegistrationResponseBuilder`
  when HTTP response tests already pin the public contract.
- Keep small pure unit tests for security primitives: JWT signer/parser behavior,
  TOTP code/replay math, SSRF URI/dialer checks, verification token consume
  semantics, assurance/freshness middleware, schema rewrite validation, and API
  key parsing/formatting.
- Keep and prioritize DB-backed HTTP integration tests for mandatory 2FA, reauth,
  destructive-route freshness, API-key resource authorization, password
  reset/verification, OIDC linking, and OAuth/OIDC hardening.

**Tasks:**
- [x] Document the full DB-backed local test flow:
  `docker compose up -d --build issuer && task test`.
- [x] Add or update CI so the required gate starts the compose `issuer` (or uses
  an equivalent migrated Postgres) and runs `task test`; keep any plain
  `go test ./...` job only as a fast DB-free smoke.
- [x] Optional only if useful: add `task test-db-up` / `task test-db-reset` as
  shortcuts for the documented compose commands.
- [x] Audit all tests that skip on `AUTHKIT_TEST_DATABASE_URL` and classify them
  as required full-suite coverage vs optional/devserver-only coverage.
- [x] Delete `TestFreshReauthRouteContract` after confirming #122 reauth
  integration tests cover the real behavior.
- [x] Shrink `http/routes_test.go` and `TestAPIHandler_PrefixNeutralRouteContract`
  to one route-group sanity check plus any genuinely important removed-route
  assertions.
- [x] Replace or delete `http/password_login_post_test.go` private-helper branch
  tests; add one HTTP-level pending-login recovery test only if the behavior is
  still needed.
- [x] Collapse permission-group route coverage to core schema-generation tests
  plus DB-backed HTTP lifecycle tests; remove duplicate HTTP route-table mirror
  assertions.
- [x] Rename/merge `*_restored_test.go` files into normal feature test files and
  remove migration-era scaffolding comments.
- [x] Delete private response-builder tests that duplicate HTTP response
  contracts.
- [x] After pruning, run `go test ./...` and `task test`; record the final test
  count / LOC reduction and any intentionally retained unit-test clusters.

---

# #125: 2FA factor hard-delete + Postgres schema cleanup (DB audit findings)

**Completed:** no

Outcome of a full DB-structure audit (2026-06-23, Paul + Claude) of the squashed
baseline schema (`migrations/postgres/001_auth_schema.up.sql` + `013_user_passkeys.up.sql`).
Two themes: (A) 2FA factors must be HARD-DELETED, not soft-disabled (Paul's
explicit call), and (B) a batch of dead/redundant/inconsistent schema objects to
clean up. Grouped here because most of A and B touch the 2FA tables; the Tier-1/3
items are independent quick wins that can land in the same migration.

MIGRATION PACKAGING (do it right, per #45's lesson): migratekit is name-tracked,
so editing the already-recorded `001` does NOT reach DBs that recorded it. Land
all schema changes here as a NEW numbered forward migration (next available, e.g.
`014_2fa_hard_delete_and_cleanup.up.sql`) with the `ALTER`/`DROP` statements — it
applies to both fresh and existing deployments. Optionally ALSO mirror the
reductions into the squashed `001` so a from-scratch DB starts clean, but the
forward migration is the source of truth for existing DBs. The local devserver DB
was already wiped + recreated on the clean baseline (item D9 below), so it will
pick up `014` on next boot.

---

## A. 2FA factors: hard-delete, not enable/disable (PRIMARY)

DECISION: removing a 2FA factor is a real row delete. The per-factor `enabled`
soft-disable flag goes away entirely. The ACCOUNT-level gate
`two_factor_settings.enabled` STAYS and keeps its meaning: enabled ⇒ 2FA is
required at login; disabled ⇒ not required.

WHY: today `TwoFactorDisableFactor`/`TwoFactorDisableAllFactors` do
`SET enabled = false` (never `DELETE`; the only `DELETE FROM two_factor_factors`
is in a test). Disabled rows are pure tombstones that are never reactivated —
re-enrolling a method has `ON CONFLICT (user_id, method) WHERE enabled = true`,
whose target excludes disabled rows, so re-enroll INSERTs a fresh row and the
dead one lingers forever. Soft-delete here buys nothing (no audit reader, no
undelete) and just accumulates garbage.

Schema (`014` migration; also fold into squashed `001` if recreating DBs):
- `two_factor_factors`: DROP COLUMN `enabled` — a row existing IS the enabled state.
- Replace `uniq_two_factor_factors_user_method` (`(user_id, method) WHERE enabled = true`)
  → plain `UNIQUE (user_id, method)`.
- Replace `uniq_two_factor_factors_default` (`(user_id) WHERE enabled = true AND is_default = true`)
  → `(user_id) WHERE is_default = true`.
- `idx_two_factor_factors_user_enabled (user_id, enabled)` → `(user_id)` (or drop;
  `uniq_two_factor_factors_user_method` already covers `user_id` prefix lookups).

Queries (`internal/db/queries/twofactor.sql`):
- `TwoFactorDisableFactor` / `TwoFactorDisableAllFactors` → `DELETE FROM profiles.two_factor_factors WHERE …`.
- Drop the `AND enabled = true` predicate and the `enabled` column from every
  factor query: `TwoFactorListFactorsByUser`, `TwoFactorDefaultFactorByUser`,
  `TwoFactorFactorByUserMethod`, `TwoFactorClearDefaultFactors`,
  `TwoFactorSetDefaultFactor`, `TwoFactorConsumeFactorTOTPStep`, `TwoFactorUpsertFactor`
  (drop `enabled` from INSERT/RETURNING; change `ON CONFLICT (user_id, method) WHERE enabled = true`
  → `ON CONFLICT (user_id, method)`).

Go (`core/service.go`):
- `twoFactorFactorFromFields(...)` — drop the `enabled` param; `TwoFactorFactor.Enabled` field removed (or hard-coded true at the boundary if a consumer still reads it).
- `Disable2FAFactor` (`~4153`): after the DELETE, if zero factors remain, flip
  `two_factor_settings.enabled = false` (already does this via `TwoFactorDisable`).
- Remove the "synthesize a factor from settings when factors empty" fallback in
  `Get2FASettings` (`~4291`): with hard-delete the invariant is
  `settings.enabled = true ⇔ ≥1 factor exists`, so the synthetic-factor shim is dead.

CONSISTENCY DECISION (passkeys): `user_passkeys` uses soft-delete (`deleted_at`),
also never reactivated. To avoid "one credential hard-deletes, the other
tombstones," decide one of:
- (preferred, matches this issue) make passkey delete a hard `DELETE` too and
  drop `user_passkeys.deleted_at` + collapse its `WHERE deleted_at IS NULL`
  partial indexes; OR
- keep passkey soft-delete only if a concrete audit/undelete need is named.
Default to hard-delete for parity unless someone justifies the tombstone.

---

## B. 2FA settings: drop the denormalized per-factor mirror (Tier 2)

`two_factor_settings.{method, phone_number, totp_secret, last_totp_step}` are a
sync-maintained copy of the DEFAULT factor: `SetDefaultFactor`/enroll write the
selected factor's fields back into settings (`service.go:4115,4243`), and
`Get2FASettings` reads settings then OVERWRITES those fields from the default
factor (`service.go:4281`). The factors table is the source of truth; the copies
are dead weight and a drift-bug source.

Schema:
- `two_factor_settings`: DROP COLUMNS `method`, `phone_number`, `totp_secret`,
  `last_totp_step`. Keep `(user_id, enabled, backup_codes, created_at, updated_at)`
  — the genuinely user-scoped bits (account gate + backup codes; 1:1 per user).
- DROP `idx_two_factor_settings_enabled` (partial `WHERE enabled = true`): unused;
  every access to the table is by PK `user_id`, nothing scans by `enabled` alone.
  (The `enabled` COLUMN stays — only the index is dead.)

Queries: drop the removed columns from `TwoFactorEnable`, `TwoFactorUpsertSettings`,
`TwoFactorSettingsByUser`; DELETE the settings-level `TwoFactorConsumeTOTPStep`
(replay protection is per-factor via `TwoFactorConsumeFactorTOTPStep`).

Go: `Get2FASettings` reads `enabled` + `backup_codes` from settings and derives
method/phone/secret display data from the default factor (already does the
override; just remove the now-absent settings reads). `TwoFactorSettings` struct:
keep `Enabled`, `BackupCodes`, `Factors`; drop the mirrored per-factor fields.

---

## C. Tier 1 — dead/redundant objects (independent quick wins)

1. **Drop `profiles.uuid_v5()` function.** Dead: its only caller `profiles.role_id()`
   was removed in the squash; no query/trigger/Go calls it. Update the assertion
   in `migrations/postgres/migrations_test.go:90` (it checks the rendered DDL
   contains `uuid_v5(` to exercise schema-rewriting) to a still-present
   `profiles.`-qualified identifier, e.g. `trg_permission_group_containment(`.
2. **Drop `users.discord_username` column.** Write-never (no INSERT/UPDATE sets it;
   `register.go` passes nil) → always NULL. `getDiscordUsername` (`service.go:3921`)
   "prefers" it (unreachable branch) then falls back to
   `user_providers.profile->>'username'` for the `discord` provider, which is the
   live source today. Drop the column + the `UserDiscordUsername` query and
   simplify `getDiscordUsername` to just `getProviderUsername(ctx, userID, "discord")`.
3. **Drop `service_tokens_group_role_idx (permission_group_id, role)`.** Leftover
   from the #95 era when `role` was FK-bound; post-#111 `role` is a plain string
   and no query filters service_tokens by role. `service_tokens_group_idx
   (permission_group_id)` covers every access (Resolve is by unique `key_id`).
   (The unused `idx_two_factor_settings_enabled` is in section B.)

---

## D. Tier 3 — consistency & relationships

5. **`users.phone_verified` → `NOT NULL DEFAULT false`.** Currently nullable
   (`boolean DEFAULT false`) while `email_verified` is `NOT NULL DEFAULT false`;
   every read carries `COALESCE(phone_verified, false)`. Make it NOT NULL and drop
   the COALESCE noise across `users.sql`.
6. **Unify `ON DELETE` policies on the permission_group FKs.** Asymmetric today:
   `service_tokens.permission_group_id` is `ON DELETE CASCADE` but
   `remote_applications.permission_group_id` has no action (blocks group delete);
   also `service_tokens.created_by → SET NULL` vs `group_invites.invited_by →
   RESTRICT`. None are bugs; make "what happens when I delete X" deliberate and
   uniform.
7. **Clean up orphaned `group_role_assignments` on hard principal delete.** The
   polymorphic `(subject_id, subject_kind)` + trigger-FK pattern has no cascade,
   so `UserDeleteHard` (purge path) leaves dangling assignment rows (harmless to
   authz — the walk LEFT JOINs and never matches a dead subject — but they
   accumulate). Add assignment cleanup to the hard-delete/purge path (and the
   remote_application delete path), or a periodic sweep.
8. **Naming debt: stop carrying permission_group ids in `org_*` fields.** The
   remote-app/service-token queries alias `permission_group_id` back to
   `org_id`/`OrgID`, and `ResolvedAPIKey.OrgID`/`OrgSlug` hold a group id "for
   backward compat." Orgs are fully gone (#111); an `OrgID` field holding a group
   id actively misleads. Rename to `PermissionGroupID`/`GroupRef`.
9. **Devserver DB recreate — DONE 2026-06-23.** The live `authkit_db` had drifted
   (orphan `delegated_users`, old `role_id` fn, pre-squash tables). Wiped via
   `docker compose down -v` + `up -d --build`; verified the fresh schema matches
   the committed baseline exactly (19 expected tables, passkeys present, no
   orphans). It will pick up the `014` cleanup migration on next issuer boot.

WHAT'S ALREADY GOOD (no change): the `WalkAssignments` recursive-CTE authz hot
path is well-indexed (no N+1); `group_custom_roles.permissions text[]` as an array
is right for small always-loaded bundles; refresh-token rotation
(current/previous hash + `WHERE revoked_at IS NULL` partial uniques) is solid;
`user_passwords.hash_algo`/`hash_params` back legacy-hash import (keep).

STATUS 2026-06-23 (Claude): IMPLEMENTED. Per Paul, all schema changes were folded
directly into the squashed baseline `001_auth_schema.up.sql` (NO `014`), and the
separate `013_user_passkeys.up.sql` was merged into `001` too (deleted) — `001` is
now the single baseline (19 tables incl. passkeys, verified by from-scratch apply).
All code/query/test changes landed and D8 was completed too (orgs fully gone from
the API). A concurrent refactor renamed package `core` → `authcore`
(`internal/authcore/`); my source edits + the three new #125 tests moved with it
intact. FINAL STATE: full `task test` GREEN across every package (incl. http +
internal/authcore); `go build ./...` clean; `task sqlc` generate+vet clean against
the from-`001` schema.

**Tasks:**
- [x] **A:** Folded into `001` (no `014`): dropped `two_factor_factors.enabled`; `uniq_two_factor_factors_user_method` → plain UNIQUE, `uniq_two_factor_factors_default` → `WHERE is_default = true`; `idx_two_factor_factors_user_enabled` → `idx_two_factor_factors_user (user_id)`.
- [x] **A:** `twofactor.sql`: `TwoFactorDisableFactor`/`TwoFactorDisableAllFactors` renamed to `TwoFactorDeleteFactor`/`TwoFactorDeleteAllFactors` (now `DELETE`); stripped `enabled` from all factor queries; `TwoFactorUpsertFactor` conflict target `(user_id, method)`.
- [x] **A:** `service.go`: dropped `enabled` param from `twoFactorFactorFromFields` (field hard-coded `true`); removed the synth-factor-from-settings fallback; kept "no factors left ⇒ disable account 2FA". New test `TestTwoFactorFactorHardDelete` (hard-delete, no tombstone, clean re-enroll).
- [x] **A:** Passkey delete: KEEP soft-delete. Rationale — passkeys are an in-flight feature (#45) with `deleted_at` as a deliberate WebAuthn choice, and its unique index already excludes tombstones (`WHERE deleted_at IS NULL`), so no garbage accumulates. Not forcing a change into another issue's active work.
- [x] **B:** Folded into `001`: dropped `two_factor_settings.{method, phone_number, totp_secret, last_totp_step}` + `idx_two_factor_settings_enabled` (kept `enabled`+`backup_codes`).
- [x] **B:** `twofactor.sql`: removed dead `TwoFactorEnable`; slimmed `TwoFactorUpsertSettings`/`TwoFactorSettingsByUser`; deleted settings-level `TwoFactorConsumeTOTPStep` (replay is per-factor).
- [x] **B:** `service.go`: `Get2FASettings` reads only `enabled`+`backup_codes`, derives method/phone from the default factor. Test `TestTwoFactorSettingsDeriveFromDefaultFactor`.
- [x] **C1:** dropped `profiles.uuid_v5()` from `001`; fixed the `migrations_test.go` schema-rewrite assertion (→ `trg_permission_group_containment(`).
- [x] **C2:** dropped `users.discord_username` + `UserDiscordUsername`; `getDiscordUsername` is the provider-profile lookup. (Vestigial nil `DiscordUsername` Go fields kept to preserve `/user/me` + consumer JSON shape.)
- [x] **C3:** dropped `service_tokens_group_role_idx`.
- [x] **D5:** `users.phone_verified` → `NOT NULL DEFAULT false`; dropped `COALESCE(phone_verified, …)` from `users.sql`; fixed `*bool`→`bool` call sites.
- [x] **D6:** `remote_applications.permission_group_id` → `ON DELETE CASCADE` (uniform with service_tokens). user-FK split (created_by SET NULL / invited_by RESTRICT) retained deliberately; documented in `001`.
- [x] **D7:** `AdminDeleteUser` clears `group_role_assignments` (orphans) + `group_invites` sent by the user (invited_by RESTRICT would block). Queries `GroupAssignmentsDeleteByUser`/`GroupInvitesDeleteByInviter`; test `TestAdminDeleteUserClearsGroupData`.
- [x] **D8:** DONE (Paul: orgs are gone, do it). `authbase.RemoteApplication.OrgID` → `PermissionGroupID`; `ResolvedAPIKey.OrgID`+`OrgSlug` (both carried the group id) collapsed to one `PermissionGroupID`; sqlc alias `AS org_id` → `permission_group_id`; all authcore/http usages updated; dead wire codes `invalid_org_slug` + `invalid_org_owner` removed. Pure Go-API change (no JSON tags → no wire/frontend impact). LEFT as a deliberate follow-up (separate concept): `verify.IssuerOptions.OrgSlug` + the token `Org` claim map an issuer→principal identity from `ra.Slug`, not the permission_group_id — renaming changes the verified-token claims contract.
- [x] **D9:** recreated the drifted devserver DB on the clean baseline (done 2026-06-23).
- [x] Regenerated sqlc (`task sqlc` generate+vet green vs the from-`001` schema); `task test` GREEN (full suite) prior to the concurrent `core`→`authcore` move. Version bump + consumer notes: PENDING (factor delete + struct-shape changes are a behavior change).

---

# #126: Shrink the v1.0 public API — drop the dead facet layer, internalize plumbing, rebuild small facets

**Completed:** no

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

**Phase 2 — internalize the plumbing (do when tree is settled):**
- [ ] Create `internal/authcore`; move the `Service` struct + all ~230 methods
  (public and private) + the data types there.
- [ ] `core` becomes a thin public package: Config/sub-configs, type aliases to the
  internal types, the curated ~40-method facade `Service` wrapping
  `*authcore.Service`, the `New*` constructors, and `Mint*`/validation re-exports.
- [ ] Curate the public method list (the ~40 an embedder needs) and KEEP NOTHING
  ELSE public on `core.Service`.
- [ ] Point `authhttp` at `internal/authcore` for the full method set; make
  `svc.Core()` return only the small facade.
- [ ] Update devserver, `riverjobs`, and tests to the new structure.
- [ ] `go build ./... && go vet ./... && go test ./...` green.

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

# #127: Rename 2FA storage to MFA and enforce MFA-required roles at assignment time

**Completed:** no

Paul decision: use the table names `mfa_settings` and `mfa_factors`.

Goal: make the storage model say what it means and move "MFA required for this
role" out of a separate after-the-fact login policy. A user should not be able
to join a role that requires MFA unless MFA is already enabled, and if the user
turns MFA off later AuthKit removes the role assignments that require MFA.

## Current state

This lifecycle does NOT exist yet.

Current AuthKit has a separate `Config.TwoFactor.Mandatory []Mandatory2FAPolicy`
system. It scans the user's live permission-group memberships during login/token
refresh and blocks normal session issuance if the user already has a matching
role but has not enrolled 2FA. That is the wrong direction for this model: the
user was allowed to get the role first, then login discovers the problem later.

Current role assignment paths do not reject MFA-required roles up front, because
roles do not yet carry `RequiresMFA`. Current 2FA disable/delete paths delete the
user's 2FA state, but do not remove role assignments that should no longer be
allowed without MFA.

## Target model

Tables:
- `profiles.mfa_settings`: one row per user. Owns account-level MFA settings:
  `user_id`, `enabled` (MFA required during login), `backup_codes`, timestamps.
- `profiles.mfa_factors`: one row per enrolled factor. Owns factor state:
  `id`, `user_id`, `method` (`email`, `sms`, `totp`), `phone_number`,
  `totp_secret`, `last_totp_step`, `is_default`, timestamps.

Rules:
- `mfa_settings.enabled = true` means login must require MFA.
- Existing rows in `mfa_factors` are the usable enrolled factors. Do not keep a
  second per-factor enabled flag.
- A user satisfies "MFA enabled" only when `mfa_settings.enabled = true` AND at
  least one `mfa_factors` row exists.
- `backup_codes` stay account-scoped in `mfa_settings`; they are not factors.

Role policy:
- Prefer `RoleDef.RequiresMFA bool` on the role definition itself.
- Remove/retire the separate `Config.TwoFactor.Mandatory []Mandatory2FAPolicy`
  runtime policy. The requirement belongs to the role, not an independent login
  rule that discovers membership after the assignment already happened.
- Every AuthKit MFA method counts equally: email, SMS, TOTP. Do not introduce
  assurance levels by method.

## Behavior

Assigning a role:
- When assigning a role with `RequiresMFA`, AuthKit checks the target user before
  inserting the `group_role_assignments` row.
- If the target user does not have `mfa_settings.enabled = true` plus at least
  one factor, reject the assignment with an MFA enrollment-required error.
- This applies to all assignment paths: permission-group member routes, root/admin
  bootstrap/admin assignment helpers, invites if accepting the invite grants a
  `RequiresMFA` role, and remote app/user role assignment helpers where relevant.

Disabling MFA:
- Disabling account MFA is allowed, but it removes every active user role
  assignment whose role has `RequiresMFA`.
- Do this in one transaction: delete/remove the role assignments, then set
  `mfa_settings.enabled = false` and delete factors as requested by the user.
- Return enough response metadata for the frontend/admin UI to know which roles
  were removed.
- Do not remove remote-application assignments when a human user disables MFA.

Login/refresh:
- Login requires MFA only from `mfa_settings.enabled`, not from scanning group
  memberships on every login.
- Because assignment enforces the precondition, a user with an MFA-required role
  should already have account MFA enabled.
- Refresh should still fail closed if the session/user is inconsistent
  (`mfa_settings.enabled = true` but no factor exists).
- Remove the old membership-scan gate from login/refresh after assignment-time
  enforcement exists.

## Non-goals

- Do not rename public HTTP routes in this issue. `/user/2fa`, `/reauth/2fa`,
  and login-time `/2fa/verify` can remain wire-compatible unless a separate route
  naming issue decides to hard-cut them to `/mfa`.
- Do not add MFA strength levels. Email/SMS/TOTP all satisfy MFA.
- Do not treat passkeys as MFA in this issue; passkey policy remains with #45.

## Tasks

- [ ] Schema hard-cut: rename `two_factor_settings` -> `mfa_settings` and
  `two_factor_factors` -> `mfa_factors` in the squashed Postgres baseline
  (`001_auth_schema.up.sql`). If this lands after a release with the old names,
  add a numbered migration instead.
- [ ] Update sqlc query files/generated code from `TwoFactor*` storage names to
  `MFA*` storage names where practical; keep public route names unchanged for now.
- [ ] Add `RequiresMFA bool` to role definitions and config validation.
- [ ] Replace `Mandatory2FAPolicy` login-time membership scanning with
  assignment-time checks against `RoleDef.RequiresMFA`.
- [ ] Remove `UserRequiresMandatory2FA` / `UserSatisfiesMandatory2FA` login-time
  policy checks once the new assignment-time lifecycle is in place.
- [ ] Update group-role assignment paths to reject assigning MFA-required roles
  to users without enabled MFA plus at least one factor.
- [ ] Update invite acceptance to enforce the same check before granting a
  `RequiresMFA` role.
- [ ] Update MFA disable/delete flow to remove MFA-required user role assignments
  in the same transaction, then disable MFA/delete factors.
- [ ] Update `/me` metadata to report MFA status from `mfa_settings` and factors;
  remove mandatory-2FA policy fields or rename them if still needed.
- [ ] Tests: assigning an MFA-required role to a user without MFA fails; assigning
  after MFA enrollment succeeds.
- [ ] Tests: invite acceptance for an MFA-required role fails until MFA is enabled.
- [ ] Tests: disabling MFA removes only the user's MFA-required role assignments
  and leaves ordinary roles intact.
- [ ] Tests: login requires MFA when `mfa_settings.enabled = true`, independent of
  role scans.
- [ ] Docs: update DB/schema docs and config examples to `mfa_settings`,
  `mfa_factors`, and `RoleDef.RequiresMFA`.

---

# #128: Add admin-directory indexes and rename API-key storage tables

**Completed:** yes

STATUS 2026-06-23 (Codex): FINISHED. The compact Postgres baseline now defines
admin-directory btree indexes plus `profiles.api_keys` /
`profiles.api_key_resources`; runtime API-key SQL, cleanup tests, generated
sqlc models, and docs use the API-key table names. Bearer tokens still use the
existing `<prefix>_st_<key_id>_<secret>` format. `task sqlc` passed against a
fresh migrated scratch database. Focused AuthCore/HTTP API-key and admin
directory tests passed against a fresh migrated scratch database. Representative
`EXPLAIN` on 50k seeded users used `users_admin_created_idx`,
`users_admin_email_idx`, `users_admin_last_login_idx`, `users_deleted_at_idx`,
and `users_admin_banned_idx`; username sorting used the existing
`users_username_key` btree. No `pg_trgm` was added because substring search has
not been measured as the bottleneck.

DB-audit follow-up for two low-risk cleanup/perf items:

1. Add btree indexes for the admin user directory paths that already exist.
2. Rename internal API-key storage away from the old `service_tokens` wording.

Keep this boring: no route redesign, no token-format change, no new search
engine unless the existing directory query actually needs substring search at
scale.

## A. Admin user directory indexes

Current `AdminListUsers` filters/sorts by:
- status: `deleted_at`, `banned_at`
- sort: `created_at`, `last_login`, `username`, `email`
- lookup/search: `username`, `email`, `phone_number` with `ILIKE`
- root role filter via `group_role_assignments` + singleton root group

Target:
- Add partial btree indexes for normal list/sort paths over non-deleted users.
- Add a deleted-user purge/list index for `deleted_at IS NOT NULL`.
- Keep the root-role join indexes as-is unless EXPLAIN shows a miss; the current
  `gra_subject_idx` and root-group lookup are already reasonable.
- Do NOT add `pg_trgm` by default. Only add trigram indexes if we decide
  substring `ILIKE '%term%'` search must stay fast on large user directories.

Candidate indexes to validate with EXPLAIN before landing:
- `users_admin_created_idx ON profiles.users (created_at DESC, id) WHERE deleted_at IS NULL`
- `users_admin_last_login_idx ON profiles.users (last_login DESC, id) WHERE deleted_at IS NULL`
- `users_admin_username_idx ON profiles.users (username, id) WHERE deleted_at IS NULL`
- `users_admin_email_idx ON profiles.users (email, id) WHERE deleted_at IS NULL`
- `users_deleted_at_idx ON profiles.users (deleted_at, id) WHERE deleted_at IS NOT NULL`
- Optional if status filter needs it: `users_admin_banned_idx ON profiles.users (banned_at, id) WHERE deleted_at IS NULL AND banned_at IS NOT NULL`

Acceptance:
- Admin list/search/sort integration tests still pass.
- `EXPLAIN` for the common sort paths uses the new indexes on a seeded test table
  large enough for the planner to care.
- No `pg_trgm` extension unless a measured query justifies it.

## B. Rename API-key storage tables

Current public product term is "API key", but storage still says
`service_tokens` / `service_token_resources`. That is survivable, but it keeps
leaking cognitive friction into code and docs.

Target storage names:
- `profiles.api_keys` replaces `profiles.service_tokens`
- `profiles.api_key_resources` replaces `profiles.service_token_resources`

Rules:
- Do not change the bearer token wire format. Keep the existing
  `<prefix>_st_<key_id>_<secret>` format unless a separate issue explicitly
  changes it.
- Do not rename public routes as part of this issue; they already say
  `/api-keys`.
- Do not add compatibility views unless there is a real downstream SQL consumer.
  AuthKit owns these tables.
- Update comments, sqlc queries, generated models, and raw SQL call sites so new
  code does not keep saying service token.

Migration packaging:
- If still pre-release with the compacted baseline only, hard-cut the table names
  directly in `migrations/postgres/001_auth_schema.up.sql`.
- If a release with the current names has already been tagged/adopted, add a
  numbered rename migration instead:
  `ALTER TABLE profiles.service_tokens RENAME TO api_keys`, etc.

## Tasks

- [x] Add and validate admin-directory btree indexes in the Postgres schema.
- [x] Run admin directory integration tests.
- [x] Capture representative `EXPLAIN` output for created_at, username, email,
  last_login, deleted, and banned filters.
- [x] Decide explicitly whether `pg_trgm` is needed; default answer should be no.
- [x] Rename `service_tokens` -> `api_keys` in schema and sqlc queries.
- [x] Rename `service_token_resources` -> `api_key_resources` in schema and sqlc
  queries.
- [x] Regenerate sqlc and update generated model/type names.
- [x] Update raw SQL in API-key service code and tests.
- [x] Update comments/docs that still describe storage as service tokens.
- [x] Assert token parsing/format tests still prove the wire token format did not
  change.
- [x] Run `task sqlc` and focused API-key/admin-directory tests.

---
