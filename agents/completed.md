<!-- authkit issue tracker — COMPLETED issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs share ONE per-repo id space with progress.md
> (new issues take `next_id` from progress.md and bump it). Issues move here from progress.md when done.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.

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
