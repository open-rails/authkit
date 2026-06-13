<!-- authkit issue tracker — FUTURE / someday issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs share ONE per-repo id space with progress.md
> (new issues take `next_id` from progress.md and bump it). Issues here are parked, not scheduled.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.

---

# #10: Magic links for verification + password reset (standard policy; excludes magic-login)

**Completed:** yes

Implemented standard policy (not configurable in AuthKit):
- Email:
  - verification: code + link (apps can embed the code in a URL)
  - password reset: link-only (high-entropy token; no reset codes)
- SMS:
  - verification: code and/or link sent through the host-provided SMS sender
  - password reset: link-only through the host-provided SMS sender

AuthKit notes:
- AuthKit does not know site base URLs or frontend routes. Host apps construct user-facing links in their templates.
- Password reset tokens are high entropy, single-use, short TTL, stored server-side as hashes (ephemeral store).
- Added confirm-link endpoints that accept a `token` field, plus backward-compatible behavior where legacy `code` fields carry the token.
- The optional Twilio SMS provider uses Twilio Messaging API, not Twilio Verify.

Out of scope: magic-link login (passwordless login links). Track separately.

**Tasks:**
- [x] Switch password reset to link-only tokens (randB64(32) + hashed storage; no 6-digit reset codes)
- [x] Add `core.EmailSenderWithPasswordResetLink` and require it for email password reset delivery
- [x] Add `core.SMSSenderWithPasswordResetLink` and use it for SMS password reset delivery (Twilio Messaging/SMS API)
- [x] Keep verification codes for email/SMS verification; apps can include a URL that embeds the verification token
- [x] Update existing reset confirm handlers to treat the value as a case-sensitive token (no uppercasing; no 6-char assumptions)
- [x] Add POST `/email/password/reset/confirm-link` (expects `token`) and POST `/email/verify/confirm-link` (expects `token`)
- [x] Update `agents/api-endpoints.md` to document confirm-link endpoints and token-based reset confirm
- [x] Run `go test ./...`

---

# #43: Service Tokens (service tokens) — long-lived, revocable, scoped machine credentials

**Completed:** yes

Add Service Tokens (service tokens): long-lived, revocable bearer credentials OWNED BY AN ORGANIZATION (not a person), for machine/automation callers (CI, the e2e operator CLI, service-to-service). Minted by an tenant admin. An service token acts AS THE TENANT, carrying a limited subset of the tenant's roles and an optional expiry. Presented as `Authorization: Bearer st_...`.

Motivation: today every automated caller (e.g. the e2e CLI: deploy-endpoint, endpoint-build status/logs polling, tag-endpoint-release, run-inference, cleanup-workers) authenticates by replaying username/password against POST /api/v1/password/login on every invocation. This (a) trips the interactive password-login rate limiter (20/3600s) that exists to protect HUMANS from credential stuffing, and (b) is the wrong primitive — a robot should not use the human login path. service tokens are the standard machine-auth primitive (cf. Docker Hub Service Tokens, Stripe sk_ keys).

Design decisions:
- IDENTITY: an service token is a SERVICE PRINCIPAL. It populates Claims.Tenant + Claims.TenantRoles and leaves Claims.UserID empty, mirroring the existing delegated-principal pattern (IsDelegated()). Add a marker (e.g. Claims.TokenType="service token" / IsService()) so the live-user ban/enrichment gate in middleware.Required is skipped (there is no user). created_by is recorded for AUDIT only; the token does not act as that user and keeps working after they leave.
- SCOPING (v1 = reuse RBAC roles): the service token carries a subset of the tenant's role slugs in `scopes`. Downstream services (tensorhub, cozy.art) ALREADY authorize off Claims.TenantRoles, so there is ZERO downstream authz change — the service token path just sets Tenant + TenantRoles from the stored scopes. A dedicated fine-grained scope vocabulary (e.g. `endpoints:deploy`, `releases:promote`) is explicitly OUT OF SCOPE for v1; can layer on later.
- NO PRIVILEGE ESCALATION (hard requirement): a user MUST NOT be able to mint an service token carrying more privilege than they themselves hold. Enforced server-side at mint time, never trusting the client:
  1. The caller must be a member of {tenant} with a role permitted to manage service tokens (owner/admin) — checked before anything else; otherwise 403.
  2. Compute the caller's EFFECTIVE tenant roles for {tenant} server-side (their tenant_memberships roles, plus implied roles from global/platform admin if applicable). Do NOT read privileges from the request.
  3. Every requested scope MUST be (a) a role slug that actually exists in {tenant}, AND (b) a member of the caller's effective tenant-role set. If ANY requested scope fails, reject the ENTIRE request with 403 `scope_exceeds_grantor` and name the offending scope(s) — never silently drop them.
  4. The minted service token's scopes are therefore always a SUBSET of the grantor's effective roles at mint time. (Snapshot semantics: scopes are frozen at creation; if the grantor's roles are later reduced, the service token keeps its granted scopes — revoke it explicitly. This matches GitHub/Stripe behavior and is acceptable for v1; a runtime re-intersection against current tenant roles is a possible future hardening, noted but out of scope.)
  5. An service token can NEVER be used to mint another service token (no token-minting scope), preventing transitive escalation.
- LIFETIME: optional `expires_at` set at creation (null = no expiry, allowed for service tokens). Host-configurable max TTL. Revocable at any time (sets revoked_at). Expiry + revocation checked on every request.
- TOKEN FORMAT: `<vendor>st_<key_id>_<secret>` where `<vendor>` is a HOST-CONFIGURABLE prefix (see below), key_id is a short NON-secret public id (indexed for O(1) lookup, avoids full-table scan + timing leaks) and secret is high-entropy (32 bytes, base62). Store ONLY sha256(secret) (high-entropy random → fast hash is correct; bcrypt unnecessary and would break O(1) lookup). Full token shown ONCE at creation, never again. The prefix lets leak-scanners and logs identify the credential type/issuer at a glance (cf. Docker `dckr_st_...`, GitHub `ghp_`/`gho_`, Stripe `sk_`).
- CONFIGURABLE APPLICATION PREFIX: the prefix identifies the ISSUING APPLICATION / host service (the one embedding authkit), NOT the tenant/tenant. It is a SINGLE value per deployment, set once via authkit configuration, and is a free BRAND choice by the host app (it need not equal the service name). For this platform, tensorhub sets `ServiceTokenPrefix: "cozy"` -> ALL its service tokens are `cozy_st_...` (the cozy.art product brand), even though the service is named tensorhub. The tenant that owns a given token is identified by its stored tenant_id + scopes, NEVER by the prefix — every tenant's tokens issued by tensorhub share the same `cozy_st_` prefix. Two-part structure: the APP segment is host-configured and brandable; the `_st_` TYPE segment is FIXED and non-configurable so middleware detection stays uniform. Default to bare `st_` when the host sets no prefix. Rationale: authkit is embedded in multiple distinct applications (tensorhub, cozy.art, openrails, doujins, hentai0); each gets its OWN app prefix so a leaked token immediately reveals which application minted it, and a unique app prefix is what enables GitHub secret-scanning / push-protection partner registration (a generic shared `st_` cannot be registered cleanly). IMPORTANT for the implementer: middleware service token detection must match on the host's CONFIGURED `<app>st_` prefix (read from authkit config), NOT a hardcoded `st_` start, since the app segment precedes the type tag. Parsing splits on `_` to recover key_id + secret after the configured prefix.
- RESOLUTION: handle service tokens in the Required/Optional MIDDLEWARE (a shared helper), NOT inside Verifier.Verify (which stays pure-JWT/stateless). If the bearer token has the `st_` prefix: parse key_id -> indexed DB lookup -> constant-time compare sha256(secret) -> reject if revoked/expired/tenant-deleted -> build Claims{Tenant, TenantRoles:scopes, service marker} -> best-effort async last_used_at update. Otherwise fall through to existing JWT verify. service tokens bypass the password-login limiter BY DESIGN (different code path).

Storage: new postgres migration, table `profiles.service_tokens` (id uuidv7 pk, tenant_id fk, key_id text unique, secret_hash bytea, name text, scopes text[], created_by uuid, created_at, last_used_at, expires_at nullable, revoked_at nullable; index on tenant_id, unique on key_id).

Endpoints (tenant-admin gated — caller must be an tenant member with owner/admin role; reuse existing tenant authz helpers):
- POST   /api/v1/tenants/{tenant}/access-tokens  {name, scopes[], expires_at?} -> 201 {id, name, scopes, expires_at, token:"st_..."}  (secret shown ONCE)
- GET    /api/v1/tenants/{tenant}/access-tokens  -> list metadata (id, name, scopes, key_id prefix, created_by, created_at, last_used_at, expires_at) — NEVER the secret
- DELETE /api/v1/tenants/{tenant}/access-tokens/{id} -> revoke (set revoked_at)

Consumer follow-ups (separate, NOT part of this authkit issue): tensorhub just bumps the authkit version (middleware handles service tokens transparently, no code change); the e2e CLI reads a TENSORHUB_service token env var and, when set, sends `Authorization: Bearer <service token>` directly, skipping password/login + token/tenant entirely.

Non-goals: PATs (personal/user-owned tokens) — explicitly deferred; everything automated here is an tenant operator action. Fine-grained non-role scope vocabulary. Token rotation endpoint (can add later).

**Tasks:**
- [x] Migration: profiles.service_tokens table + indexes (unique key_id, index tenant_id)
- [x] Add host-configurable `ServiceTokenPrefix` to authkit config — a free BRAND choice set by the issuing application (tensorhub sets it to `cozy` -> `cozy_st_...`), one value per deployment, NOT per-tenant. Default empty -> bare `st_`. Validate (lowercase alnum, short). Fixed `_st_` type segment is NOT configurable
- [x] Token format helpers: generate/parse/format <app>st_<key_id>_<secret> using the configured app prefix; sha256 hashing of secret
- [x] core: MintServiceToken (gen key_id+secret, hash, optional expiry w/ host max-TTL cap, insert), ListServiceTokens, RevokeServiceToken, ResolveServiceToken(token) -> (tenant, scopes, ok)
- [x] NO-ESCALATION ENFORCEMENT (mint time, server-side): (1) caller must be owner member of {tenant} (or platform global admin) else 403; (2) compute caller's effective tenant roles server-side, never from request; (3) every requested scope must exist in {tenant} AND be in the caller's effective roles, else reject WHOLE request 403 `scope_exceeds_grantor` naming the offending scope; (4) minted scopes ⊆ grantor effective roles (snapshot); (5) no scope grants service token-minting (an service token has no UserID so it can never reach the mint handler)
- [x] Claims: add service-principal marker (TokenType/IsService) so middleware skips the live-user ban+enrichment gate; populate Tenant + TenantRoles from service token scopes
- [x] Middleware: service token branch in Required/Optional (shared resolveServiceToken helper) before JWT verify — detect via the host's CONFIGURED `<app>st_` prefix (not hardcoded), indexed lookup by key_id, constant-time secret compare, revoked/expired/tenant-deleted checks, best-effort async last_used_at; fall through to JWT otherwise
- [x] Routes: POST/GET/DELETE /tenants/{tenant}/access-tokens, tenant-owner gated (reuses requireOrgOwner)
- [x] Tests: full lifecycle (create -> use -> list -> revoke -> rejected), expiry rejection, prefix detection + JWT fall-through, secret-shown-once, constant-time compare; service token path bypasses the password-login limiter by construction (separate code path, no rateLimited call in Required)
- [x] Tests for NO ESCALATION: non-owner member cannot mint (403); owner cannot grant a scope they lack (403 scope_exceeds_grantor, whole request rejected, offending scope named); owner granting exactly their own roles succeeds; requesting a non-existent tenant role rejected; global admin may grant any defined scope; an service token cannot mint another service token
- [x] Docs: update agents/api-endpoints.md + README with an service token section and security guidance (storage, revocation, leak response)
- [ ] Version bump + publish (git tag — left to maintainer); consumer follow-ups: tensorhub bumps authkit + sets ServiceTokenPrefix="cozy"; e2e CLI reads TENSORHUB_service token env and sends it as Bearer

---

# #49: Magic-link login (passwordless) via email/SMS (separate from verify/reset)

**Completed:** no

Add optional passwordless login using one-time magic links. This is intentionally separate from verification/password reset links.

Goals:
- Allow a user to request a login link to email (and optionally SMS) and authenticate by clicking it.
- Keep existing password + 2FA flows intact; magic login is additive and can be disabled entirely.

Security notes:
- High-entropy, single-use, short TTL tokens stored as hashes.
- Prevent open redirects; fixed redirect or allowlist.
- Rate limit requests and token consumption; do not leak whether a user exists.
- Consider session fixation and device binding (optional).

UX:
- Link lands on host frontend route (e.g. `/auth/magic?token=...`) which calls AuthKit to consume token and then stores session tokens.

Provider notes:
- Email is straightforward.
- SMS magic links require Twilio Messaging/SMS API (not Twilio Verify).

**Tasks:**
- [ ] Add request endpoint(s): POST /auth/magic-link/request (email/phone) with anti-enumeration response
- [ ] Add consume endpoint(s): POST /auth/magic-link/confirm {token} -> mint session (access/refresh) and consume token
- [ ] Add ephemeral store keys + TTL + single-use enforcement
- [ ] Add rate limits for request + confirm
- [ ] Add optional sender interfaces for magic-login links (email + SMS messaging)
- [ ] Add tests (token lifecycle, request anti-enumeration, confirm success/expired)
- [ ] Docs: flows, security guidance, host frontend route expectations

---

# #50: AuthKit as a standalone service (first-class deployment target)

**Completed:** no

Today AuthKit is primarily used as a library embedded in host services (doujins/hentai0/openrails) and via a devserver used for E2E testing.

Define and implement a supported mode where AuthKit runs as its own standalone HTTP service that:
- mints and verifies JWTs for multiple downstream services
- serves JWKS at a stable URL
- provides the full AuthKit API surface under `/auth/*`
- can be deployed independently (Docker/Kubernetes) with clear configuration and operational guidance.

Goals:
- Stable, documented deployment contract (env/config) for AuthKit-as-a-service.
- Downstream services can integrate by trusting issuers (JWKS fetch) + expected audiences.
- Support multi-instance deployments safely (durable store + Redis for ephemeral/rate-limit where required).

Non-goals:
- Forcing downstream services to stop embedding AuthKit (embedding remains valid).
- Becoming a full OAuth authorization server with third-party client registration UX (keep AuthKit's scope).

Key design questions to answer:
- Issuer and audience strategy (single issuer vs per-service issuers; how to partition).
- Key management (rotation, persistence, JWKS caching headers).
- Storage requirements (Postgres always; Redis optional vs required for HA).
- Service-to-service auth and admin API exposure.

**Tasks:**
- [ ] Define the standalone service contract
    - Public base URL + issuer URL (`AUTHKIT_ISSUER`)
    - Audience model (per downstream service vs shared audiences)
    - Required configuration for prod vs dev (DB_URL, Redis, proxy/trust headers, CORS, etc.)
- [ ] Create a production-grade server entrypoint
    - Dedicated `cmd/authkit-server` (or similar)
    - Health endpoints (ready/live)
    - Structured logging + request IDs
    - Graceful shutdown
- [ ] Key management & JWKS
    - Decide persistence strategy for signing keys (Postgres vs filesystem vs KMS)
    - Key rotation policy + backward-compatible JWKS publication
    - Cache headers on `/.well-known/jwks.json`
- [ ] Storage & HA posture
    - Postgres required for durable state
    - Decide when Redis is required (multi-instance) for ephemeral state and rate limiting
    - Document store modes and safe defaults
- [ ] Service-to-service integration guidance
    - Document how downstream services should verify tokens (issuer list, aud, jwks url)
    - Provide example configs for OpenRails/Doujins
    - Add a minimal example client/verifier snippet
- [ ] Docker/Kubernetes packaging
    - A dedicated Dockerfile for the standalone server image
    - Example `docker-compose.yaml` (Postgres + Redis + AuthKit)
    - K8s manifests/Helm hints (optional)
- [ ] Security hardening
    - Ensure no dev-only endpoints ship enabled by default
    - Trusted proxy configuration for IP extraction (X-Forwarded-For/CF-Connecting-IP)
    - Default rate limits on sensitive endpoints
- [ ] Documentation
    - Update README with "Standalone deployment" section
    - Add operational runbook (migrations, backups, key rotation, incident notes)
    - Add an explicit compatibility note for embedded usage

---

# #72: Remote `Signer` backend — private keys stay in HashiCorp Vault Transit; sign over the wire, fetch only public keys for JWKS

**Completed:** no

Builds on #70 (the `jwt.Signer` boundary + config-driven backend selection; the hard invariant that no private key material crosses the authkit→host boundary). This is the payoff that boundary unlocks: a signer backend where the private key is **generated in and never leaves Vault** — not on the app's disk, not in its container, not in its process memory. authkit signs by sending a remote message to Vault; it only ever pulls **public** keys (to publish JWKS). Not scheduled — parked until we want hardware-grade key isolation. The local `KeySource` backend (#70) stays the default for dev and simple deploys.

Concept: implement `VaultTransitSigner` satisfying `jwt.Signer.Sign(ctx, claims)`:
- **Sign**: build the JWT signing input (`base64url(header).base64url(payload)`), POST it to Vault Transit `POST <mount>/sign/<key>` (with the right `signature_algorithm` / `hash_algorithm` / `marshaling_algorithm` for the JOSE alg), receive `vault:v<N>:<b64sig>`, strip the `vault:vN:` prefix, base64url the raw signature, and assemble the compact JWT. The private key is used inside Vault only.
- **JWKS / public keys**: fetch from Vault Transit `GET <mount>/keys/<key>` (returns the public key per version); build the JWKS from all non-retired versions. Map `kid = <key>-v<N>` so it lines up with the `vault:vN` the sign call used; verifiers are unchanged (they still consume JWKS). Cache public keys with a TTL + background refresh.
- **Rotation**: Vault Transit key *versions* map directly onto authkit's active+retiring model — the active signing version is latest (or `min_encryption_version`); older public versions stay in JWKS until their tokens expire. Rotation is a Vault operation, no app redeploy.

Key provenance change vs local mode: the Vault transit key is created **non-exportable** (`exportable=false`) — the opposite of today's e2e `vault-bootstrap`, which creates exportable keys to render PEMs. In remote mode there is no PEM render step and no `keys.json` at all.

Config / selection (init-time, host-uniform, same boundary as #70 — host passes a locator, never key bytes):
- Select via `AUTHKIT_SIGNER=vault-transit` (default `local`), or implicitly when the Vault knobs are set.
- `AUTHKIT_VAULT_ADDR`, `AUTHKIT_VAULT_TRANSIT_MOUNT`, `AUTHKIT_VAULT_KEY_NAME`, plus Vault auth (token or AppRole `role_id`/`secret_id`, renewable lease). Reuse the existing vault client patterns (e.g. tensorhub `internal/vault`).
- Host call sites (`signer.Sign(...)` / Service mint methods) and the verifier path are byte-for-byte identical to local mode — switching is config-only.

Operational properties to design for:
- **Degraded mode**: if Vault is unreachable, *minting* fails (token issuance errors) but *verification* keeps working from cached JWKS/public keys — so validation doesn't go down with Vault. Make this explicit and tested.
- **Latency / hot path**: every mint becomes one Vault round-trip. Fine for low-volume service/delegated JWTs; evaluate for the high-volume user-access-token path (connection pooling, Vault performance-standby/agent, regional Vault). Document the trade-off; don't silently put a network hop on every login.
- **Auth lifecycle**: token/AppRole renewal, lease expiry handling, and fail-closed on auth loss.

Non-goals: removing the local backend (kept as default for dev/simple prod); changing the verifier or JWKS contract; tensorhub's artifact-signing key (separate trust domain — though it could adopt the same remote pattern in its own follow-up). Composes with #50 (standalone authkit service) but is independent of it.

**Tasks:**
- [ ] `VaultTransitSigner` implementing `jwt.Signer`: sign via Transit `sign/<key>`; JOSE alg ↔ Vault `signature_algorithm`/`hash_algorithm`/`marshaling`; strip `vault:vN:` + base64url; assemble compact JWT.
- [ ] Public-key/JWKS source from Transit `keys/<key>` (all live versions); `kid = <key>-v<N>`; TTL cache + refresh; verifier path unchanged.
- [ ] Rotation mapping: Transit versions → active + retiring keys in JWKS; honor `min_encryption_version`.
- [ ] Init selection + config (`AUTHKIT_SIGNER`, `AUTHKIT_VAULT_*`, token/AppRole auth) behind the #70 `Signer` seam; host code + verifier identical to local mode.
- [ ] Non-exportable transit key provisioning path (and update e2e/render tooling so remote mode skips PEM render / `keys.json`).
- [ ] Degraded-mode behavior: mint fails closed when Vault is down; verify continues from cached JWKS — with tests.
- [ ] Latency/auth-lifecycle hardening: connection reuse, lease renewal, fail-closed on auth loss; document the per-mint round-trip trade-off.
- [ ] Docs: "Remote signing (Vault Transit)" — security model (key never leaves Vault), config, rotation, degraded mode, perf; cross-link #70.
- [ ] Tests: sign→verify round-trip against a dev Vault Transit; rotation adds a new JWKS entry; alg/marshaling correctness; Vault-down degraded path.
