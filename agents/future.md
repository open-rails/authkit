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

# #43: API keys - long-lived, revocable, scoped machine credentials

**Completed:** yes

Superseded by #86. Product/API terminology is **API key**: an org-owned opaque shared secret with assigned permissions and optional resource scopes. It is not a user access token, refresh token, delegated access token, service JWT, or remote application/issuer.

Storage still uses `profiles.service_tokens` and generated sqlc names until a separate storage migration is worth the churn.

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

---

# #101: TOTP (authenticator-app) 2FA method — offline second factor alongside email/SMS

**Completed:** no

Add **TOTP** (RFC 6238 — Google Authenticator / Authy / 1Password / Microsoft Authenticator) as a third 2FA `method`, alongside the existing `email` and `sms` code delivery. Today `profiles.two_factor_settings.method IN ('email','sms')` and every second factor is a server-sent 6-digit code (`Require2FAForLogin` → email/SMS). Both require deliverability and are the weaker factors: SMS is SIM-swap/intercept-prone and costs per send; email 2FA falls to mailbox compromise. TOTP is the industry-standard **offline** second factor — the authenticator app and server independently derive the same `HMAC(secret, time_step)` code, so there's no message to deliver, intercept, or pay for, and it's phishing/SIM-swap resistant relative to SMS. Both peer libraries ship it (authboss `totp2fa`, go-auth TOTP); authkit is the gap. It matters more here because authkit's 2FA is explicitly aimed at **admin accounts** (`COMMENT ON TABLE … 'admin accounts'`), exactly where offline, delivery-independent MFA belongs.

This reuses the existing single-method-per-user model, backup codes (10× 8-char, already hashed + single-use), the `Create/Verify/Clear2FAChallenge` gate, and the generic `POST /2fa/verify` endpoint (`handleUser2FAVerifyPOST` is already method-agnostic — it just calls `Verify2FACode`). A user picks **email OR sms OR totp**; multi-method / TOTP-with-SMS-fallback stays out of scope (separate future expansion).

## What's genuinely different from email/sms (the design work)

1. **No send step.** `Require2FAForLogin` must branch on method: for `totp` it skips code generation, the ephemeral store, and email/SMS delivery entirely. The `/password/login` 2FA branch returns `{requires_2fa:true, user_id, method:"totp", challenge}` with nothing sent — the user reads the code from their app. Verify still goes through the existing challenge-gated `/2fa/verify`.

2. **Two-step prove-possession enrollment** (mirrors today's SMS setup, which already verifies a code before enabling):
   - `POST /user/2fa/totp/start` (new, auth-required) → server generates a random **160-bit base32** secret, stores it as **pending/unconfirmed** (NOT enabled), returns `{secret, otpauth_uri}`. AuthKit returns the `otpauth://totp/{issuer}:{account}?secret=…&issuer=…&algorithm=SHA1&digits=6&period=30` provisioning URI — **not** a QR image. Host renders the QR (consistent with authkit's "host owns the frontend" stance; same reason we don't render reset/verify pages).
   - `POST /user/2fa/enable` with `{method:"totp", code:"123456"}` → verify the code against the **pending** secret; on success flip `enabled=true`, persist the secret, and return `backup_codes` (existing `handleUser2FAEnablePOST` response shape, unchanged).

3. **Verify computes instead of compares.** `Verify2FACode` must branch: for `totp`, compute the expected code(s) from the stored secret over the current 30s step **±1 window** (RFC 6238 defaults: SHA1 / 6 digits / 30s) for clock skew, instead of looking up an ephemeral stored hash. `VerifyBackupCode` is unchanged.

4. **Replay protection (new).** A TOTP code is valid for its whole 30s window, so it can be replayed within that window — email/SMS codes don't have this problem (single-use ephemeral hash, deleted on consume). Track the **last consumed time-step per user** and reject reuse: either a `last_totp_step bigint` column or an ephemeral key `2fa:totp:laststep:<user_id>`. Without this, a captured code is replayable for up to ~90s with the ±1 window.

5. **Secret at rest = first persistent 2FA secret.** email/sms 2FA store no long-lived secret; the TOTP shared secret is bearer-equivalent — anyone who reads it can mint codes forever. It must be stored **encrypted**, not plaintext base32. Preferred: a host-provided encryption key (new `core.Config` field, AES-GCM envelope) so a DB read alone doesn't yield live secrets; at minimum, document the trust requirement and gate enrollment on a key being configured. **This is the main new security decision — resolve before merge.**

## Schema & deps

- New migration `migrations/postgres/00N_totp_2fa.up.sql` (do NOT edit `001_auth_schema.up.sql` — migrations are name-tracked in `public.migrations` and never re-applied): add `totp_secret bytea` (the encrypted envelope) nullable, relax the `method` CHECK to `IN ('email','sms','totp')`, optionally add `last_totp_step bigint`. Keep the `phone_required_for_sms` constraint. `method varchar(10)` already fits `'totp'`. Then `make sqlc` to regenerate `internal/db` and update `TwoFactorEnable` / `TwoFactorSettingsByUser`.
- **Dependency choice:** implement RFC 6238 with the stdlib (`crypto/hmac`, `crypto/sha1`, `encoding/base32`, `encoding/binary`) — HOTP+TOTP is ~40 lines and matches authkit's minimal-dependency posture — OR adopt `github.com/pquerna/otp` (well-tested, also builds provisioning URIs). Recommend stdlib to avoid new dependency surface in an auth library; decide during implementation.

## Integration points (real symbols)

- **core**: `TwoFactorSettings` (add `TOTPSecret`), `Enable2FA` (accept `totp`, persist secret from pending), `Get2FASettings`, `Require2FAForLogin` (branch — no-op delivery for totp), `Verify2FACode` (branch — compute vs. compare); new `StartTOTPEnrollment` / `generateTOTPSecret` / `verifyTOTPCode` + secret encrypt/decrypt helpers.
- **http**: new `handleUser2FAStartTOTPPOST`; `handleUser2FAEnablePOST` (accept `method:"totp"` + verify code against pending secret, parallel to the existing SMS branch); `twoFactorStatusResponse` / `handleUser2FAStatusGET` (report `"totp"`); `/password/login` 2FA branch (skip send for totp). `handleUser2FAVerifyPOST` needs no change.
- **routes/buckets**: register `POST /user/2fa/totp/start`; add a `RL2FAStartTOTP` rate-limit bucket (parallel to `RL2FAStartPhone`).
- **docs**: README 2FA section (method list, totp enroll flow, otpauth URI, secret-at-rest note) and `agents/api-endpoints.md`.

## Non-goals

WebAuthn/passkeys (separate future); QR-image generation (return the otpauth URI); multi-method / per-method fallback; encrypted-secret key management beyond one host-provided key.

**Tasks:**
- [ ] Decide secret-at-rest model (host-provided AES-GCM key via `core.Config` vs. documented-plaintext) and the RFC 6238 impl choice (stdlib vs `pquerna/otp`)
- [ ] Migration `00N_totp_2fa.up.sql`: `totp_secret`, `method` CHECK += `'totp'`, optional `last_totp_step`; `make sqlc` + regenerate `internal/db`
- [ ] core: `generateTOTPSecret` (160-bit base32), `otpauth://` URI builder, `verifyTOTPCode` (±1 window), secret encrypt/decrypt
- [ ] core: branch `Require2FAForLogin` (no send for totp) and `Verify2FACode` (compute for totp); extend `Enable2FA` to persist the confirmed secret
- [ ] core: pending-secret storage (ephemeral store, single-use, short TTL) + replay guard (`last_totp_step` / `2fa:totp:laststep:<user>`)
- [ ] http: `handleUser2FAStartTOTPPOST` (returns `{secret, otpauth_uri}`); enable branch for `method:"totp"`; status reports `"totp"`; login branch skips send
- [ ] routes + `RL2FAStartTOTP` bucket
- [ ] Tests: enroll→confirm→login round-trip; wrong/expired code; ±1 window skew; replay rejected within a window; backup-code path still works; secret stored encrypted (not plaintext base32)
- [ ] Docs: README 2FA + `agents/api-endpoints.md`
- [ ] `go test ./...`

---

# #102: Broaden audit taxonomy to org/RBAC/admin/credential security events + optional PII redaction

**Completed:** no

AuthKit already has the audit *mechanism* — a pluggable, best-effort `AuthEventLogger` sink (`core/audit.go`) with a ClickHouse implementation (`migrations/clickhouse/001_auth_analytics.up.sql` → `user_auth_session_events`) and a reader (`AuthEventLogReader.ListSessionEvents`, consumed by `http/admin_signins.go`). But the taxonomy is **session-lifecycle only**: `SessionEventType` is exactly `session_created | session_revoked | password_changed | password_recovery | session_failed`, and `AuthSessionEvent` is session-shaped (`user_id`, `session_id`, `method`, `reason`, `ip`, `ua`).

The irony driving this issue: AuthKit *generates* exactly the events a compliance auditor (SOC2 / GDPR / HIPAA) cares about — and that single-tenant auth libraries can't — precisely because of its multi-tenant authority surface, yet **none of them reach the sink**:

- **API keys** — mint, revoke (org-owned machine credentials gaining/losing authority).
- **Org RBAC** — `DefineRole`, `SetRolePermissions`, role delete, membership add/remove, role (re)assignment.
- **Org lifecycle** — create, rename, provision (`ProvisionOrg` / `ReconcileOrgManifest`), `EnsureOwnerGrants`.
- **2FA** — `Enable2FA`, `Disable2FA`, `RegenerateBackupCodes`.
- **Identity linking** — OAuth/OIDC account link complete, unlink.
- **Admin actions** — admin set-password, ban/unban, soft-delete, `ImportUser`, `CreateUser`.
- **Invites** — create, accept, decline, revoke.

"Who granted `merchant:payments:refund` to which role in which org, and when" is the canonical audit question, and today it's unanswerable from the event stream. Turning the existing-but-narrow sink into a full security-event stream leans into where AuthKit is already ahead of authboss/go-auth (which inspired this — go-auth advertises "comprehensive audit logging with PII redaction" but, being single-tenant, has far less worth auditing).

## The core design call: a new `SecurityEvent`, added *additively* — do NOT widen `AuthSessionEvent`

The new events are **actor → target (+ org)** shaped, not session shaped. A role-permission change has an *actor* (who did it — a user, an admin, an API key, a service principal), a *target* (the role/org/user affected), an *org context* (auditors filter by org), an *action*, and a *detail* (permissions added/removed; old/new role). Forcing that into the session-shaped `AuthSessionEvent` (which has `session_id`/`method`/`reason`) is wrong.

So: keep `AuthEventLogger.LogSessionEvent` / `AuthSessionEvent` **unchanged** (existing ClickHouse sinks must not break — this is a hard back-compat constraint), and add a **separate, optional** `SecurityEventLogger.LogSecurityEvent(ctx, SecurityEvent)`. A sink may implement zero, one, or both interfaces. `SecurityEvent` carries: `OccurredAt`, `Issuer`, `OrgID`, `ActorType`+`ActorID`, `Action` (a new `SecurityEventType`), `TargetType`+`TargetID`, `Detail map[string]any` (or structured JSON), `IPAddr`, `UserAgent`, `RequestID`. This whole change is **purely additive**: new interface, new struct, new optional hook, new ClickHouse table — existing callers/sinks/readers are untouched.

## PII redaction hook (the other half of go-auth's pitch)

Add an optional `Redactor` applied in the emit path **before** the event reaches the sink, to BOTH session and security events. Default is **no-op** (zero overhead, matching the existing best-effort/non-blocking contract and go-auth's "no-op by default"). Ship a built-in `DefaultPIIRedactor` keyed by a host secret: HMAC/truncate `ip_addr` (e.g. zero the last octet or HMAC it), drop or hash `user_agent`, hash any email/phone/username that appears in `Detail`, keep the stable pseudonymous `user_id`/`org_id`. Hosts under GDPR/HIPAA can enable it; hosts that want raw forensics leave it off.

## Best-effort vs. assurance (surface, don't over-build)

Existing session audit is fire-and-forget (`_ = s.authlog.LogSessionEvent(...)`) — an audit-sink outage must never fail an auth mutation, and that invariant stays the default. But compliance auditors dislike silently dropped grant events. Decide whether a small set of high-assurance security events (e.g. permission grants, admin set-password) get an opt-in strict/buffered mode (fail-closed or local spool) — or whether that's explicitly out of scope and documented as a known limitation. Default stays best-effort regardless.

## Emission sites

Emit one `SecurityEvent` at each authority-mutation site, ideally through a single internal helper so the actor/org/request-context extraction isn't duplicated. The authoritative list: role define/replace/delete (`DefineRole`, `SetRolePermissions`), membership add/remove/assign, org create/rename/provision, `Enable2FA`/`Disable2FA`/`RegenerateBackupCodes`, API-key mint/revoke, OAuth link/unlink, admin set-password/ban/unban/soft-delete, `ImportUser`, invite create/accept/decline/revoke. Actor identity comes from the request claims (user / admin / API key / service principal); `ProvisionOrg` and `ReconcileOrgManifest` emit with a deploy/bootstrap actor.

## Reader & optional org-scoped audit API

Extend the reader with `ListSecurityEvents(ctx, filter)` (filter by org, actor, action types, time range). Optionally expose an **org-scoped** audit-read endpoint (`GET /orgs/:org/audit` or `/admin/security-events`) gated by a new reserved `org:audit:read` permission — letting an org owner see their own org's audit trail is itself a compliance feature. Scope-flag this: the event stream + redaction is the core deliverable; the read API can be a follow-up if it bloats the change.

## Non-goals

- **No per-access-token mint telemetry** — the ClickHouse comment already draws this line ("no per-access-token mint telemetry"); user-access-token issuance is high-volume hot-path and stays out. Machine-credential *mint* (API key / service principal provisioning) is in because it's low-volume authority granting.
- Not a SIEM, query UI, or alerting engine — just a structured, pluggable, redactable event stream + reader.
- No change to the existing `AuthEventLogger`/`AuthSessionEvent`/`user_auth_session_events` contract.

**Tasks:**
- [ ] Decide event model (recommended: additive `SecurityEvent` + `SecurityEventLogger.LogSecurityEvent`, leave `AuthEventLogger.LogSessionEvent` unchanged)
- [ ] Define `SecurityEventType` taxonomy (api_key.mint/revoke, role.define/permissions_changed/delete, member.add/remove/role_changed, org.create/rename/provision, twofactor.enable/disable/codes_regenerated, identity.link/unlink, admin.set_password/ban/unban/soft_delete/import_user, invite.create/accept/decline/revoke)
- [ ] `SecurityEvent` struct (occurred_at, issuer, org_id, actor_{type,id}, action, target_{type,id}, detail, ip, ua, request_id) + central emit helper that pulls actor/org/request-context from claims
- [ ] Optional `Redactor` hook applied to BOTH session + security events before the sink; default no-op; ship `DefaultPIIRedactor` (HMAC ip/email/phone, drop ua) keyed by a host secret
- [ ] Wire `WithSecurityLogger` + `WithRedactor` on core + http `Service`; preserve best-effort/non-blocking emit
- [ ] Add emits at every authority-mutation site listed above (one event each, correct actor/target/org)
- [ ] ClickHouse migration `002_*.up.sql`: new `auth_security_events` table (do NOT edit `001_*`; name-tracked, never re-applied); `ORDER BY (issuer, org_id, occurred_at, action)`
- [ ] Decide best-effort vs. opt-in strict/buffered mode for high-assurance events; document the choice
- [ ] Reader `ListSecurityEvents(ctx, filter)` (+ optional org-scoped `GET /orgs/:org/audit` gated by reserved `org:audit:read` — scope-flag)
- [ ] Tests: each emit site fires exactly one event with correct actor/target/org; redactor applied; sink outage never fails the mutation; existing `AuthEventLogger` sink + `ListSessionEvents` unaffected (back-compat)
- [ ] Docs: README "Audit & security events" section + `agents/api-endpoints.md`; state the no-per-token-mint-telemetry non-goal

---

# #103: Emit OIDC `amr`/`acr`/`auth_time` assurance claims — let resource servers gate sensitive ops on fresh + MFA auth ("sudo mode")

**Completed:** no

Pairs with #101 (TOTP) and should land alongside it. Today AuthKit access tokens say *who* the user is (`sub`, `sid`, entitlements) but not *how* or *when* they authenticated. Add the OIDC-standard `amr` (authentication methods, RFC 8176), `acr` (assurance class), and `auth_time` (last authentication unix ts) claims so any resource server holding the token can enforce **step-up / "sudo mode"** — the GitHub pattern: re-prove identity for a sensitive action (delete repo, rotate keys, change billing), then hold elevated privilege for a bounded window. A resource server gates a sensitive endpoint by requiring `amr` contains a strong factor (`otp`) AND `auth_time` is recent. GitHub's window is 2h sliding; the point is it's bounded and the policy lives at the consuming endpoint.

**The window already exists server-side — this projects it into the token.** AuthKit has the sudo-mode machinery internally: `RequireFreshSession(ctx, userID, sessionID, now) (SessionFreshness, error)` returns `ReauthRequiredForSensitiveOps` / `ErrReauthenticationRequired`, and `MarkSessionAuthenticated(...)` is the elevate step (used today by `handleUserPasswordPOST` → password change, and `SetPasswordAfterFreshAuth`). But it's **session-bound and issuer-local**: the freshness lives on the session record and is only legible to the issuing service via a DB lookup. In AuthKit's whole paradigm — bearer tokens verified by *downstream* resource servers (cozy-art → tensorhub, etc.) — those services can't call `RequireFreshSession`; they only hold the JWT. So they currently cannot gate on "was this user MFA-fresh." `amr`/`acr`/`auth_time` is the cross-service projection of the freshness state AuthKit already tracks. (authboss's "half-auth vs full-auth" distinction is the same idea; this is its token-native form.)

Two gaps to close:
1. **Method is not recorded.** `MarkSessionAuthenticated` flips a freshness timestamp but doesn't capture whether the re-auth was a password or a strong factor (email/SMS 2FA, TOTP #101, passkey). GitHub gates some actions on 2FA specifically; AuthKit can't express "MFA-fresh" vs merely "password-fresh" until the method is stored.
2. **Nothing reaches the JWT.** `auth_time`/`amr`/`acr` aren't emitted, so no downstream gate is possible.

## Design

**Record method + assurance at (re)authentication time.** Extend the session freshness record to store the methods used and the authentication timestamp (the freshness ts already written by `MarkSessionAuthenticated` IS `auth_time`). Give `MarkSessionAuthenticated` (and the initial login/2FA paths) an `amr []string` so each auth path declares its factor. Map AuthKit methods → RFC 8176 `amr` values:
- password login → `["pwd"]`
- email/SMS 2FA → `["pwd","otp","mfa"]` (or `sms`)
- TOTP (#101) → `["pwd","otp","mfa"]`
- Solana SIWS → `["swk"]` (software-secured key) — decide exact value
- OIDC login → pass through the upstream IdP's `amr` when present, else `["pwd"]` — decide
- passkey (future) → `["swk"|"hwk","mfa"]`

**Emit the claims.** Add `amr`, `acr`, `auth_time` to the `extra map[string]any` already threaded into `IssueAccessToken` by every login path (`password_login_post.go`, `user_2fa_verify_post.go`, `oidc_browser.go`, `oauth2_browser.go`, `service_solana.go`, `service_sessions.go` refresh). `acr` is an optional assurance class string — either NIST-style `aal1`/`aal2` or an app-defined level; decide whether AuthKit sets it or leaves it host-policy.

**Verify side + gating middleware.** Add `AMR []string`, `ACR string`, `AuthTime time.Time` to `http/claims.go` `Claims` and parse them. Add helpers `Claims.HasAMR(m)`, `Claims.AuthenticatedWithin(d)`, and middleware mirroring the existing `RequireEntitlement` family in `http/middleware.go`:
- `RequireFreshAuth(maxAge)` — `auth_time` within the window (sudo mode for resource servers).
- `RequireMFA()` / `RequireAMR("otp")` — a strong factor was used.
- `RequireACR(level)` — minimum assurance class.

These compose: `RequireMFA()` + `RequireFreshAuth(15*time.Minute)` = "MFA used within 15 min." Like `RequireEntitlement`, they **fail closed** and **deny machine credentials** (service JWT / API key / delegated have no interactive `amr`/`auth_time`).

## Subtleties to get right

- **Snapshot semantics (reuse the entitlements mental model).** `amr`/`acr`/`auth_time` are snapshotted into the access token at issuance, exactly like entitlements. A step-up (`MarkSessionAuthenticated`) only becomes visible to resource servers once the client **re-issues the access token** (refresh via `POST /token`). Document this as the token-model analog of GitHub's cookie sudo timer: after re-auth, refresh, then retry the sensitive call. The README already explains snapshot-vs-live for entitlements — point at it.
- **Single source of truth.** The `auth_time` claim must come from the same session freshness timestamp `MarkSessionAuthenticated` writes — do not invent a parallel clock. `RequireFreshSession` stays the issuer-local gate for AuthKit's own sensitive routes; the claims are its downstream projection. Keep them consistent.
- **Back-compat.** Purely additive. Tokens minted before this carry no `amr`/`auth_time`; routes that don't require them are unaffected; the new middleware denies tokens lacking the claims (fail-closed by design).
- **OIDC pass-through** vs. flattening to `["pwd"]` is a real decision — upstream IdPs may assert their own `amr`/`acr` and a federation may want to honor it.

## Non-goals

- Not a full AAL/IAL identity-proofing framework — just the three standard claims + freshness gating.
- No change to `RequireFreshSession`/`MarkSessionAuthenticated` semantics beyond recording the method (the window logic stays).
- Per-endpoint sudo policy (which actions need step-up, and the window length) is **host/resource-server policy**, expressed by mounting the middleware — AuthKit ships the primitive, not the catalog of sensitive actions.

**Tasks:**
- [ ] Store auth method(s) + timestamp on the session freshness record; extend `MarkSessionAuthenticated` (and initial login/2FA) to accept `amr []string`
- [ ] Decide the AuthKit-method → RFC 8176 `amr` mapping (pwd/otp/mfa/sms/swk; OIDC pass-through y/n) and whether AuthKit sets `acr`
- [ ] Emit `amr`/`acr`/`auth_time` via the `extra` map in every `IssueAccessToken` call site (password, 2FA, oidc, oauth2, solana, refresh)
- [ ] `Claims` gains `AMR`/`ACR`/`AuthTime` + parsing (`http/claims.go`); helpers `HasAMR`, `AuthenticatedWithin`
- [ ] Middleware `RequireFreshAuth(maxAge)`, `RequireMFA()`/`RequireAMR(...)`, `RequireACR(level)` in `http/middleware.go`; fail-closed; deny machine credentials
- [ ] Ensure `auth_time` is sourced from the same freshness ts as `RequireFreshSession` (one clock)
- [ ] Tests: each login path emits the right `amr`; step-up updates `auth_time` only after refresh; `RequireFreshAuth`/`RequireMFA` allow/deny correctly incl. machine creds; back-compat for claimless tokens
- [ ] Docs: README token-claims + a "Step-up / sudo mode" section (snapshot semantics, refresh-after-reauth, compose with #101); `agents/api-endpoints.md`
