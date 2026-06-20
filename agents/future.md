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
