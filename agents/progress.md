<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 90

---

# #89: Bootstrap-user password seed-once + reset_required idempotency

**Completed:** yes

DONE (v0.38.0): `BootstrapUserPassword.Enforce` added (default false = seed-once); password applied only when `created || Enforce`; `Enforce`+`ResetRequired` rejected. Unit test for validation + DB-backed seed-once/enforce behavior test (skips without `AUTHKIT_TEST_DATABASE_URL`).

Independent of OpenRails #527 (OpenRails is removing bootstrap user/password seeding entirely), but a real AuthKit bug for any consumer that seeds users through `ReconcileBootstrapManifest`.

Today `applyBootstrapUserPassword` (core/bootstrap_manifest.go) re-asserts the manifest password on EVERY reconcile: `plaintext` mode resets a rotated password back to the manifest value (no-ops only if it already matches), `hash` mode unconditionally overwrites, and `reset_required` re-writes the reset sentinel on every run — so a user who completed a reset is forced back into reset-required on the next server boot/reconcile. The `created` bool is already computed at the call site (line ~155) but ignored for the password decision.

Fix — seed-once by default:
- Apply a manifest password only when the user is newly CREATED, OR an explicit per-password `enforce: true` opt-in is set.
- `reset_required` and `hash` modes obey the same gate (no every-run clobber).
- Reject `enforce: true` combined with `reset_required` (forcing a reset every run is nonsensical).
- Skipped-existing counts as PasswordsKept.

**Tasks:**
- [ ] Add `enforce bool` to `BootstrapUserPassword` (default false = seed-once).
- [ ] Gate password application on `created || password.enforce`.
- [ ] Validate `enforce` XOR `reset_required`.
- [ ] Tests: existing user's rotated password survives reconcile (default); `enforce` re-asserts; `reset_required` is one-shot, not re-fired per boot.

---

# #88: Provisioning + authority primitives for OpenRails' merchant model

**Completed:** no

PARTIAL (v0.38.0): (b) CONFIRMED — `owner` is already assignable to a remote_application member (`validateOrgRole`/`canonicalizeOrgRole` accept it, no reserved-role guard); regression test `TestRemoteApplicationOwnerMembershipGrantsWildcard` added (owner→wildcard `*` via `ResolveRemoteApplicationAuthority`). REMAINING: (a) tx-aware provisioning — DEFERRED; OpenRails #527 uses the compensating-delete fallback for now. (c) claim-stripping / `enabled`-kill-switch regression tests — not yet added. (d) optional one-call helper — not done.

Supports OpenRails #527's unified atomic `ProvisionMerchant` (one merchant ↔ one backing org ↔ one issuer-as-owner) and locks in the security invariants the model depends on.

**(a) Transaction-aware provisioning.** OpenRails must create the AuthKit org + register the issuer as an owner-member in the SAME Postgres transaction as the OpenRails `merchants` row (one rollback unit; self-hosted shares one DB across the `profiles` + `openrails` schemas). Today `ProvisionOrg` / `UpsertRemoteApplication` / `AddRemoteApplicationMember` run on the Service's own pool. Expose tx-aware variants that accept an external querier / `pgx.Tx` (or a `WithTx`-scoped Service) so the caller owns the transaction. Fallback if cross-domain tx proves impractical: document a compensating-delete contract (create org → create merchant → on failure delete org) — but tx-aware is preferred.

**(b) Full-authority role on a remote_application.** DECIDED (OpenRails): the issuer gets the `owner` role — auto-seeded with wildcard `*` → full authority over its merchant. `ProvisionOrg` already calls `AddRemoteApplicationMember(org.Slug, ra.ID, issuer.Role)` and each remote_application has a single `OrgID` (#77). AuthKit must ensure `owner` is assignable to a remote_application member; if any reserved-role guard treats `owner` as human-founder-only, lift it for RA memberships. This is now load-bearing for the OpenRails merchant model.

**(c) Lock in invariants (regression tests, not new behavior).** The redesign DEPENDS on these existing behaviors; add tests so they cannot silently break:
- Federated / remote_application issuer tokens have platform-authority claims (`global_roles` / `org_roles` / `roles`) STRIPPED on verify — only the `isLocal` signer is trusted for them.
- `remote_application.enabled=false` is the trust kill-switch (disabled issuer → tokens rejected).
- Stored-authority resolution (`RemoteApplicationOrgRoles`), never self-claimed.

**(d) Optional convenience.** A single `ProvisionMerchantOrg(org, issuer-as-owner)` helper so OpenRails doesn't hand-compose CreateOrg + UpsertRemoteApplication + AddRemoteApplicationMember.

**Tasks:**
- [ ] Tx-aware provisioning APIs (accept external `pgx.Tx` / DBTX) for org-create + remote_application upsert + membership add; or document the compensating-delete fallback.
- [ ] Ensure the `owner` role is assignable to a remote_application member (`AddRemoteApplicationMember`); lift any reserved-role guard that treats `owner` as human-founder-only.
- [ ] Regression tests: federated authority-claim stripping; `enabled=false` rejection; stored-authority (not self-claimed) resolution.
- [ ] (Optional) one-call org + issuer-as-owner provisioning helper.

Consumer: OpenRails #527 `ProvisionMerchant` + `merchantForIssuer` simplification.

---

# #87: Verify-only AuthKit Service (optional token signer)

**Completed:** yes

DONE (v0.38.0): `Config.VerifyOnly` builds a no-signer Service and skips key discovery; all mint paths return `ErrMissingSigner` (the four Mint* methods already guarded; added the same guard to the access-token path); JWKS serves an empty set; verification + RBAC unaffected. Test `TestVerifyOnlyServiceRejectsMinting` (no DB). Consumed by OpenRails `controlplane.New` (verify-only when no key is discoverable).

Enables OpenRails #527: OpenRails must run as a PURE VERIFIER with no token-signing key when it has no login-capable users (all identity arrives as host-app delegated tokens, or as in-process host-trusted calls in embedded mode). Today `authcore.Config.Keys == nil` triggers auto-discovery (env → /vault/auth → dev-generated), so a Service ALWAYS ends up with a signer.

Requirement — a first-class verify-only construction:
- Explicit "no signer" mode (a `Config` flag, or a `jwt.NoSigner()` sentinel KeySource) that does NOT auto-discover/generate.
- ALL token-minting paths (`IssueAccessToken`, login/session issue, `MintServiceJWT` / `MintCustomJWT`, remote_application self-token mint, password-session issue) return a typed, exported `ErrNoSigner` — never panic, never generate.
- ALL verification + RBAC reads (`VerifyDelegatedAccess`, remote_application resolution, `HasPermission`, org/role lookups) work fully with no signer.
- The JWKS endpoint serves an empty key set (or 410) in verify-only mode.
- `WithPostgres` and existing construction are otherwise unaffected.

**Tasks:**
- [ ] Add explicit verify-only / no-signer construction; nil Keys no longer silently auto-discovers when verify-only is requested.
- [ ] Mint paths return exported `ErrNoSigner` in verify-only mode.
- [ ] JWKS endpoint empty / 410 in verify-only mode.
- [ ] Tests: verify-only Service verifies tokens + evaluates permissions; every mint path returns `ErrNoSigner`; JWKS is empty.

Consumer: OpenRails `controlplane.New` makes the signing key optional — key presence is the enablement signal (present ⇒ mint-capable; absent ⇒ verify-only), instead of a hard boot failure.

---

# #86: Rename long-lived service tokens to API keys in public surfaces

**Completed:** yes

AuthKit's long-lived `profiles.service_tokens` are API keys in product terms: opaque bearer credentials stored as a hash, revocable, expirable, scoped to org permissions/resources, and used by machines via `Authorization: Bearer ...`.

Problem: "service token" collides with JWT access tokens and delegated service tokens. Keep the storage/internal implementation name for now; change the public/bootstrap terminology to API keys.

Target public shape:

```yaml
orgs:
  - slug: example
    api_keys:
      - name: operator
        permissions:
          - openrails:admin
        resources:
          - kind: openrails.merchant
            id: example
        expires_at: null
        output:
          file: ./.secrets/openrails/operator.key
```

Rules:
- `api_keys` is the preferred manifest/bootstrap field.
- `service_tokens` may be accepted only as a temporary deprecated alias if needed for existing manifests; do not document it.
- API keys are org-owned, not user-owned. `created_by` is audit only.
- `permissions` and `resources` keep the existing meaning.
- `output` writes the plaintext once; existing non-empty output means keep, do not mint.
- Current presented keys still use the existing `<prefix>_st_<key_id>_<secret>` mechanics.
- `prefix` is configured once by the issuing app/deployment through `APIKeyPrefix`, e.g. OpenRails can use `or`, Tensorhub can use `th`, Doujins can use `dj`.
- Prefix has no authorization meaning; DB metadata owns org, permissions, resources, expiry, and revocation.
- Prefix validation stays boring: lowercase letters/numbers, short, no underscores, no tenant/user data, no secrets.
- Do not rename DB tables/functions in this issue unless it is mechanically free.

**Tasks:**
- [x] Add `api_keys` to `OrgManifestOrg`, mapped to the existing service-token provisioning implementation.
- [x] Reject manifests that specify both `api_keys` and `service_tokens` for the same org.
- [x] Add `APIKeyPrefix` / `APIKeyMaxTTL`; keep existing `ServiceTokenPrefix` / `ServiceTokenMaxTTL` as deprecated aliases.
- [x] Expose/document the API-key prefix as the self-describing app/deployment prefix (`or`, `th`, `dj`).
- [x] Add `/orgs/{org}/api-keys` route aliases while keeping `/service-tokens` during the terminology cut.
- [x] Rename public docs/comments/API text to API keys for the long-lived opaque credential.
- [x] Tests: `api_keys` mints/keeps like current `service_tokens`; mixed `api_keys` + `service_tokens` fails explicitly; `/api-keys` route is gated like the legacy route.

Follow-up if we want the simplified public key string:
- Mint new API keys as `<prefix>_<base64url_secret>`.
- Resolve by digest/hash of the presented key or normalized secret, not by a public key id.
- Keep accepting existing `<prefix>_st_<key_id>_<secret>` keys for deployed credentials during migration.

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** no

Add passkeys (WebAuthn/FIDO2) as a first-class authentication method in authkit, alongside password, OIDC, and SIWS. Passkeys are phishing-resistant, usernameless-capable credentials bound to the relying party (RP) domain. A user can register one or more passkeys and authenticate with them; a successful login mints the SAME access/refresh session as the password path (and honors the optional `org` body param).

LIBRARY: github.com/go-webauthn/webauthn for ceremony options + attestation/assertion verification. authkit owns storage, ephemeral challenge handling, session minting, routing, policy.

RP CONFIG (host-provided, on core.Config): RPID (registrable domain), RPDisplayName, allowed Origins. Derive defaults from BaseURL/Issuer; validate RPID is a registrable suffix of each origin.

CEREMONIES (begin -> finish; challenge state in the EphemeralStore, same pattern as SIWS challenges + reset tokens, short-TTL single-use): REGISTRATION (AUTH'd user) begin->CreationOptions (challenge, RP, per-user handle, excludeCredentials, residentKey=preferred) + finish (verify attestation, store credential). AUTHENTICATION (login) begin->RequestOptions supporting BOTH discoverable/usernameless AND username-scoped (prefer discoverable) + finish (verify assertion, sign-count clone detection, update sign_count/last_used, mint session).

STORAGE: new profiles.user_passkeys (id uuidv7, user_id fk, credential_id bytea UNIQUE, public_key bytea, sign_count bigint, aaguid bytea, transports text[], attestation_fmt text, label, created_at, last_used_at, deleted_at). A per-user random user_handle (NOT the user id) maps handle->user for usernameless login.

SECURITY: RPID/origin phishing-resistance (library-enforced); sign-count regression -> reject (clone); single-use short-TTL challenges; anti-enumeration on username-scoped login begin; rate-limit begin+finish; live-user ban/deleted gate on login.

MIGRATION PACKAGING (do it right): add profiles.user_passkeys as a NEW NUMBERED migration (002_user_passkeys.up.sql), NOT appended to the consolidated 001 file — migratekit is name-tracked and won't re-apply 001 to DBs that already recorded it, so tables added to 001 never reach existing deployments (the service_tokens gotcha). A new numbered file IS applied to existing DBs.

ROUTES (new RouteGroup RoutePasskeys): POST /passkeys/register/begin (AUTH), POST /passkeys/register/finish (AUTH), POST /passkeys/login/begin (PUBLIC), POST /passkeys/login/finish (PUBLIC), GET /passkeys (AUTH; metadata only), DELETE /passkeys/{id} (AUTH), PATCH /passkeys/{id} rename (AUTH, optional).

NON-GOALS: enterprise/attestation-conveyance policy (accept 'none'); MDS metadata validation; account recovery when all passkeys are lost (rely on existing password/email recovery).

**Tasks:**
- [ ] Add go-webauthn dep; WebAuthn RP config on core.Config (RPID, RPDisplayName, Origins) + BaseURL-derived defaults + validation (RPID a registrable suffix of each origin).
- [ ] NEW numbered migration 002_user_passkeys.up.sql: profiles.user_passkeys + indexes (unique credential_id, index user_id). Do NOT append to 001.
- [ ] Storage: CRUD for user_passkeys (create/list-by-user/get-by-credential-id/update-sign-count+last-used/soft-delete) + per-user user_handle generation & handle->user lookup.
- [ ] Registration ceremony: begin (CreationOptions, excludeCredentials, ephemeral single-use challenge) + finish (verify attestation, persist). AUTH-gated.
- [ ] Authentication ceremony: begin (discoverable + username-scoped, anti-enumeration) + finish (verify assertion, sign-count clone-check, update sign_count/last_used, mint access+refresh honoring `org`, live-user gate).
- [ ] Management routes: GET /passkeys (metadata only), DELETE /passkeys/{id}, optional PATCH rename.
- [ ] RouteGroup RoutePasskeys + registration; challenge state via EphemeralStore (single-use, short TTL) like SIWS.
- [ ] Rate-limit buckets for register/login begin+finish; anti-enumeration on username-scoped login begin.
- [ ] Tests: full register + login ceremonies via a software-authenticator fixture; sign-count regression rejection; usernameless login; list/delete; anti-enumeration; rate limits.
- [ ] Docs: api-endpoints.md + README passkey section (RP config, ceremony flow, frontend navigator.credentials notes, security model, recovery out-of-scope).
- [ ] Version bump + publish; consumer notes (host mounts RoutePasskeys + sets RP config; frontend integrates the WebAuthn JS ceremonies).

---

# #85: Remote-application allowed origins for delegated browser requests

**Completed:** yes

Add browser origin policy to `remote_application`, keyed to the same issuer trust record used for delegated JWT verification. AuthKit should own both the policy and the middleware/helpers that enforce it; OpenRails and host apps should mount AuthKit-provided plumbing rather than re-implement issuer/CORS logic.

Problem found during the OpenRails config audit: OpenRails has a `merchant_cors` shape that looks per-merchant, but its current behavior is only a flattened global CORS allow-list. That does not enforce "a Doujins delegated-user request for Doujins may only come from doujins.com"; it only says "this browser origin may call this OpenRails instance." In public merchant registration, where Doujins and Evil can both register valid issuers and allowed origins, preflight CORS adds no tenant-isolation value because the preflight has no JWT issuer. Auth still protects data; CORS is compatibility/browser hardening, not authorization.

CURRENT OPENRAILS WIRING:
- `config.MerchantCORS` is only consumed by `Config.AllowedCORSOrigins()`, which unions `cors_origins` + all merchant origins.
- Standalone (`newPublicEngine`), embedded net/http (`embedhttp.Assembler`), and embedded gin self-service all pass that union into generic CORS middleware before auth.
- The delegated browser surfaces (`/v1/self/*` and `/v1/merchant-admin/*`) already resolve `ResolvedDelegated.Issuer` and pin the merchant from that validated issuer, but they do not check `Origin` against the issuer.
- Webhooks and service-token/server-to-server routes should not use this browser-origin policy.

The right source of truth is AuthKit's `remote_application`: it already binds `issuer -> JWKS/static keys -> audiences -> enabled -> org owner`. For browser-delegated traffic, the issuer that signed the delegated JWT should also define the exact browser origins allowed to present that issuer's tokens. Example: issuer `https://auth.doujins.com` may allow `https://doujins.com` and `https://www.doujins.com`; issuer `https://auth.hentai0.com` may allow only Hentai0 origins.

SECURITY MODEL:
- CORS preflight is browser compatibility and carries no JWT, so it can only be checked against the union of enabled remote_application origins. In an anyone-can-register merchant system, that union is not a meaningful security boundary.
- The actual protected request must verify the JWT, resolve its `iss` to a remote_application, then reject mismatched `Origin`. This is best-effort browser hardening, not authentication: non-browser clients can spoof `Origin`.
- AuthKit should provide the CORS/preflight middleware and the delegated-request origin gate. OpenRails should only call/mount those AuthKit pieces.
- No `Origin` means non-browser/server-to-server and should not be blocked by this check unless a caller opts into browser-only mode.
- Allowed origins are exact scheme+host+optional-port matches. No wildcards, no suffix matching.
- This is for browser-delegated user requests, not webhooks.
- AuthKit should enforce `request Origin in allowed_origins for verified token issuer` after JWT verification resolves the remote_application.
- `merchant_cors` should be deleted from OpenRails config once AuthKit exposes this policy. Do not replace it with an OpenRails-specific delegated-auth config.

**Tasks:**
- [x] Add `allowed_origins text[] NOT NULL DEFAULT '{}'` to `profiles.remote_applications` in a new numbered migration; do not patch the already-applied baseline only.
- [x] Add `AllowedOrigins []string` to `core.RemoteApplication`, upsert/list/get SQL, bootstrap config, and remote-application HTTP request/response bodies.
- [x] Validate origins in AuthKit: trim, dedupe, require `http` or `https`, require host, reject path/query/fragment, exact strings only. In production guidance, prefer `https`; keep `http://localhost:*` usable for dev.
- [x] Preserve the issuer trust invariant: origin policy is metadata on the same registered issuer; do not create a separate merchant CORS map.
- [x] Expose allowed origins through `RemoteApplicationSource` / verifier-loaded issuer metadata.
- [x] Add AuthKit-owned middleware/helpers:
      optional preflight CORS middleware using the union of enabled `remote_application.allowed_origins` for browser compatibility, and delegated-request middleware that verifies JWT then enforces `Origin` against the verified issuer.
- [x] Add a tiny helper such as `OriginAllowedForIssuer(ctx, issuer, origin)` or equivalent lookup; it should return false for unknown/disabled issuers and true for empty origin only when the caller opts into non-browser allowance.
- [x] Open OpenRails follow-up issue #519: remove `merchant_cors` and use AuthKit-provided CORS/delegated middleware or `DelegatedAuthenticator` integration. OpenRails should not own delegated issuer-origin policy.
- [x] Tests: register remote_application with origins, reject malformed origins, AuthKit CORS preflight allows only the enabled-origin union, disabled/unknown issuer fails closed, and delegated middleware rejects `issuer A + origin B`.
