<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 100

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

**Completed:** yes

DONE for the #527-blocking scope (v0.38.0):
- (b) `owner` is assignable to a remote_application member (`validateOrgRole`/`canonicalizeOrgRole` accept it; no reserved-role guard). Regression test `TestRemoteApplicationOwnerMembershipGrantsWildcard` (owner→wildcard `*` via `ResolveRemoteApplicationAuthority`).
- (c) invariant lock-in — ALREADY COVERED by the existing suite: claim-stripping (`TestDelegatedAccessRejectsRolesClaim`/`RejectsOrgClaim`/`RejectsOrgIDClaim`), `enabled`=false kill-switch (`http/federation_test.go` disabled-issuer → 403; `LoadRemoteApplications` enabledOnly in `verifier_coherence_test`), stored-authority (delegated tests + the new owner-on-RA test). No new tests needed.

OPTIONAL / not needed (deliberately deferred): (a) tx-aware provisioning — OpenRails #527 uses authkit's idempotent `ProvisionOrg` + merchant upsert (re-apply converges), so a single cross-domain tx is not required; (d) one-call org+issuer helper. Reopen if a future consumer needs strict atomicity.

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

# #86: Rename long-lived machine credentials to API keys in public surfaces

**Completed:** yes

AuthKit's long-lived `profiles.service_tokens` are API keys in product terms: opaque bearer credentials stored as a hash, revocable, expirable, scoped to org permissions/resources, and used by machines via `Authorization: Bearer ...`.

Problem: the previous public name collided with user access tokens, delegated access tokens, service JWTs, and remote applications/issuers. Keep the storage/sqlc implementation name for now; change the public/bootstrap terminology to API keys.

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
- `service_tokens` is rejected as an unknown legacy manifest field; do not accept or document it.
- API keys are org-owned, not user-owned. `created_by` is audit only.
- `permissions` and `resources` keep the existing meaning.
- `output` writes the plaintext once; existing non-empty output means keep, do not mint.
- Current presented keys still use the existing `<prefix>_st_<key_id>_<secret>` mechanics.
- `prefix` is configured once by the issuing app/deployment through `APIKeyPrefix`, e.g. OpenRails can use `or`, Tensorhub can use `th`, Doujins can use `dj`.
- Prefix has no authorization meaning; DB metadata owns org, permissions, resources, expiry, and revocation.
- Prefix validation stays boring: lowercase letters/numbers, short, no underscores, no org/user data, no secrets.
- Do not rename DB tables/sqlc methods in this issue unless it is mechanically free.

**Tasks:**
- [x] Add `api_keys` to `OrgManifestOrg`, mapped to the existing storage implementation.
- [x] Reject legacy `service_tokens` manifest fields.
- [x] Add `APIKeyPrefix` / `APIKeyMaxTTL`; remove the old public config aliases.
- [x] Expose/document the API-key prefix as the self-describing app/deployment prefix (`or`, `th`, `dj`).
- [x] Add `/orgs/{org}/api-keys` routes and remove the old route spelling.
- [x] Rename public docs/comments/API text to API keys for the long-lived opaque credential.
- [x] Tests: `api_keys` mints/keeps through the existing storage path; legacy `service_tokens` fails explicitly; `/api-keys` route is gated by `org:api_keys:manage`.

Follow-up if we want the simplified public key string:
- Mint new API keys as `<prefix>_<base64url_secret>`.
- Resolve by digest/hash of the presented key or normalized secret, not by a public key id.
- Keep accepting existing `<prefix>_st_<key_id>_<secret>` keys for deployed credentials during migration.

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** yes

Add passkeys (WebAuthn/FIDO2) as a first-class authentication method in authkit, alongside password, OIDC, and SIWS. Passkeys are phishing-resistant, usernameless-capable credentials bound to the relying party (RP) domain. A user can register one or more passkeys and authenticate with them; a successful login mints the SAME access/refresh session as the password path (and honors the optional `org` body param).

LIBRARY: github.com/go-webauthn/webauthn for ceremony options + attestation/assertion verification. authkit owns storage, ephemeral challenge handling, session minting, routing, policy.

RP CONFIG (host-provided, on core.Config): RPID (registrable domain), RPDisplayName, allowed Origins. Derive defaults from BaseURL/Issuer; validate RPID is a registrable suffix of each origin.

CEREMONIES (begin -> finish; challenge state in the EphemeralStore, same pattern as SIWS challenges + reset tokens, short-TTL single-use): REGISTRATION (AUTH'd user) begin->CreationOptions (challenge, RP, per-user handle, excludeCredentials, residentKey=preferred) + finish (verify attestation, store credential). AUTHENTICATION (login) begin->RequestOptions supporting BOTH discoverable/usernameless AND username-scoped (prefer discoverable) + finish (verify assertion, sign-count clone detection, update sign_count/last_used, mint session).

STORAGE: new profiles.user_passkeys (id uuidv7, user_id fk, credential_id bytea UNIQUE, public_key bytea, sign_count bigint, aaguid bytea, transports text[], attestation_fmt text, label, created_at, last_used_at, deleted_at). A per-user random user_handle (NOT the user id) maps handle->user for usernameless login.

SECURITY: RPID/origin phishing-resistance (library-enforced); sign-count regression -> reject (clone); single-use short-TTL challenges; anti-enumeration on username-scoped login begin; rate-limit begin+finish; live-user ban/deleted gate on login.

MIGRATION PACKAGING (do it right): add profiles.user_passkeys as a NEW NUMBERED migration (002_user_passkeys.up.sql), NOT appended to the consolidated 001 file — migratekit is name-tracked and won't re-apply 001 to DBs that already recorded it, so tables added to 001 never reach existing deployments. A new numbered file IS applied to existing DBs.

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

Problem found during the OpenRails config audit: OpenRails has a `merchant_cors` shape that looks per-merchant, but its current behavior is only a flattened global CORS allow-list. That does not enforce "a Doujins delegated-user request for Doujins may only come from doujins.com"; it only says "this browser origin may call this OpenRails instance." In public merchant registration, where Doujins and Evil can both register valid issuers and allowed origins, preflight CORS adds no merchant-isolation value because the preflight has no JWT issuer. Auth still protects data; CORS is compatibility/browser hardening, not authorization.

CURRENT OPENRAILS WIRING:
- `config.MerchantCORS` is only consumed by `Config.AllowedCORSOrigins()`, which unions `cors_origins` + all merchant origins.
- Standalone (`newPublicEngine`), embedded net/http (`embedhttp.Assembler`), and embedded gin self-service all pass that union into generic CORS middleware before auth.
- The delegated browser surfaces (`/v1/self/*` and `/v1/merchant-admin/*`) already resolve `ResolvedDelegated.Issuer` and pin the merchant from that validated issuer, but they do not check `Origin` against the issuer.
- Webhooks and API-key/server-to-server routes should not use this browser-origin policy.

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

---

# #94: Enforce the no-escalation invariant on EVERY grant path + a found gap (remote-app direct grant) — code + tests

**Completed:** yes

DONE (2026-06-20): delegated access-token `permissions` are now verified against
the issuer remote application's stored authority before platform gates can trust
them. The same namespace-anchored glob matcher backs remote application access
tokens, delegated access tokens, and `Claims.HasPermission`. Platform gates now
accept validated delegated `platform:*`/concrete permission claims while
preserving live DB checks for local users and continuing to reject delegated role
claims. Tests cover accepted stored glob authority, out-of-ceiling rejection, and
claiming broader `platform:*` than stored authority.

AuthKit-side implemented: `IssueAccessToken` no longer mints profile or role
claims for normal user access tokens; it keeps `sid` from caller extras and
authoritative short-lived `entitlements`. README/API docs now point profile,
bootstrap, org membership, role, and permission state to live endpoints/DB state.
Regression coverage:
`TestIssueAccessToken_SlimUserClaimsKeepsSessionAndEntitlements` and
`TestPasswordLoginAndRefreshMintSlimUserAccessTokens`.

Consumer migration remains open. A 2026-06-20 sweep still found downstream
references that need a real consumer pass before this issue can close:
Doujins `internal/auth/middleware/user_context.go` still falls back to
`claims.Roles`; Hentai0 `internal/auth/provider_authkit.go` still copies
`claims.Roles`; both repos have comments/docs around `profiles.global_roles`.

CRITICAL INVARIANT (Paul, "checked doubly so"): **you can never grant a permission you do not yourself hold.** A caller with `org:members:manage` / `org:roles:manage` / `org:remote_applications:manage` / `org:api_keys:manage` must NOT be able to hand a member, role, API key, or remote application any permission outside their own effective set — blocking escalation (handing out `owner`/`org:*`, or `root:*`, that the grantor lacks). Enforced by `ValidateGrant` (returns `offending` for perms the actor lacks; `owner`/`org:*` passes within its org, a `global`-scoped operator passes, and the bootstrap system-actor passes).

**GAP FOUND (2026-06-19):** the remote-application DIRECT permission-grant path does NOT call `ValidateGrant`. `handleRemoteApplicationPermissionPOST` (`http/remote_application_handlers.go:295`) only checks catalog MEMBERSHIP (`AddRemoteApplicationPermission` → `ErrUnknownPermission`) — it does NOT check no-escalation. So anyone who can manage a remote application can grant it ANY catalog permission, including perms the grantor lacks (`root:*`, …); the remote-app then acts with escalated authority. Real escalation hole.

Coverage today — HAVE the check: role-perm set (`org_role_permissions_handlers.go:58`), role assign-to-member (`org_membership_roles_handlers.go:66`), API-key mint (`api_keys_handlers.go:209`), org invite (`service_org_invites.go:55`). MISSING: remote-app direct grant.

Root cause: `ValidateGrant` is enforced in the HTTP handlers, NOT in the core mutators (`AddRemoteApplicationPermission`, `AssignRole`, `SetRolePermissions`, `MintServiceToken`). So any NEW grant path that forgets the check is a silent escalation hole — exactly what happened here.

**Tasks:**
- [ ] FIX the gap: add `ValidateGrant` to `handleRemoteApplicationPermissionPOST`; reject 403 `permission_grant_denied` when `offending` is non-empty (mirror the role/API-key paths).
- [ ] Defense-in-depth: enforce no-escalation in the CORE grant mutators too, with an explicit trusted/`SystemActor` bypass for bootstrap/manifest seeding (which legitimately seeds `owner`=`org:*` that nobody holds yet). HTTP keeps its check (belt + suspenders) so the invariant can't be lost by a future handler.
- [ ] Comprehensive tests, ONE per grant path: a grantor holding a STRICT SUBSET cannot grant outside it (→ 403/`offending`); `owner`(`org:*`) / a global operator CAN; granting any perm the grantor lacks is blocked. Cover member-role assign, role-perm set, API-key mint, org invite, AND remote-app direct grant.
- [ ] Regression test locking THIS gap: a remote-app manager lacking `root:users:ban` cannot grant it to a remote application.

NOTE: unify-on-roles is DECIDED (roles-only — see #95): dropping `service_token_permissions` + `remote_application_permissions` direct lists DELETES the remote-app/API-key direct-grant paths and closes this whole class by construction. Until that lands, every direct-grant path MUST call `ValidateGrant`. Also: with globs first-class (#95), `ValidateGrant` must EXPAND globs when checking no-escalation — granting `org:members:*` requires the grantor to effectively hold all of `org:members:*`.

---

# #95: RBAC permission model — granular CRUD + positive glob wildcards + owner/operator apex + `org:` shared namespace + unify-on-roles

**Completed:** no

HARDENING DONE (2026-06-20):
- [x] `POST /admin/orgs/{id}/recover` requires a fresh local session after the
      `platform:orgs:recover` gate. Stale sessions now return
      `reauth_required`; delegated/remote-application tokens cannot perform the
      recovery mutation because they have no local refresh-session freshness.
- [x] Swept legacy token-borne global-admin bypasses: no remaining
      `claimsHasGlobalAdmin` / `GlobalRoles == admin` authorization bypasses.
- [x] Hot org permission checks now use one DB round-trip:
      `OrgUserHasPermissionToken` resolves slug/rename + membership + single
      role permission grant in one indexed `EXISTS` query.
- [x] Hot platform permission checks now use one DB round-trip:
      `PlatformUserHasPermissionToken` checks `platform_user_roles` joined to
      `platform_role_permissions` in one indexed `EXISTS` query.
- [x] Tests: live DB HTTP test covers recover permission + stale/fresh reauth;
      live DB core tests cover org/platform direct and glob checks; Docker
      Compose E2E covers remote/delegated platform-gate behavior against the
      running devserver/Postgres stack.

The TARGET AuthKit permission model after the 2026-06-19 design pass with Paul (master design doc). Consolidates the already-split pieces — #92 (rename `PermissionCatalog`→`Permissions`), #93 (remove `!perm` negation), #94 (no-escalation on all grant paths) — plus the model decisions below. Hard-cut, no legacy. Consumer: OpenRails #537.

## Grammar
- Permissions are `<namespace>:<resource>:<action>`, lowercase, colon-separated.
- **Actions are CRUD: `{create, read, update, delete}`.** `read` = list + get-detail (ONE action; secrets are NEVER returned by any read). No separate `list`; no `:manage` action. (Paul chose `read` over `list` — more conventional; remember it also implies list.)
- **Positive GLOB wildcards are first-class (AWS-IAM style; `*` is a wildcard CHARACTER) — but globs MUST be namespace-anchored. There is NO bare `*`:**
  - `org:*` — everything under `org:` (the org owner).
  - `org:members:*` — all CRUD on members ("manage" with NO manage perm).
  - `org:*:read` — read across all org resources ("view-all" with NO viewer role).
  - `platform:*` — all platform-layer (Layer 2) operations.
  - **NO bare `*`** (Paul, 2026-06-19): a standalone `*` god-token is DROPPED — "everything" is `org:*` + `platform:*` (the two namespaces/layers), stated explicitly. A grant must have a namespace prefix before any `*` → reject a bare `*`. Bonus: a future new namespace is then NEVER silently auto-granted.
- **No `:manage` permission, and no manage/viewer ROLE bundles** — the globs above express "all CRUD on X" and "read all" directly (Paul: "you don't need `:manage`, `org:members:*` already means it").
- **Negation (`!perm`) is BANNED** (#93) — the ONLY removed operator. Net: positive globs + literals, **allow-only, no deny**. Negation's silent-no-op fail-open is gone; globs are purely additive (a glob auto-includes a newly-added matching catalog perm — intended for coarse grants; use specific perms for least-privilege).

## TWO LAYERS (Kubernetes `Role` vs `ClusterRole` — Paul, 2026-06-19)
Org authority and platform authority are **different object TYPES**, not the same grant with a hidden scope — "maximum obviousness." **This SUPERSEDES the earlier `is_global` org + `@ scope` approach (both DROPPED), and `root:` → `platform:`.**

**Layer 1 — Org RBAC (the `Role` layer; exists today).** A user is a MEMBER of an org with org-role(s) (`org_memberships` → `org_roles` → `org_role_permissions`). Org roles grant **`org:<resource>:<action>`**, scoped to THAT org. `owner` = `org:*` (everything in that ONE org); reusable across orgs (the same role definition works in any org you're a member of). Resources: `members`/`roles`/`api_keys`/`remote_applications` + host resources (OpenRails `org:credits:*`, tensorhub `org:repo:*`). Globs apply within the layer (`org:*`, `org:members:*`, `org:*:read`).

**Layer 2 — Platform RBAC (the `ClusterRole` layer; NEW — super-admins only).** A user is ASSIGNED platform-role(s) **directly — no org involved.** A **completely separate object type: NEW tables `platform_roles` / `platform_role_permissions` / `platform_user_roles`** — NOT the `orgs` table, NO `is_global` flag, NO special org name. A platform role can't be created or assigned through the org system, so **you can't get platform power by being added to an org.** Platform roles grant **ONLY `platform:<resource>:<action>`** — platform/DIRECTORY resources that manage *entities*, with no per-org form: `platform:users:*` (the account directory — ban/edit/delete an account), `platform:orgs:*` (the org directory — rename/transfer-owner/soft-delete + slug lifecycle + anti-takeover **recover** of any org; NO admin-create), `platform:roles:*` (define platform roles), `platform:members:*` (the platform-admin roster), `platform:metrics:*`. **ENTITY-LEVEL ONLY (Paul 2026-06-20): a platform-admin manages orgs as whole entities at a high level and NEVER their day-to-day internals — NOT members, role definitions, api-keys, or remote-applications, not even read-only.** The ONE sanctioned reach inside is **`platform:orgs:recover`** — a coarse all-or-nothing anti-takeover reset (defined below), never granular internal management. (api-keys + remote-applications are org-nested sub-resources, not platform resources.)

**A platform role does NOT grant `org:` perms** (Paul, 2026-06-20 — corrected; the two namespaces are DISJOINT). A platform admin manages the *account / org as an ENTITY* (ban a user, suspend a merchant) but **cannot act INSIDE an org** (read cozy's billing, `org:credits:*`) and **cannot act AS a user** — it does NOT inherit what org members can do. Acting inside an org requires actual org MEMBERSHIP (deliberate) or an explicit, audited break-glass. A host needing a genuine cross-org power defines a `platform:` resource for it (e.g. tensorhub `platform:repos:moderate`), never blanket `org:*`. **Stricter than k8s `cluster-admin` on purpose** — least privilege: the platform team runs the platform, not every tenant's private data.

**super-admin** = a platform role holding `platform:*` = full DIRECTORY authority (all users + orgs + metrics; `reserved-names` + `recover` fold under `orgs`). For day-to-day administration of a specific org's internals it still must be added as a MEMBER (deliberate) — the ONLY direct reach-in is the coarse `platform:orgs:recover` anti-takeover reset.

**Two DISJOINT namespaces, one per layer — no overlap.** `org:` perms exist ONLY in org roles (one org, via membership); `platform:` perms exist ONLY in platform roles (the directory). No string is shared across layers, so there is no "same perm, different scope" subtlety: a perm's namespace tells you its layer, and the layer is a different table. So there is NO `@ scope`, NO `is_global`, NO bare `*`, and NO cross-org `org:*`. AuthKit owns the two layers + their enforcement; the app still owns what any perm MEANS. **Delete the old global-roles-as-flags plane + app-local role→perm maps** (the doujins drift source) — both layers are AuthKit-owned roles now.

## Platform layer — examples + boundaries
- **Examples (separate layers, separate namespaces):** cozy owner → **org**-role `org:*` (everything in cozy); directory auditor → **platform**-role `platform:users:read` + `platform:orgs:read` (read the user + org DIRECTORIES — NOT any org's internal data); support desk → **platform**-role `platform:users:read` + `platform:users:update`; super-admin → **platform**-role `platform:*` (full directory authority — still not inside any org).
- **No ambiguity — by STRUCTURE + DISJOINT namespaces.** Org grants and platform grants come from DIFFERENT TABLES (`org_role_permissions` vs `platform_role_permissions`) into DIFFERENT FIELDS of the principal: `org_grants` (keyed by org, `org:` perms only) vs `platform_grants` (flat, `platform:` perms only). The namespaces don't overlap: an `org:` perm can ONLY come from an org membership; a `platform:` perm can ONLY come from a platform role. So a regular user (nothing in `platform_user_roles`) has empty `platform_grants` and is denied every `platform:` route; a platform admin (no org memberships) has empty `org_grants` and can't touch any org's internals. Platform roles get human names (`super-admin`/`support-desk`/`platform-auditor`) for audit readability — but the TABLE + namespace are the boundary.
- **Globs are namespace-anchored (no bare `*`):** `org:*`, `org:members:*`, `org:*:read`, `platform:*`, `platform:users:*`. A grant must have a namespace prefix before any `*`; "everything a platform role can hold" = `platform:*` (it CANNOT hold `org:*`), never a standalone `*`.
- **`users` (account) ≠ `members` (org membership).** Banning is a platform op: `POST /admin/users/{id}/ban` gates on **`platform:users:ban`**; removing someone from an org is `org:members:delete`.
- **Who gets platform roles:** users / API keys / remote-apps, assigned a platform role DIRECTLY (`platform_user_roles`). **Delegated/federated tokens are BARRED** from platform roles (verifier allowlist — a tenant can never mint itself platform authority).
- **Single-tenant apps** (doujins/hentai0/cozy-art): app users + staff live in the ORG layer (one org); the *operators* (you) hold **platform** roles. **Multi-tenant** (tensorhub): customer orgs are normal orgs; tensorhub staff hold platform roles. Either way platform authority is the separate layer, never an org.

## `org:` is the SHARED per-org namespace
- REVERSES the old "`org:` is reserved, hosts must use `merchant:`." `org:` now means "scoped to one org," and BOTH AuthKit's base perms AND the host's per-org resources live there.
- AuthKit reserves only the RESOURCE NAMES inside it: `members`, `roles`, `api_keys`, `remote_applications`, `settings` (the org's own name/profile). The host owns every other `org:<resource>` (tensorhub `org:repo:*`, OpenRails `org:credits:*`, …).
- `owner == org:*` therefore covers AuthKit management AND host resources in one grant.
- Cross-org / platform capabilities live in the SEPARATE `platform:` namespace (Layer 2 / `platform_roles`) — a different object type — so an org `owner` (`org:*`) can never reach platform authority.

## AuthKit base perms → granular CRUD
| resource | create | read (=list+detail) | update | delete |
|---|---|---|---|---|
| members | add | list members + roles | change role | remove |
| roles | define | list roles + perms | set perms / rename | delete |
| api_keys | mint | list metadata (NEVER secret) | — (immutable; rotate = create+delete) | revoke |
| remote_applications | register | list + detail | edit config / origins | delete |
| settings | — | read org (`GET /orgs/{org}`) | rename / edit metadata (`POST /orgs/{org}/rename`) | — |

(`org:settings` has no create/delete — the org *entity* is created/soft-deleted at the directory level via `platform:orgs:*`, Layer 2; `org:settings` is just the owner editing their own org's name/profile.) Old coarse perms RETIRED: `org:<resource>:manage` → glob `org:<resource>:*`; coarse `org:read` → glob `org:*:read`.

The **`platform:`** namespace (Layer-2 platform-only resources, granted in `platform_roles`) — the resources with NO per-org form. Full native catalog:

| `platform:` resource | actions | gates / notes |
|---|---|---|
| `users` | read, update, ban, delete | the global account directory (`/admin/users/*`). `users`=account ≠ `org:members`=membership. |
| `orgs` | read, update (rename + transfer-owner), delete (SOFT), reserved-names, recover | the **org-admin** surface — administer ANY org as an ENTITY at **`/admin/orgs/*`**; **entity-level ONLY** (NO day-to-day member/role/api-key/remote-app internals, not even read-only — those are org-side, break-glass via membership). DISTINCT from a user self-managing their OWN org (`/orgs/{org}/*` via `org:settings:*`, Layer 1). `read` = the org directory (list/search/inspect any org); `update` = rename + transfer-owner (surgical reassign, keeps the team); `delete` = SOFT (`orgs.deleted_at`, restorable → doubles as suspend). `reserved-names` (folded IN from a standalone perm, Paul 2026-06-20) = restrict/unrestrict/park/claim over the org SLUG pool — justified because the owner-namespace IS org-backed (parking a "user" slug mints a personal org); ONE perm for all those slug ops. **`recover`** = the **anti-takeover / account-recovery** reset for a compromised org (Paul 2026-06-20): ATOMICALLY revoke ALL the org's api-keys, disable ALL its remote-applications, demote ALL current members (strip every role), and assign `owner` to one specified rightful-owner — bad actors locked out, good owner restored. Coarse all-or-nothing (NOT granular internal management); heavily audited; separately grantable. **No `create`** — org creation is self-service (`POST /orgs`) or park/claim, never an admin-mint (mirrors `platform:users`). **No `suspend`** — soft-delete is the reversible disable. AuthKit's soft-delete does NOT cascade APP-owned resources (OpenRails billing / tensorhub repos) — the app reacts to org-deletion for its own cleanup. || `roles` | create, read, update, delete | DEFINE platform roles + their perms (the `platform_roles` / `platform_role_permissions` definitions). Parallels `org:roles`. |
| `members` | create (add), read (list), delete (remove) | the **platform-admin roster** — WHO holds platform roles (`platform_user_roles`; `/admin/roles/{grant,revoke}`). Renamed from `assignments` (Paul 2026-06-20: parallels `org:members`; "assignment" didn't read right). DISTINCT from `platform:users` (the directory of ALL accounts) — `platform:members` is just the admin team (the platform behaves like a root org whose members are the admins). **The single most dangerous perm — it mints new platform-admins** — split from `roles` (define ≠ assign) and guarded hardest (no-escalation: can't grant a platform perm you don't hold). |
| `metrics` | read | platform metrics. |

**Why org-less remote-apps are latent — the payer model (verified in `controlplane/customer.go` #491, Paul 2026-06-20).** A payer is one of THREE: **native** (a regular AuthKit user / embedded caller — the subject UUID *is* the payer id; invoker = payer = self-pay); **org-bound** (`UNIQUE(merchant, org_id)` — the ORG is the payer, ANY member invokes on its behalf → **invoker ≠ payer = real delegation**); **org-less federated** (`UNIQUE(merchant, issuer, subject)` — a FOREIGN subject vouched for by an org-less remote-app; each self-pays). Paul's framing holds exactly: invoker ≠ payer (true delegation) happens ONLY in the org-bound branch, and there an org member is EITHER a remote-application (machine) OR a role-assigned user (human) — both polymorphic `org_memberships` rows. An "org-less payer" is therefore just **self-pay**, which a native AuthKit user already covers; the org-less-remote-app path only buys per-subject billing for a host with its OWN identity system — which none of the 4 consumers is. Hence (DECIDED, Paul 2026-06-20) there is **no org-less remote-app at all** — `remote_applications.org_id` becomes **NOT NULL** and remote-apps are modeled as a pure **org-nested sub-resource, exactly like api-keys** (an issuer "attached to nothing" makes as little sense as an api-key attached to nothing). Proof by the standalone case: if doujins runs OpenRails standalone, it seeds itself as a remote issuer — but it must ALSO seed its own org + merchant to have anything to bill, so the issuer is org-attached by construction. Consequences: drop `platform:remote_applications` ENTIRELY (no platform resource, no row above); move the flat `/remote-applications` routes under `/orgs/{org}/remote-applications` (org in the PATH, like api-keys); delete the global `GET /remote-applications` admin list and the org-less branch in `canManageRemoteApplicationByIssuer`. (If the operator ever wants a federation-trust audit view — "which external issuers can mint tokens against my platform" — add it later as a read-only audit/metrics endpoint, NOT a managed resource; api-keys has no such view either, so default is to omit it.)

## Unify principals on ROLES (drop direct permission lists)
- users / API keys / remote_applications ALL get permissions via **role(s)** — ONE grant path, already no-escalation-guarded (#94).
- **Resource-scope is a separate per-principal binding** (API key `Resources{Kind,ID}`, remote-app org/issuer) — orthogonal to *what* perms.
- **DROP** `service_token_permissions` + `remote_application_permissions` direct lists. Bespoke set → custom role. This DELETES the direct-grant paths, closing the #94 escalation class by construction. DECIDED (Paul): API keys + remote-apps get ROLES, not arbitrary permission bundles — so adding/removing a permission later is a ONE-PLACE change (edit the role), not a sweep across every key. (Tradeoff accepted: some role proliferation for one-off machine creds.)

## Tasks
**Design FROZEN 2026-06-20 (Paul) — the decisions above are locked; the checkboxes below are the implementation breakdown (hard-cut, no legacy).**
- [ ] Glob matching in `effectivePermsForTokens` + `ValidateGrant`: `*` as an AWS-style wildcard CHAR in namespace-anchored globs (`org:*`, `org:members:*`, `org:*:read`, `platform:*`, `platform:users:*`); REJECT a bare standalone `*`; allow-only, no negation (#93). No-escalation EXPANDS globs (granting `org:members:*` requires holding all of `org:members:*`).
- [ ] Granularize base perms per resource (`org:` = members/roles/api_keys/remote_applications × CRUD, in ORG roles; `platform:` = users(read/update/ban/delete)/orgs(read/update/delete/reserved-names/recover)/roles/members/metrics, in PLATFORM roles — api_keys + remote_applications are NOT platform resources, org-only); retire `…:manage` + coarse `org:read`; handlers gate on the specific action. Add the `platform:users:*` account-admin surface (ban/read/delete) distinct from `org:members:*`, and `platform:orgs:reserved-names` over `/admin/orgs/{restrict,unrestrict,park,claim}` (no `/accounts/` bucket; folds the old standalone `platform:reserved-names`).
- [ ] Make `org:` the shared per-org namespace; reserve only the 4 resource names; allow host-defined `org:<resource>` perms.
- [ ] **Remote-applications → pure org sub-resource (Paul 2026-06-20; same shape as api-keys).** Migration: `profiles.remote_applications.org_id` → **NOT NULL** (drop the org-less category entirely; greenfield single-baseline → edit the baseline + the `COMMENT`). Move the FLAT routes (`POST/DELETE/GET /remote-applications`, org_id in body) → **`/orgs/{org}/remote-applications`** (org in the PATH), gated in-handler on `org:remote_applications:*`. DELETE the global `GET /remote-applications` admin-list route + the `admin(...)` wrapper + the org-less branch in `canManageRemoteApplicationByIssuer`. Confirm the verifier still loads issuers globally by `iss` (nesting is management-only, not a verification change). No consumer change — OpenRails #527 bootstrap already provisions each issuer under its merchant's backing org.
- [ ] Tighten prebuilt `owner` role from `*` → `org:*` (Layer 1). Build **Layer 2 — Platform RBAC**: new tables `platform_roles` / `platform_role_permissions` / `platform_user_roles` (NOT the orgs table; NO `is_global`, NO `@ scope`). Assign platform roles to users / API keys / remote-apps DIRECTLY; a platform role grants **ONLY `platform:*`** (directory resources) — it does NOT grant `org:*` (the two namespaces are DISJOINT; the platform admin manages entities, never acts inside an org or as a user); super-admin = `platform:*`. ValidateGrant REJECTS an `org:` perm on a platform role and a `platform:` perm on an org role. Bar delegated/federated tokens from platform roles (verifier allowlist). NO bare `*`; globs namespace-anchored.
- [ ] Collapse `read`/`list` to a single `read` action; secrets never returned by any read.
- [ ] Unify principals on roles; drop `service_token_permissions` + `remote_application_permissions` direct lists; resource-scope stays a separate binding.
- [ ] **Efficient lookup (CONTRACT: ≤ 1 DB round-trip per request).** Resolve a principal's grants per layer via a SINGLE indexed JOIN — platform: `SELECT permission FROM platform_user_roles ur JOIN platform_role_permissions p ON p.platform_role = ur.platform_role WHERE ur.user_id = $1`; org: the analogue with `org_id` + `member_id`. Index the join columns (`platform_user_roles.user_id`, `platform_role_permissions.platform_role`, and the org equivalents). **Memoize per request:** resolve each layer's grant set ONCE at request start, stash in the request context, and have every gate match the cached set — a handler checking N perms does 1 resolution, not N. Globs keep the set tiny (a `platform:*` role = ONE row, never enumerated); the match itself is in-memory glob/prefix (µs). Regular users short-circuit (0 rows in `platform_user_roles` → no second step). OPTIONAL, only for extreme throughput: a short-TTL (5–30s) per-principal cache invalidated on role change — but the DEFAULT stays request-time resolution (instant revocation, never-stale grants; perms are NEVER baked into the JWT).
- [ ] Tests: glob expansion + no-escalation over globs; `owner`=`org:*` covers a host-defined `org:repo:*`; a platform role REJECTS any `org:` perm and an org role REJECTS any `platform:` perm (DISJOINT namespaces); a platform admin can't read any org's internal data nor act as a user; `platform:users:ban` gates the account-ban route; secrets unreadable; a delegated/federated token can NEVER hold a platform-role grant; **a handler with N perm-checks issues exactly ONE resolution query (memoization holds).**
- [ ] **Build the `/admin/orgs/*` org-admin surface (Paul 2026-06-20 — the missing org-management routes).** Mirrors `/admin/users/*`; **entity-level ONLY** (NO day-to-day member/role/api-key/remote-app internals, not even read-only — break-glass via membership), with the single coarse exception `recover` (below). Routes → perm: `GET /admin/orgs` (directory — paginated, search by slug, filter state/personal) → `platform:orgs:read`; `GET /admin/orgs/deleted` → `platform:orgs:read`; `GET /admin/orgs/{org}` (entity detail: slug/owner/is_personal/state/member-count/timestamps) → `platform:orgs:read`; `POST /admin/orgs/{org}/rename` → `platform:orgs:update`; `POST /admin/orgs/{org}/transfer-owner` (surgical reassign — owner-left / white-glove, keeps the team) → `platform:orgs:update`; `DELETE /admin/orgs/{org}` (SOFT) → `platform:orgs:delete`; `POST /admin/orgs/{org}/restore` → `platform:orgs:delete`; `POST /admin/orgs/{restrict,unrestrict,park,claim}` (org SLUG lifecycle; park/claim take `kind: org|user` in the body — user-kind mints a personal org) → `platform:orgs:reserved-names` (folds the old standalone perm; replaces the dead 404 `POST /admin/org/{park,claim}` stubs AND the old `/admin/account(s)/*` paths; reuses `handleAdminAccountPark/Claim/RestrictPOST`); **`POST /admin/orgs/{org}/recover` (anti-takeover reset — body `{new_owner_user_id}`: ATOMICALLY revoke ALL api-keys, disable ALL remote-apps, demote ALL members, assign owner to the rightful user → lock the attacker out, restore the good owner) → `platform:orgs:recover`** (separately grantable; max-audited). **DROP `platform:orgs:create`** (self-service or park/claim, never an admin-mint). ALL slug-lifecycle + recover live under `/admin/orgs/*` (NO `/admin/users/{park,claim}`, NO `/admin/reserved-names/*`, NO `/accounts/`); then delete the old `/admin/account(s)/*` + dead `/admin/org/*` routes + the dead `POST /admin/users/toggle-active` stub (NO active/inactive concept — ban + soft-delete are the only account states).
- [ ] **Routes + naming.** The platform surface is **`/admin/*`** (Paul 2026-06-20: `/platform/*` reads too vague; `/admin/` is the explicit operator-console prefix — and there's NO URL collision, because per-org admin lives under `/orgs/{org}/*`, never under `/admin/`). The gate stays **`requirePlatformPermission`** (NOT `RequireAdmin*`) and the perm namespace stays **`platform:`** — the disjoint Layer-2 plane — even though the URL says `/admin`; role name = **platform-admin**. **FOUR gate tiers** (Paul: self routes are a more primitive check — they have no target, they just modify the caller): **public** (ungated) · **self** (authenticated-only; acts on the caller, no target → IDOR-proof by construction) · **org** (`org:` perm for the path `{org}`) · **platform** (`platform:` perm). Platform routes → perm: `GET /admin/users*` → `platform:users:read`; `/admin/users/{ban,unban}` → `platform:users:ban`; `/admin/users/{set-*, */password-reset, */sessions/revoke}` → `platform:users:update`; `DELETE /admin/users/{id}` + `/restore` → `platform:users:delete`; **`/admin/orgs/*` (org-admin, entity-level: directory + rename/transfer-owner/soft-delete + slug lifecycle + anti-takeover recover)** → `platform:orgs:{read,update,delete,reserved-names,recover}`; the slug lifecycle `/admin/orgs/{restrict,unrestrict,park,claim}` (park/claim take `kind: org|user`) → `platform:orgs:reserved-names`, and `/admin/orgs/{org}/recover` → `platform:orgs:recover` (NO `/accounts/` bucket, NO `/admin/users/park`, NO `/admin/reserved-names/*` — all folded under `/admin/orgs`); `/admin/roles/{grant,revoke}` (assign/unassign a platform-admin) → `platform:members:{create,delete}` (define-a-role is the separate `platform:roles:*`). **No remote-application route under `/admin/`** — remote-apps are org-nested (below). ORG routes gate IN-HANDLER on the `org:` perm for the path `{org}` (`/orgs/{org}/members*` → `org:members:*`, `/roles*` → `org:roles:*`, `/api-keys*` → `org:api_keys:*`, **`/orgs/{org}/remote-applications*` → `org:remote_applications:*` (NEW home — moved from the flat `/remote-applications`, nested like api-keys)**, `GET /{org}` + `/rename` → `org:settings:{read,update}`, `/invites*` → `org:members:*`). SELF routes (`/user/*`, `/me/*`, own 2FA/sessions) → authenticated-only. PUBLIC routes (login/register/reset/verify/availability/owner-lookup) ungated.

#92/#93/#94 are the already-split sub-pieces of this model. Consumer reframe: OpenRails #537 (merchant→`org:`, platform super-admin → the `platform:` layer); then the doujins/tensorhub/cozy-art string flips.

---

# #96: Public/self route cleanup — phone reset, identity providers, namespaces, orgs

**Completed:** yes

## Metadata

- Category: bug/cleanup
- Status: done
- Passes: true

Phone password reset currently sends a reset token/link by SMS (`RequestPhonePasswordReset` → `SendPasswordResetLink`), but the public route table only exposes `POST /phone/password/reset/{request,confirm}`. Email has the browser handoff route `POST /email/password/reset/confirm-link` that consumes the token and returns a short-lived `reset_session`; phone lacks the matching public token-consume route even though `POST /phone/password/reset/confirm` expects `reset_session + new_password`.

Provider discovery is also too vague as `GET /providers`. Hard-cut it to `GET /identity-providers` because the list includes enabled external identity providers across OIDC and OAuth2; do NOT keep `/providers` as an alias.

`GET /owners/{slug}` also collapses two valid resources into one "owner" answer. A username and an org slug can legitimately match (for example a user `cozy` and org `cozy`), so hard-cut it to `GET /namespaces/{slug}` with an explicit typed response shape: `user`, `org`, and per-kind `claimable` fields. Do NOT keep `/owners/{slug}` as an alias.

`GET /user/bootstrap` is a current-caller bootstrap bundle, not a target-user resource. Hard-cut it to `GET /me/bootstrap` so the URL matches the rest of the self namespace; do NOT keep `/user/bootstrap` as an alias.

Native-user org-scoped access tokens are being removed entirely. There should be one normal user auth token, not one token per org membership. Delete `POST /token/org` and remove optional `org` token-minting from `/token` and `/password/login`; org authorization should resolve from the route/path + server-side membership/role/permission lookup, not from an org baked into the access token. Remove docs/tests/comments that describe native-user "org-scoped access tokens". This is separate from delegated/federated token models, which remain governed by their own issuer/subject/resource authority. `/me/permissions` becomes principal-level only. Per-org caller info lives directly on `GET /orgs/{org}`, which returns org metadata plus the caller's single `role` and effective permissions. The org membership model is one role per org membership, so response shapes should use `role: string`, not `roles: []`.

`GET /orgs/{org}/me` and `POST /orgs/{org}/permissions/check` are redundant once `GET /orgs/{org}` returns role + permissions. Delete both; frontends can check `permissions.includes(...)`, and backend handlers still enforce permissions server-side.

`GET /orgs` is a current-caller membership listing, not a platform-wide org directory. Hard-cut it to `GET /me/orgs`; keep `POST /orgs` unchanged for self-service org creation.

`/me/invites` is specifically org invites, not a generic inbox. Hard-cut it to `/me/org-invites` including accept/decline child routes; do NOT keep `/me/invites` as an alias.

## Tasks

- [x] Add `POST /phone/password/reset/confirm-link` as an alias to the existing password-reset token handoff handler (`token` → `reset_session`).
- [x] Hard-cut `GET /providers` → `GET /identity-providers` in route registration and tests; remove old `/providers` support.
- [x] Hard-cut `GET /owners/{slug}` → `GET /namespaces/{slug}`; remove old `/owners/{slug}` support.
- [x] Hard-cut `GET /user/bootstrap` → `GET /me/bootstrap`; remove old `/user/bootstrap` support.
- [x] Delete `POST /token/org`.
- [x] Remove optional `org` request handling from `POST /token` and `POST /password/login`; no org-scoped access-token mint path remains.
- [x] Delete org-scoped token helpers/claims that only exist for that model (`ExchangeRefreshTokenWithOrg`, `IssueOrgAccessToken`, `org`/`org_roles`/legacy org `roles` claim minting), or leave only compatibility-free internals if another active path proves it still needs them.
- [x] Sweep docs/tests/comments for native-user "org-scoped access token" language and remove it; do not conflate this with delegated/federated token authority.
- [x] Make `/me/permissions` principal-level only.
- [x] Change `GET /orgs/{org}` to return org metadata plus caller membership `{role, permissions}`.
- [x] Delete `GET /orgs/{org}/me` and `POST /orgs/{org}/permissions/check`.
- [x] Hard-cut `GET /orgs` → `GET /me/orgs`; remove old `/orgs` list support while keeping `POST /orgs` as self-service org creation.
- [x] Hard-cut `GET /me/invites` and `POST /me/invites/{invite_id}/{accept,decline}` → `/me/org-invites...`; remove old `/me/invites` support.
- [x] Redesign namespace lookup response to avoid a single `status`/`entity_kind`/`canonical_slug` winner: return typed `user`, `org`, and `claimable` fields so user+org same-slug cases are explicit.
- [x] Document the phone reset route, identity-provider route rename, namespace lookup rename/shape, bootstrap route rename, org-scoped-token removal, `/me/orgs` rename, `/me/org-invites` rename, and org lookup response shape in `README.md` and `agents/api-endpoints.md`.
- [x] Add one HTTP route/handler test proving phone confirm-link consumes a reset token and returns `reset_session`.
- [x] Add one route test proving `/identity-providers` exists and `/providers` is gone.
- [x] Add one namespace route/response test proving `/namespaces/{slug}` can represent same-slug user+org without collapsing to one owner, and `/owners/{slug}` is gone.
- [x] Add one route test proving `/me/bootstrap` exists and `/user/bootstrap` is gone.
- [x] Add route/API tests proving `/token/org` is gone, `/token` and `/password/login` reject/ignore `org`, `/me/permissions` is not org-scoped, `GET /orgs/{org}` returns org `role` + permissions, `/orgs/{org}/me` and `/orgs/{org}/permissions/check` are gone, `/me/orgs` exists, and `GET /orgs` is gone.
- [x] Add route tests proving `/me/org-invites` accept/decline routes exist and `/me/invites` is gone.

---

# #97: Slim normal user access-token claims to session identity only

**Completed:** yes

DONE (2026-06-20): normal AuthKit user access tokens now carry only registered
JWT identity, `sub`, `sid`, and authoritative short-lived `entitlements`. They
no longer mint profile or role/global-role snapshots. Consumers were migrated:
Doujins request context now resolves roles through its DB `UserRoleRepo` and its
frontend token bootstrap no longer derives role/profile/admin/email state from
JWT payload fields; Hentai0 request context uses DB roles and its frontend token
bootstrap no longer derives role/profile/admin/email state from JWT payload
fields; Cozy Art was swept and had no normal-user role/profile JWT dependency to
change. Validation: AuthKit `go test ./...`; Doujins
`go test ./internal/server ./internal/auth/middleware` and
`pnpm -C frontend exec tsc --noEmit`; Hentai0
`go test ./internal/auth ./internal/api` and
`pnpm -C frontend exec tsc -b --noEmit`; live Docker Compose stack
`go test -tags=e2e ./testing -run TestDevserverE2E -count=1` proves
password-login and refresh tokens from the running devserver/Postgres keep
`sub`, `sid`, and authoritative `entitlements` while omitting profile and role
claims.

Normal AuthKit user access tokens currently carry profile snapshots and authority snapshots:
`global_roles`, legacy `roles`, `entitlements`, `email`, `email_verified`,
`username`, `discord_username`, plus `sid` supplied by login/refresh paths.

This is backwards for the new authorization model for roles/profile data. User
permissions and roles are live DB state, not token authority. Profile data
belongs on `/me` / `/me/bootstrap`, not in every bearer token. Entitlements are
different: the entitlement claim is an authoritative short-lived snapshot issued
by AuthKit's configured entitlements provider. A later DB check may improve
freshness/revocation behavior, but it does not make the JWT entitlement claim a
mere UI hint.

Target token shape for normal user access tokens:
- Keep registered claims: `iss`, `sub`, `aud`, `iat`, `exp`.
- Keep `sid` for now. It is session identity used by logout, reauth/freshness,
  session-preserving password changes, and host session context.
- Keep `entitlements` as an authoritative short-lived snapshot.
- Remove `global_roles` and `roles`.
- Remove profile claims: `email`, `email_verified`, `username`,
  `discord_username`.

Do not change delegated/service token shapes in this issue. Delegated/service
tokens intentionally carry explicit `permissions` / attributes for their own
models; this issue is only about normal AuthKit human-user access tokens minted
by `IssueAccessToken`.

Known current consumers to migrate first:
- Doujins reads `Claims.GlobalRoles` / `Claims.Roles`, `Claims.Username`, and
  `Claims.Entitlements` into request context. Move roles/permissions to
  DB-backed middleware/enrichment and profile display to `/me`.
- Hentai0 server reads `Claims.Roles`, `Claims.Username`, and
  `Claims.Entitlements`; its frontend also decodes token payload fields for
  `isAdmin`, `isPremium`, email, username, and email verification. Move frontend
  state to `/me` / profile fetch and server authorization to DB-backed role /
  entitlement lookup.
- Cozy Art mostly uses `Claims.UserID` / `Claims.SessionID` for normal-user
  paths; verify no profile/role/entitlement token dependency remains before the
  AuthKit hard-cut.

**Tasks:**
- [x] Audit AuthKit tests/docs and the three consumers (`~/doujins`,
      `~/hentai0`, `~/cozy/cozy-art`) for reads of user-token profile,
      role/global-role, and entitlement claims.
- [x] Update consumers so normal-user request context is built from live DB /
      profile endpoints, not access-token roles/profile; token entitlements stay
      authoritative by design.
- [x] In AuthKit `IssueAccessToken`, stop minting `global_roles`, `roles`,
      `email`, `email_verified`, `username`, `discord_username`, and
      keep `sid` merging from login/refresh `extra`; keep `entitlements` as an
      authoritative short-lived snapshot.
- [x] Keep `Claims` parsing backward-tolerant only if needed for third-party
      inbound tokens, but stop documenting those fields as normal AuthKit
      user-token output.
- [x] Update `/me`, `/me/bootstrap`, and docs so they are the supported source
      for user profile/bootstrap state.
- [x] Add an AuthKit integration/HTTP test proving login/refresh user access
      tokens contain `sub` + `sid` and do not contain roles, profile fields, or
      authoritative role/profile claims; `entitlements` remains authoritative.
- [x] Add focused consumer tests proving admin/premium/profile UI still works
      without those token claims.

---

# #98: Validate delegated JWT permissions against remote-application stored authority

**Completed:** yes

DONE (2026-06-20): delegated access-token `permissions` are now verified against
the issuer remote application's stored authority before platform gates can trust
them. The same namespace-anchored glob matcher backs remote application access
tokens, delegated access tokens, and `Claims.HasPermission`. Platform gates now
accept validated delegated `platform:*`/concrete permission claims while
preserving live DB checks for local users and continuing to reject delegated role
claims. Tests cover accepted stored glob authority, out-of-ceiling rejection, and
claiming broader `platform:*` than stored authority.

LIVE E2E (2026-06-20): `go test -tags=e2e ./testing -run TestDevserverE2E
-count=1` now seeds a remote_application, org role, membership, and platform
permission authority into the Docker Compose Postgres stack, signs real
delegated JWTs, and calls the running devserver. It covers: remote application
access token accepted with `typ=remote-application-access+jwt`; wrong `typ`
rejected; delegated `platform:orgs:read` accepted by an admin platform gate
when covered by stored `platform:*`; delegated `platform:orgs:recover` rejected
by the recover route's fresh local-session requirement; delegated
out-of-ceiling concrete permission rejected at verify; delegated broader
`platform:*` than stored authority rejected at verify; and a delegated token
without the route's required platform permission failing the platform gate with
403.
That live test found and fixed a real DB-backed gap: remote_application
authority now expands `platform:*` against AuthKit's platform catalog, not only
the org/app permission catalog.

Delegated JWTs may carry concrete `permissions`, but those permissions must be
bounded by the issuing remote application's stored DB authority. Today
remote-application self tokens are down-scoped against stored authority, but
delegated tokens are only catalog-validated. That is not enough: a remote app
must not be able to mint any catalog-valid `platform:*` or `org:*` permission
for its delegated users.

Target model:
- Remote application stored authority is the ceiling.
- Delegated JWT `permissions` are concrete requested permissions, not role
  claims.
- Verification resolves `iss` -> remote application -> stored authority, then
  rejects any delegated permission outside that ceiling.
- Platform gates may accept either a local user with live DB platform permission
  or a delegated token whose `permissions` claim has already been validated
  against the remote application's stored authority.
- Do not add delegated platform-role claims. Roles are local assignment
  structure; delegated tokens carry concrete down-scoped permissions.

Example:

```json
{
  "delegated_sub": "external-user-123",
  "permissions": ["platform:orgs:recover"]
}
```

This is valid only when the issuer remote application already has authority for
`platform:orgs:recover`.

**Tasks:**
- [x] Audit delegated verification and confirm where `permissions` are currently
      catalog-validated without stored-authority intersection.
- [x] Add verifier-time delegated permission ceiling check: resolve issuer
      remote application, load its effective stored authority, and reject
      out-of-ceiling claims.
- [x] Support glob matching consistently with the permission model
      (`platform:*` may cover `platform:orgs:recover`; bare `*` stays invalid).
- [x] Teach platform gates to accept validated delegated permission claims for
      `platform:*` checks, alongside local-user live DB platform permissions.
- [x] Keep platform role claims rejected/ignored on delegated tokens.
- [x] Tests: delegated token within issuer authority passes a platform gate;
      delegated token claiming a permission outside issuer authority is rejected
      at verify; catalog-valid but unassigned `platform:*` cannot be minted by a
      weaker remote application.

---

# #99: Canonicalize remote application access token naming

**Completed:** yes

DONE (2026-06-20): the canonical product/API name is now **remote application
access token** with JOSE `typ=remote-application-access+jwt`. AuthKit comments,
README/API docs, and active OpenRails consuming comments/docs were swept to use
the new name while retaining low-level invariant notes: the token carries neither
`sub` nor `delegated_sub`; identity is validated `iss -> remote_application`.
Tests pin the wire constant and wrong-`typ` rejection.

LIVE E2E (2026-06-20): the Docker Compose devserver test signs a real remote
application access token and proves the running verifier accepts it, then signs
the same remote-application JWT shape with the wrong JOSE `typ` and proves the
running server rejects it.

AuthKit already uses JOSE `typ` headers for its JWT classes:

- normal user access token: `typ=access+jwt`
- delegated access token: `typ=delegated-access+jwt`
- remote application acting as itself: `typ=remote-application-access+jwt`

It also has a separate service-JWT shape: `typ=service+jwt` plus
`token_use=service`. That is not the same thing as a remote application access
token, and API keys are opaque shared secrets with DB-resolved authority, not
JWTs.

The remote-application self-token already has the right wire value, but docs and
comments still use several names: "remote_application self-token", "JWKS
principal self-token", and "SELF-token". Standardize product/API language on
**remote application access token** and keep the wire type as
`remote-application-access+jwt`.

- [x] Keep `jwtkit.RemoteApplicationAccessTokenType =
      "remote-application-access+jwt"` as the canonical JOSE `typ` value.
- [x] Rename comments/docs from "remote_application self-token" / "JWKS
      principal self-token" to "remote application access token" where the
      user-facing concept is being described.
- [x] Keep lower-level implementation comments only where they clarify the
      invariant: the token carries neither `sub` nor `delegated_sub`; identity is
      the validated `iss -> remote_application`.
- [x] Update README / API docs token taxonomy:
      user access token, delegated access token, remote application access token,
      service JWT, API key.
- [x] Sweep OpenRails comments/docs that consume this AuthKit token type and use
      the same name.
- [x] Add/keep tests proving `RemoteApplicationAccessTokenType` is
      `remote-application-access+jwt` and verifier rejects the wrong `typ`.
