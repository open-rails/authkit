<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 86

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
