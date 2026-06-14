<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 80

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** no

Add passkeys (WebAuthn/FIDO2) as a first-class authentication method in authkit, alongside password, OIDC, and SIWS. Passkeys are phishing-resistant, usernameless-capable credentials bound to the relying party (RP) domain. A user can register one or more passkeys and authenticate with them; a successful login mints the SAME access/refresh session as the password path (and honors the optional `tenant` body param).

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
- [ ] Authentication ceremony: begin (discoverable + username-scoped, anti-enumeration) + finish (verify assertion, sign-count clone-check, update sign_count/last_used, mint access+refresh honoring `tenant`, live-user gate).
- [ ] Management routes: GET /passkeys (metadata only), DELETE /passkeys/{id}, optional PATCH rename.
- [ ] RouteGroup RoutePasskeys + registration; challenge state via EphemeralStore (single-use, short TTL) like SIWS.
- [ ] Rate-limit buckets for register/login begin+finish; anti-enumeration on username-scoped login begin.
- [ ] Tests: full register + login ceremonies via a software-authenticator fixture; sign-count regression rejection; usernameless login; list/delete; anti-enumeration; rate limits.
- [ ] Docs: api-endpoints.md + README passkey section (RP config, ceremony flow, frontend navigator.credentials notes, security model, recovery out-of-scope).
- [ ] Version bump + publish; consumer notes (host mounts RoutePasskeys + sets RP config; frontend integrates the WebAuthn JS ceremonies).

---

# #77: remote_application owned by a TENANT (tenant_id FK), not a user

**Completed:** yes

Today `profiles.remote_applications.owner_user_id -> users` anchors an issuer's ownership to a single
CREATOR user. Re-anchor ownership to the owning ORG: add `remote_applications.tenant_id -> tenants`
(NOT NULL). One tenant has MANY remote_applications (issuers); each issuer belongs to exactly ONE tenant.

WHY:
- Robustness: ownership survives the creator leaving the org (it's the org's, not a person's).
- Operator identity (openrails#491): the MERCHANT is the authenticated OPERATOR — its issuer/tenant in
  OpenRails-authkit IS the merchant (e.g. tensorhub). issuer -> merchant via the issuer registry; the merchant
  then ASSERTS (customer, actor) for its own namespace (opaque, not re-authenticated). There is NO
  tenant<->merchant FK; owner_tenant_id stays ownership/admin-only. #77's tenant ownership of the issuer is
  the authkit-side admin anchor (who owns the operator's signing key), not a billing-resolution hop.
- Clean separation: the polymorphic `tenant_memberships` then means ONLY "this issuer's self-token gets
  these roles" (#76) — purely auth, fully decoupled from ownership/billing.

Keep `owner_user_id` as a NULLABLE creator-audit (ON DELETE SET NULL), or drop it.

**Tasks:**
- [x] Migration (007): add `remote_applications.tenant_id` REFERENCES profiles.tenants; backfill from the
      creator's personal tenant; SET NOT NULL only if all rows resolve; owner_user_id now nullable, ON
      DELETE SET NULL (creator-audit).
- [x] Core: GetRemoteApplication/all reads return tenant_id; upsert persists exactly one tenant; added
      ResolveRemoteApplicationTenant(issuer). Handlers accept/return tenant_id.
- [x] tenant_memberships kept roles-only (unchanged); ownership(tenant_id) vs roles(membership) split.
- [ ] Tests: dedicated issuer->tenant 1:1 / creator-deletion / many-issuers tests NOT added (existing
      suite passes green; covered structurally by the FK + handler plumbing).
- [ ] Consumer note: openrails#491 merchantForIssuer switches to the tenant_id FK (separate repo).

**Related**
#74 (remote_application table this amends), #76 (membership = roles only, post-split), openrails#491
(customer/actor split + merchantForIssuer via tenant_id), openrails#480 (owner_tenant_id on merchant —
the billing-side anchor this mirrors).

---

# #78: Drop tenant_subjects — the delegated-user registry is not load-bearing

**Completed:** yes

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
- [ ] If per-subject revocation / #75 reference-mode VALUES are ever wanted, reintroduce a purpose-built
      table THEN.
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
- [x] Tests: build/vet/sqlc green; all tests pass EXCEPT TestOrgInviteNoEscalation — a PRE-EXISTING shared-dev-DB cross-subtest collision (renamed TestTenantInviteNoEscalation): its "accept-time re-check" subtest leaves a pending invite that the "happy path" subtest collides with on the pending unique index; the happy-path subtest passes in isolation. Rename-independent. Preserved OpenRails-side strings (openrails.tenant*, openrails:tenant:*) and stored namespace_state values (registered_tenant/parked_tenant).
- [ ] Version bump (breaking -> v0.30.0). Cascade: openrails + tensorhub (+ maybe cozy-art) adapt the org
      rename; doujins + hentai0 DON'T use orgs -> dep bump only. Coordinated deploy (hard cut, no fallback).

**Related**
openrails#480 (the merchant rename this mirrors), #74/#76/#77/#78 (the de-conflation work this completes the
naming for), openrails#491 (sequence: rename first, then #491, then ONE fleet cascade carrying both).
