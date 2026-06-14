<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 79

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

**Completed:** no

Today `profiles.remote_applications.owner_user_id -> users` anchors an issuer's ownership to a single
CREATOR user. Re-anchor ownership to the owning ORG: add `remote_applications.tenant_id -> tenants`
(NOT NULL). One tenant has MANY remote_applications (issuers); each issuer belongs to exactly ONE tenant.

WHY:
- Robustness: ownership survives the creator leaving the org (it's the org's, not a person's).
- Deterministic MERCHANT resolution (openrails#491): issuer -> remote_app.tenant_id is a single FK hop to
  exactly ONE tenant; the tenant is the OPERATOR and is 1:1 with its merchant, so a token resolves
  issuer -> tenant -> merchant (the billing namespace). The actor's customer (payer) is the end-user under
  that merchant. This SUPERSEDES the current stance (owner_tenant_id "ownership-only, one tenant owns MANY
  merchants, never used to resolve from a token"): make owner_tenant_id UNIQUE (1:1) + resolution-bearing.
  No membership-walk / "first matching membership" ambiguity. The tenant = operator (owns merchant +
  issuers), NOT the customer.
- Clean separation: the polymorphic `tenant_memberships` then means ONLY "this issuer's self-token gets
  these roles" (#76) — purely auth, fully decoupled from ownership/billing.

Keep `owner_user_id` as a NULLABLE creator-audit (ON DELETE SET NULL), or drop it.

**Tasks:**
- [ ] Migration: add `remote_applications.tenant_id uuid NOT NULL REFERENCES profiles.tenants`; backfill
      from existing ownership; make owner_user_id nullable (creator-audit) or drop.
- [ ] Core: GetRemoteApplication returns tenant_id; create/update enforce exactly one tenant; add a
      ResolveRemoteApplicationTenant (by tenant_id FK).
- [ ] Keep tenant_memberships for self-token ROLES only (#76); document ownership(tenant_id) vs
      roles(membership) split.
- [ ] Tests: issuer->tenant is 1:1; ownership survives creator-user deletion; one-tenant-many-issuers.
- [ ] Consumer note: openrails#491 merchantForIssuer switches to the tenant_id FK.

**Related**
#74 (remote_application table this amends), #76 (membership = roles only, post-split), openrails#491
(customer/actor split + merchantForIssuer via tenant_id), openrails#480 (owner_tenant_id on merchant —
the billing-side anchor this mirrors).

---

# #78: Drop tenant_subjects — the delegated-user registry is not load-bearing

**Completed:** no

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
- [ ] Replace the TouchTenantSubject* call in the delegated-token middleware with a read-only
      GetRemoteApplication(issuer) enabled lookup, so unknown/disabled issuers still fail closed — but with
      NO per-request write.
- [ ] Delete core/tenant_subjects.go + the TenantSubjectTouch query + the db model.
- [ ] Migration: DROP TABLE profiles.tenant_subjects.
- [ ] Confirm nothing else reads it (attribute_defs #75 key on remote_application, not subject; permissions
      #76 likewise).
- [ ] If per-subject revocation or #75 reference-mode (pre-stored) attribute VALUES are ever wanted,
      reintroduce a purpose-built table THEN — do not keep this one speculatively.
- [ ] Tests: delegated auth still works with the table gone; unknown/disabled issuer still rejected
      (fail-closed gate preserved); no per-request write on the delegated path.

**Related**
#74 (created the remote_application model + re-pointed this table), #75 (attribute DEFS stay; only defs are
stored — values ride on the token), #76 (permissions on the principal), openrails#491 (delegated-user
(issuer, subject) is tracked on the BILLING side as the actor — the non-redundant place).
