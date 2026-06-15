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

**Completed:** yes — but PARTIALLY REVERSED by #81 (2026-06-14): the AUTH finding still holds (no verify-path
read), but downstream APP + BILLING domains DO want a stable FK anchor for the delegated user, so the table
is restored as `delegated_users` for cross-domain FKs (not for auth). See #81.

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
- [x] Tests: build/vet/sqlc green; all tests pass. TestOrgInviteNoEscalation was a test-isolation bug (the "accept-time re-check" subtest correctly leaves a pending invite; the "happy path" subtest reused the same invitee and collided on the pending unique index during SETUP) — FIXED 4564339 by giving the happy-path subtest a distinct invitee; the no-escalation SECURITY invariant was verified intact. Preserved OpenRails-side strings (openrails.tenant*, openrails:tenant:*) and stored namespace_state values (registered_tenant/parked_tenant).
- [ ] Version bump (breaking -> v0.30.0). Cascade: openrails + tensorhub (+ maybe cozy-art) adapt the org
      rename; doujins + hentai0 DON'T use orgs -> dep bump only. Coordinated deploy (hard cut, no fallback).

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
      so a SET value still validates). Idempotent; fresh 001..011 chain green.
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
#77 (set NOT NULL — this reverses it), #79 (org rename), #81 (delegated_users restore), openrails#491
(org-binding -> payer-resolution switch).

---

# #81: delegated_users — RESTORED (011) then REVERTED / RE-DROPPED (invoker is opaque text, no FK)

**Completed:** restore shipped (011); RE-DROP pending (owner reversal 2026-06-15)

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
ACTION (do it yourself, no sub-agents): new migration DROPs profiles.delegated_users;
delete core/delegated_users.go (TouchDelegatedUser / GetDelegatedUser /
ListDelegatedUsersForIssuer) + its sqlc queries + tests; re-run sqlc; re-tag synced
with openrails. The RESTORE (011) recorded below is now HISTORICAL. See openrails#491
(the paired `invoker_id uuid FK` -> `invoker text` reversal).
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

**Outcome:** delegated_users restored (011) as a cross-domain FK anchor; uuidv7 pk, idempotency on the
UNIQUE natural key (no uuidv5/derived id). sqlc regen + build/vet/full-suite green. Consumer cascade
(openrails#491 invoker_id FK; tensorhub soft du_ -> real FK) is the separate follow-up noted below.
**Re-drop tasks (the reversal — supersedes the restore above):**
- [ ] New migration: `DROP TABLE IF EXISTS profiles.delegated_users` (idempotent). It carries no
      load-bearing data (write-mostly; nothing FKs to it now).
- [ ] Delete core/delegated_users.go (TouchDelegatedUser / GetDelegatedUser / ListDelegatedUsersForIssuer),
      its sqlc query file + generated code + models entry, and delegated_users_test.go. Re-run sqlc.
- [ ] Build/vet/full-suite green on a fresh migration chain; re-tag authkit synced with openrails.

**Related**
#78 (original drop — #81 un-dropped, this reversal re-drops; #78's finding was right all along),
#80 (nullable org_id — unaffected, stays), openrails#491 (paired reversal: invoker_id uuid FK -> invoker
text, no FK), [[invoker-opaque-text-polymorphic]] memory.
