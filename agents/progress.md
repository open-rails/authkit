<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 77

---

# #76: JWKS-principal programmatic auth — a self-signed external key as a first-class credential with STORED permissions/role (parallel to service tokens)

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

---

# #75: App-specific escape hatch — the delegated-token `attributes` bag as the remote_application→platform contract, with INLINE + REFERENCE claim modes (reference resolves against a generic AuthKit-hosted definition registry)

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

# #67: Standardize embedder verification config on AUTH_REQUIRE_VERIFIED_REGISTRATIONS bool; retire 'none' from the embedder surface

**Completed:** no

Fleet decision (2026-06-11): every authkit embedder (doujins, hentai0, tensorhub, cozy-art) exposes ONE registration-verification knob: config key auth.require_verified_registrations / env AUTH_REQUIRE_VERIFIED_REGISTRATIONS, a bool, DEFAULT TRUE. Semantics: true => core.RegistrationVerificationRequired (verification gates login); false => core.RegistrationVerificationOptional (verification email/SMS is STILL SENT on signup when a sender is configured, but never blocks login; with no sender, core already degrades gracefully by creating the user as verified and sending nothing — see CreatePendingRegistration* 'verified := s.email == nil'). The 'none' tier (no verification artifacts at all) is no longer reachable from any embedder's config; embedders were migrated to this pattern in their own repos on 2026-06-11.

authkit-side follow-ups: (1) document the canonical embedder pattern (bool -> Required/Optional mapping, the graceful no-sender behavior under Optional, and the recommended AUTH_REQUIRE_VERIFIED_REGISTRATIONS name) in the README/embedding docs so new hosts don't re-invent names (history: doujins alone has cycled through AUTH_VERIFICATION_REQUIRED, AUTH_REQUIRE_VERIFIED_REGISTRATIONS, AUTH_REGISTRATION_VERIFICATION, and back); (2) decide whether core.RegistrationVerificationNone should be deprecated/removed from core now that no first-party embedder uses it — if kept (e.g. for the devserver/tests), mark it internal/dev-only in the policy docs; (3) align authkit-devserver: DEVSERVER_REGISTRATION_VERIFICATION currently defaults to 'none'; switch it to the same bool name + optional-by-default-false / required-default-true semantics so the devserver mirrors what hosts actually run.

DECISION 2026-06-11 (Paul): authkit KEEPS the tri-state enum (none/optional/required) as its library interface — third-party embedders may legitimately want 'none'. Do NOT convert core.Config.RegistrationVerification to a bool. The bool (AUTH_REQUIRE_VERIFIED_REGISTRATIONS, default true, true=>required, false=>optional) is the FIRST-PARTY EMBEDDER config convention only; each app maps bool->enum at its config boundary (already done in doujins/hentai0/tensorhub/cozy-art).

**Tasks:**
- [ ] Document the canonical embedder pattern in README/embedding docs: AUTH_REQUIRE_VERIFIED_REGISTRATIONS bool (default true), true=>Required, false=>Optional (still sends, never blocks; no-sender degrades gracefully).
- [x] Decide fate of core.RegistrationVerificationNone: KEEP the enum incl. 'none' (decision 2026-06-11, see description); document it as available to embedders that want no-verification behavior, while the first-party convention maps bool->required/optional.
- [ ] authkit-devserver: replace DEVSERVER_REGISTRATION_VERIFICATION tri-state (default 'none') with the standardized bool knob.
- [ ] Add a core test asserting Optional-with-no-sender creates the user as verified and sends nothing (locks in the graceful-degrade contract embedders now rely on).

---

# #68: HARD CUT: delegated tokens are issuer-only — no tenant_id AND no tenant slug claims

**Completed:** no

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

**Completed:** no

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
