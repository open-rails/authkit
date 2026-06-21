<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 101

---

# #100: allow application-defined permission prefixes in org-scoped RBAC

**Completed:** no
**Status:** IN_PROGRESS 2026-06-20 (Claude): app-defined org-scoped prefixes already work as opaque strings end-to-end (a role granted `repo:*` passes `HasPermission("repo:read")` — see `TestHasPermissionUsesSingleRoleGrantQuery`); the missing piece OpenRails #554 needs was OWNER coverage. Implemented as an OPT-IN, redesigning line-43's "owner does not auto-grant app prefixes": new `Config.OwnerOwnsAppResources bool` (default FALSE — AuthKit imposes no ownership policy, #95 owner=`org:*` preserved). When an app sets it true, the prebuilt `owner` role is seeded `org:*` PLUS one `<ns>:*` glob per non-`platform:` namespace it declares in `Config.Permissions` (`ownerGrantTokens`), so the org owner owns every app resource namespace (OpenRails `merchant:*`; future TensorHub `endpoint:*`/`repo:*`/`dataset:*`). `EnsureOwnerGrants(orgSlug)` reconciles owners of pre-existing orgs. Files: core/org_role_permissions.go (helpers + 4 owner-seed sites consolidated), core/config.go + core/service.go (flag), core/owner_grants_test.go (pure + PG-backed: owner holds `merchant:*`, still can't reach `platform:`, default-off stays `org:*`, reconcile). Full `go test ./core/` green against PG. REMAINING: verify/strengthen platform-disjointness + app-catalog-rejects-`org:`/`platform:` guard tests; README/api-endpoints.md docs; version bump.

ORIGINAL PLAN 2026-06-20: AuthKit should reserve the RBAC scope mechanics, not every permission namespace. `platform:` stays AuthKit-reserved for platform roles. `org:` stays AuthKit-reserved for AuthKit's own org-management routes. Applications embedding AuthKit may define their own org-scoped permission prefixes, such as OpenRails `merchant:*`, and AuthKit stores/checks them as opaque strings.

## Problem

OpenRails wants merchant permissions like `merchant:payments:refund`, scoped to
the AuthKit org that owns the merchant. AuthKit should allow that. The current
model and comments lean too hard toward "org roles contain `org:*` permissions"
and make app-owned resource prefixes feel invalid or second-class.

Permissions are just strings in AuthKit's DB. AuthKit's job is:

- store role -> permission strings;
- validate that grants are known and non-escalating;
- expand namespace globs against the declared catalog;
- keep platform and org-scoped authority disjoint.

AuthKit should not require application permissions to start with `org:`.

## Target Model

- `platform:*` is reserved for AuthKit platform roles only.
- `org:*` is reserved for AuthKit org-management permissions only.
- App permissions are declared by the embedding app in `Config.Permissions`.
- App permissions may use app-chosen prefixes: `merchant:*`, `repo:*`, `endpoint:*`, `billing:*`, etc.
- Org roles may include AuthKit `org:*` permissions and app-defined permissions.
- Platform roles may include only AuthKit `platform:*` permissions.
- `owner` keeps `org:*` for AuthKit org-management. It should not automatically grant every app-defined prefix unless the app explicitly grants those permissions to the role.
- Globs remain namespace-anchored and catalog-expanded. `merchant:*` expands over declared `merchant:` permissions; bare `*` stays invalid.

## Tasks

- [ ] Rename comments/docs that imply org-scoped roles must use `org:` permissions; say org-scoped roles can hold AuthKit `org:*` plus app-defined permission strings.
- [ ] Keep `platform:` blocked from org roles and every app permission catalog.
- [ ] Keep `org:` blocked from app permission catalogs except AuthKit's built-in org-management permissions. DEFERRED: coupled to OpenRails #554 — OpenRails STILL declares app `org:` perms today (`org:credits:read`, `org:billing:read`, ...); enforcing this now would reject its catalog. Enforce once #554 moves OpenRails to `merchant:*`. (Today `Permissions()` silently drops an app perm that collides with a base `org:` name — base wins — so there is no escalation risk, just no hard rejection yet.)
- [x] Ensure app-declared prefixes like `merchant:` validate in `Config.Permissions`, role permission writes, and API-key role grants. VERIFIED: `Config.Permissions` accepts any namespace (opaque); `SetRolePermissions` stores tokens opaquely; `ValidateGrant` expands app globs against the catalog with no-escalation; `TestHasPermissionUsesSingleRoleGrantQuery` (`repo:*`) + `TestOwnerHoldsAppNamespaceEndToEnd` (`merchant:*`) cover role-write -> HasPermission end-to-end.
- [x] Ensure `ValidateGrant` no-escalation works for app-defined literals and globs (`merchant:payments:refund`, `merchant:*`) exactly like it does for `org:*`. VERIFIED: `ValidateGrant` (org_role_permissions.go) expands every token against `knownPermissions()` (base ∪ app) and requires the actor to hold each expanded perm — namespace-agnostic, so app prefixes behave exactly like `org:*`.
- [x] Ensure `ValidatePlatformGrant` still rejects every non-`platform:` token, including app prefixes. VERIFIED + TESTED: platform_rbac.go:302 rejects any non-`platform:` token as unknown even with `actorAll`; `TestPlatformGrantRejectsAppNamespace` proves `merchant:*` / `merchant:payments:refund` / `org:members:read` are all rejected on a platform grant.
- [x] Add tests proving an org role can hold an app permission, a user with that role passes `HasPermission`, and an app glob expands only over declared app perms. DONE: existing `TestHasPermissionUsesSingleRoleGrantQuery` (`repo:*` role -> `HasPermission("repo:read")`) + new `TestOwnerHoldsAppNamespaceEndToEnd` (`merchant:*`).
- [x] Add tests proving platform roles reject `merchant:*`. DONE: `TestPlatformGrantRejectsAppNamespace`. (App-catalog-rejects-`org:`/`platform:` test is paired with the deferred validation above — coupled to OpenRails #554.)
- [x] **NEW (opt-in owner ownership, #554 prerequisite):** add `Config.OwnerOwnsAppResources` so the org `owner` auto-owns every app-declared resource namespace (`<ns>:*`), default off; `ownerGrantTokens` + `seedOwnerGrants` (4 seed sites) + `EnsureOwnerGrants` reconcile; pure + PG-backed tests (owner holds `merchant:*`, can't reach `platform:`, default-off stays `org:*`). Redesigns the line-43 "owner does not auto-grant" note into an explicit app opt-in.
- [x] Update README permission docs with the reserved-prefix rule, an OpenRails-style `merchant:*` example, and the `OwnerOwnsAppResources` opt-in. DONE in README.md RBAC section (also corrected the #95-stale "owner seeded with `*`" -> `org:*`). (`agents/api-endpoints.md` org-RBAC table is unaffected — it documents the reserved `org:` management routes only.)

## Acceptance

- AuthKit stores and evaluates app-defined permission prefixes as opaque strings.
- `platform:` remains reserved to platform roles and cannot appear in org roles or app catalogs.
- `org:` remains reserved to AuthKit org-management and cannot be redefined by apps.
- OpenRails can define `merchant:*` permissions and bind them to routes while AuthKit scopes the grant to the owning org.
- No schema migration is needed.

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** no

**VERIFICATION 2026-06-20 (Claude):** the `yes` marker was WRONG — the feature is
ENTIRELY ABSENT in code. No `go-webauthn` dependency, no `002_user_passkeys`
migration (migrations are 001–007, none touch passkeys), no `profiles.user_passkeys`
table, no `RoutePasskeys` group/handlers/storage, no `*passkey*`/`*webauthn*` files
anywhere. None of the tasks below are implemented. Reopened.

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
