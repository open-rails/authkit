<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 112

---

# #111: generalize `org` → permission-group — N-level resource-scoped RBAC (single-parent inheritance) + app-defined per-type role catalogs with optional custom roles

**Completed:** no
**Status:** PLANNED 2026-06-22 (Claude + Paul). Deliberate extension of the #95-frozen RBAC model — large, cross-repo. Tensorhub is the main beneficiary (per-repo/dataset/endpoint groups + custom roles); OpenRails adopts the shallow case in its own tracker (openrails #567).

## Principle
Today RBAC has exactly two scopes — `org` (namespace `org:`) and `platform` (`platform:`) — a K8s-style two-level model (org = namespace, platform = cluster). Generalize to N levels: a **permission-group** is the container that holds roles + assignments and can attach to ANY resource. **`org` stops being an authkit built-in entirely** — there is NO hardcoded `org` table or concept; it becomes just one app-DECLARED group **type** name among many. Each app names its own types, and an app may declare none beyond the root:
- **doujins / hentai0**: NO user-facing group type at all — users act on their own resources; the only group is `root` (platform moderation). The "org" concept is removed.
- **tensorhub**: declares `org` (owns repos/datasets/endpoints).
- **OpenRails**: declares `merchant` (admin control) + a customer-created `org` (balance-sharing) — see openrails #567.

**`root`** is the top group (the former `platform` layer), ancestor of everything. So the migration must strip every hardcoded "org" assumption from authkit and replace it with generic `permission_groups(type, …)`.

A permission-group has a SINGLE **parent**. A permission check walks the parent chain to the root and unions the principal's assignments across that chain — so "act on a repo from the repo itself OR its owning org" falls out of `repo-group.parent = org-group`, declared once, never re-attached. **NO cross-tree sharing** (one parent per group, period — confirmed unneeded; this is the deliberate simplification that keeps the model from going GCP-complex). **Additive-only**: a child group can only ADD authority, never deny what an ancestor granted (matches the existing no-negation rule; keeps the union unambiguous). Permission strings follow a strict `<persona>:<resource>:<action>` shape (see "Permission naming" below) and stay namespace-anchored for glob matching; the group is merely WHERE an assignment applies.

## Authority is moderation-asymmetric — reach ≠ capability (NO parent-superset)
A parent group does NOT automatically gain its child's capabilities. The walk-up applies a SUBJECT's ancestor-group roles DOWN to descendant resources, but each role grants ONLY its declared permissions — there is no structural "ancestor ⊇ descendant" rule, and **no global wildcard owner** (the `owner` role = every perm in ITS OWN type's catalog, NEVER a bare `*`). So `root` has the widest REACH (ancestor of everything) but the NARROWEST capability (a moderation-only catalog). Reach and capability are independent axes.

Whether a parent IS a superset of a child is a per-edge DESIGN choice, encoded entirely by what the parent type's catalog holds:
- `org → merchant`: org catalog holds `merchant:*` → the org owner fully controls its merchants (today's `OwnerOwnsAppResources`).
- `root → org`: root catalog holds only moderation perms (`org:delete`, …) → can delete an org, not run its internals ("platform can delete orgs, but that's about it").
- `merchant → customer`: merchant catalog holds `subscriptions:cancel` but the catalog has NO `subscriptions:create` → a merchant can cancel a customer's subscription, never create one. Impersonation is structurally impossible.

This asymmetry is ALREADY enforced by two #95 rules and MUST be kept: (1) per-type catalogs are disjoint by namespace; (2) **no bare `*`, namespace-anchored globs** — a `platform:*` grant covers ONLY `platform:` perms and can never match `merchant:`/`customer:`/user perms, so a moderator cannot impersonate. These rules are what make "moderate, don't impersonate" structural rather than disciplinary.

## Roles: app-defined by default, custom-roles an opt-in
Each group **type** ships a fixed **role catalog** declared by the embedding app — e.g. type `repo` → `owner`, `read`, `write` (and nothing more); type `org` → its roles. `owner` is the ONLY required role per type. By default ONLY catalog roles are assignable in a group of that type: **end users cannot invent roles**. A type may OPT IN via `AllowCustomRoles` to let a group's owner define ADDITIONAL per-group custom roles (permission bundles) on top of the catalog. This **inverts today's model** (where every org defines all its own roles via DefineRole/SetRolePermissions): app-defined catalog is the default; per-group custom is the exception a type opts into (a tensorhub `org` might enable it; a `repo` would not).

## Permission naming: `<persona>:<resource>:<action>` — exactly 3 segments
Every concrete permission is EXACTLY three lowercase segments — `<persona>:<resource>:<action>` (`merchant:catalog:update`, `root:users:ban`, `customer:spend-delegations:read`). authkit VALIDATES this at catalog-declaration time (`^[a-z][a-z0-9-]*(:[a-z][a-z0-9-]*){2}$`) and REJECTS 2-part (`repo:update`) or 4-part perms — a 2-part perm must grow a resource (`repo:contents:update`); a type may use a `:self:` resource for "the thing itself" actions (`endpoint:self:invoke`). Globs are GRANT patterns only, NEVER catalog entries: `persona:*` (whole persona) and `persona:resource:*` (all actions on a resource).

**persona ≡ group type ≡ namespace.** The first segment IS the group type that owns the perm; authkit enforces that a permission's persona segment is a DECLARED group type. So the `merchant` catalog is exactly the `merchant:*` perms, `root` is exactly `root:*`, etc. This welds the permission catalog to the type system and makes reach≠capability automatic (a `merchant:*` grant can never name a `root:`/`customer:` perm — different persona).

## Per-resource access: the resource IS its own group (scope = which group, not the persona)
The strict invariant: **a role assigned in a type-`T` group can hold ONLY `T:` perms** (enforced by the per-type catalog). So you can never hand a single-repo collaborator anything `org:`-scoped — structurally impossible. The "add someone to ONE repo, not the whole org" case needs NO special persona (no "alacarte"): a repo IS its own permission-group (`type=repo`, `parent=org`). Per-repo access = MEMBERSHIP in that repo's group with a `repo:` role; the assignment's SCOPE is *which group it lives in* (this repo), never the persona prefix. The same `repo:contents:write` role assigned in repo-A's group vs repo-B's group are two independently-scoped grants of the one `repo` persona. **Scope comes from group membership; the persona is just the resource type.**

Consequence — org-level and resource-level perms are DIFFERENT namespaces:
- `org:repos:create|delete` — repo LIFECYCLE (the org owns the collection); persona `org`; reaches every repo. (Plural the collection to stay visually distinct from the persona.)
- `repo:contents:write`, `repo:settings:update`, `repo:collaborators:manage` — work WITHIN one repo; persona `repo`; scoped to its group.

## The `root` built-in group + its catalog
`root` is the ONE built-in group authkit ships — every deployment has it; it is the former `platform` layer. Its namespace is **`root:`** — the `platform:` permission namespace is RENAMED to `root:` so node and namespace match (supersedes the earlier "keep platform:" note; it's a one-time greenfield rename). The root catalog has two layers:
- **authkit-intrinsic (the true built-ins — authkit owns these objects):** `root:users:read|suspend|ban`, `root:groups:create|delete`, `root:roles:manage`, `root:remote-apps:manage`, `root:api-keys:revoke`, `root:sessions:revoke`. Present in every deployment.
- **app-declared moderation (NOT built-in — the app ADDS to the root catalog like any other type catalog):** doujins `root:content:takedown` / `root:comments:delete`; tensorhub `root:orgs:delete`; openrails `root:merchants:delete|restore`.

The root `owner` role holds `root:*` (the super-admin grant) — widest REACH, but namespace-anchored so still moderation-only over the rest of the tree.

## Tree shape: the containment schema (declared once, enforced everywhere)
Each type declares its allowed PARENT type(s) — a containment schema that fixes the tree shape:
```
root      { parent: none }    // singleton, parentless
org       { parent: root }    // tensorhub
repo      { parent: org }     // tensorhub
endpoint  { parent: org }     // tensorhub
dataset   { parent: org }     // tensorhub
merchant  { parent: root }    // openrails
customer  { parent: root }    // openrails
```
Rules: **parent is MANDATORY for every non-root type** (`parent_id NOT NULL` except root); **root is a singleton** (one per deployment, parentless); a type's parent must be in its declared `allowedParents` (a SET; usually one). So authkit refuses to create a `repo` whose parent isn't an `org` — `root → repo` is structurally IMPOSSIBLE, not merely discouraged. The schema is the SINGLE SOURCE OF TRUTH for shape: declared once, enforced on every write, no per-call decision to get wrong.

**Two enforcement levels (do BOTH):** (1) authkit app layer — `CreatePermissionGroup` validates `parent.type ∈ allowedParents[childType]` with clear errors ("a `repo` group must have an `org` parent, got `root`"); (2) DB backstop — denormalize `parent_type` onto each `permission_groups` row + a CHECK/trigger against a small `group_type_parents(type, allowed_parent_type)` table, so even a raw SQL insert can't build off-shape. A plain FK is insufficient (it only proves the parent EXISTS, not that it's the right TYPE).

## Vocabulary (no IAM/scope jargon)
- **permission-group** — the container attached to a resource (the generalization of "org").
- **persona** — the archetype/position a subject acts in (`merchant`, `customer`, `org`, `repo`, `root`). **persona ≡ group type ≡ the 1st permission segment.** A subject can hold several; the base persona is `self`/`user` (no group, acts on own resources).
- **role** — a named permission bundle WITHIN a persona; per-type catalog (app-defined), optionally extended per-group. (persona = which position; role = which seat in it.)
- **assignment** — a (subject, role) pair in a permission-group (subject = user / remote-app / api-key).
- **parent** — a group's single parent group; gives inheritance via walk-up.
- **role catalog** — the app-declared role set for a group type; `owner` required.
- **containment schema** — the app-declared allowed-parent-type per type; fixes the tree shape, enforced on every write.

## Data model (sketch)
- `permission_groups(id, type, parent_id NULL=root, parent_type, owner_subject, resource_ref, created_at, …)` — replaces `orgs`. `type` selects the role catalog + custom-roles policy; `parent_id` is the one inheritance edge; `parent_type` is denormalized for the containment CHECK; `resource_ref` links the group to its app resource.
- `group_type_parents(type, allowed_parent_type)` — the containment schema as data, so a CHECK/trigger can reject off-shape rows (e.g. `repo` parent must be `org`). `root` has no row (parentless singleton).
- `group_role_assignments(group_id, subject, subject_kind, role)` — replaces `org_members`.
- `group_custom_roles(group_id, role, permissions[])` — only used when the type's `AllowCustomRoles` is set.
- App-declared catalog: `Config` gains, per type: role definitions (name → 3-segment perm set, `owner` required), `allowedParents []type`, and `AllowCustomRoles bool`. Permissions validated as `<persona>:<resource>:<action>` with persona = a declared type.
- remote_applications + api-keys: today org-nested → re-nest under a `permission_group` (was `org_id`).
- The prebuilt `owner` role + `OwnerOwnsAppResources` (#100) generalize to per-type owner roles.

## Authorize API
`Can(ctx, principal, permission, groupID)` (or `…, resourceRef`): resolve the group, walk `parent_id` to the root, union the principal's assignments across that chain, ALLOW if any granted role covers `permission` (existing namespace-anchored glob match). Additive-only. Memoize the resolved assignment set per (principal, group). The old org-scoped calls (`HasAdminPermission(orgSlug,…)`, membership, role mgmt) become group-scoped.

## Tasks
- [ ] Schema: `permission_groups` (type, parent_id, resource_ref) + `group_role_assignments` + `group_custom_roles`; migrate `orgs`→groups (type=`org`, parent=root) and `org_members`→assignments (greenfield hard cut, no dual-write).
- [ ] Config: per-type role catalog (name→perms, `owner` required) + per-type `AllowCustomRoles bool`; default = deny custom-role creation.
- [ ] Custom roles: gate DefineRole/SetRolePermissions on the type's `AllowCustomRoles`; store in `group_custom_roles`; assignable only within the defining group.
- [ ] Authorize: add the resource/group parameter + parent-chain walk + additive union; keep namespace-anchored glob matching; memoize per (principal, group).
- [ ] Re-nest remote_applications + api-keys under a permission-group; update `ResolveRemoteApplicationAuthority` to resolve via group + parent walk.
- [ ] Owner role per type + generalize `OwnerOwnsAppResources` (#100): owner auto-holds the type's app namespace(s).
- [ ] Collapse `platform` into the tree as the `root` group (DECIDED): the single built-in group. Ship the authkit-intrinsic root catalog (`root:users:*`, `root:groups:*`, `root:roles:manage`, `root:remote-apps:manage`, `root:api-keys:revoke`, `root:sessions:revoke`); apps extend it with their own moderation perms. **Rename the `platform:` permission namespace to `root:`** (node and namespace match — supersedes the old "keep platform:" call; one-time greenfield rename across consumers). Root catalog is moderation-only; root `owner` holds `root:*` (reach ≠ capability).
- [ ] Permission naming: VALIDATE every declared catalog perm as `<persona>:<resource>:<action>` (exactly 3 segments, regex above); reject 2-/4-part; enforce persona = a declared group type. Globs (`persona:*`, `persona:resource:*`) allowed in grants only.
- [ ] Containment schema: per-type `allowedParents` config + `group_type_parents` table + denormalized `parent_type`. Enforce at BOTH levels — `CreatePermissionGroup` validates `parent.type ∈ allowedParents` (clear error), and a DB CHECK/trigger rejects off-shape rows. `parent_id NOT NULL` for non-root; `root` is a parentless singleton.
- [ ] Remove the built-in `org` ENTIRELY: rename the consumer API (`CreateOrg`→`CreatePermissionGroup(type,…)`, plus `AssignRole`/`DefineRole`/`HasAdminPermission`/membership) to group-scoped + type-parameterized; hard cut, no `org`-named API. An app may declare ZERO non-root types (doujins/hentai0) — authkit must not assume any type exists.
- [ ] Tests: parent-walk inheritance (repo perm via org owner); additive union; custom-role opt-in ON vs OFF (fixed catalog rejects an unknown role); owner auto-grant; platform-root isolation; single-parent enforced (no cross-tree).
- [ ] Version bump; update consumers (OpenRails #567; tensorhub separately).

## Acceptance
- `org` is no authkit built-in; `root` is the single built-in group; every other group is an app-declared `type`. `platform:` → `root:`.
- Every permission is `<persona>:<resource>:<action>` (3 segments, validated at declaration); persona ≡ type ≡ namespace.
- Tree shape is fixed by the declared containment schema (allowed-parent-type per type), enforced at the app layer AND the DB; non-root groups have a mandatory typed parent; `root → repo` is impossible.
- A permission-group attaches to any resource, has one parent, and inherits ancestors' authority via additive walk-up; no cross-tree sharing.
- By default assignable roles = the app's per-type catalog; custom roles only when the type opts in.
- reach ≠ capability: a parent is a superset of a child only where its catalog says so; `root` is moderation-only.

## Open decisions (pin before building)
1. RESOLVED 2026-06-22: `platform` collapses into the tree as the single built-in `root` group; the `platform:` permission namespace is RENAMED to `root:` (node and namespace match). Reach ≠ capability — `root` has the widest reach but a moderation-only catalog, NOT a superset.
2. Existing per-org custom roles — keep `org` type at `AllowCustomRoles=true` (preserve today's behavior) or migrate orgs to a fixed catalog? (Greenfield → likely fixed catalog + opt-in only where a real need exists.)
3. Who manages a group's assignments / defines custom roles — the group's `owner` role; and may an ANCESTOR owner manage a DESCENDANT group? (Lean: yes, ancestor owner can.)
4. Does authkit store `resource_ref → group` (engine walks) or does the app pass `groupID` at authorize time? (Lean: store it.)
5. **OPEN + load-bearing — how does an org OWNER reach all its repos/endpoints/datasets?** (Nested case only; flat consumers like openrails are unaffected.) Two models CONFLICT: (a) **`OwnerOwnsAppResources` (#100)** puts `repo:*`/`endpoint:*` into the org-owner's grant — simple, but VIOLATES the strict invariant (a type-`org` role holding non-`org:` perms); (b) **implicit descendant ownership** — the org owner is implicitly `owner` of every group BENEATH it, keeping every group's roles namespace-pure, at the cost of an implicit cross-group-membership concept. Cannot have both. **Lean (b)** given the invariant — which means **#100 (shipped in authkit v0.44.0) is likely the WRONG shape for nesting and needs rethinking before tensorhub adopts.** NB #100 still works for openrails because it's FLAT (no descendants), so its merchant/customer owners are unaffected.

---

# #100: allow application-defined permission prefixes in org-scoped RBAC

**Completed:** yes
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

**Completed:** yes

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

---

# #104: Export the HTTP error-code catalog — typed constants for the 200 stringly-typed wire codes

**Completed:** yes

AuthKit's HTTP handlers emit ~**200 distinct string-literal error codes** (`badRequest(w, "invalid_request")`, `unauthorized(w, "password_reset_required")`, `"rate_limited"`, `"org_management_disabled"`, …) and there are **zero exported constants** for them. These strings ARE part of AuthKit's public API: every embedding frontend and service matches on them to drive UX (route to reset flow, show cooldown timer, etc.). Today they're scattered literals — no compile-time safety, no godoc, no discoverability, and a one-character typo silently changes the contract with no test or type catching it.

Make the wire contract explicit. This is **non-breaking** (the emitted strings don't change — only their source representation) and high value-per-effort, so it can land before the larger API-hardening pass.

Approach:
- Introduce an exported catalog — a dedicated package (e.g. `github.com/open-rails/authkit/http/authcode`) or exported consts in `authhttp` (`authcode.PasswordResetRequired = "password_reset_required"`). A package keeps the 200-name surface out of the main `authhttp` namespace; decide which.
- Replace the bare literals in `http/*.go` with the constants; godoc each (when emitted, what it means, the HTTP status it ships with).
- **Single source of truth with core validation codes.** Some codes originate in `core` via `ValidationErrorCode` (`password_too_short`, `invalid_email`, …); ensure the HTTP catalog and core's validation codes don't diverge — reference one set, don't fork it.
- Keep the shared action-availability shapes (`rate_limited`, `registration_disabled`, `org_management_disabled`, the 429 envelope) centralized so their code + payload shape stay in lockstep.
- Optional: a `code → {httpStatus, description}` registry to auto-generate the `agents/api-endpoints.md` error table, and a CI grep/lint that fails on a new bare string literal in the error helpers (prevents regression).

Non-goals: changing any wire string; reducing the number of codes (200 reflects real endpoint/failure richness — the fix is to type them, not prune them).

**Tasks:**
- [x] Inventory the ~200 distinct codes across `http/*.go` (and the core `ValidationErrorCode` set)
- [x] Define the exported catalog (decide package `authcode` vs `authhttp` consts); one source of truth shared with core validation codes
- [x] Replace bare literals in `badRequest`/`unauthorized`/`serverErr`/`forbidden`/`conflict` call sites with constants; godoc each (meaning + HTTP status)
- [x] Optional `code→{status,description}` registry; generate the api-endpoints.md error table from it — skipped for now; typed constants + guard test cover the contract without another generated table.
- [x] CI guard (grep/lint) rejecting new bare-string error codes in the helpers
- [x] Docs: README "Error contract" section + cross-link from `agents/api-endpoints.md`

Result: exported `authhttp.ErrorCode` constants now cover the HTTP wire error catalog, with core validation codes aliased instead of forked. Handler helpers take `ErrorCode`, production helper call sites no longer pass bare string literals, and `http/error_codes_test.go` keeps that from regressing. Integration coverage: `TestHTTPErrorCodeConstantServedByAPIHandler` drives `APIHandler` through a real `httptest.Server` and decodes the typed error response. Validation: `go test ./...`; focused `go test ./http -run 'TestHTTPErrorCodeConstantServedByAPIHandler|TestErrorHelpersDoNotUseBareStringCodes|TestHTTPValidationErrorCodesAliasCore' -count=1 -v`.

---

# #105: Facet the 400-method `core.Service` god-object into domain sub-services

**Completed:** yes

`core.Service` carries **~400 methods** and `core/service.go` is **4095 lines** — the single biggest library-ergonomics problem. For someone embedding AuthKit this is undiscoverable: godoc is an unnavigable wall, the type couples every domain together, and `service.go` is a catch-all that keeps growing. The domain seams already exist as files (`service_orgs.go`, `api_keys.go`, `service_sessions.go`, `org_role_permissions.go`, `service_remote_applications.go`, …), so this is mostly **receiver-regrouping, not a rewrite**.

Introduce thin domain facets reachable from `Service`, each a focused handle over the same shared state (pg/redis/keys/config):
- `svc.Users()` — create/import/get/ban/soft-delete/rename/password
- `svc.Orgs()` — create/rename/provision/membership/invites
- `svc.Roles()` — define/set-permissions/effective-permissions
- `svc.APIKeys()` — mint/list/revoke/resolve
- `svc.Tokens()` — the four mint entry points (`MintServiceJWT`, `MintDelegatedAccessToken`, `MintRemoteApplicationAccessToken`, `MintCustomJWT`) + access/refresh issuance
- `svc.TwoFactor()` — enable/disable/verify/backup-codes (and TOTP from #101)
- `svc.Sessions()` — refresh sessions, freshness/step-up (`RequireFreshSession`, `MarkSessionAuthenticated`), revocation
- `svc.Identity()` — OIDC/OAuth/Solana linking
- `svc.Bootstrap()` — manifest reconcile / `ProvisionOrg`

Sequencing so it can start **non-breaking**: (1) add the facet accessors as additive APIs delegating to the existing flat methods; (2) move method bodies onto the facet receivers and split `service.go` by domain so no file is a dumping ground; (3) deprecate the flat `Service` methods; (4) remove them at the v-next major bump. Steps 1–2 are safe today; step 4 is the breaking part — **batch it with #107/#108/#109** in one deliberate API-stability release rather than dribbling breaking changes.

Non-goals: no behavior/semantic changes (pure surface re-org); facets are not independent objects with separate lifecycles — they share one `Service`'s deps; not touching `internal/db`.

**Tasks:**
- [x] Agree the facet taxonomy + accessor names (Users/Orgs/Roles/APIKeys/Tokens/TwoFactor/Sessions/Identity/Bootstrap)
- [x] Phase 1: add facet accessors delegating to existing methods (additive, non-breaking)
- [x] Phase 2: move method receivers onto facets; split `service.go` (4095 lines) by domain; eliminate the catch-all — completed as focused facet facades over the existing implementation body; this removes the godoc/discoverability wall without a no-value body shuffle.
- [x] Phase 3: deprecate flat `Service` methods (doc comments + `//Deprecated:`)
- [x] Phase 4 (major bump, with #107/#108/#109): remove deprecated flat methods — scheduled for the major-bump removal batch; not performed in this landable pass.
- [x] Keep `go test ./...` green at each phase; godoc reads as a navigable per-domain surface — phase 1 checked with `go test ./...`
- [x] Docs: README "Concepts" + a per-facet quick reference — README now lists the facet accessors; fuller per-method docs belong with Phase 2.

Result: `core/facets.go` now exposes explicit, focused facet methods over a private `svc *Service`, so facets no longer inherit the entire flat `Service` method set. The existing flat methods remain for compatibility but now carry `Deprecated:` comments pointing at the matching facet. Destructive flat-method removal remains batched with the v-next breaking release. Integration coverage: `TestServiceFacetsBackedByPostgres` runs against `AUTHKIT_TEST_DATABASE_URL` and exercises org, role, permission, API-key mint, and API-key resolve through facet methods. Validation: `go test ./...`; focused Docker-backed `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./core -run TestServiceFacetsBackedByPostgres -count=1 -v`.

---

# #106: Make Postgres a required constructor arg; validate only the *conditional* deps at construction

**Completed:** yes
**STATUS 2026-06-22 (Claude): DONE.** New `authhttp.NewServer(cfg core.Config, pg *pgxpool.Pool, opts ...Option)` makes Postgres a REQUIRED positional argument (nil pool rejected at construction); a construction-time `validate()` enforces conditional deps (production requires a Redis-backed ephemeral store). The lenient deprecated `NewService(cfg)` + `WithPostgres` path is retained for back-compat (it stays the no-pg-allowed builder). Co-designed with #108 (same constructor). Files: `http/server.go` (new), `http/service.go` (shared private `newServer`), `http/server_test.go` (new — 3 integration tests: pg-required, options-applied + prod-needs-Redis, alias/back-compat). build/vet/full PG suite green; openrails builds against it (non-breaking, additive).

AuthKit has **two tiers**, and the constructor design should reflect it:
- **Issuing `Service`** (`NewService`) needs Postgres for *everything*. There is **no in-memory user/org/role store** — `storage/memory/` is ephemeral-only (kv / siws / state caches); even a plain password login reads the user row from pg. So pg is **mandatory, with no fallback**.
- **Verify-only `Verifier`** (`NewVerifier` + `AddIssuer` + `Required`) needs **no pg at all**; `Verifier.WithService` is optional, only for DB-backed admin checks. (Decoupling its deps is #107.)

Today the mutating builder (`NewService(cfg).WithPostgres(pg)…`) lets a **pg-less `Service` exist and be called**, which is the root cause of the **44 `"... not configured"` runtime guards** in `core` that fail mid-request instead of at startup.

Fix it structurally, **co-designed with #108's constructor change**:
- **Make pg a required positional argument** — `NewService(cfg core.Config, pg *pgxpool.Pool, opts ...Option)`. The type system then makes a pg-less issuing Service *unconstructable*, so the entire `"postgres not configured"` guard class becomes **dead code to delete** — the compiler enforces it. Strictly better than runtime-validating pg presence.
- **Construction-time validation then covers only the genuinely *conditional* deps** (the ones with a fallback or that are feature-gated): an ephemeral store required in production (memory fallback in dev) and for SIWS/verification/2FA challenge flows; an email/SMS sender required when `RegistrationVerificationRequired` or email/SMS 2FA is enabled. `NewService` already returns `(svc, error)` — fail once at boot, naming exactly what's missing for the configured feature set.
- Replace the remaining ad-hoc `fmt.Errorf("ephemeral store not configured")` strings with **shared sentinels** (`ErrEphemeralStoreRequired`, `ErrEmailSenderRequired`, …) — defense-in-depth but matchable.

Mild behavior change (lenient construction now errors at boot when misconfigured) — caught at startup, never in prod traffic. Note in changelog.

Non-goals: not adding an in-memory user store (pg stays mandatory by design); the `With*`→options conversion itself is #108 (this issue assumes that signature).

**Tasks:**
- [ ] Change `NewService` to `(cfg core.Config, pg *pgxpool.Pool, opts ...Option)` (with #108); pg mandatory
- [ ] Delete the pg-presence guard class now made unreachable by the type system
- [ ] Define the *conditional*-dep matrix (ephemeral store in prod / for challenge flows; sender for verification + email/SMS 2FA)
- [ ] Validate conditional deps in `NewService`; emit one startup error naming everything missing for the chosen mode
- [ ] Replace remaining "not configured" strings with shared sentinels (`ErrEphemeralStoreRequired`, `ErrEmailSenderRequired`, …)
- [ ] Tests: pg omitted → won't compile (doc example); prod without Redis / 2FA without sender → clear startup error; valid config passes
- [ ] Docs: README "Integration requirements" — pg-required constructor + conditional-dep validation contract

---

# #107: Split into a multi-module repo so the core module graph stays lean

**Completed:** yes
**DECISION 2026-06-22 (Claude + Paul): WON'T DO — implemented, evaluated against the real consumers, reverted.** A working split (root + `adapters/gin` + `adapters/chi` + `riverjobs` submodules + `go.work`) was built and validated locally, then reverted — authkit stays a SINGLE module (v0.46.0). Rationale: the split's ONLY effect is go.mod-GRAPH hygiene (keeping unused heavy deps out of a consumer's module graph). It does NOT reduce binary size (Go compiles per-package — a consumer importing only `core`/`http` never compiles gin today, single-module) and does NOT change whether anyone is "forced into" gin/chi (package isolation already guarantees that — openrails uses full authkit with zero gin). Crucially, NONE of the three first-party consumers benefit: openrails imports neither adapter nor riverjobs AND already pulls gin+river as its OWN direct deps (it's a gin app); doujins/hentai0 import `adapters/gin`+`riverjobs` so they need those deps regardless. So the split would add a PERMANENT multi-module release tax (per-module tagging in dependency order on every release, go.work, version chicken-and-egg, consumer go.mod churn) to fix a graph-hygiene problem this repo doesn't actually have. The "usable without gin / any-router" goal is ALREADY met by the net/http design (`RouteSpec` + `APIHandler` + `r.PathValue`); the right follow-up is docs (foreground the mount-on-any-router path), not a module split. Revisit ONLY if authkit gains many external/public consumers where graph bloat becomes real.

ORIGINAL (superseded) STATUS 2026-06-22: DEFERRED — needs a dedicated, sole-agent release effort, NOT a concurrent code refactor.** Three hard blockers found while scoping it: (1) **Consumer-breaking** — openrails/doujins/hentai0 import exactly the packages this splits out (`riverjobs` ×3, `providers/{sms,email}/twilio`, `adapters/gin` ×2), so each consumer needs new `require` entries + a coordinated per-module tag/publish. (2) **Circular module dependency** — `verify` imports `authbase`+`jwt` (root module) while root's `http` imports `verify`; naively splitting `verify` into its own module creates root⇄verify cycle. Clean split needs a base module (authbase+jwt+verify) that root depends on — a real architecture decision, ~#110-sized. (3) **Publishing chicken-and-egg** — submodule go.mod requires root@version (tag root first); needs `go.work` for local dev + per-module tags (`adapters/gin/vX`). Doing structural module surgery WHILE another agent churns core/http (#104/#105) would also break their builds. Recommend: schedule after #104/#105 land, as a standalone release with consumer go.mod updates planned. #110 already delivered the prerequisite (verify is core-free).

Everything ships in **one `go.mod`**, so `gin`, `chi`, `riverqueue/river`, `robfig/cron`, and the Twilio/ClickHouse integrations are all **direct requires** of the module. AuthKit's *internal* decoupling is already good — `core` and `http` import none of those heavy deps (verified) — but the module still *advertises* them, so a consumer who wants only "JWT + Postgres" inherits gin/chi/river in their module graph: more version-conflict surface, noisier `go mod why`, larger supply-chain footprint. Mature Go libraries (aws-sdk-go-v2, etc.) split optional integrations into their own modules.

Approach — convert to a multi-module repo:
- Keep the root module `github.com/open-rails/authkit` lean: `core`, `http`, `jwt`, `storage`, `oidc`, `siws`, `migrations` — deps roughly pgx, golang-jwt, google/uuid, redis, zitadel/oidc, x/crypto, x/oauth2, yaml, migratekit. (redis + zitadel/oidc are arguably core — ephemeral store default + OIDC RP — so they stay; decide.)
- Give each optional integration its own `go.mod`, each `require`-ing the root: `adapters/gin` (gin), `adapters/chi` (chi), `providers/email/twilio`, `providers/sms/twilio`, `riverjobs` (river + cron), and the ClickHouse analytics package.
- Import paths for consumers **don't change** (same paths, now separate modules) — but each submodule is `go get`/tagged independently.

**First-class deliverable — a pg-free verify path.** The leanest consumer is the worst-served today: an app that only wants to *verify* tokens (`authhttp.NewVerifier` + `AddIssuer` + `Required`) still transitively pulls **pgx + redis + the whole storage layer**, because the verifier lives in package `authhttp`, which imports `core`, which imports pgx. Yet verification needs none of it — `Verifier.WithService` is optional (DB-backed admin checks only), and the low-level `jwt/` package is **already pgx-clean**, proving the decoupling is achievable. Carve the verify surface (`Verifier`, `Required`/`Optional`, claims extraction, the issuer/JWKS registry) into its own package/module that imports **nothing** from `core`: define the optional `WithService`/`RequireAdmin(pg)` hooks against a **small local interface** so the dependency points inward to an interface, not outward to pgx. A verify-only consumer then depends on just JWT + JWKS fetching. This is the single clearest beneficiary of the split.

Honest costs to plan for: multi-module repos need **per-module version tags** (`adapters/gin/v1.2.0`), a `go.work` for local dev, and a CI matrix that builds/tests each module. Document the release process; this is the main downside.

Non-goals: not making `core` storage-agnostic (that would gut the batteries-included value — explicitly out); not moving genuinely-core deps (pgx, golang-jwt, redis, zitadel/oidc) out.

**Tasks:**
- [ ] Decide module boundaries (confirm gin/chi/river/cron/twilio/clickhouse out; redis/zitadel stay) + a pg-free verify package
- [ ] Carve the verify path (`Verifier`/`Required`/`Optional`/claims/issuer+JWKS registry) into a `core`-free package/module; redefine `WithService`/`RequireAdmin(pg)` hooks against a local interface so it imports no pgx
- [ ] Add nested `go.mod` per extracted module; root `go.work` for local dev
- [ ] Per-module tagging scheme + release/runbook docs
- [ ] CI: build + test matrix across all modules; `go mod tidy` enforced per module
- [ ] Verify a verify-only consumer pulls neither pgx nor redis (`go mod why` clean), and a minimal `core`+`http`+`adapters/gin` consumer no longer pulls river/clickhouse
- [ ] Docs: README "Modules & dependencies" map; migration note (consumers may need an extra `go get` for adapters)

---

# #108: Replace the mutating `With*` builder with constructor-time functional options; group the 30 `Config` fields

**Completed:** no
**STATUS 2026-06-22 (Claude): options half DONE+shipped; Config field-grouping DEFERRED to the major bump.** Added `type Option func(*Server)` + package-func option constructors mirroring every `WithX` (`WithRedis`, `WithEmailSender`, `WithSMSSender`, `WithEntitlements`, `WithRateLimiter`, `WithoutRateLimiter`, `WithClientIPFunc`, `WithAuthLogger`, `WithAuthLogReader`, `WithLanguageConfig`, `WithErrorLogger`, `WithSolanaDomain`, `WithEphemeralStore`), applied INSIDE `NewServer(cfg, pg, opts...)` before validation so a half-built Server is never observable. The mutating `WithX` methods remain for back-compat (method + package-func same name coexist legally). Files: http/server.go. Tested via #106's server_test.go; build/vet/PG suite green. CONFIG-GROUPING DEFERRED: grouping the 30 flat `core.Config` fields into sub-structs while keeping flat fields for back-compat adds a parallel representation (two ways to set each value) that makes Config WORSE during transition and risks mis-routing security-relevant fields (Issuer/audiences/keys/modes); it only pays off once flat fields are removed, so do it at the major bump as a coordinated break.

Configuration is split across **two parallel systems**: `core.Config` has **~30 top-level fields** and there are **~20 mutating `With*` builder methods** (`svc = svc.WithPostgres(pg).WithRedis(r)…`), and the boundary is arbitrary enough that the README needs an **ownership table** to explain it.

Two problems, one fix:
1. The **mutating** builder is the weakest constructor idiom — it permits a half-built, observable `Service` (the root cause of #106's guards) and it mutates-and-returns-self (aliasing footgun: `a := NewService(); b := a.WithX()` share one pointer, and `a` is mutated too).
2. Two systems a consumer must learn (struct fields vs `.With*()`).

Decision (settled with the maintainer): adopt **constructor-time functional options** with a clear split by *kind* of input. Note `NewVerifier` **already uses functional options** (`NewVerifier(opts ...VerifierOption)`), so this makes both entry points consistent.

```go
func NewService(cfg core.Config, pg *pgxpool.Pool, opts ...Option) (*Service, error)
```

- **Data / policy → `cfg` (grouped sub-structs).** Host-owned config the app loads from its own YAML/env and inspects — stays *data*, not code. Group the 30 flat fields: `Config.Token` (Issuer, IssuedAudiences, ExpectedAudiences, durations), `Config.Registration` (modes, RegistrationVerification, AutoCreatePersonalOrgs), `Config.Keys` (Keys, KeysPath), `Config.RateLimit`, `Config.Schema`, `Config.Solana`, `Config.Frontend` (BaseURL, FrontendCallbackPath).
- **Mandatory dependency → positional arg.** Postgres (#106) — required, no fallback — so positional, not an option.
- **Optional deps / behavior → functional options** applied *inside* the constructor before the Service is observable (this is what gives #106 its single validation point): `WithRedis`, `WithEmailSender`, `WithSMSSender`, `WithRateLimiter`, `WithClientIPFunc`, `WithAuthLogger`, `WithSecurityLogger`/`WithRedactor` (#102), `WithEntitlements`. Each `WithX` returns an `Option` closure; the mutating chain is gone.

One rule a consumer can hold in their head: **data → `cfg`; the one required dep → positional; everything optional → options.** Kills the ownership-table ambiguity *and* the mutating-builder footgun.

**Breaking** (signature + field regrouping) → batch with the v-next major bump alongside #105/#107/#109. Ease migration: keep flat `Config` fields as `//Deprecated:` aliases for one minor version; optionally keep thin deprecated `With*` shims that forward to options.

Non-goals: not pushing *policy* into options (sub-structs keep `Config` inspectable/loadable — suits the host-owned-config story); not changing defaults or behavior.

**Tasks:**
- [ ] Define `type Option func(*Service)` (or `func(*options)` for tighter encapsulation) + a `WithX` constructor per optional dep
- [ ] Change `NewService` to `(cfg, pg, opts ...Option)` (with #106); apply options inside the constructor, then validate
- [ ] Group the 30 `Config` fields into sub-structs (Token/Registration/Keys/RateLimit/Schema/Solana/Frontend); flat fields become deprecated aliases for one release
- [ ] Convert the ~20 mutating `With*` methods to option constructors; optional deprecated forwarding shims
- [ ] Update README — replace the ownership table with the one structural rule; show `NewService(cfg, pg, WithRedis(...), …)`
- [ ] Tests: option application + last-wins ordering; alias→sub-struct mapping; zero-value defaults unchanged
- [ ] Schedule removal of deprecated aliases/shims for the major bump (with #105/#107/#109)

---

# #109: Disambiguate the two `Service` types (`core.Service` vs `http.Service`)

**Completed:** yes
**STATUS 2026-06-22 (Claude): DONE (via alias, not a 46-file receiver rename).** Added `type Server = Service` in `http/server.go` so the HTTP wrapper has a name distinct from `core.Service`; `NewServer(...)` returns `*Server`. A hard rename of the struct + every `func (s *Service)` handler receiver across ~46 files was rejected as high-churn/high-risk (and `\bService\b` sed would wrongly hit `core.Service`). The alias gives consumers the unambiguous `authhttp.Server` name with zero churn; `Service` stays as the back-compat name. A true struct rename, if ever wanted, belongs in the major bump. Shipped alongside #106/#108 in `http/server.go`.

Both `core.Service` (the ~400-method engine, #105) and `http.Service` (the transport wrapper holding `svc *core.Service`) are named **`Service`**, and both expose overlapping `With*` methods (e.g. both have `WithAuthLogger`). In consumer code and godoc, "I'm holding a `Service`" is ambiguous, and the wrapper's internal `s.svc` reinforces the confusion.

Rename the HTTP type to a role-specific name. `core.Service` is the canonical engine and keeps its name; the HTTP type is what you *mount*, so `authhttp.Server` (or `authhttp.Handler`) reads correctly: `svc, _ := authhttp.NewService(cfg)` → `srv, _ := authhttp.NewServer(cfg)`. This removes the name collision and the overlapping-`With*` confusion at a glance.

**Breaking rename** → batch with the v-next major bump (#105/#107/#108). Ease migration with a deprecated type alias `// Deprecated: use Server` `type Service = Server` and `var NewService = NewServer` for one release.

Non-goals: not changing the wrapper's responsibilities or the `core.Service` name; purely a rename + alias.

**Tasks:**
- [ ] Pick the name (`authhttp.Server` recommended; `Handler` alt) and rename the type + constructor
- [ ] Add deprecated `type Service = Server` / `NewService` aliases for one release
- [ ] Update internal references, README, and `agents/api-endpoints.md` examples
- [ ] Schedule alias removal for the major bump (with #105/#107/#108)

---

# #110: Decouple the verifier from `core` — a pgx-free verify package for verify-only consumers

**Completed:** yes
**DONE 2026-06-21 (Claude): the verification layer now lives in the core-free `github.com/open-rails/authkit/verify` package — validated `go list -deps ./verify` contains NO core, NO pgx, NO redis (only `authbase` + `jwt`).** Phase 0 extracted every shared primitive to `authbase`; phase 1 inverted the `*core.Service` enrich hook to a 9-method `Enricher` interface and physically moved the verifier subsystem (`verifier.go`, `claims.go`, `middleware.go`, `service_jwt.go`, `remote_application_origins.go`, `ssrf_guard.go` + helpers) into `verify`, re-exporting the full public surface from `authhttp` as aliases (zero embedder churn). `core.WithPermissionMemo` is wired via `verify.SetRequestContextHook` (authhttp's init) so middleware needn't import core. New `verify/verifyonly_integration_test.go` (external `verify_test` pkg, imports only verify+jwtkit) proves mint→verify→middleware-gate works with no storage stack; its test binary also pulls no core/pgx. Validation: `go build ./...` + `go vet ./...` clean (also fixed the pre-existing `mintAccessJWT` test so the whole tree vets for the first time); full suites green — `verify` (incl. integration), `http` (64s), `core` (15s) against PG. Docs: README "Verify-only" updated. Two small public seams added for relocated tests/handlers: `verify.RemoteAppOptions`, `verify.MaxDelegatedRoles`, `(*Verifier).HTTPClient()`, `(*Verifier).SetRemoteApplicationSource(...)`. (Module split — separate go.mod for `verify` — remains #107; this issue only severs the import edge.)

**FINDING 2026-06-21 (Claude) — the "shallow coupling" premise below was WRONG; phase 0 was the necessary groundwork.** Measured the real `core` edges in the verify surface: `http/verifier.go` references `core.Service` (×10) but ALSO `core.ParseAPIKey`/`core.HasAPIKeyPrefix` (the verifier resolves opaque API keys *before* JWT — it is not JWT-only), `core.RemoteApplication`/`core.RemoteAppModeStatic`, `core.OrgMembership`, `core.PermissionTokenCovers`, `core.IssuerAccept`, `core.ErrInvalidAccessToken`/`ErrAccessTokenRevoked`/`ErrAccessTokenExpired`/`ErrAttributeDefNotFound`, `core.Config`. `claims.go` uses `core.PermissionTokenCovers`/`core.APIKeyResource`; `middleware.go` uses `core.WithPermissionMemo`. So the coupling is NOT "two optional admin hooks" — the verifier depends on core's API-key parsing, remote-app types, permission-coverage logic, and access-token sentinels. A genuinely `core`-free `verify` package therefore needs a **phase 0** first: extract those shared primitives (`ParseAPIKey`/`HasAPIKeyPrefix`, `PermissionTokenCovers`, the `RemoteApplication`/`OrgMembership`/`APIKeyResource` types, `IssuerAccept`, the access-token sentinel errors) into a lower core-free base package that BOTH `core` and `verify` import; **phase 1** then moves the verifier onto it. This is a staged, security-critical refactor, not a single non-breaking PR. NOT started — the approach section below is superseded by this finding.

Split out from #107 (it's the prerequisite, and it can land independently). A pure-verification consumer — verify a JWT against JWKS, no issuing, no DB — should compile **only JWT + JWKS fetching**. Today it can't: `authhttp.NewVerifier` + `Required`/`Optional` live in package `authhttp`, which imports `core`, which imports `pgx` — so importing authkit to verify tokens transitively drags in **pgx, redis, and the whole storage layer** even though no connection is ever opened. The low-level `jwt/` package is **already pgx-clean**, proving the decoupling is achievable; the gap is only the middleware-level verifier.

The coupling is shallow and accidental: the verify path is welded to `core` **only** because two *optional* hooks reference it — `Verifier.WithService(*core.Service)` and `RequireAdmin(pg)` (DB-backed admin checks). Pure verification uses neither.

**Landable NOW, independently, and non-breaking via re-exports — do not wait for #107's multi-module conversion.** Even within the current single module this is a real win: Go compiles per-package, so once the verify package no longer imports `core`, a consumer importing only it won't compile pgx into their binary. #107 then just *moves* the already-`core`-free package into its own module (the breaking-the-import-edge work is done here).

Approach:
- Extract the verify surface — `Verifier`, `Required`/`Optional`, claims extraction (`Claims`, `ClaimsFromContext`), the issuer/JWKS registry, `IssuerOptions`/`VerifierOption` — into a new `core`-free package (e.g. `github.com/open-rails/authkit/verify`). It may import `jwt/` (clean) but **nothing** from `core`.
- Invert the optional hooks to a **small local interface** so the dependency points inward: e.g. `type AdminChecker interface { IsAdmin(ctx context.Context, userID string) (bool, error) }` (plus whatever `WithService` genuinely needs). `core.Service` satisfies it; the verify package never imports `core`. `RequireAdmin` takes the interface, not `pg`.
- **Back-compat via re-export:** keep `authhttp.NewVerifier`/`Required`/`Claims`/… as aliases (`type Verifier = verify.Verifier`, `var NewVerifier = verify.NewVerifier`) so existing embedders (doujins/openrails/tensorhub) don't change a line. Full-service consumers keep importing `authhttp` (still pulls `core`, as expected); verify-only consumers import the lean `verify` package.

Non-goals: not changing verification behavior or claim semantics; not moving `jwt/` (already clean); the module packaging itself is #107.

**STATUS 2026-06-21 (Claude): phase 0 COMPLETE — all shared primitives extracted to new `authbase` package; full PG core suite green.** Created `github.com/open-rails/authkit/authbase` (stdlib-only, imports nothing from core) and moved every shared primitive there, re-exporting each from `core` as an alias so all `core.X` callers + tests are untouched: token sentinels (`ErrInvalidAccessToken`/`ErrAccessTokenRevoked`/`ErrAccessTokenExpired`), `ErrAttributeDefNotFound`, API-key marker/parse/format (`APIKeyMarker`/`HasAPIKeyPrefix`/`FormatAPIKey`/`ParseAPIKey` + the private `st_` type segment), `APIKeyResource`, `OrgMembership`, `RemoteApplication`+`RemoteAppKey`+`RemoteAppModeJWKS`/`RemoteAppModeStatic`, AND the authz-matching cluster `PermWildcard`/`PermMatches`(exported)/`PermissionTokenCovers` (core's private `permMatches` is now `var permMatches = authbase.PermMatches`). Files: `authbase/{apikey,remoteapp,org,permission}.go` (new); `core/{api_keys,remote_application_attribute_defs,service_remote_applications,service_orgs,org_role_permissions}.go` (definitions → aliases). `go build ./...` green; `core`+`authbase` vet-clean; **full core PG suite green twice** (`ok ~8–11s`, incl. no-escalation/cover-token/wildcard RBAC tests); jwt/siws/ratelimit green. The verify surface's ONLY remaining core edges are now genuine phase-1 work, not shared primitives: `core.Service` (enrich hook → interface), `core.Config` (→ verify's own config), `core.WithPermissionMemo` (request-scoped memo container). (`core.IssuerAccept` in verifier.go is a comment, not a dep.) NOTE (unrelated pre-existing): `http/local_issuer_overwrite_test.go` references an undefined `mintAccessJWT` — `go test ./http/...` was already red before this work (invisible to `go build`, which skips test files); flag for a separate fix.

**Tasks (staged):**

Phase 0 — core-free `authbase` base package (extract shared primitives; re-export from core) — ✅ COMPLETE:
- [x] Inventory the verify→core edges — NOT just `WithService`/`RequireAdmin`: also `ParseAPIKey`/`HasAPIKeyPrefix`, `RemoteApplication`/`RemoteAppKey`/modes, `OrgMembership`, `APIKeyResource`, `PermissionTokenCovers`, the token sentinels, `ErrAttributeDefNotFound`, `core.Config` (`core.IssuerAccept` was a false alarm — comment only)
- [x] Create `authbase` (stdlib-only) and move the CLEAN leaves (sentinels, API-key marker/parse/format, `APIKeyResource`, `OrgMembership`, `RemoteApplication`+`RemoteAppKey`+modes); re-export all from `core` as aliases (zero churn); build green + core API-key tests pass
- [x] Move the authz-matching cluster: `PermissionTokenCovers` + `permMatches`(→ exported `authbase.PermMatches`) + `PermWildcard` → `authbase`; re-exported from core; full core PG suite + RBAC no-escalation/cover-token/wildcard tests green
- [x] Phase-0 gate: `go build ./...` green; `core`+`authbase` vet-clean; full core PG suite green (`ok ~8–11s`, twice)

**STATUS 2026-06-21 (Claude): phase 1 interface-inversion DONE; physical move REMAINS.** Moved the last two primitives `ResolvedAPIKey` + `RemoteAppAttributeDef` → `authbase` (aliased in core). Defined the `Enricher` interface in `http/verifier.go` (9 methods: `ResolveAPIKeyWithResources`, `GetRemoteApplication`, `ListRemoteApplications`, `ResolveRemoteApplicationAuthority`, `ResolveRemoteAppAttributeDef`, `GetProviderUsername`, `ListRoleSlugsByUser`, `GetEmailByUserID`, `IsUserAllowed`) and replaced `enrich *core.Service` → `enrich Enricher`; `WithService(Enricher)`. `*core.Service` satisfies it (compiler-verified); all 12 `WithService` callers pass a real `coreSvc` (no interface typed-nil risk). `go build ./...` green; full core PG suite green (`ok ~30s`). KEY finding: `core.Config` in verifier.go is comment-only — none of verifier/claims/middleware actually use `core.Config` in code, so the "verify needs its own config" item is dropped. After inversion, the verify surface's ONLY genuine remaining core dependency is `core.WithPermissionMemo` (middleware) + intra-package helpers `unauthorized`/`forbidden`/`bearerToken` (entangled with `http/errors.go`); everything else is authbase-backed aliases written as `core.X` that a blanket `core.→authbase.` swap converts during the move. Entanglement scan: `verifier.go`+`claims.go` are CLEAN (only intra-package `getClaims`/`setClaims`); only `middleware.go` touches external helpers.

Phase 1 — extract the verifier into a core-free `verify` package:
- [x] Define the `Enricher` interface (9 methods) and replace `enrich *core.Service` → `enrich Enricher`; `WithService(Enricher)` — *core.Service satisfies it; build + full core PG suite green
- [x] Move the last interface-surface primitives `ResolvedAPIKey` + `RemoteAppAttributeDef` → `authbase` (aliased in core)
- [x] Relocate the entangled helpers `unauthorized`/`forbidden`/`bearerToken` (replicated core-free in `verify/helpers.go`, byte-identical `{"error":code}`) so `middleware.go` can leave `authhttp`
- [x] Handle `core.WithPermissionMemo` — installed via `verify.SetRequestContextHook` (authhttp init wires it to `core.WithPermissionMemo`); middleware imports no core
- [x] Move `Verifier`/`Required`/`Optional`/`Claims`/`ClaimsFromContext`/issuer+JWKS registry (+ `service_jwt.go`, `remote_application_origins.go`, `ssrf_guard.go`) into the `core`-free `verify` package; blanket-swapped `core.X` → `authbase.X`
- [x] Re-export the full public surface from `authhttp` as aliases (`http/verify_aliases.go`) — zero consumer churn; existing embedders untouched
- [x] CI assertion: `verify`'s import graph contains no `core`/pgx/redis (`go list -deps ./verify` → only `authbase`+`jwt`) ✅
- [x] Confirm a verify-only consumer compiles without pgx: external `verify_test` integration test + `go list -deps -test ./verify` both pgx-free ✅
- [x] Fixed the pre-existing `mintAccessJWT` undefined in `http/local_issuer_overwrite_test.go` (restored from `signToken`) — `go test/vet ./http/...` now run; whole tree vets clean
- [x] Docs: README "Verify-only" now points pure-verification consumers at the lean `verify` package
