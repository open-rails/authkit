<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 113

---

# #112: sanctioned post-construction entitlements setter — break the embedded-billing init cycle

**Completed:** yes
**STATUS 2026-06-22 (Claude): DONE — shipped in v0.48.0 (additive, non-breaking).** Adds ONE blessed post-construction setter, `(*core.Service).SetEntitlementsProvider(p)` plus the `authhttp.Service`/`Server` delegate — the single deliberate exception to #108's options-only rule. Rationale: an embedded billing engine (OpenRails) authenticates THROUGH the host's authkit (it needs the Verifier+Core, so the Service must exist first) yet is itself the SOURCE of the entitlements provider — a genuine bidirectional init cycle, so the provider cannot exist at NewServer/NewService time. Hosts build auth → build engine with it → `svc.SetEntitlementsProvider(engine.EntitlementsProvider())`. Safe because entitlements are read LAZILY at token-mint time; call during wiring, before serving. Hosts WITHOUT the cycle keep using the `WithEntitlements` construction option. Retires the host-side `deferredEntitlements` holder doujins/hentai0 carried after #108 (see openrails #568, Option B). Files: core/service.go, http/service.go, core/service_token_claims_test.go (`TestSetEntitlementsProvider_LateBoundProviderEnrichesToken` — a provider installed after construction enriches the minted token). build/vet/full PG suite green.

## Tasks
- [x] `(*core.Service).SetEntitlementsProvider(EntitlementsProvider)` — plain (non-chainable) setter, documented as the cyclic-dependency exception
- [x] `(*authhttp.Service).SetEntitlementsProvider(core.EntitlementsProvider)` delegate (covers the `Server` alias)
- [x] Test: build without entitlements, set after construction, assert the minted access token carries the entitlement
- [x] Tag v0.48.0 (additive); adopt in doujins + hentai0 to delete the holder

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

## Per-type management profile (the app decides how each type's groups may be used)
Beyond the role catalog, each type declares a **management profile** — an `api-routes` block of `true|false` flags choosing which group-management operations authkit exposes as AUTO-GENERATED routes. Each flag governs **whether the route is generated, NOT whether the capability exists**: the host can ALWAYS perform the operation via authkit *core* (bootstrap seeding, internal admin tools) even with the route off. So `api-routes.X: false` means "no public route (404)", not "impossible" — that's exactly why the container is named `api-routes`. Leaves:
- `api-routes.member-assignment` — generate `/:persona/:id/members` (+ `.../members/:user/roles`): add/remove members and assign/unassign their roles. (off ⇒ membership is seeded out-of-band, e.g. the bootstrap manifest.)
- `api-routes.custom-role-creation` — generate `/:persona/:id/roles` POST/DELETE: define/delete CUSTOM role bundles. (off ⇒ only the predefined catalog roles exist — still fully assignable; this flag is SOLELY about defining NEW roles. Replaces the old `roles: fixed|custom`.)
- `api-routes.api-key-minting` — generate `/:persona/:id/api-keys`: mint/list/revoke keys (each assigned a catalog role).
- `api-routes.remote-app-registration` — generate `/:persona/:id/remote-applications`: register/manage remote-apps (a distinct credential kind from api-keys).
- `api-routes.invitation` — generate the human invite flow.

The predefined catalog is the SAME role set assignable to EVERY enabled credential kind (a member, an api-key, or a remote-app each get one of the type's catalog roles, subject to no-escalation). **The flags DRIVE ROUTE GENERATION** (see HTTP surface): a disabled flag → no route → 404, so the API surface mirrors the profile exactly.

Examples (only the ON flags listed):
- `org` (tensorhub): members + custom-roles + api-keys + remote-apps + invites — full.
- `repo`: members (collaborators) only — thin.
- `merchant` (openrails): members + api-keys + remote-apps (custom-roles OFF — fixed owner/support/viewer).
- `customer` (openrails): members + api-keys + remote-apps (custom-roles OFF — fixed owner/member); budget WINDOWS are openrails-DOMAIN.
- doujins `root`: custom-roles OFF (predefined admin/moderator); `api-routes.member-assignment` = the "assign operator roles via API" vs "seed admins via bootstrap only" choice.

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
- `permission_groups(id, type, parent_id NULL=root, parent_type, owner_subject, resource_ref, created_at, …)` — replaces `orgs`. `type` selects the role catalog + custom-roles policy; `parent_id` is the one inheritance edge; `parent_type` is denormalized for the containment CHECK; `resource_ref` links the group to its app resource AND is the API addressing key — a route's `(persona, resource-id)` resolves to the group via `resource_ref`; the group `id` is INTERNAL-only, never exposed in a request/response.
- `group_type_parents(type, allowed_parent_type)` — the containment schema as data, so a CHECK/trigger can reject off-shape rows (e.g. `repo` parent must be `org`). `root` has no row (parentless singleton).
- `group_role_assignments(group_id, subject, subject_kind, role)` — replaces `org_members`.
- `group_custom_roles(group_id, role, permissions[])` — only used when the type's `AllowCustomRoles` is set.
- App-declared catalog: `Config` gains, per type: role definitions (name → 3-segment perm set, `owner` required), `allowedParents []type`, and a **management profile** (all bool) `api-routes:{member-assignment, custom-role-creation, api-key-minting, remote-app-registration, invitation}` — each gates generation of one route group. Permissions validated as `<persona>:<resource>:<action>` with persona = a declared type.
- remote_applications + api-keys: today org-nested → re-nest under a `permission_group` (was `org_id`).
- The prebuilt `owner` role + `OwnerOwnsAppResources` (#100) generalize to per-type owner roles.

## Authorize API
`Can(ctx, principal, permission, groupID)` (or `…, resourceRef`): resolve the group, walk `parent_id` to the root, union the principal's assignments across that chain, ALLOW if any granted role covers `permission` (existing namespace-anchored glob match). Additive-only. Memoize the resolved assignment set per (principal, group). The old org-scoped calls (`HasAdminPermission(orgSlug,…)`, membership, role mgmt) become group-scoped.

## Built-in roles + group-management perms
- **Built-in roles:** per group type — `owner` (required; = `<type>:*`, namespace-pure, NEVER bare `*`, NEVER another persona) + `member` (base membership, minimal/no perms). authkit seeds both on group-create (today's `OrgRolesSeedOwnerMember`, generalized). `root` additionally ships `super-admin` (= `root:*`).
- **Built-in perms (authkit-provisioned in EVERY type's catalog — the group-self-management set):** `<type>:members:manage`, `<type>:roles:manage`, `<type>:api-keys:manage`, `<type>:read`. They gate the auto-generated per-persona management routes (`/:persona/:resource-id/*`, below); the app adds its DOMAIN perms alongside (all `<type>:`-namespaced). `root` also ships the intrinsic identity perms (`root:users:*`, `root:groups:*`, `root:sessions:revoke`, …).

## HTTP surface — AUTO-GENERATED per-persona routes (DECIDED)
authkit **auto-generates** the group-management HTTP surface from the declared personas + their management profiles — the host writes no management routes, just mounts the generated set. Shape: **`/:persona/:resource-id/…`**, one route TREE per persona, emitting ONLY the endpoints that persona's profile enables:
- `api-routes.member-assignment` → `/:persona/:resource-id/members` (add/remove/list) + `/:persona/:resource-id/members/:user/roles` (assign/unassign)
- `api-routes.custom-role-creation` → `/:persona/:resource-id/roles[/:role]` (define/delete custom roles); when OFF → only GET (list the fixed catalog), no define/delete
- `api-routes.api-key-minting` → `/:persona/:resource-id/api-keys` (mint/list/revoke)
- `api-routes.remote-app-registration` → `/:persona/:resource-id/remote-applications`
- `api-routes.invitation` → the invite endpoints

**Addressed by the RESOURCE's own id, NOT the permission-group id.** `:resource-id` is the merchant / customer / org / repo / endpoint id the caller ALREADY has — e.g. `/merchant/m_1234/members`, `/repo/r_5678/members`; authkit resolves `(persona, resource-id) → permission-group` internally via `resource_ref`. **The permission-group id is INTERNAL — it never appears in a request or response,** so callers never read or handle it (more ergonomic to code against). The route is self-validating: `:persona` must match the resolved group's type, else 404. (`root`, having no host resource, is the singleton/implicit case — addressed by its app/deployment key per open decision #6.)

**A disabled capability is NOT generated → calling it 404s** — the route surface IS the capability spec (you can't hit what doesn't exist; stronger than a runtime 403). Each generated route gates on `<persona>:<resource>:<action>` (e.g. `POST /merchant/m_1234/members` → `merchant:members:manage`). **Discovery stays cross-persona-generic:** `/me/groups` lists the caller's memberships as `{persona, resource-id, role}` (again, no group id). The route surface is CONFIG-DERIVED (varies per declared personas) — OpenAPI/docs generated from the same config. authkit also keeps its AUTH/IDENTITY HTTP (login/register/token/refresh/`/me`/sessions/2FA/OIDC/JWKS) + the intrinsic `/admin/*`.

**HOST owns (calls core):** RESOURCE LIFECYCLE — create/delete the org/repo/merchant *record* + its paired group (host tables + side effects: seed billing, notify, the org-slug lifecycle gated by `root:orgs:*`). authkit generates the *management* of an existing group; the host owns *creating/destroying* it. The `org`-NAMED routes are DROPPED — `/org/:id/*` is just the auto-generated tree for the `org` persona.

## Tasks
- [ ] Schema: `permission_groups` (type, parent_id, resource_ref) + `group_role_assignments` + `group_custom_roles`; migrate `orgs`→groups (type=`org`, parent=root) and `org_members`→assignments (greenfield hard cut, no dual-write).
- [ ] Config: per-type role catalog (name→perms, `owner` required) + per-type **management profile** (all bool, conservative defaults = all false / no API routes): `api-routes.member-assignment`, `api-routes.custom-role-creation`, `api-routes.api-key-minting`, `api-routes.remote-app-registration`, `api-routes.invitation`. Each flag = generate-that-route-group-or-not (false ⇒ 404; host can still do it via core).
- [ ] Custom roles: gate DefineRole/SetRolePermissions on the type's `AllowCustomRoles`; store in `group_custom_roles`; assignable only within the defining group.
- [ ] Authorize: add the resource/group parameter + parent-chain walk + additive union; keep namespace-anchored glob matching; memoize per (principal, group).
- [ ] Re-nest remote_applications + api-keys under a permission-group; update `ResolveRemoteApplicationAuthority` to resolve via group + parent walk.
- [ ] Owner role per type = `<type>:*` (namespace-pure; NEVER bare `*`, NEVER another persona's namespace). **`OwnerOwnsAppResources` (#100) is OBSOLETE** (decision #5): the org owner reaches its repos/endpoints via `org:<R>:*` (covered by `org:*`), NOT by holding `repo:*` — drop the cross-namespace owner seed (it survives only as a no-op for flat consumers, or is removed).
- [ ] HTTP surface (DECIDED — auto-generated per-persona, addressed by RESOURCE id): build a ROUTE GENERATOR that, from each declared persona + its management profile, emits `/:persona/:resource-id/{members, members/:user/roles, roles[/:role], api-keys, remote-applications, invites}` — ONLY the profile-enabled endpoints (disabled ⇒ NOT generated ⇒ 404). `:resource-id` = the resource's OWN id (merchant/repo/org id the caller already has); resolve `(persona, resource-id) → group` via `resource_ref` — the permission-group id is INTERNAL, never in requests/responses. Validate `:persona` against the resolved group's type (404 on mismatch); gate each route on `<persona>:<resource>:<action>`. Cross-persona discovery `/me/groups` (returns `{persona, resource-id, role}`). Generate OpenAPI from the same config. Keep auth/identity + intrinsic `/admin/*`. HOST owns resource-lifecycle/domain routes. No `org`-named special-case — `/org/:org-id/*` is just the `org` persona's generated tree.
- [ ] Built-ins: provision the per-type group-management perm set (`<type>:members:manage` etc.) in EVERY type's catalog; seed `owner` (=`<type>:*`) + `member` per group on create; ship `root` `super-admin` (=`root:*`).
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
2. RESOLVED 2026-06-22 (Paul): FIXED catalogs by default — `api-routes.custom-role-creation` OFF per type. The ONLY type that opts in is tensorhub's **`org`** (org-owners define custom roles for their own org); EVERYTHING else is fixed — openrails/doujins/hentai0/cozy-art entirely, AND even within tensorhub the per-resource types `repo`/`endpoint`/`dataset` stay fixed (only app-defined predefined roles are assignable, no custom). Greenfield baseline → no production custom-role data to preserve.
3. RESOLVED 2026-06-22 (Paul): a group's `owner` manages its OWN assignments. An ancestor may manage a descendant's assignments ONLY where the ancestor TYPE's catalog declares that management perm — NOT a blanket ancestor power. ✓ A tensorhub `org` owner manages its child `repo`/`endpoint`/`dataset` memberships (incl. adding out-of-org collaborators) because the `org:` catalog declares it (e.g. `org:repo:members-manage`). ✗ `root` CANNOT add/remove members on a descendant (e.g. someone's `org`) — root's catalog is moderation-only (delete/restore/ban) and declares NO membership-management perm; a root-admin must not meddle in another person's org membership. Mechanically this is just decision #5's walk-up applied to the manage-assignments action (allowed iff the subject holds `LT:RT:members-manage` at an ancestor of type LT) — so the auto-generated `api-routes.member-assignment` route DENIES a root principal on a group root has no catalog perm for. reach ≠ capability holds on the management plane too.
4. RESOLVED 2026-06-22 (Paul): authkit STORES `resource_ref → group` (created at `CreatePermissionGroup` time) and resolves + walks the tree internally; the app names the RESOURCE, group-id stays internal (matches the `/:persona/:resource-id` route design).
5. RESOLVED 2026-06-22 by the two-persona model (tensorhub #498) — option (c), cleaner than both originally posed. **Org-level resource perms live in the `org:` namespace** (`org:repo:*`, `org:endpoint:*`, `org:dataset:*`), so the org owner reaches all its resources via `org:*` (which already covers them) — namespace-pure, NO `OwnerOwnsAppResources` cross-namespace grant, NO implicit descendant membership. **Authorize rule:** to do `<action>` on a resource of type `RT`, allow if the subject holds, at ANY ancestor group of type `LT` in the walk-up chain, the perm `LT:RT:<action>` — i.e. `RT:RT:<action>` at the resource itself (collaborator) OR `org:RT:<action>` at the owning org (member/owner). Every level's perm is `LT:`-pure, so the invariant holds and authority can come from either level. **This OBSOLETES #100's `OwnerOwnsAppResources` for the nested case** (it stays a no-op for flat consumers like OpenRails, or is removed). (Originally considered: (a) #100 cross-namespace grant — violates the invariant; (b) implicit descendant ownership — namespace-pure but adds implicit membership. (c) beats both.)
6. RESOLVED 2026-06-22 (Paul): `root` STAYS a single built-in singleton — NO multi-root, NO per-app scoping. doujins + hentai0 are two apps on ONE AuthKit instance (shared users + DB) and SHARE moderation authority — the same staff moderate both, so one shared `root` is correct, not a conflict. (The earlier "a doujins admin must not moderate hentai0" premise was wrong.) The engine keeps the simple singleton-root model; co-deployed apps share it.
7. **CLARIFY — `root` is the OPERATOR layer (not strictly "moderation"), AND operator-capability ≠ user-property.** root's catalog includes staff OPERATIONAL/visibility privileges, not just moderation ACTIONS — e.g. `root:ratelimit:bypass`, `root:content:view-restricted` (moderators), `root:users:manage` (#416). reach ≠ capability still holds (`root:`-namespaced, can't impersonate or reach `merchant:`/`org:`/user-self). **But a USER PROPERTY is NOT a root perm/role.** Per-user perks (premium, beta-access) are ATTRIBUTES/ENTITLEMENTS that live on the USER, granted by an operator — NOT root memberships (else the operator roster fills with every beta/comp user). The clean line: the **authority-to-grant** is an operator capability (a `root:` perm, or in the OpenRails ecosystem the `merchant:customer-settings:update` grant endpoint); the **granted flag** is a user property. Concrete mechanism (openrails, VERIFIED): `POST /v1/merchant/customers/:id/entitlements {entitlement, days?}` appends a `kind=entitlement, source_type='admin'` row to the append-only **#514 grant ledger**, which `MaterializeGrant` projects to an `entitlements` window (`end_at NULL` ⇒ indefinite); revoke = a new `revoke` event, never a delete. So doujins/hentai0's old `premium.bypass` + `beta-tester` role (#416/#176) become ENTITLEMENTS, not root roles — and the earlier `root:premium:bypass` example is RETRACTED (premium is a user entitlement, not an operator perm).

# #100: allow application-defined permission prefixes in org-scoped RBAC

**Completed:** yes
**Status:** DONE 2026-06-22 (Claude): closed the remaining guard-test + docs tail and fixed a real (low-severity) disjointness gap found while verifying. app-defined org-scoped prefixes already work as opaque strings end-to-end (a role granted `repo:*` passes `HasPermission("repo:read")` — see `TestHasPermissionUsesSingleRoleGrantQuery`); OWNER coverage shipped earlier as the OPT-IN `Config.OwnerOwnsAppResources` (default FALSE; when true the prebuilt `owner` is seeded `org:*` PLUS one `<ns>:*` glob per non-`platform:` app namespace via `ownerGrantTokens`/`seedOwnerGrants`; `EnsureOwnerGrants` reconciles pre-existing orgs). 2026-06-22 follow-up: **GAP FOUND + FIXED** — an app-declared `platform:` perm leaked into the ORG catalog (`Permissions()` deduped only on base-name collision, never filtered the reserved `platform:` namespace), so `knownPermissions()` contained it and `ValidateGrant` would accept a `platform:` token on an ORG role with `actorAll`. (Not a live escalation — org-layer grants never confer real platform authority, which is read only from the disjoint `platform_user_roles` plane — but it violated the Target-Model/Acceptance "`platform:` cannot appear in any app catalog or org role".) Fix: `Permissions()` now drops any `IsPlatformPermission(n)` app perm (1-line guard, org_role_permissions.go) — symmetric to the existing base-wins `org:` dedup. `ResolveRemoteApplicationAuthority` still intentionally re-adds the BASE platform catalog for the verifier path, so legit base-`platform:` resolution is unaffected. Added guard tests: `TestOrgCatalogRejectsPlatformNamespace` (app `platform:` perm/glob absent from org catalog + rejected by `ValidateGrant`; app `merchant:` ns passes) and `TestOrgCatalogBaseWinsOnReservedCollision` (documents CURRENT #554-deferred behavior: base wins silently on `org:` collision, non-colliding app `org:` perms still accepted). Platform-disjointness already well-covered by `TestPlatformRBAC` (both directions + no-escalation) and `TestPlatformGrantRejectsAppNamespace`. Docs: README RBAC sentence extended with the explicit two-namespace reserved-prefix rule (`platform:` dropped; `org:` base-wins, hard rejection deferred to #554). api-endpoints.md needs no change (endpoint reference; already documents the reserved `org:` routes + opaque app perms). Files: core/org_role_permissions.go (filter + doc), core/org_role_permissions_test.go (2 new guard tests), README.md (RBAC section only). Targeted `go test ./core/ -run 'Perm|Platform|Grant|Owner|RBAC|Escalat|OrgCatalog'` and full `go test ./core/` both green against PG. No version bump (left to the concurrent config refactor / release step). REMAINING: only the OpenRails #554-coupled HARD rejection of app `org:` perms (deferred, below) — nothing else.

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
- [x] Keep `platform:` blocked from org roles and every app permission catalog. DONE 2026-06-22: `Permissions()` now drops any app-declared `platform:` perm (`IsPlatformPermission` guard) so it never enters the org catalog/`knownPermissions()`; `ValidatePlatformGrant` already rejects every non-`platform:` token on the platform side; org `ValidateGrant` already rejects `platform:` tokens (not in org catalog). Tests: `TestOrgCatalogRejectsPlatformNamespace` (new), `TestPlatformRBAC`, `TestPlatformGrantRejectsAppNamespace`.
- [ ] Keep `org:` blocked from app permission catalogs except AuthKit's built-in org-management permissions. DEFERRED (the ONLY remaining #100 item): coupled to OpenRails #554 — OpenRails STILL declares app `org:` perms today (`org:credits:read`, `org:billing:read`, ...); enforcing a HARD rejection now would reject its catalog. Enforce once #554 moves OpenRails to `merchant:*`. Today `Permissions()` silently drops an app perm that COLLIDES with a base `org:` name — base wins — so there is no escalation risk, just no hard rejection of *non-colliding* app `org:` perms yet. Current behavior locked by `TestOrgCatalogBaseWinsOnReservedCollision`.
- [x] Ensure app-declared prefixes like `merchant:` validate in `Config.Permissions`, role permission writes, and API-key role grants. VERIFIED: `Config.Permissions` accepts any namespace (opaque); `SetRolePermissions` stores tokens opaquely; `ValidateGrant` expands app globs against the catalog with no-escalation; `TestHasPermissionUsesSingleRoleGrantQuery` (`repo:*`) + `TestOwnerHoldsAppNamespaceEndToEnd` (`merchant:*`) cover role-write -> HasPermission end-to-end.
- [x] Ensure `ValidateGrant` no-escalation works for app-defined literals and globs (`merchant:payments:refund`, `merchant:*`) exactly like it does for `org:*`. VERIFIED: `ValidateGrant` (org_role_permissions.go) expands every token against `knownPermissions()` (base ∪ app) and requires the actor to hold each expanded perm — namespace-agnostic, so app prefixes behave exactly like `org:*`.
- [x] Ensure `ValidatePlatformGrant` still rejects every non-`platform:` token, including app prefixes. VERIFIED + TESTED: platform_rbac.go:302 rejects any non-`platform:` token as unknown even with `actorAll`; `TestPlatformGrantRejectsAppNamespace` proves `merchant:*` / `merchant:payments:refund` / `org:members:read` are all rejected on a platform grant.
- [x] Add tests proving an org role can hold an app permission, a user with that role passes `HasPermission`, and an app glob expands only over declared app perms. DONE: existing `TestHasPermissionUsesSingleRoleGrantQuery` (`repo:*` role -> `HasPermission("repo:read")`) + new `TestOwnerHoldsAppNamespaceEndToEnd` (`merchant:*`).
- [x] Add tests proving platform roles reject `merchant:*`. DONE: `TestPlatformGrantRejectsAppNamespace`. App-catalog-rejects-`platform:` is now also tested AND enforced (`TestOrgCatalogRejectsPlatformNamespace` + the `Permissions()` filter, 2026-06-22). App-catalog-rejects-`org:` remains the deferred half (OpenRails #554) — current base-wins behavior locked by `TestOrgCatalogBaseWinsOnReservedCollision`.
- [x] **NEW (opt-in owner ownership, #554 prerequisite):** add `Config.OwnerOwnsAppResources` so the org `owner` auto-owns every app-declared resource namespace (`<ns>:*`), default off; `ownerGrantTokens` + `seedOwnerGrants` (4 seed sites) + `EnsureOwnerGrants` reconcile; pure + PG-backed tests (owner holds `merchant:*`, can't reach `platform:`, default-off stays `org:*`). Redesigns the line-43 "owner does not auto-grant" note into an explicit app opt-in.
- [x] Update README permission docs with the reserved-prefix rule, an OpenRails-style `merchant:*` example, and the `OwnerOwnsAppResources` opt-in. DONE in README.md RBAC section (also corrected the #95-stale "owner seeded with `*`" -> `org:*`); 2026-06-22 extended the sentence with the explicit two-namespace reserved-prefix rule (app `platform:` perms dropped; app `org:` base-name collisions drop with base winning, hard rejection deferred to #554). (`agents/api-endpoints.md` org-RBAC table is unaffected — it documents the reserved `org:` management routes only.)

## Acceptance

- AuthKit stores and evaluates app-defined permission prefixes as opaque strings.
- `platform:` remains reserved to platform roles and cannot appear in org roles or app catalogs.
- `org:` remains reserved to AuthKit org-management and cannot be redefined by apps.
- OpenRails can define `merchant:*` permissions and bind them to routes while AuthKit scopes the grant to the owning org.
- No schema migration is needed.

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** no
**REOPENED 2026-06-22 (Paul + Claude): the feature is NOT implemented — flag corrected from a stale `yes`.** Verified absent: no `go-webauthn` dependency, no `profiles.user_passkeys` migration/table, no `RoutePasskeys` group/handlers/storage, no `*passkey*`/`*webauthn*` source. The tasks below are all still open.

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

**Completed:** yes
**STATUS 2026-06-22 (Claude): HARDCUT DONE — full no-back-compat break, targeting v0.47.0.** Superseded the earlier "options half + grouping deferred" plan: the maintainer chose a clean hardcut, so flat `core.Config` fields ARE now grouped into typed sub-structs AND ALL chainable `WithX` methods are REMOVED from both `core.Service` and `http.Service` (no deprecated shims, no parallel representation — the transition-cost objection that motivated deferral does not apply to a hardcut). Config sub-structs: `Token{Issuer,IssuedAudiences,ExpectedAudiences,AccessTokenDuration,RefreshTokenDuration,SessionMaxPerUser}`, `Frontend{BaseURL,CallbackPath}`, `Registration{Verification,AutoCreatePersonalOrgs,NativeUserMode,OrgMode}`, `Keys{Source,Path,VerifyOnly}`, `Identity{Providers,ProviderDescriptors}`, `APIKeys{Prefix,MaxTTL}`, `RBAC{Permissions,DefaultRoles,OwnerOwnsAppResources}`; top-level `Environment`,`Schema`,`SolanaNetwork`. Removed the old `SolanaConfig` and the `ResourceScopeAuthorizer` Config field (now `WithResourceScopeAuthorizer` option; SNS auto-on via `WithSolanaSNSResolver`, timeout 3s/cache 24h fixed). Constructors: `core.NewService(opts Options, keys Keyset, coreOpts ...Option)`, `core.NewFromConfig(cfg Config, pg *pgxpool.Pool, extraOpts ...Option)` (pg may be nil at the CORE layer — verify-only/config tests; the mandatory-pg #106 contract is enforced at the host-facing `authhttp.NewServer`, which rejects nil), `authhttp.NewServer(cfg, pg, opts ...Option)`; `authhttp.NewService` removed. NOTE `core.Options` (low-level flat struct) is intentionally UNCHANGED — only the high-level `Config` was regrouped. Also fixed a latent bug: `NewFromConfig` had been silently dropping its `pg`/`extraOpts` args. Files: core/config.go, core/options.go (new), core/service.go, core/ephemeral.go, http/server.go, http/service.go, every test file + authkit-devserver.go migrated. Full `go test ./...` green against AUTHKIT_TEST_DATABASE_URL. README examples updated to the grouped Config + options API. Consumers SHIPPED: openrails v0.52.0 (on authkit v0.47.0), doujins + hentai0 bumped to authkit v0.47.0 + openrails v0.52.0 (all pushed).

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
- [x] Define `type Option` + a `WithX` constructor per optional dep — `core.Option` (core/options.go) + `authhttp.Option` (http/server.go)
- [x] Constructors apply options inside, then validate — `core.NewService`/`NewFromConfig`/`authhttp.NewServer`
- [x] Group the `Config` fields into sub-structs (Token/Frontend/Registration/Keys/Identity/APIKeys/RBAC + top-level Environment/Schema/SolanaNetwork) — HARDCUT, no flat aliases
- [x] Remove the chainable `With*` methods from core.Service AND http.Service — HARDCUT, no forwarding shims
- [x] Update README — all examples migrated to grouped `Config` sub-structs + `NewServer(cfg, pg, opts...)` / functional options (no flat fields, no `WithX` chains, `DisableRateLimiter`→`WithoutRateLimiter`)
- [x] Tests: every test file + devserver migrated to grouped `Config` + options; full `go test ./...` green
- [x] (was: schedule shim removal) N/A — hardcut removed everything in one break

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
