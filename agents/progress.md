<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 116

---

# #111: generalize `org` → permission-group — N-level resource-scoped RBAC (single-parent inheritance) + app-defined per-type role catalogs with optional custom roles

**Completed:** yes
**Status:** SHIPPED v0.49.0 (2026-06-22, BREAKING hard cut). org/platform RBAC fully replaced by the generic permission-group engine: typed single-parent groups, additive walk-up authorize (reach != capability), app-declared per-type catalogs + opt-in custom roles, containment enforced at app + DB (migration 008), 3-segment `<persona>:<resource>:<action>` perms, intrinsic `root` (platform: → root:), auto-generated per-persona management routes. org/platform removed entirely (no legacy/compat); api-keys + remote-apps re-nested under permission-groups. **v0.50.0 (2026-06-22) COMPLETES the route surface: api-keys/remote-applications/invites/custom-roles management routes ALL wired (ZERO 501 stubs; TestAllGeneratedRoutesWired guards it), + the group-invite core flow, + /me/groups + member listing, + restored auth/identity tests (oauth2/registration/admin/delegation/federation), all integration-tested vs live PG.** `go build/vet/test ./...` green (17 packages). Route surface is config-derived (a persona gets only its enabled ManagementProfile flags' routes: ~6 members-only, ~12 openrails merchant/customer, ~17 full tensorhub org); the `invitation` family is off-by-default and the drop candidate if no consumer adopts it. Consumers must migrate: openrails #567, tensorhub #498, doujins #416, hentai0 #176, cozy-art #152 (order: openrails first — it's embedded by doujins/hentai0/cozy-art + consumed by tensorhub).
**Status (original):** PLANNED 2026-06-22 (Claude + Paul). Deliberate extension of the #95-frozen RBAC model — large, cross-repo. Tensorhub is the main beneficiary (per-repo/dataset/endpoint groups + custom roles); OpenRails adopts the shallow case in its own tracker (openrails #567).

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
- [x] Schema: `permission_groups` (type, parent_id, resource_ref) + `group_role_assignments` + `group_custom_roles`; migrate `orgs`→groups (type=`org`, parent=root) and `org_members`→assignments (greenfield hard cut, no dual-write).
- [x] Config: per-type role catalog (name→perms, `owner` required) + per-type **management profile** (all bool, conservative defaults = all false / no API routes): `api-routes.member-assignment`, `api-routes.custom-role-creation`, `api-routes.api-key-minting`, `api-routes.remote-app-registration`, `api-routes.invitation`. Each flag = generate-that-route-group-or-not (false ⇒ 404; host can still do it via core).
- [x] Custom roles: gate DefineRole/SetRolePermissions on the type's `AllowCustomRoles`; store in `group_custom_roles`; assignable only within the defining group.
- [x] Authorize: add the resource/group parameter + parent-chain walk + additive union; keep namespace-anchored glob matching; memoize per (principal, group).
- [x] Re-nest remote_applications + api-keys under a permission-group; update `ResolveRemoteApplicationAuthority` to resolve via group + parent walk.
- [x] Owner role per type = `<type>:*` (namespace-pure; NEVER bare `*`, NEVER another persona's namespace). **`OwnerOwnsAppResources` (#100) is OBSOLETE** (decision #5): the org owner reaches its repos/endpoints via `org:<R>:*` (covered by `org:*`), NOT by holding `repo:*` — drop the cross-namespace owner seed (it survives only as a no-op for flat consumers, or is removed).
- [x] HTTP surface (DECIDED — auto-generated per-persona, addressed by RESOURCE id): build a ROUTE GENERATOR that, from each declared persona + its management profile, emits `/:persona/:resource-id/{members, members/:user/roles, roles[/:role], api-keys, remote-applications, invites}` — ONLY the profile-enabled endpoints (disabled ⇒ NOT generated ⇒ 404). `:resource-id` = the resource's OWN id (merchant/repo/org id the caller already has); resolve `(persona, resource-id) → group` via `resource_ref` — the permission-group id is INTERNAL, never in requests/responses. Validate `:persona` against the resolved group's type (404 on mismatch); gate each route on `<persona>:<resource>:<action>`. Cross-persona discovery `/me/groups` (returns `{persona, resource-id, role}`). Generate OpenAPI from the same config. Keep auth/identity + intrinsic `/admin/*`. HOST owns resource-lifecycle/domain routes. No `org`-named special-case — `/org/:org-id/*` is just the `org` persona's generated tree.
- [x] Built-ins: provision the per-type group-management perm set (`<type>:members:manage` etc.) in EVERY type's catalog; seed `owner` (=`<type>:*`) + `member` per group on create; ship `root` `super-admin` (=`root:*`).
- [x] Collapse `platform` into the tree as the `root` group (DECIDED): the single built-in group. Ship the authkit-intrinsic root catalog (`root:users:*`, `root:groups:*`, `root:roles:manage`, `root:remote-apps:manage`, `root:api-keys:revoke`, `root:sessions:revoke`); apps extend it with their own moderation perms. **Rename the `platform:` permission namespace to `root:`** (node and namespace match — supersedes the old "keep platform:" call; one-time greenfield rename across consumers). Root catalog is moderation-only; root `owner` holds `root:*` (reach ≠ capability).
- [x] Permission naming: VALIDATE every declared catalog perm as `<persona>:<resource>:<action>` (exactly 3 segments, regex above); reject 2-/4-part; enforce persona = a declared group type. Globs (`persona:*`, `persona:resource:*`) allowed in grants only.
- [x] Containment schema: per-type `allowedParents` config + `group_type_parents` table + denormalized `parent_type`. Enforce at BOTH levels — `CreatePermissionGroup` validates `parent.type ∈ allowedParents` (clear error), and a DB CHECK/trigger rejects off-shape rows. `parent_id NOT NULL` for non-root; `root` is a parentless singleton.
- [x] Remove the built-in `org` ENTIRELY: rename the consumer API (`CreateOrg`→`CreatePermissionGroup(type,…)`, plus `AssignRole`/`DefineRole`/`HasAdminPermission`/membership) to group-scoped + type-parameterized; hard cut, no `org`-named API. An app may declare ZERO non-root types (doujins/hentai0) — authkit must not assume any type exists.
- [x] Tests: parent-walk inheritance (repo perm via org owner); additive union; custom-role opt-in ON vs OFF (fixed catalog rejects an unknown role); owner auto-grant; platform-root isolation; single-parent enforced (no cross-tree).
- [x] Version bump (v0.49.0 + v0.50.0 shipped). Consumer migration is cross-repo and tracked in those trackers: openrails #567, tensorhub #498, doujins #416, hentai0 #176, cozy-art #152 (order: openrails first — embedded by doujins/hentai0/cozy-art + consumed by tensorhub).

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

# #113: bind intrinsic admin user routes to root permissions + collapse deleted-user listing into `/admin/users`

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Intrinsic `/admin/users...` routes now use one shared root-permission gate: user JWTs authorize through `svc.Can(user_id, "user", "root", "", perm)`, while API-key, delegated, and remote-application principals authorize through `claims.HasPermission(perm)`. Remote application self tokens now load stored permission-group authority via `ResolveRemoteApplicationAuthority`. `root:users:update` is in the intrinsic root catalog. `GET /admin/users/deleted` is removed; deleted users are listed through `GET /admin/users?status=deleted`. The user-list role filter is hard-cut to `root_role`. Validation: `go test ./...` passed.
**FOLLOW-UP 2026-06-23 (Claude) — finished the cleanup the Codex pass left behind.** The Codex pass bound `/admin` to root perms but kept a BESPOKE admin-auth path (`adminRequired` closure in `http/routes.go` + `(*Service).requireAdminPermission` in `http/admin_routes.go`), which violates the design rule "there is no separate admin tier — admin authority is just `root:*` perms gated through the granular permission system." Audit + fix: (1) **removed `adminRequired`/`requireAdminPermission` entirely**; renamed the method to a GENERIC, group-parameterized gate `(*Service).requirePermission(groupType, resourceRef, perm, next)` (user JWTs → `svc.Can(...)`, machine principals → `claims.HasPermission`), and the `/admin/users...` routes now call it via a `rootPermission(perm, h)` closure = `required(s.requirePermission(core.RootType, "", perm, h))`. Same behavior + same passing tests, but no admin-specific auth construct. (2) **Deleted 10 ORPHANED `Err*Platform*` HTTP error-code constants** in `http/error_codes.go` (`ErrAssignPlatformRoleFailed`, `ErrPlatformRole{Define,Delete,Lookup,Members,SetPerms}Failed`, `ErrPlatformRolesListFailed`, `ErrPlatformPermission{,s}LookupFailed`, `ErrRevokePlatformRoleFailed`) — leftovers from the removed platform-role/permission management routes (zero live refs, not referenced by `error_codes_test.go`). (3) Verified the #111/#112 engines are genuinely present (not stubs): `Can()` parent-walk + additive union, migration 008 containment trigger, 3-segment + namespace-purity validation, route generator (zero live 501 stubs), `SetEntitlementsProvider` mint-wiring + its passing test. Validation: `go build/vet ./...` clean; DB-free http + core permission tests + the #112 setter test green. (Full PG suite needs `AUTHKIT_TEST_DATABASE_URL`, unset here.) REMAINING (cosmetic, not done — see Tasks): a few stale comments still describe the old org/platform model.

## Current surface
`GET /admin/users` is already the dashboard list route. It is paginated and queryable:
- `page` / `page_size` (defaults page=1, page_size=50, max=200)
- `search` (username/email/phone ILIKE)
- `root_role` (root permission-group role slug; `admin` maps to `super-admin`). The old `role` query name was ambiguous once users could belong to many permission groups, so the dashboard contract is hard-cut to `root_role`.
- `status` (`active`, `banned`, `deleted`, `any`; empty = non-deleted)
- `sort` (`created_at`, `last_login`, `username`, `email`; empty = `created_at`)
- `order` (`desc` by default; `asc` flips it)
- `entitlement` (provider-backed filter; errors if no filter provider is configured)

`GET /admin/users/deleted` is redundant: it only forces `status=deleted` and then runs the same list/count query. Remove it and use `GET /admin/users?status=deleted` instead.

## Authorization model
The same admin route must authorize all supported principal shapes:
- Regular user JWT: authorize through the root permission-group, `svc.Can(user_id, "user", "root", "", perm)`.
- API key: authorize through `claims.Permissions` / `claims.HasPermission(perm)`.
- Delegated user token: authorize through `claims.Permissions` / `claims.HasPermission(perm)`.
- Remote application self token: authorize through stored remote-application authority surfaced in `claims.Permissions`; verifier wiring resolves `ResolveRemoteApplicationAuthority` instead of an empty permission ceiling.

## Permission map
- `GET /admin/users` -> `root:users:read`
- `GET /admin/users/{user_id}` -> `root:users:read`
- `GET /admin/users/{user_id}/signins` -> `root:users:read`
- `POST /admin/users/ban` -> `root:users:ban`
- `POST /admin/users/unban` -> `root:users:ban`
- `POST /admin/users/set-email` -> add/use `root:users:update`
- `POST /admin/users/set-username` -> add/use `root:users:update`
- `POST /admin/users/set-password` -> add/use `root:users:update`
- `POST /admin/users/{user_id}/sessions/revoke` -> `root:sessions:revoke`
- `POST /admin/users/{user_id}/password-reset` -> `root:users:update`
- `DELETE /admin/users/{user_id}` -> `root:users:delete`
- `POST /admin/users/{user_id}/restore` -> `root:users:delete`

## Tasks
- [x] Add `root:users:update` to AuthKit's intrinsic root permission catalog; keep existing `root:users:read|suspend|ban|delete` stable.
- [x] Add one shared HTTP permission gate for route specs, not per-handler ad hoc checks. It must accept user JWTs via root-group `Can`, and API-key/delegated/remote-app principals via `claims.HasPermission`.
- [x] Extend the verifier/core enricher seam so remote application self tokens load stored permission-group authority (`ResolveRemoteApplicationAuthority`) into `claims.Permissions`.
- [x] Apply the shared gate to every intrinsic `/admin/users...` route according to the map above.
- [x] Remove `GET /admin/users/deleted`; make `GET /admin/users?status=deleted` the only deleted-user listing route.
- [x] Rename the admin user-list role filter from ambiguous `role` to `root_role` and document it as filtering only membership in the singleton root permission group.
- [x] Keep `GET /admin/users` pagination/filter/sort behavior and document it as the admin dashboard list contract.
- [x] Add tests for all four principal shapes: root-admin user JWT, API key with `root:users:read`, delegated token with `root:users:read`, and remote application self token with `root:users:read`.
- [x] Add denial tests: authenticated user without root permission, API key without root permission, delegated token without root permission, remote application without stored root permission.
- [x] Add route/table tests proving `/admin/users?status=deleted` works and `/admin/users/deleted` is gone.
- [x] Run `go test ./...` and update this issue with the exact validation result. Result: passed 2026-06-23.

### Follow-up cleanup (Claude 2026-06-23) — eliminate the bespoke admin tier + dead remnants
- [x] Remove the `adminRequired` closure (`http/routes.go`) and the `(*Service).requireAdminPermission` method (`http/admin_routes.go`) — there must be NO admin-specific auth construct.
- [x] Replace them with a GENERIC granular gate `(*Service).requirePermission(groupType, resourceRef, perm, next)` (users → `svc.Can`; machine principals → `claims.HasPermission`); intrinsic root-scoped routes call it via a `rootPermission(perm, h)` closure bound to `core.RootType`.
- [x] Delete the 10 orphaned `Err*Platform*` HTTP error-code constants in `http/error_codes.go` (dead remnants of the removed platform-role/permission routes; zero live refs).
- [x] Re-verify #111/#112 are genuinely wired (Can parent-walk, migration 008 containment trigger, 3-seg validation, route generator zero-stub, entitlements mint setter + test). Confirmed.
- [x] Cosmetic: deleted/fixed stale comments describing the old org/platform model — removed the dead `http/routes.go` remote-app org-nested comment block; rewrote the `core/service.go` token-claims note (was "profiles.platform_roles + platform:* perms" → permission-group engine #111); rewrote the `RBACConfig`/`DefaultRole` `org:`/`platform:` docstrings in `core/config.go` (Permissions/DefaultRoles/OwnerOwnsAppResources now described accurately; OwnerOwnsAppResources flagged as the legacy #100 no-op superseded by #111). build + vet green.

## Acceptance
- No intrinsic admin-user route is reachable by a merely authenticated user.
- Admin authority is permission-based, not route-name-based or role-name-based.
- All four supported principal classes can call admin routes when they carry the required root permission.
- Deleted-user dashboard listing uses `GET /admin/users?status=deleted`; the duplicate `/admin/users/deleted` route is removed.

---

# #114: collapse password reset + verification link APIs to one confirm route per channel

**Completed:** yes
**Status:** DONE 2026-06-23 (Codex). Hard-cut the redundant `confirm-link` JSON endpoints. Password reset confirm now accepts `{token,new_password}` and consumes the one-time reset token directly; no public reset-session handoff remains. Email/phone verification token confirms were folded into `/email/verify/confirm` and `/phone/verify/confirm` alongside the existing code paths. Removed public `*/confirm-link` route registrations and updated docs. Validation: `go test ./http`; `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable go test ./http -run 'TestPasswordResetConfirmConsumesTokenDirectly|TestVerificationConfirmAcceptsCodeOrToken' -count=1`; `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable go test ./...` all passed.

## Current surface
Password reset currently has three routes per channel:
- `POST /email/password/reset/request`
- `POST /email/password/reset/confirm` with `{reset_session,new_password}`
- `POST /email/password/reset/confirm-link` with `{token}` -> `{reset_session}`
- `POST /phone/password/reset/request`
- `POST /phone/password/reset/confirm` with `{reset_session,new_password}`
- `POST /phone/password/reset/confirm-link` with `{token}` -> `{reset_session}`

Email/phone verification does make the same route-shape mistake, but with a real distinction in payloads: `confirm` is the code path and `confirm-link` is the token path.
- `POST /email/verify/request`
- `POST /email/verify/confirm` with `{code}`
- `POST /email/verify/confirm-link` with `{token, identifier?, email?}`
- `POST /phone/verify/request`
- `POST /phone/verify/confirm` with `{phone_number, code}`
- `POST /phone/verify/confirm-link` with `{token, identifier?, phone_number?}`

## Target surface
Password reset:
- `POST /email/password/reset/request`
- `POST /email/password/reset/confirm` with `{token,new_password}`
- `POST /phone/password/reset/request`
- `POST /phone/password/reset/confirm` with `{token,new_password}`

Verification:
- `POST /email/verify/request`
- `POST /email/verify/confirm` with either `{code}` or `{token, identifier?, email?}`
- `POST /phone/verify/request`
- `POST /phone/verify/confirm` with either `{phone_number,code}` or `{token, identifier?, phone_number?}`

## Notes
- The reset token is already a short-lived, one-time bearer secret stored by hash in the ephemeral store. `core.ConfirmPasswordReset(ctx, token, new_password)` already exists, so the HTTP handler should call it directly.
- The existing `reset_session` adds a second bearer secret and a second request without materially improving security for this API surface.
- Hosts should set the reset/verify page with `Referrer-Policy: no-referrer` or same-origin and call `history.replaceState` after reading the token from the URL.
- No AuthKit `GET` link endpoint is needed; clicked links land on the host frontend, not on AuthKit JSON routes.

## Tasks
- [x] Change email password reset confirm to accept `{token,new_password}` and call `ConfirmPasswordReset`; delete `reset_session` from the HTTP contract.
- [x] Change phone password reset confirm to accept `{token,new_password}` and call `ConfirmPasswordReset`; keep the current phone response shape only if an existing consumer needs `user_id`.
- [x] Remove `POST /email/password/reset/confirm-link` and `POST /phone/password/reset/confirm-link` from `http/routes.go`.
- [x] Merge email verification token confirmation into `POST /email/verify/confirm`: `{code}` keeps the current code path; `{token}` runs the current `confirm-link` path.
- [x] Merge phone verification token confirmation into `POST /phone/verify/confirm`: `{phone_number,code}` keeps the current code path; `{token}` runs the current `confirm-link` path.
- [x] Remove `POST /email/verify/confirm-link` and `POST /phone/verify/confirm-link` from `http/routes.go`.
- [x] Delete now-unused confirm-link handlers/tests or fold their test cases into the confirm-route tests.
- [x] Update `agents/api-endpoints.md`, README examples, and route-table tests so the public surface shows two routes per channel.
- [x] Add/adjust focused HTTP tests: reset token+password succeeds once, reused token fails, reset-session payload is rejected, code verification still works, token verification works, removed confirm-link routes 404.
- [x] Run `go test ./...` and update this issue with the exact validation result. Result: passed with `AUTHKIT_TEST_DATABASE_URL=postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable`.

## Acceptance
- Password reset has exactly two public routes per channel: `request` and `confirm`.
- Email and phone verification have exactly two public routes per channel: `request` and `confirm`.
- There is no public `*/confirm-link` route in the canonical API surface.
- Existing one-time token semantics remain enforced by the ephemeral store.

---

# #101: TOTP (authenticator-app) 2FA method — offline second factor alongside email/SMS

**Completed:** no
**Status:** PLANNED 2026-06-23 (Paul + Codex). Move into active work because it feeds #103: AuthKit needs a strong offline MFA method before token assurance can distinguish merely password-fresh sessions from MFA-fresh sessions.

## Linkage

- #103 projects authentication assurance into access tokens via `amr`, `acr`, and `auth_time`.
- This issue adds the `totp` factor that should map to `["pwd","otp","mfa"]` when used after password auth.
- The reauth path in #103 must be able to use TOTP to upgrade the current session, not just use 2FA during login.

## Goal

Add **TOTP** (RFC 6238 — Google Authenticator / Authy / 1Password / Microsoft Authenticator) as a third 2FA `method`, alongside the existing `email` and `sms` code delivery.

Today `profiles.two_factor_settings.method IN ('email','sms')` and every second factor is a server-sent 6-digit code (`Require2FAForLogin` -> email/SMS). Both require deliverability and are weaker factors. TOTP is offline: the authenticator app and server independently derive the same time-based code.

This reuses the existing single-method-per-user model, backup codes, the `Create/Verify/Clear2FAChallenge` gate, and the generic `POST /2fa/verify` endpoint. A user picks **email OR sms OR totp**. Multi-method fallback stays out of scope.

## Design

1. No send step. `Require2FAForLogin` branches on method: for `totp`, it skips code generation, ephemeral code storage, and email/SMS delivery. The password-login 2FA branch returns `{requires_2fa:true,user_id,method:"totp",challenge}`.

2. Two-step enrollment:
- `POST /user/2fa` with `{method:"totp"}` generates a random 160-bit base32 secret, stores it as pending/unconfirmed, and returns `{secret,otpauth_uri}`. AuthKit returns the provisioning URI, not a QR image.
- `POST /user/2fa` with `{method:"totp",code:"123456"}` verifies the code against the pending secret, enables TOTP, persists the encrypted secret, and returns backup codes.

3. Verify computes instead of compares. `Verify2FACode` branches for `totp` and computes expected codes over the current 30s step with a +/-1 window. `VerifyBackupCode` stays unchanged.

4. Replay protection. Track the last consumed TOTP time-step per user and reject reuse. Prefer a `last_totp_step bigint` column unless implementation shows an ephemeral key is cleaner.

5. Secret at rest. TOTP is the first persistent 2FA shared secret, so store it encrypted. Prefer a host-provided AES-GCM key in core config and gate TOTP enrollment unless it is configured.

## Schema and deps

- Add a migration: `totp_secret`, `method` CHECK includes `'totp'`, and `last_totp_step`.
- Regenerate sqlc.
- Implement RFC 6238 with the Go stdlib unless a real edge case makes `github.com/pquerna/otp` worth owning.

## Integration points

- **core**: `TwoFactorSettings`, `Enable2FA`, `Get2FASettings`, `Require2FAForLogin`, `Verify2FACode`, new `StartTOTPEnrollment`, secret encrypt/decrypt helpers.
- **http**: unified `POST /user/2fa`, `DELETE /user/2fa`, `POST /user/2fa/backup-codes`, `GET /user/2fa`, password-login 2FA branch.
- **routes/buckets**: keep per-method/per-action buckets internally even though setup/enable shares `POST /user/2fa`.
- **docs**: README 2FA section and `agents/api-endpoints.md`.

## Route cleanup

Keep `GET /user/2fa` as the status route.

Collapse enrollment into one authenticated route:
- `POST /user/2fa` with `{method:"email"}` enables email 2FA and returns backup codes.
- `POST /user/2fa` with `{method:"sms",phone_number:"..."}` starts/restarts SMS setup and sends a code.
- `POST /user/2fa` with `{method:"sms",phone_number:"...",code:"..."}` verifies the pending SMS setup and enables SMS 2FA.
- `POST /user/2fa` with `{method:"totp"}` starts/restarts TOTP setup and returns `{secret,otpauth_uri}`.
- `POST /user/2fa` with `{method:"totp",code:"..."}` verifies the pending TOTP setup and enables TOTP 2FA.

Use resource-shaped routes for sensitive mutations:
- `DELETE /user/2fa` disables 2FA.
- `POST /user/2fa/backup-codes` regenerates backup codes and returns them once.

Keep public login verification separate:
- `POST /2fa/verify` remains the password-login second-factor completion route and mints a new session.
- Authenticated step-up reauth belongs to #103, not this login route.

Remove old ceremony routes from the canonical API surface:
- `POST /user/2fa/start-phone`
- `POST /user/2fa/enable`
- `POST /user/2fa/disable`
- `POST /user/2fa/regenerate-codes`

## Tasks

- [ ] Add host-provided AES-GCM TOTP secret encryption config; fail closed for TOTP enrollment when missing.
- [ ] Add migration for `totp_secret`, `last_totp_step`, and `method IN ('email','sms','totp')`; regenerate sqlc.
- [ ] Add stdlib TOTP secret generation, otpauth URI builder, and code verification with +/-1 step skew.
- [ ] Add pending TOTP enrollment storage with short TTL.
- [ ] Extend `Enable2FA` to verify pending TOTP before enabling and persisting the encrypted secret.
- [ ] Branch `Require2FAForLogin` and `Verify2FACode` for `totp`.
- [ ] Add replay protection for consumed TOTP time steps.
- [ ] Replace setup/enable routes with unified `POST /user/2fa`; keep per-method rate limits internally as needed.
- [ ] Replace `POST /user/2fa/disable` with `DELETE /user/2fa`.
- [ ] Replace `POST /user/2fa/regenerate-codes` with `POST /user/2fa/backup-codes`.
- [ ] Update 2FA status to report `method:"totp"`.
- [ ] Wire TOTP into #103 reauth so a TOTP code can upgrade the current session and record MFA `amr`.
- [ ] Remove old 2FA ceremony routes from `http/routes.go`.
- [ ] Add tests: enroll -> confirm -> login, wrong/expired code, +/-1 skew, replay rejected, backup-code path still works, secret is not stored plaintext.
- [ ] Update README and `agents/api-endpoints.md`.
- [ ] Run `go test ./...` and record the result here.

## Acceptance

- TOTP can be enrolled only after prove-possession of the generated secret.
- TOTP login works through the existing 2FA challenge flow without sending email/SMS.
- TOTP secrets are encrypted at rest.
- TOTP codes cannot be replayed in the same accepted time step.
- #103 can treat TOTP-backed reauth as MFA-fresh.
- The canonical authenticated 2FA management surface is `GET/POST/DELETE /user/2fa` plus `POST /user/2fa/backup-codes`.

---

# #103: Emit OIDC `amr`/`acr`/`auth_time` assurance claims and collapse sensitive contact-change routes

**Completed:** no
**Status:** IN PROGRESS 2026-06-23 (Paul + Codex). Token assurance primitives are implemented; `/reauth/2fa` and contact-change route collapse remain. Promote the existing issuer-local fresh-auth machinery into token-visible assurance claims, and use the same "stale session -> reauth required -> retry" pattern to simplify the account email/phone change API.

## Naming

Use "sudo mode" as a docs-friendly nickname only. Public API names should stay boring and standard: fresh auth, step-up auth, `auth_time`, `amr`, `acr`, `reauth_required`.

## Current problem

AuthKit already tracks session freshness server-side:
- `RequireFreshSession(ctx, userID, sessionID, now)` returns `ErrReauthenticationRequired` when the current session is too old for a sensitive operation.
- `MarkSessionAuthenticated(ctx, userID, sessionID)` upgrades the current session after reauth.
- `/reauth/password` and linked-provider reauth already call `MarkSessionAuthenticated`.
- `/user/me` already exposes freshness state to frontends.

But this is issuer-local. Downstream resource servers only see JWTs, so they cannot tell whether the user recently re-proved identity or used MFA. Tokens say who the user is, not how or when they authenticated.

The account contact-change routes also expose too much HTTP ceremony for the same pattern. Email and phone change currently have separate `request`, `confirm`, `resend`, and `cancel` routes. The real flow is simpler: an authenticated user asks to change the value; AuthKit either accepts, rejects, or returns `reauth_required`; after reauth the frontend retries; confirmation proves control of the new destination.

## Target contact-change surface

Email:
- `POST /user/email/change` with `{new_email,password?}` starts or restarts the pending change. If the session is stale and no valid inline password is supplied, return `403 reauth_required` with `reauth_methods` and `fresh_auth`.
- `POST /user/email/change` with `{code}` confirms the pending change and applies the new email.

Phone:
- `POST /user/phone/change` with `{phone_number,password?}` starts or restarts the pending change. If the session is stale and no valid inline password is supplied, return `403 reauth_required` with `reauth_methods` and `fresh_auth`.
- `POST /user/phone/change` with `{phone_number,code}` confirms the pending change and applies the new phone.

Rules:
- Request/start requires fresh auth or a valid inline password, exactly like today.
- Confirm requires the destination proof code, not fresh auth; the pending change was already gated at creation.
- Resend does not need a route. Posting the same target again supersedes the pending record and sends a new code.
- Cancel does not need a route. Pending changes expire, and a new request supersedes the old pending record.
- Payloads that mix start and confirm fields ambiguously should return `invalid_request`.
- Remove the old `request`, `confirm`, `resend`, and `cancel` contact-change routes from the canonical API surface.

## Token assurance design

Record method and assurance at authentication time. Extend the session freshness record to store the methods used and the authentication timestamp. The freshness timestamp already written by `MarkSessionAuthenticated` is the source of truth for `auth_time`.

Minimum useful access-token claims:
- `auth_time`: when this session last proved identity.
- `amr`: how identity was proved (`pwd`, `otp`, `mfa`, etc.).
- `acr`: optional assurance class; add now only if AuthKit chooses a concrete class mapping. Do not invent meaningless levels.

Extend `MarkSessionAuthenticated` and initial login/2FA paths to accept the authentication methods used. Tentative AuthKit method mapping:
- password login or password reauth -> `["pwd"]`
- email/SMS 2FA -> `["pwd","otp","mfa"]`
- TOTP (#101) -> `["pwd","otp","mfa"]`
- Solana SIWS -> `["swk"]`
- OIDC login -> pass through upstream `amr` when present, otherwise decide whether to flatten to `["pwd"]`
- passkey (future) -> `["swk","mfa"]` or `["hwk","mfa"]`, depending on credential metadata

Emit `amr`, `acr`, and `auth_time` through the existing `extra map[string]any` passed to `IssueAccessToken` by password login, 2FA login, OIDC/OAuth login, Solana login, refresh, and any reauth-triggered refresh path.

Verify side:
- Add `AMR []string`, `ACR string`, and `AuthTime time.Time` to verified claims.
- Add helpers `Claims.HasAMR(m)` and `Claims.AuthenticatedWithin(d)`.
- Add middleware: `RequireFreshAuth(maxAge)`, `RequireMFA()` / `RequireAMR("otp")`, and `RequireACR(level)`.
- These must fail closed for missing claims and deny machine credentials.

Authenticated step-up route:
- Keep `POST /2fa/verify` for login only; it verifies the password-login 2FA challenge and mints a new session.
- Add `POST /reauth/2fa` for authenticated step-up. With no `code`, email/SMS methods send a reauth code and TOTP returns the method/challenge metadata. With `code`, it verifies the current user's configured factor, calls `MarkSessionAuthenticated` with MFA `amr`, returns `fresh_auth`, and lets the frontend refresh the access token before retrying.
- Store any email/SMS reauth code against the current user + current session, not just the user, so a code from one browser session cannot upgrade another session.
- Backup codes may be accepted for login recovery, but should not count as MFA-fresh step-up unless explicitly decided; default to not using backup codes for sudo-mode reauth.

## Subtleties

- Snapshot semantics: `amr`/`acr`/`auth_time` are snapshotted into the access token. After step-up, the client refreshes the access token, then retries the sensitive downstream call.
- Single clock: `auth_time` must come from the same freshness timestamp used by `RequireFreshSession`.
- Method matters: password-fresh and MFA-fresh are not the same. Do not store only a timestamp.
- Back-compat: existing tokens without these claims still work on routes that do not require them.
- Per-endpoint sudo policy is host/resource-server policy. AuthKit ships the primitives and uses them for its own sensitive account routes.

## Tasks

- [x] Add method/assurance storage to the session freshness record.
- [x] Extend `MarkSessionAuthenticated` and initial login/2FA paths to record `amr`.
- [ ] Decide whether AuthKit should set concrete `acr` levels. Current implementation parses/gates `acr` but does not mint it.
- [x] Emit `amr`/`auth_time` from every access-token issuance path by deriving them from the `sid` session. `acr` remains unset until a real assurance-class mapping exists.
- [x] Parse `amr`/`acr`/`auth_time` into verified claims; add `HasAMR` and `AuthenticatedWithin`.
- [x] Add `RequireFreshAuth(maxAge)`, `RequireMFA()` / `RequireAMR(...)`, and `RequireACR(level)` middleware; fail closed and deny machine credentials.
- [ ] Add `POST /reauth/2fa` for authenticated MFA step-up; do not reuse login-only `POST /2fa/verify`.
- [ ] Gate `DELETE /user/2fa` and `POST /user/2fa/backup-codes` on fresh auth / MFA step-up.
- [ ] Collapse email change to `POST /user/email/change` for both start/restart and confirm.
- [ ] Collapse phone change to `POST /user/phone/change` for both start/restart and confirm.
- [ ] Remove the old contact-change `request`, `confirm`, `resend`, and `cancel` routes from `http/routes.go`.
- [ ] Update `agents/api-endpoints.md`, README examples, and route-table tests.
- [ ] Add focused tests for stale session -> `reauth_required` -> reauth -> retry, inline password fallback, code confirmation, same-target resend-by-repost, ambiguous payload rejection, removed old routes, token claim emission, and downstream middleware gates. Middleware/parser coverage exists in `verify/claims_assurance_test.go`; remaining tests are for the reauth/contact-change flows.
- [ ] Run `go test ./...` and record the result here.

## Acceptance

- Resource servers can require recent auth and/or MFA using token claims only.
- AuthKit's issuer-local fresh-auth gate and token `auth_time` use one source of truth.
- Password-fresh and MFA-fresh are distinguishable.
- Login 2FA and authenticated step-up 2FA are separate flows: `/2fa/verify` mints login sessions; `/reauth/2fa` upgrades the current session.
- Email change has one canonical public route: `POST /user/email/change`.
- Phone change has one canonical public route: `POST /user/phone/change`.
- The frontend can treat contact changes as: submit change, handle success/error/`reauth_required`, reauth, retry.
- No public contact-change `request`, `confirm`, `resend`, or `cancel` routes remain in the canonical API surface.

---

# #115: Stripe-style error envelope — nest `{type, code, message, param}` to match openrails

**Completed:** mostly
**Status:** IMPLEMENTED 2026-06-23 (Claude) — envelope + helpers done; docs + version bump remain. Added the shared core-free envelope `authbase/httperror.go` (`ErrorObject{Type,Code,Message,Param,Metadata}`, `ErrorEnvelope`, `ErrorTypeForStatus`, `ErrorMessage` curated+humanized catalog) used by BOTH `http/errors.go` and `verify/helpers.go`, so authhttp + verify emit the identical nested `{"error":{type,code,message,param?,metadata?}}` shape. Type is derived from HTTP status (openrails taxonomy strings); `code` values unchanged (#104); rate-limit/availability context moved into `error.metadata` (`tooMany`/`tooManyAvailability`/`reauthRequired`/username-rename all fold into `sendErrData`). `param` auto-attached for known identity-validation codes via `validationParam` map + `badRequestParam`. Tests: `authbase` envelope unit tests + updated `TestHTTPErrorCodeConstantServedByAPIHandler` (asserts nested code/type/message) green; `go build/vet ./...` green; DB-free `http`/`verify` error tests green. REMAINING (`[ ]` below): README "Error contract" + `agents/api-endpoints.md` docs, and the BREAKING version bump (v0.51.0) + consumer-migration note. NOTE: landed on a shared working tree alongside concurrent #103/#114 work.
**Status (original):** PLANNED 2026-06-23 (Claude). authkit emits a FLAT, code-only error envelope `{"error":"<code>"}` while openrails emits the full Stripe-style NESTED envelope `{"error":{"type","code","message","param?","metadata?"}}` (openrails `pkg/api/error.go`). Same ecosystem, two different error shapes — a client hitting both APIs gets inconsistent errors. This brings authkit's envelope to the SAME Stripe shape openrails uses, keeping the 240 existing `ErrorCode` values stable as the `code` field. Done CENTRALLY at the error helpers (`http/errors.go` + `verify/helpers.go`) so the ~all call sites are untouched. BREAKING wire change.

## Problem
- authkit today (`http/errors.go`): `type errResp struct { Error ErrorCode json:"error" }` → `{"error":"invalid_request"}`. Rate-limit/availability data rides as TOP-LEVEL siblings (`retry_after_seconds`, ...). No `type`, no human `message`, no `param`.
- openrails (`pkg/api/error.go`): `{"error":{"type":"invalid_request_error","code":"...","message":"...","param":"...","metadata":{...}}}` + a Stripe type taxonomy + importable `ErrorType*`/`Code*` consts.
- Both ALREADY use importable constants (authkit: 240 `authhttp.ErrorCode`, guard-tested; openrails: `pkg/api`). This issue is ONLY about envelope SHAPE + adding `type`/`message`/`param`, NOT de-stringifying (already done, #104).

## Target envelope (mirror openrails/Stripe)
```json
{ "error": { "type": "authentication_error", "code": "invalid_credentials",
             "message": "The email or password is incorrect.",
             "param": null, "metadata": { "retry_after_seconds": 30 } } }
```
- `code` — UNCHANGED: the existing `authhttp.ErrorCode` value (stable contract; 240 constants kept).
- `type` — NEW: small taxonomy aligned EXACTLY with openrails' strings — `invalid_request_error` (400/404/409), `authentication_error` (401), `authorization_error` (403), `rate_limit_error` (429), `api_error` (>=500). Derived from HTTP status, same as openrails `inferErrorTypeAndCode`.
- `message` — NEW: human-readable, localized via the existing `LanguageMiddleware`/request-locale. English default from a `code -> message` catalog; humanized-code fallback (`password_too_short` -> "Password too short.") so it is NEVER empty.
- `param` — NEW (optional): the offending field for validation errors (`email`, `password`, ...); omitted otherwise.
- `metadata` — NEW (optional): machine-readable context; the rate-limit/availability fields (`retry_after_seconds`, `limit`, `remaining`, action-availability) MOVE off the top level INTO `error.metadata`.

## Design
- **Central, call-site-free.** Change only the helpers: `sendErr`/`sendErrData`/`tooMany`/`tooManyAvailability` build the nested envelope; the ~all `badRequest(w, code)`/`unauthorized(w, code)`/... call sites stay as-is.
- **Shared, core-free envelope.** Put envelope types + builder (`Error{Type,Code,Message,Param,Metadata}`, `ErrorEnvelope{Error}`, `typeForStatus`, `Message(code, locale)`) in a stdlib-only package BOTH `authhttp` and the core-free `verify` package import (extend `authbase`, or a new `autherr`) — so `verify/helpers.go` (which #110 made emit the byte-identical flat envelope) stays in lockstep. NO import of openrails (authkit is the lower layer — see Open decision 3).
- **Type from status** (openrails parity): 400/404/409->`invalid_request_error`, 401->`authentication_error`, 403->`authorization_error`, 429->`rate_limit_error`, >=500->`api_error`.
- **Message catalog**: `code -> English message` map + humanized fallback; locale hook reads the request locale.
- **Param**: add `badRequestParam(w, code, param)` (+ envelope support); wire on validation paths that know the field; omitted elsewhere (full coverage incremental).

## Tasks
- [ ] Define the shared core-free envelope types + builder (`Error{Type,Code,Message,Param,Metadata}` + `ErrorEnvelope`) and `typeForStatus(status)` mirroring openrails' taxonomy strings; stdlib-only, importable by `authhttp` AND `verify`.
- [ ] `code -> message` catalog (English) + humanized-code fallback (never empty) + `Message(code, locale)` hook reading the request locale (LanguageMiddleware).
- [ ] Rewrite `http/errors.go` helpers (`sendErr`, `sendErrData`, `tooMany`, `tooManyAvailability`, `registrationDisabled`, ...) to emit the nested envelope; move rate-limit/availability sibling fields into `error.metadata`.
- [ ] Mirror the change in `verify/helpers.go` (`unauthorized`/`forbidden`) so the verify-only surface emits the identical envelope.
- [ ] Add `param` support + `badRequestParam` helper; wire on the obvious validation paths (email/password/username/phone), omit elsewhere.
- [ ] Update guard tests: keep the no-bare-string guard; ASSERT every emitted error carries non-empty `type` + `code` + `message` nested under `error`; update existing tests that decode the OLD flat `{"error":"code"}` (centralize on a test helper reading `error.code`).
- [ ] Docs: README "Error contract" + `agents/api-endpoints.md` — document the nested shape + type taxonomy; note it matches openrails/Stripe.
- [ ] Version bump (BREAKING -> v0.51.0). Record the consumer-migration follow-up (frontends + openrails/doujins/hentai0/tensorhub/cozy-art read `.error` as a string today -> must read `error.code`).

## Acceptance
- Every authkit HTTP error is `{"error":{type,code,message,...}}`; `code` values unchanged from #104; `type` in the openrails taxonomy; `message` always non-empty.
- `authhttp` and `verify` emit byte-identical envelope shapes.
- Rate-limit/availability context lives under `error.metadata`, not as top-level siblings.
- Guard test rejects bare-string codes AND empty `type`/`message`.
- authkit's envelope is structurally identical to openrails' `pkg/api.ErrorResponse`.

## Open decisions (pin while building)
1. Localize messages now or English-only v1? Lean ENGLISH-ONLY v1 (Stripe returns English), locale hook in place; localized catalogs follow.
2. `param` coverage — envelope supports it; wire only the obvious validation fields in v1, expand incrementally.
3. Share types with openrails? authkit is the LOWER layer (openrails imports authkit), so authkit defines the canonical envelope; a FOLLOW-UP could have openrails `pkg/api` re-export authkit's types to unify on ONE definition. Out of scope here.
4. Back-compat — clean break (no dual-emit), matching the #111 precedent; coordinate consumer migration via the version bump.
