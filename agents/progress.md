<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 138

---

---

# #136: Root RBAC redesign — owner/admin tiers, core-enforced no-escalation, bootstrap seed-if-absent

**Completed:** no

Proposed 2026-06-23 (Paul + Claude design session). Rework the `root` persona's
operator model into a clean two-tier scheme with escalation safety enforced in
CORE, not left to callers. Land this BEFORE consumers adopt (doujins #420) so they
migrate to the final shape once. doujins + hentai0 share ONE root group.

STATUS 2026-06-23 (Codex): API-key resource-scope escalation path fixed in
core. `MintAPIKeyWithOptions` now fails closed for non-empty `resources` unless a
host-supplied `WithAPIKeyResourceAuthorizer` allows the exact scope request; the
HTTP mint path no longer has any bypass because it calls the same core method.
DB-backed HTTP integration tests cover ordinary API-key mint/list/revoke, denied
resource scopes when no authorizer is configured, allowed scoped keys resolving
with resources, and a rejected cross-resource escalation attempt. Also updated
stale root-owner HTTP test setup to use the genesis group-assignment path under
the new owner/admin model. Validation:
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./http -run 'TestGroupAPIKey' -count=1 -v`
and
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./... -count=1`
passed against the running compose Postgres.

STATUS 2026-06-23 (Codex): Remaining #136 implementation is now DONE in the
working tree. Runtime assignment gates now use `<persona>:roles:manage` in both
generated HTTP member-mutation routes and core no-escalation checks; API-key role
grants now run the same core no-step-up check before insert; the legacy
owner-reserved root helper was removed so the unchecked genesis path can seed
`owner`; bootstrap owner seeding is covered as seed-if-absent and zero-owner
recovery. `ListRoleSlugsByUserErr` already exists on the public facade. Focused
DB-backed validation passed:
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./internal/authcore -run 'TestAssignRoleBySlugAs_NoEscalation_DB|TestAssignRoleBySlug_AllowsOwnerGenesis|TestReconcileBootstrapManifest|TestGeneratedRoutes_GatesAreCorrect' -count=1 -v`
and full DB-backed validation passed:
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./... -count=1`.
Release/tag remains a separate finalization step because this is still an
uncommitted dirty worktree and the repo is already tagged beyond the old
`v0.60.0` target (`v0.61.0`).

## Motivation
1. The root persona ships TWO equivalent `root:*` roles — `owner`
   (reserved/unassignable) and `super-admin` (assignable) — redundant and
   confusing ("why two god-mode roles?").
2. Role ASSIGNMENT is actor-less and does NOT enforce no-privilege-escalation:
   `assignRoleBySlug`/`AssignGroupRole` take (target, role) with no actor; the only
   guard is the blunt "owner slug is reserved". Before the 2026-06-23 API-key
   fix above, API-key resource scopes had the same caller-enforced shape. So a
   weak role able to call a grant path could mint a STRONGER role (e.g.
   super-admin), and API-key minters could previously attach host-defined
   resource scopes unless each caller remembered to close it.

## Target model
- **owner** = the apex. Holds `root:*`. Seeded via the bootstrap manifest
  (deploy-time). Manages root roles INCLUDING other owners (holds
  `root:roles:manage` via `root:*`).
- **admin** = an APP-declared operational role: a bundle of `root:` perms (e.g.
  `root:users:ban`, `root:content:moderate`) MINUS `root:roles:manage`, so admins
  do the work but cannot promote anyone. ("admin can't make admins" = just
  withhold one perm.) Declared by consumers (doujins #420), not authkit.
- Drop **super-admin** (folded into owner): remove `SuperAdminRoleName` from the
  intrinsic root persona. The `super-admin`→`admin` normalize shim in consumers
  goes away.

## Core-enforced invariants (the heart of this issue)
Every RUNTIME grant (root roles, org roles, AND api-key role grants) must pass,
enforced in authcore — NOT the caller:
1. **Capability:** actor holds the persona's role-manage perm (`root:roles:manage`
   for root). The "can assign at all" gate → admins lacking it can't promote.
2. **No step-up:** `perms(targetRole) ⊆ perms(actor in that persona-instance)`,
   subset-OR-equal, using existing wildcard coverage
   (`permission_group_authorize.Can` semantics: `root:*` ⊇ `root:users:ban`, but
   `{root:users:ban}` ⊉ `root:*`). Scoped to the same persona-instance. So owner
   (`root:*`) may grant owner+admin; a holder of `{root:users:ban}` may grant at
   most `{root:users:ban}`, never owner/admin.

This SUBSUMES the owner-reserved hack: only an actor holding `root:*` can grant
`root:*` → "only owners mint owners" falls out of the general rule. DELETE the
special-case reserved check. Generalizes to org personas + api-key role grants;
API-key resource-scope authorization is already core-enforced by the
`WithAPIKeyResourceAuthorizer` fix above. Requires making the assignment path
ACTOR-AWARE (add actor subjectID / an actor-aware variant) across
assign/unassign + the admin grant/revoke HTTP adapters + api-key role grant.

## Bootstrap = genesis + recovery
- The OPERATOR (bootstrap.yaml + deploy access) is the true root of trust; DB
  owners are runtime delegates. Bootstrap seeding BYPASSES the runtime rules
  (capability/no-escalation) — it is the genesis path. The manifest already seeds
  users + root roles; today "admin" mints super-admin — repoint to `owner`.
- **No "last owner" guard.** Removing all owners is allowed: worst case runtime
  role administration is soft-frozen (nobody holds `root:roles:manage`), NOT a
  lockout — the operator re-seeds an owner via bootstrap. One fewer edge case /
  source of bugs.
- Policy: owner seeding is **seed-if-absent** (break-glass — acts only when there
  are zero owners, never fights runtime owner edits), NOT idempotent
  desired-state. Day-to-day owner management stays in the runtime API.

## Open decision
`root:roles:manage` currently means "define/inspect operator roles" (role
DEFINITIONS). There is NO separate `root:roles:assign` / `root:members:assign` for
granting a role to a USER (membership). For this model one perm gating both
("owners assign, admins don't") suffices; split later only if we want an "assigns
other admins but can't edit role defs" tier.

## Tasks
- [x] Make role assignment ACTOR-AWARE (root + org + api-key paths).
- [x] Enforce capability + no-escalation (subset, wildcard-correct) in authcore.
- [x] Enforce API-key resource-scope no-escalation in core: non-empty
      `resources` require `WithAPIKeyResourceAuthorizer`; absent authorizer
      rejects by default with `resource_scope_denied`.
- [x] Route HTTP API-key minting through the core resource-scope authorizer path
      and return the specific `resource_scope_denied` error for denied scopes.
- [x] Enforce API-key role-grant no-step-up in core before insert; the creator
      must hold `<persona>:roles:manage` and cover the requested API-key role's
      effective permissions.
- [x] Drop `super-admin` from intrinsic root; keep `owner` as apex; delete the
      owner-reserved special case (subsumed by no-escalation).
- [x] Bootstrap: seed `owner` (not super-admin), seed-if-absent; NO last-owner guard.
- [x] Add an ERROR-RETURNING role/permission read (e.g. `ListRoleSlugsByUserErr`)
      so consumers can surface role-resolution failures instead of swallowing
      (today `ListRoleSlugsByUser` returns `[]string`, no error). Needed by doujins #420.
- [x] Tests: escalation attempts rejected (weak role can't grant stronger/owner);
      owner grants owner+admin; admin (no roles:manage) can't grant; bootstrap
      genesis bypasses; zero-owner recoverable via bootstrap.
- [x] Tests: DB-backed API-key integration covers normal key mint/list/revoke,
      fail-closed resource scopes, allowed scoped-key resolution, and rejected
      cross-resource and cross-role escalation.
- [ ] Release/tag finalization from a clean commit + update release target. SEMVER
      docs are updated; old `v0.60.0` target is stale because the repo is already
      tagged at `v0.61.0`.

## Cross-repo
Consumers adopt via doujins #420 (doujins + hentai0 share ONE root group).
