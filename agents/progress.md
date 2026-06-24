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
`AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_db?sslmode=disable' go test ./internal/authcore -run 'TestAssignRoleBySlugAs_NoEscalation_DB|TestAssignRoleBySlug_AllowsOwnerGenesis|TestApplyBootstrapManifest|TestGeneratedRoutes_GatesAreCorrect' -count=1 -v`
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

---

# #49: Passwordless contact login and wallet account creation

**Completed:** no

Add an optional passwordless contact flow for AuthKit users. A host can ask for phone or email, send an OTP and/or magic link, then mint a normal AuthKit session after confirmation. This remains separate from verification/password-reset links (#10) and additive to existing password, passkey, OIDC, and 2FA flows.

The OpenRails wallet use case needs one extra behavior beyond the old future plan: create-or-login. If the verified contact belongs to an existing user, confirm logs that user in. If no user exists and the host enables passwordless auto-registration, confirm creates a user with a generated username, verified email/phone, and no password. The user can add a password or passkey later, but first checkout should not require either.

## Goals

- Allow passwordless login by email OTP, email magic link, SMS OTP, and SMS magic link where senders support it.
- Allow create-if-missing for products like OpenRails customer wallets that need quick account creation at checkout.
- Keep existing `/register`, `/password/login`, passkey, OIDC, verification, password reset, and 2FA behavior intact.
- Record session assurance accurately: `amr=email` for email-confirmed login, `amr=sms` for phone-confirmed login, and no fake `pwd`.
- Keep the feature host-enabled; private deployments can leave it unmounted or disabled.

## Non-goals

- Do not replace password login or passkeys.
- Do not make verification links double as login links. Passwordless login gets its own purpose, token kind, TTL, rate limits, and audit events.
- Do not leak whether an identifier exists. Start always returns the same accepted response.
- Do not require username/password before first passwordless account creation.
- Do not make SMS magic links depend on Twilio Verify. Use the host SMS sender/Messaging API path already used for SMS links.

## API shape

- `POST /passwordless/start`
  - Body: `{ "identifier": "email-or-phone", "mode": "code|link|both", "return_to": optional }`
  - Behavior: normalize identifier, rate-limit by IP and identifier, create a pending passwordless challenge, send code/link if the host permits this channel, and always return an anti-enumeration `202`.
- `POST /passwordless/confirm`
  - Body for OTP: `{ "identifier": "email-or-phone", "code": "123456" }`
  - Body for magic link: `{ "token": "high-entropy-token" }`
  - Behavior: consume the challenge once, find or create the user as configured, mint access/refresh tokens, and return the same token response shape as existing login.

Use prefix-neutral AuthKit route names; host apps may mount them under `/auth/*`.

## Data model / token storage

- Store passwordless challenges in the existing ephemeral store pattern, keyed by hashed code/link token.
- Bind short OTP codes to the normalized identifier so a guessed code cannot verify another account.
- Store high-entropy magic-link tokens as hashes and consume them globally by token.
- Track purpose separately from verify/reset: `passwordless_login`.
- For create-if-missing challenges, store normalized identifier, channel, generated username candidate, preferred language if known, return target if allowed, TTL, and attempt counters.
- Do not insert a `profiles.user_passwords` row for passwordless-created users until they set a password.

## User creation behavior

- Existing verified contact: confirm logs in that user.
- Existing unverified contact: confirm marks that contact verified and logs in the user only if the challenge was sent to that contact.
- Missing contact with auto-registration disabled: consume or reject per policy but return a non-enumerating error shape.
- Missing contact with auto-registration enabled: create a user with generated username, set the verified email or phone, no password, and issue a session.
- Generated usernames must use the existing AuthKit username validation/reservation rules and retry on collision.

## Security notes

- Short OTPs need identifier binding, attempt caps, short TTL, and per-identifier rate limits.
- Magic-link tokens need high entropy, single-use consumption, short TTL, and safe return-target handling.
- Start and confirm endpoints need audit events for request, success, failure, account created, and rate-limit rejection.
- Session minting should call the existing `IssueRefreshSessionWithAuthMethods` path with the right auth method.
- Sensitive operations can still require step-up or MFA later; this flow only establishes wallet/login identity.

## Tasks

- [ ] Add feature/options wiring for passwordless login and passwordless auto-registration; default disabled unless a host enables it.
- [ ] Add route specs for `POST /passwordless/start` and `POST /passwordless/confirm`.
- [ ] Add core methods to create, store, consume, and expire passwordless challenges using the existing ephemeral-store pattern.
- [ ] Add email and SMS delivery support for passwordless OTP/link messages, reusing the existing sender style where practical.
- [ ] Add create-if-missing user path with generated username, verified email/phone, and no password row.
- [ ] Add existing-user login path that verifies the contacted identifier and mints access/refresh tokens with `amr=email` or `amr=sms`.
- [ ] Add anti-enumeration behavior and rate limits for start and confirm.
- [ ] Add safe `return_to` handling or explicitly return tokens only to the caller and let the host own navigation.
- [ ] Add DB-backed tests for email OTP login, email magic-link login, SMS OTP login, SMS magic-link login, create-if-missing, existing-user resume, generated username collision, no password row, disabled feature, duplicate/expired token, invalid code attempt caps, and anti-enumeration responses.
- [ ] Update README, `agents/api-endpoints.md`, and SEMVER notes with the new flow and host integration guidance.

## Cross-repo

- OpenRails SaaS #19 will use this for customer wallet login/account creation at checkout while keeping merchant-app authentication separate.
