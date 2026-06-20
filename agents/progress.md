<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 100

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

---

# #94: Enforce the no-escalation invariant on EVERY grant path + a found gap (remote-app direct grant) — code + tests

**Completed:** no

**VERIFICATION 2026-06-20 (Claude):** NOT complete — the "EVERY grant path" claim
is false. The four named org paths + platform DO enforce `ValidateGrant`
(member-role assign, role-perm set, API-key mint, org invite), and the ORIGINAL
remote-app DIRECT-permission gap was genuinely closed by #95 (migration 006 dropped
`remote_application_permissions`; the handler is gone). BUT the escalation class
MOVED to the remote-app ROLE-ASSIGNMENT path: `handleRemoteApplicationMembershipPOST`
(`http/remote_application_handlers.go`) and core `AddRemoteApplicationMember`
(`core/remote_application_memberships.go:24`) assign ANY role — INCLUDING `owner`
(= `org:*`) — to a remote-app gated ONLY on `org:remote_applications:update`, with
NO `ValidateGrant`. So a manager who lacks `org:*` can escalate a remote-app to
owner — the exact class this issue exists to close. No test locks it. AND the
defense-in-depth task (no-escalation in the CORE mutators `AssignRole`/
`SetRolePermissions`, not only the HTTP handlers) is still not done — which is
precisely why this slipped through. Reopened; the open task is now the
role-assignment path, not the deleted direct-grant path.

DONE (2026-06-20): delegated access-token `permissions` are now verified against
the issuer remote application's stored authority before platform gates can trust
them. The same namespace-anchored glob matcher backs remote application access
tokens, delegated access tokens, and `Claims.HasPermission`. Platform gates now
accept validated delegated `platform:*`/concrete permission claims while
preserving live DB checks for local users and continuing to reject delegated role
claims. Tests cover accepted stored glob authority, out-of-ceiling rejection, and
claiming broader `platform:*` than stored authority.

AuthKit-side implemented: `IssueAccessToken` no longer mints profile or role
claims for normal user access tokens; it keeps `sid` from caller extras and
authoritative short-lived `entitlements`. README/API docs now point profile,
bootstrap, org membership, role, and permission state to live endpoints/DB state.
Regression coverage:
`TestIssueAccessToken_SlimUserClaimsKeepsSessionAndEntitlements` and
`TestPasswordLoginAndRefreshMintSlimUserAccessTokens`.

Consumer migration remains open. A 2026-06-20 sweep still found downstream
references that need a real consumer pass before this issue can close:
Doujins `internal/auth/middleware/user_context.go` still falls back to
`claims.Roles`; Hentai0 `internal/auth/provider_authkit.go` still copies
`claims.Roles`; both repos have comments/docs around `profiles.global_roles`.

CRITICAL INVARIANT (Paul, "checked doubly so"): **you can never grant a permission you do not yourself hold.** A caller with `org:members:manage` / `org:roles:manage` / `org:remote_applications:manage` / `org:api_keys:manage` must NOT be able to hand a member, role, API key, or remote application any permission outside their own effective set — blocking escalation (handing out `owner`/`org:*`, or `root:*`, that the grantor lacks). Enforced by `ValidateGrant` (returns `offending` for perms the actor lacks; `owner`/`org:*` passes within its org, a `global`-scoped operator passes, and the bootstrap system-actor passes).

**GAP FOUND (2026-06-19):** the remote-application DIRECT permission-grant path does NOT call `ValidateGrant`. `handleRemoteApplicationPermissionPOST` (`http/remote_application_handlers.go:295`) only checks catalog MEMBERSHIP (`AddRemoteApplicationPermission` → `ErrUnknownPermission`) — it does NOT check no-escalation. So anyone who can manage a remote application can grant it ANY catalog permission, including perms the grantor lacks (`root:*`, …); the remote-app then acts with escalated authority. Real escalation hole.

Coverage today — HAVE the check: role-perm set (`org_role_permissions_handlers.go:58`), role assign-to-member (`org_membership_roles_handlers.go:66`), API-key mint (`api_keys_handlers.go:209`), org invite (`service_org_invites.go:55`). MISSING: remote-app direct grant.

Root cause: `ValidateGrant` is enforced in the HTTP handlers, NOT in the core mutators (`AddRemoteApplicationPermission`, `AssignRole`, `SetRolePermissions`, `MintServiceToken`). So any NEW grant path that forgets the check is a silent escalation hole — exactly what happened here.

**Tasks:**
- [ ] FIX the gap: add `ValidateGrant` to `handleRemoteApplicationPermissionPOST`; reject 403 `permission_grant_denied` when `offending` is non-empty (mirror the role/API-key paths).
- [ ] Defense-in-depth: enforce no-escalation in the CORE grant mutators too, with an explicit trusted/`SystemActor` bypass for bootstrap/manifest seeding (which legitimately seeds `owner`=`org:*` that nobody holds yet). HTTP keeps its check (belt + suspenders) so the invariant can't be lost by a future handler.
- [ ] Comprehensive tests, ONE per grant path: a grantor holding a STRICT SUBSET cannot grant outside it (→ 403/`offending`); `owner`(`org:*`) / a global operator CAN; granting any perm the grantor lacks is blocked. Cover member-role assign, role-perm set, API-key mint, org invite, AND remote-app direct grant.
- [ ] Regression test locking THIS gap: a remote-app manager lacking `root:users:ban` cannot grant it to a remote application.

NOTE: unify-on-roles is DECIDED (roles-only — see #95): dropping `service_token_permissions` + `remote_application_permissions` direct lists DELETES the remote-app/API-key direct-grant paths and closes this whole class by construction. Until that lands, every direct-grant path MUST call `ValidateGrant`. Also: with globs first-class (#95), `ValidateGrant` must EXPAND globs when checking no-escalation — granting `org:members:*` requires the grantor to effectively hold all of `org:members:*`.
