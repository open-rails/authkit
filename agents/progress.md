<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 72

---

# #71: Surface delegated-token role UUIDs (attributes.roles) on DelegatedPrincipal.Roles

**Completed:** yes

Let a self-issuing tenant carry the actor's ROLE UUIDs in a delegated token and surface them on the verified principal, so downstream services (tensorhub) can use role UUIDs as budget-scope keys. Mirrors the existing `attributes.tier` -> `UserTier` derivation. The top-level `roles` claim stays forbidden on delegated tokens (invariant `delegated_access_has_roles`); role UUIDs ride under `attributes.roles` as opaque scope keys, not authority.

- VERIFY (http/verifier.go): for delegated tokens, lift `attributes.roles` (JSON array of UUID strings) onto `Claims.DelegatedRoles` via new helper `rawUUIDStringsAttribute` — validates each as a well-formed UUID (google/uuid), drops malformed/non-string entries individually (doesn't fail the token), caps at `maxDelegatedRoles` = 64.
- PRINCIPAL (http/claims.go): added `Roles []string` to `DelegatedPrincipal` (UUID strings; consumers parse to uuid) + `DelegatedRoles []string` carrier on `Claims`; populated in `Delegated()`.
- MINT (http/delegation.go): added convenience `Roles []string` to `DelegatedAccessParams`, emitted into `attributes.roles` (typed field wins over `Attributes["roles"]`; blanks dropped; caller map not mutated).
- TEST: http/delegated_roles_test.go — round-trip, malformed-dropped, absent (backward compat), capped.

Backward compatible: tokens without `attributes.roles` -> empty Roles. Existing non-delegated `Roles`/`TenantRoles` behavior untouched. `go build ./...` + `go test ./...` green.

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

---

# #70: Host-configurable key resolution — overridable keys path + explicit KeySource constructors; consistent adoption

**Completed:** no

authkit already ships an opt-in key resolver, separate from the verify/sign core: `jwt.KeySource` + `jwt.NewAutoKeySource`, wired via `core.Config.Keys` (nil ⇒ auto-resolve). Auto priority: env (`ACTIVE_KEY_ID` / `ACTIVE_PRIVATE_KEY_PEM` / `PUBLIC_KEYS`) → filesystem `DefaultAuthKeysPath` = `/vault/auth` (`keys.json` under it) → generate-and-persist under `.runtime/authkit/` (HARD-FAIL in prod). Envelope: `{active_key_id, active_private_key_pem, public_keys}`.

The design is right; two gaps make embedders silently diverge instead of using it:

1. **The filesystem source path is hard-coded** to `/vault/auth` with no host override. An embedder that renders its keyset anywhere else — host-run dev pointing at `~/cozy/e2e/.secrets/<app>/auth/keys.json`, or any non-K8s mount — cannot point the resolver at it; it falls through to dev-gen. There must be a host-overridable path.

2. **Inconsistent adoption → silent dev keys.** cozy-art constructs `core.Config{}` with `Keys: nil`, sets none of the env vars, and has no `/vault/auth/keys.json` on the host, so authkit auto-generates a throwaway key for its user-login issuer — its JWKS becomes a per-process random key instead of the managed keyset its compose/Vault renders. Meanwhile tensorhub doesn't use this resolver at all for its platform issuer: it reimplements the same env→/vault/auth→.runtime ladder in its own `platformjwt.autoKeyStore`. One concern, three behaviors.

Goal: **one JWT keypair per app** (its issuer identity, the only thing on its JWKS — plus retiring keys during rotation), loaded ONE uniform way via `KeySource`, and reused for ALL of that app's JWT signing — user access/refresh tokens AND service/delegated JWTs to tensorhub/openrails (those differ only in claims: `aud`, `sub=service:…`, `token_use` — never in key). No app should manage a second JWT key. Key discovery stays OUT of the verifier — `KeySource` is an opt-in library the host composes (via `Config.Keys`) or lets auto-resolve.

A host therefore loads ONE `KeySource` and uses it twice: hands it to `core.Config.Keys` (user-token issuer + JWKS), and reuses its **active signer** for its own delegated/service-JWT signer. So `KeySource` must expose the active signer + public keys cleanly (it already backs the JWKS; make sure host reuse for ad-hoc signing is a supported, documented path — no need for a parallel keypair like cozy-art's `platform_signer` or tensorhub's `platformjwt`).

(The ONLY legitimately separate signing key in this fleet is tensorhub's **artifact** key, which signs build artifacts, not JWTs — different trust domain, not on the JWKS. Out of scope here.)

Design:
- **Host-overridable keys path**: add `core.Config.KeysPath` (and an `AUTHKIT_KEYS_PATH` env) feeding `tryLoadFromFilesystem`; keep `/vault/auth` as the default so existing External-Secrets/K8s embedders are unchanged.
- **Explicit, composable constructors** so hosts don't depend on auto-magic: `FileKeySource(path)` (point straight at a keys.json), `EnvKeySource()`, `GeneratedKeySource(dir)` (the dev generate+persist source, configurable dir, prod hard-fail preserved). Refactor `NewAutoKeySource` to compose these.
- **Expose the active signer for reuse**: a stable accessor on `KeySource` (active `jwtkit.Signer` + public keys) so a host can sign its delegated/service JWTs with the SAME key it gave authkit. This is what lets every app collapse to one JWT key.
- **Docs**: a "Key resolution for embedders" section — the one-key principle, priority order, envelope format, prod requirements, opt-in via `Config.Keys`, decoupled from the verifier, and the active-signer reuse pattern.

Consumer adoption is tracked in the umbrella issue **cozy-art #143** (one uniform key location + env/config name; collapse each app onto a single JWT key), covering all four embedders:
- cozy-art (`core.Config{Keys:nil}` → silent dev-gen; plus a SEPARATE `platform_signer`/`servicejwt` key) and doujins (`keySource = nil`, `internal/server/server.go`): load one `KeySource`, give it to authkit AND the delegated signer.
- hentai0 (`internal/infra/authkit.go` already calls `NewAutoKeySource()`): move onto the configurable path.
- tensorhub: delete `platformjwt.autoKeyStore`'s bespoke ladder + separate platform key; sign capability/platform JWTs with authkit's `KeySource`. (Artifact key stays separate.)

**Tasks:**
- [ ] `core.Config.KeysPath` + `AUTHKIT_KEYS_PATH` env override for the filesystem source (default stays `/vault/auth`)
- [ ] Export `FileKeySource(path)`, `EnvKeySource()`, `GeneratedKeySource(dir)`; refactor `NewAutoKeySource` to compose them
- [ ] Expose the active signer + public keys on `KeySource` for host-side delegated/service-JWT signing (one key, two signers); document the reuse pattern
- [ ] Docs: "Key resolution for embedders" (one-key principle, priority order, envelope, prod requirements, opt-in + core-decoupled, active-signer reuse)
- [ ] Tests: configurable path resolves; env precedence preserved; prod still hard-fails when no key is found; active-signer accessor round-trips (sign → verify via JWKS)
- [ ] go build / go vet / go test green
