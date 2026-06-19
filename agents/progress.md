<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.


next_id: 86

---

# #45: Passkey (WebAuthn/FIDO2) authentication — register, login, manage

**Completed:** no

Add passkeys (WebAuthn/FIDO2) as a first-class authentication method in authkit, alongside password, OIDC, and SIWS. Passkeys are phishing-resistant, usernameless-capable credentials bound to the relying party (RP) domain. A user can register one or more passkeys and authenticate with them; a successful login mints the SAME access/refresh session as the password path (and honors the optional `org` body param).

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
- [ ] Authentication ceremony: begin (discoverable + username-scoped, anti-enumeration) + finish (verify assertion, sign-count clone-check, update sign_count/last_used, mint access+refresh honoring `org`, live-user gate).
- [ ] Management routes: GET /passkeys (metadata only), DELETE /passkeys/{id}, optional PATCH rename.
- [ ] RouteGroup RoutePasskeys + registration; challenge state via EphemeralStore (single-use, short TTL) like SIWS.
- [ ] Rate-limit buckets for register/login begin+finish; anti-enumeration on username-scoped login begin.
- [ ] Tests: full register + login ceremonies via a software-authenticator fixture; sign-count regression rejection; usernameless login; list/delete; anti-enumeration; rate limits.
- [ ] Docs: api-endpoints.md + README passkey section (RP config, ceremony flow, frontend navigator.credentials notes, security model, recovery out-of-scope).
- [ ] Version bump + publish; consumer notes (host mounts RoutePasskeys + sets RP config; frontend integrates the WebAuthn JS ceremonies).

---

# #85: Remote-application allowed origins for delegated browser requests

**Completed:** yes

Add browser origin policy to `remote_application`, keyed to the same issuer trust record used for delegated JWT verification. AuthKit should own both the policy and the middleware/helpers that enforce it; OpenRails and host apps should mount AuthKit-provided plumbing rather than re-implement issuer/CORS logic.

Problem found during the OpenRails config audit: OpenRails has a `merchant_cors` shape that looks per-merchant, but its current behavior is only a flattened global CORS allow-list. That does not enforce "a Doujins delegated-user request for Doujins may only come from doujins.com"; it only says "this browser origin may call this OpenRails instance." In public merchant registration, where Doujins and Evil can both register valid issuers and allowed origins, preflight CORS adds no tenant-isolation value because the preflight has no JWT issuer. Auth still protects data; CORS is compatibility/browser hardening, not authorization.

CURRENT OPENRAILS WIRING:
- `config.MerchantCORS` is only consumed by `Config.AllowedCORSOrigins()`, which unions `cors_origins` + all merchant origins.
- Standalone (`newPublicEngine`), embedded net/http (`embedhttp.Assembler`), and embedded gin self-service all pass that union into generic CORS middleware before auth.
- The delegated browser surfaces (`/v1/self/*` and `/v1/merchant-admin/*`) already resolve `ResolvedDelegated.Issuer` and pin the merchant from that validated issuer, but they do not check `Origin` against the issuer.
- Webhooks and service-token/server-to-server routes should not use this browser-origin policy.

The right source of truth is AuthKit's `remote_application`: it already binds `issuer -> JWKS/static keys -> audiences -> enabled -> org owner`. For browser-delegated traffic, the issuer that signed the delegated JWT should also define the exact browser origins allowed to present that issuer's tokens. Example: issuer `https://auth.doujins.com` may allow `https://doujins.com` and `https://www.doujins.com`; issuer `https://auth.hentai0.com` may allow only Hentai0 origins.

SECURITY MODEL:
- CORS preflight is browser compatibility and carries no JWT, so it can only be checked against the union of enabled remote_application origins. In an anyone-can-register merchant system, that union is not a meaningful security boundary.
- The actual protected request must verify the JWT, resolve its `iss` to a remote_application, then reject mismatched `Origin`. This is best-effort browser hardening, not authentication: non-browser clients can spoof `Origin`.
- AuthKit should provide the CORS/preflight middleware and the delegated-request origin gate. OpenRails should only call/mount those AuthKit pieces.
- No `Origin` means non-browser/server-to-server and should not be blocked by this check unless a caller opts into browser-only mode.
- Allowed origins are exact scheme+host+optional-port matches. No wildcards, no suffix matching.
- This is for browser-delegated user requests, not webhooks.
- AuthKit should enforce `request Origin in allowed_origins for verified token issuer` after JWT verification resolves the remote_application.
- `merchant_cors` should be deleted from OpenRails config once AuthKit exposes this policy. Do not replace it with an OpenRails-specific delegated-auth config.

**Tasks:**
- [x] Add `allowed_origins text[] NOT NULL DEFAULT '{}'` to `profiles.remote_applications` in a new numbered migration; do not patch the already-applied baseline only.
- [x] Add `AllowedOrigins []string` to `core.RemoteApplication`, upsert/list/get SQL, bootstrap config, and remote-application HTTP request/response bodies.
- [x] Validate origins in AuthKit: trim, dedupe, require `http` or `https`, require host, reject path/query/fragment, exact strings only. In production guidance, prefer `https`; keep `http://localhost:*` usable for dev.
- [x] Preserve the issuer trust invariant: origin policy is metadata on the same registered issuer; do not create a separate merchant CORS map.
- [x] Expose allowed origins through `RemoteApplicationSource` / verifier-loaded issuer metadata.
- [x] Add AuthKit-owned middleware/helpers:
      optional preflight CORS middleware using the union of enabled `remote_application.allowed_origins` for browser compatibility, and delegated-request middleware that verifies JWT then enforces `Origin` against the verified issuer.
- [x] Add a tiny helper such as `OriginAllowedForIssuer(ctx, issuer, origin)` or equivalent lookup; it should return false for unknown/disabled issuers and true for empty origin only when the caller opts into non-browser allowance.
- [x] Open OpenRails follow-up issue #519: remove `merchant_cors` and use AuthKit-provided CORS/delegated middleware or `DelegatedAuthenticator` integration. OpenRails should not own delegated issuer-origin policy.
- [x] Tests: register remote_application with origins, reject malformed origins, AuthKit CORS preflight allows only the enabled-origin union, disabled/unknown issuer fails closed, and delegated middleware rejects `issuer A + origin B`.
