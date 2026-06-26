<!-- authkit issue tracker — ACTIVE issues -->

> One `# #<id>: <name>` section per issue, separated by `---` lines; section anchor for
> tooling is a line starting with `# #`. IDs are stable for an issue's whole lifecycle and
> share ONE per-repo id space; new issues take `next_id` below and bump it.
> CONCURRENT EDITS: only ever edit/append your own issue's section with targeted string
> replacement — never rewrite the whole file.
> DONE/CLOSED issues are archived in `completed.md`; an issue stays HERE only while it
> still has pending CROSS-REPO consumer work to track (e.g. #111).


next_id: 145

---

# #144: Rename frontend OIDC callback config to OIDCReturnPath

**Completed:** no

Proposed 2026-06-26 (Paul + Codex). `embedded.FrontendConfig.CallbackPath` is
too vague and reads like the OAuth/OIDC provider callback URL. In AuthKit it is
not that. AuthKit owns the backend provider callback; this field is the host SPA
landing route after AuthKit finishes the OIDC/social login flow.

BREAKING HARDCUT before v1.0: no compatibility alias, no deprecated field.

## Target shape

```go
Frontend: embedded.FrontendConfig{
    BaseURL:       "https://app.example.com",
    OIDCReturnPath: "/login/callback",
}
```

Meaning: after OIDC/social login completes, AuthKit redirects the browser to
`BaseURL + OIDCReturnPath` with the login result.

## Tasks

- [ ] Rename `FrontendConfig.CallbackPath` to `OIDCReturnPath`.
- [ ] Update config normalization/defaulting to keep the default path
      `/login/callback`.
- [ ] Update OIDC browser-flow code to use `OIDCReturnPath`.
- [ ] Update README/examples and first-party consumers.
- [ ] Search docs/comments/tests for `CallbackPath` and replace with the new
      name where it refers to this frontend landing route.
- [ ] Validate with `go test ./...`.

---

# #143: Client API cleanup — explicit NewClient constructors + small capability interfaces

**Completed:** no

STATUS 2026-06-26 (Claude): small capability interfaces STARTED (additive,
non-breaking). Added `authkit.Authorizer` + `authkit.TokenIssuer` (the two with real
consumers — authz gate, platform token minting) in `interfaces.go`, with conformance
proofs in `embedded/conformance.go` (`var _ authkit.Authorizer = (*embedded.Client)(nil)`).
Grown from real consumption, NOT the 7-interface taxonomy — the rest land when a
signature actually narrows. Also dropped `ApplyBootstrapManifestFile` from the contract
(Paul's call; lands in #142's portability audit). build+vet+gofmt green; full suite green.
Client-first construction is folded into #142 (one migration, with remote).

REVIEW (Claude, 2026-06-26): strong core, trim the edges.
- KEEP (the real win): client-first construction — `authhttp.NewServer(client, httpOpts)`,
  drop `.Client()`, split embedded-vs-http options, pare `Server` to adapter methods.
  Honest layering (server = adapter over a client the host owns); kills the escape
  hatch the old `NewServer(cfg,pg)` needed. Do it.
- DON'T delete `authkit.Client`. The broad interface IS #142's swap seam — a host
  flipping embedded↔remote holds ONE `authkit.Client` field. Small capability
  interfaces COEXIST with it (hold broad at the swap point, pass narrow slices to
  functions). Deleting it loses the one-line swap #138/#142 are built on.
- GROW the small interfaces from REAL consumption points (`verify.PermissionChecker`
  is the model — 1 method, the gate uses it), NOT 7 speculative ones upfront. Define
  `Authorizer` + maybe `TokenIssuer` now; add the rest when a signature actually
  narrows. A 7-interface taxonomy is the opposite over-engineering from the kitchen sink.
- REJECT moving `Config` → root `authkit.Config`. #138 deliberately partitioned
  `Config`/`Options`/ports into `embedded` as ENGINE CONSTRUCTION, off the wire
  contract (remote uses its own `remote.Config{BaseURL,Token}`). Don't re-blur it —
  keep `embedded.Config`.
- `embedded.New` → `NewClient` is optional bikeshed; `New` is the Go idiom (etcd
  `clientv3.New`). Skip unless the `NewClient`/`NewClient`/`NewServer` symmetry is
  worth the rename.
- SEQUENCING: this reshapes the SAME construction/interface surface as #142 (remote).
  Separate issues → consumers migrate TWICE. Batch the client-first changes WITH #142
  so consumers move once, to the final v1.0 shape.
- BASELINE: cozy-art + tensorhub are still on pre-#138 `core` (never migrated to
  v0.65/0.66). Bring them current via #138/#141 first — #143 shouldn't be their first move.

Proposed 2026-06-26 (Paul + Codex, after reviewing current AuthKit plus
doujins/hentai0/cozy-art/tensorhub consumers). The current public seam is too
wide and too vaguely named:
- `embedded.New(...)` constructs an in-process client, but reads less clearly than
  `authhttp.NewServer(...)`.
- future `remote.New(...)` would repeat the same vague constructor name.
- root `authkit.Client` is a 94-method kitchen-sink interface. Real consumers use
  small slices: route mounting + verification, DB-backed authorization, user/admin
  management, bootstrap/import tooling, permission-group/federation operations,
  and token issuing. The broad concrete client can exist, but hosts should not be
  pushed to depend on one giant interface.
- `embedded.Client` is the concrete in-process engine and may remain broad; the
  problem is the broad root interface (`authkit.Client`) that every backend is
  asked to satisfy forever.
- `authhttp.Server` should be an HTTP adapter over a client, not a programmatic
  auth facade. It should expose route handlers/specs, verifier, and maybe HTTP
  health/status helpers only.
- `embedded` also re-exports too many contract/config/helper types; it should be
  the in-process implementation package, not the namespace where every AuthKit
  concept lives.

BREAKING HARDCUT before v1.0: no backwards compatibility, no deprecated aliases,
no transition shims. Do this as a public-interface cleanup, then update all four
first-party consumers in the same release train.

## Target shape

Construction names:
```go
embeddedClient, err := embedded.NewClient(cfg, pg, opts...)
remoteClient, err := remote.NewClient(remote.Config{BaseURL: "...", Token: "..."})
server := authhttp.NewServer(embeddedClient, httpOpts...)
```

Package roles:
| Package | Role |
|---|---|
| `authkit` | public contract types, DTOs, sentinel errors, validation helpers, and small capability interfaces |
| `authkit/embedded` | in-process client implementation + construction options only |
| `authkit/remote` | future remote client implementation over the management API |
| `authkit/http` | mountable HTTP server/routes over an AuthKit client + verifier aliases |
| `authkit/verify` | token verifier and middleware primitives |

Minimal embedded-host import surface:
| Package | Normal host use |
|---|---|
| `authkit` | config, DTOs, errors, validation, permission helpers, small interfaces |
| `authkit/embedded` | `NewClient` + embedded runtime options |
| `authkit/http` | `NewServer` + route specs/handlers/options |
| `authkit/verify` | protect host-owned routes + read claims |
| `authkit/adapters/{gin,chi}` | router convenience when the host uses that router |
| `authkit/migrations/postgres` | host migration command |
| `authkit/migrations/clickhouse` | standard auth/event logging migration command when enabled |

Optional/advanced packages, not part of the normal embedding story:
`adapters/twilio/*`, `adapters/riverjobs`, `oidc`, `authprovider`, `lang`,
`password`, `jwt`, `ratelimit/*`, `storage/*`, `siws`, and `authtest`.

Rule: Postgres migrations are required standard setup because Postgres is the
system of record. ClickHouse migrations are standard optional setup: not
required to boot AuthKit, but the normal path when auth/event logging is enabled.

Host mental model:
- construct the programmatic client first (`embedded.NewClient` now, `remote.NewClient`
  later),
- pass that client to `authhttp.NewServer(...)` to expose the HTTP route surface,
- keep programmatic management/provisioning/RBAC/token work on the client instead of
  pulling a hidden client back out of the server.

## Tasks

- [x] CONSTRUCTION SHAPE (client-first: `authhttp.NewServer(client, httpOpts)`, drop
      `.Client()`, split embedded-vs-http options) FOLDED INTO #142 and DONE there
      (2026-06-26): `NewServer(client, opts)`, `.Client()` dropped, options split
      (engine→`embedded.New`, http→`authhttp`), 34 in-repo sites migrated. See #142
      "Construction shape". `embedded.New` stays (Go idiom); New-vs-NewClient is an open
      naming bikeshed, not blocking. External consumer migration pending the next bump.
- [~] Design the first small root interfaces from real consumers, not speculation:
      (DONE: `Authorizer` + `TokenIssuer` in `interfaces.go`. The rest grow when a real
      signature narrows — not pre-built.)
      - `Authorizer`: `Can`, `ListEffectivePermissions`, `IsUserAllowed`,
        `ListRoleSlugsByUserErr`.
      - `UserAdmin`: admin list/get/session/ban/unban/soft-delete/session revoke.
      - `RoleManager`: root and permission-group role assignment/removal.
      - `PermissionGroups`: create/resolve groups, list memberships/members,
        invite links, API keys.
      - `Federation`: remote applications + delegated attribute definitions.
      - `TokenIssuer`: delegated token + service JWT minting.
      - `Bootstrapper`: bootstrap manifest + import/migration-only helpers.
- [x] DECISION: KEEP `authkit.Client` as the broad swap seam — #142 needs ONE interface
      both embedded+remote satisfy for the one-line embedded↔remote swap. The small
      capability interfaces COEXIST with it (hold the broad one at the swap point; pass
      narrow slices to functions). Not a compat shim — a deliberate contract.
- [ ] Keep `embedded.Client` broad as the concrete engine type if that is the
      simplest implementation. Do not confuse concrete method count with public
      interface size.
- [x] Pare `authhttp.Server` down to HTTP-adapter methods only (DONE 2026-06-26):
      dropped the `SetEntitlementsProvider` engine passthrough (host now calls it on
      its own client). Remaining exported methods are all HTTP adapters/status:
      `APIHandler`, `APIRoutes`, `OIDCHandler`, `OIDCBrowserRoutes`, `JWKSHandler`,
      `PermissionGroupRoutes`, `Routes`, `Verifier`, and the SMS-health status reads
      (`SMSAvailable`/`SMSHealthy`/`SMSHealthReason`/`CheckSMSHealth` — kept as useful
      status helpers). No programmatic auth facade remains.
- [x] DECISION: contract types already live in root `authkit` (#141 hardcut moved them;
      `embedded` re-exports ENGINE symbols only). `Config`/`Options`/ports STAY in
      `embedded` — engine construction, not wire contract (#138 partition; remote uses
      its own `remote.Config`). Examples read `embedded.New(embedded.Config{...}, pg)`.
- [ ] Keep `embedded.Option` only for in-process construction dependencies
      (`WithEmailSender`, `WithSMSSender`, `WithEntitlements`,
      `WithEphemeralStore`, etc.). Do not make `embedded` a dumping ground for
      validation constants and DTO aliases.
- [x] DECISION: simplify RBAC persona containment. A group instance already has
      exactly one parent (`parent_id`/`parent_persona`); the public schema should
      also declare exactly one parent persona per persona type, not
      `AllowedParents []string`.
- [ ] Replace `PersonaDef.AllowedParents []string` with `PersonaDef.Parent string`
      hard-cut. Empty parent is valid only for the intrinsic `root` persona;
      every non-root persona names exactly one parent persona. Do not default
      missing parent to `root`; missing parent is a config error.
- [x] DECISION: host-defined top-level personas must explicitly write
      `Parent: authkit.RootPersona`. Do not treat empty `Parent` as root, and do
      not ask host apps to define the intrinsic root persona themselves.
- [x] DECISION: RBAC config has two separate declarations: (1) the complete
      concrete permission catalog (`persona:resource:action`), and (2) persona
      roles that reference those permissions. Do not make roles the only source
      of the permission universe.
- [ ] Validate persona role permissions against the catalog. App-declared roles
      should reference declared concrete permissions; reserve wildcard grants
      such as `<persona>:*` for AuthKit's generated owner role and deliberate
      internal expansion.
- [ ] Update `BuildSchema`/`NewGroupSchema` validation and containment seeding for
      singular parent persona definitions. No configurable multi-parent hierarchy.
- [ ] Update Postgres containment storage/query naming if useful
      (`group_persona_parents` currently models many allowed parents); keep the
      runtime group instance model singular.
- [ ] Update docs/examples to show `persona:resource:action` permissions inside
      persona roles, e.g. `root:users:ban`, `merchant:subscriptions:cancel`,
      `endpoint:deployments:restart`.
- [x] DECISION: each persona, including the intrinsic root persona, should expose
      only three optional management capabilities, all off by default: allow API
      keys, allow remote applications, and allow custom role definitions. Custom
      role definitions mean a specific permission-group instance may define
      additional local roles; when off, only the application-declared/hardcoded
      persona roles exist.
- [ ] Replace the current split public shape
      (`AllowCustomRoles` plus `Routes.CustomRoleCreation`, `Routes.APIKeyMinting`,
      `Routes.RemoteAppRegistration`) with one clearer persona capability block,
      e.g. `Capabilities: authkit.PersonaCapabilities{APIKeys: true,
      RemoteApplications: true, CustomRoles: true}`. Keep member assignment and
      invite acceptance as standard permission-group behavior, not part of this
      optional capability list.
- [ ] Allow host config to override root persona capabilities without requiring
      the host to redefine the whole intrinsic root persona. Root uses the same
      capability names and route-generation rules as every other persona.
- [ ] Route generation should derive API-key, remote-application, and custom-role
      management routes directly from those three capabilities. Disabled means
      no generated public route.
- [x] DECISION: simplify identity-provider config. Do not expose separate
      built-in vs custom-provider fields; a provider is a provider.
- [ ] Delete `IdentityConfig.ProviderDescriptors`.
- [ ] Replace `IdentityConfig.Providers map[string]oidc.RPConfig` with
      `IdentityConfig.Providers []authprovider.Provider`.
- [ ] Keep provider name inside `authprovider.Provider.Name`, not as a map key.
- [ ] Add small helper constructors for built-ins only if they materially improve
      examples, e.g. `authprovider.Google(clientID, clientSecret)`.
- [ ] Update first README example to use either `Identity: embedded.IdentityConfig{}`
      or one built-in provider constructor, not custom-provider descriptor plumbing.
- [x] DECISION: TOTP secret-encryption keys use the same security model as signing
      keys: AuthKit reads them from the vault-mounted key directory (`Keys.Path`,
      `/vault/auth` by default); host apps do not manually load/pass secrets during
      normal embedded setup.
- [x] DECISION: replace `TwoFactorConfig.RequireEnrollment bool` with explicit
      host policy: `Mode` (`authkit.TwoFactorDisabled|Optional|Required`) plus
      `Methods []authkit.TwoFactorMethod` (`Email|SMS|TOTP`). `Disabled` means no
      user 2FA enrollment/challenge routes are usable; `Optional` means users may
      enroll; `Required` means every user must enroll before normal session use.
      Role-level `RequiresMFA` stays available for narrower enforcement.
- [x] DECISION: backup codes are not host-configurable. When 2FA enrollment is
      available, backup-code generation/recovery is always available as the
      standard recovery path.
- [ ] Move 2FA policy vocabulary to root `authkit`: `TwoFactorMode`,
      `TwoFactorDisabled`, `TwoFactorOptional`, `TwoFactorRequired`,
      `TwoFactorMethod`, `TwoFactorEmail`, `TwoFactorSMS`, `TwoFactorTOTP`.
- [ ] Update `embedded.TwoFactorConfig` to use `Mode` and `Methods`; remove
      `RequireEnrollment` from the public config hard-cut.
- [ ] Gate 2FA routes and service operations from config: disabled means no
      enroll/challenge/verify flow; optional/required expose only configured
      methods, and fail closed when a method dependency is missing (for example,
      SMS sender absent).
- [ ] Keep backup-code routes/operations tied to 2FA availability, not to a
      separate config flag.
- [ ] Treat the TOTP encryption key as first-class key material, not incidental
      config: define the file format, load path, validation, reload/rotation story,
      and error semantics at the same rigor level as JWT signing keys.
- [ ] Add vault/file loading for `TwoFactor.TOTPSecretKey` under `Keys.Path`.
      Use strict file permissions/parse validation, require 16/24/32 bytes after
      decoding, and fail closed for TOTP enrollment if the key is missing or invalid.
- [ ] Decide whether TOTP key config needs the same knobs as signing keys
      (`Source`/custom provider, path override, reloadable file source). Prefer a
      small shared key-loading abstraction over host apps reading secrets manually.
- [ ] Design TOTP key rotation deliberately: encrypted TOTP secrets need either a
      key id/version prefix or a keyring so old enrolled secrets remain decryptable
      after rotation while new enrollments use the active key.
- [ ] Keep the explicit `TwoFactor.TOTPSecretKey []byte` override for tests and
      custom key management, but make it an override over the file source, not the
      normal path.
- [ ] Document the expected vault-mounted TOTP key filename/format next to the JWT
      `keys.json` docs.
- [x] DECISION: registration policy enums belong in root `authkit`, not `embedded`,
      because they are shared public contract vocabulary for embedded + future remote.
- [x] DECISION: simplify `RegistrationMode` to public self-registration policy only:
      keep `Open`, `InviteOnly`, and `Closed`; delete `AdminOnly`,
      `AdminBootstrapOnly`, and `ManifestOnly`. Operators can always create users
      through privileged APIs/bootstrap/manual DB operations outside public native
      registration mode.
- [x] DECISION: `InviteOnly` means account onboarding by valid invite, not a generic
      permission-group consent flow. Owners/admins can directly add existing users
      to permission groups; invite links are only for onboarding someone who does
      not already have an account.
- [x] DECISION: do not send email/SMS notifications when an existing user is directly
      added to a permission group. It is spam-prone because owners can unilaterally
      add people to their own groups. Email/SMS belongs only to explicit invite
      onboarding for non-users.
- [x] DECISION: when an owner/admin tries to add an email that does not belong to
      an existing account, AuthKit should send an invite email asking that person
      to register or log in, then manually accept the invite link.
- [x] DECISION: email-bound invites may only be redeemed by an account with that
      same verified email. If an invite is sent to `fidika@gmail.com`, registering
      or logging in as `someoneelse@gmail.com` must not redeem it.
- [x] DECISION: support two group invite kinds: (1) general-purpose shareable link
      with no bound email, redeemable by whoever has the link within expiry/max-use
      limits; (2) email-bound invite, redeemable only by an account with the same
      verified email.
- [x] DECISION: invites are time-bound manual accepts. Do not auto-add users to
      permission groups after signup/login; the recipient must click/open the
      invite link and accept/redeem it. Default validity should be a few days for
      both shareable links and email-bound invite links.
- [x] DECISION: invite creation/email sending must be rate-limited. A user must
      not be able to spam a large number of invite emails quickly.
- [ ] Move `RegistrationVerificationPolicy` +
      `RegistrationVerificationNone|Optional|Required` to root `authkit`.
- [ ] Move simplified `RegistrationModeOpen|InviteOnly|Closed` to root `authkit`
      and delete `AdminOnly`, `AdminBootstrapOnly`, and `ManifestOnly`.
- [ ] Update `embedded.RegistrationConfig` to use the root registration enum types
      so future `remote` and host docs do not import shared vocabulary from
      `embedded`.
- [ ] Make `InviteOnly` real: a valid email-bound group invite should authorize
      account creation for that email, then require the user to manually accept
      the time-bound invite link to receive the group membership/role.
- [ ] Preserve the existing email-bound redemption rule in the onboarding flow:
      invite email must equal the redeemer account's verified email.
- [ ] Make the invite API/docs name the two invite kinds clearly: shareable link
      versus email-bound invite.
- [x] RESEARCH: registration gating lives in `internal/authcore/service.go`:
      `normalizeRegistrationMode`, `Options.PublicNativeUserRegistrationEnabled`,
      `CreatePendingRegistration*`, `ConfirmPendingRegistration*`,
      `CreatePendingPhoneRegistration*`, passwordless auto-registration, and
      Solana/OIDC auto-create paths all need invite-aware registration checks.
- [x] RESEARCH: group invite storage already mostly fits the model:
      `migrations/postgres/001_auth_schema.up.sql` has `group_invite_links` with
      optional `email`, `max_uses`, `uses`, `expires_at`, and `revoked_at`.
- [x] RESEARCH: invite creation/redemption lives in
      `internal/authcore/group_invite_links.go`: `externalInvitesEnabled`,
      `CreateGroupInviteLink`, `inviteURL`, `sendGroupInviteEmail`,
      `RedeemGroupInviteLink`, plus default TTLs
      (`defaultEmailInviteTTL`, `defaultShareableInviteTTL`).
- [x] RESEARCH: permission-group HTTP member/invite routes live in
      `http/permission_group_operations.go` and `http/permission_group_routes.go`.
      `memberRequest` currently accepts only `user_id`, so "add by email, invite if
      unknown" requires an API/request-shape change.
- [x] RESEARCH: public route registry in `http/routes.go` already has registration,
      passwordless, verification, and `/invites/redeem`; invite landing/start may need
      either a new unauthenticated route or an invite token parameter accepted by
      existing registration/passwordless routes.
- [ ] Update `internal/authcore/service.go` registration checks so `InviteOnly`
      rejects ordinary public registration but allows registration when a valid,
      unexpired email-bound invite exists for the registering email.
- [ ] Update passwordless/OIDC/Solana auto-registration paths to honor the same
      invite-aware rule under `InviteOnly`.
- [ ] Update `internal/authcore/group_invite_links.go` defaults so both shareable
      and email-bound invite links are time-bound for a few days; keep explicit
      per-invite expiry overrides.
- [ ] Update `CreateGroupInviteLink` / `CreateGroupInviteLinkRequest` /
      `GroupInviteLinkCreated` contract docs to name the two kinds: no-email
      shareable link vs email-bound invite.
- [ ] Update `http/permission_group_operations.go` add-member flow: existing
      `user_id` adds directly and silently; email with no account creates/sends an
      email-bound invite instead of failing or auto-adding.
- [ ] Add invite-specific rate limits around invite creation/email sending,
      preferably keyed by actor user, target email, and group; return a stable
      rate-limit error instead of sending more mail.
- [ ] Add/adjust HTTP route support so an unauthenticated invite recipient can land
      on the invite link, register or log in, then manually redeem/accept the same
      invite. Do not auto-redeem after account creation.
- [ ] Add integration tests for: existing user direct add no notification; unknown
      email creates invite; invite-bound registration allowed under `InviteOnly`;
      wrong verified email cannot redeem; manual accept required; expired/revoked/
      exhausted invite rejected; shareable link still obeys expiry/max-use.
- [ ] Make examples and docs use root contract names:
      `authkit.Config`, `authkit.User`, `authkit.ValidateUsername`,
      `authkit.SubjectKindUser`, `authkit.RegistrationVerificationRequired`, etc.
      `embedded` should appear only for `embedded.NewClient` and embedded-only
      options/types.
- [ ] Pare embedding docs down to the normal-host packages only:
      `authkit`, `embedded`, `authhttp`, `verify`, one router adapter, and
      `migrations/postgres` plus `migrations/clickhouse`. Put `jwt`, `oidc`, `authprovider`, `storage`,
      `ratelimit`, `siws`, `password`, Twilio adapters, River jobs, and
      `authtest` in an advanced/support section.
- [ ] Keep direct `jwt` use out of normal host examples. Token signing should go
      through `client.MintDelegatedAccessToken` / `client.MintServiceJWT`; hosts
      should not handle private keys for routine embedding.
- [ ] Move advanced engine hooks out of the first README constructor example:
      `WithEntitlements` (host billing/product entitlements projected into access
      tokens plus admin user detail/list enrichment and entitlement filtering),
      and `WithClickHouse` (auth/session history backed by ClickHouse). Keep them
      documented only in advanced/support sections.
- [x] DECISION: delete API-key resource scopes entirely. API keys should be
      scoped by their permission group plus one role; if a host needs narrower
      scope, it should mint the key on a narrower permission group such as
      `repo` under `org`, not attach a second opaque resource list to the key.
- [x] DECISION: API-key verification is built in, not a host constructor option.
      AuthKit verifies key ID/secret, revocation/expiry, permission group state,
      and role permissions through the verifier's client-backed enricher.
- [ ] Remove `WithAPIKeyResourceAuthorizer`,
      `APIKeyResourceAuthorizer(Func)`, `APIKeyResourceAuthorizationRequest`,
      `APIKeyResource`, `ErrResourceScopeDenied`, and API-key `Resources` fields
      from public/core/http contracts.
- [ ] Remove the `resources` field from `POST /<persona>/<instance_slug>/api-keys`
      request/response/list payloads; API-key minting remains governed by
      `<persona>:credentials:manage` plus the existing no-step-up role-grant
      check.
- [ ] Preserve built-in credential-management permissions: root operators use
      intrinsic `root:credentials:manage`; host personas use generated
      `<persona>:credentials:manage`. Group owners may mint/revoke API keys for
      permission groups they own, but still cannot grant an API-key role above
      their own effective permissions.
- [ ] Drop `profiles.api_key_resources` from the hard-cut Postgres schema and
      delete resource-scope normalization/load/list/authorization code and tests.
- [x] DECISION: first-run embedded constructor options should be only normal
      runtime dependencies: `WithRedis`, `WithEmailSender`, and `WithSMSSender`.
      Everything else is either config, automatic default, advanced/support, or
      test/internal plumbing.
- [x] DECISION: `authhttp.LanguageConfig` should expose only `Supported` and
      `Default`. Do not make the query parameter or cookie name configurable;
      hardcode both to `lang`.
- [ ] Delete public `LanguageConfig.QueryParam` and `LanguageConfig.CookieName`.
      No language config should mean English-only: supported languages `["en"]`,
      default `"en"`.
- [x] DECISION: remove public SMS `DeliveryConfirmTimeout` configuration. The
      Twilio sender should use a fixed internal delivery-confirm timeout around
      10-15 seconds; hosts should not tune this in normal AuthKit setup.
- [ ] Delete `DeliveryConfirmTimeout` from public SMS sender config and docs; keep
      one package-private constant for the internal default.
- [x] DECISION: delete `WithDBTXWrapper` entirely. It was only a sqlc/pgx
      query-decorator seam for hypothetical counting/spy queriers, and current
      source has no test/user call sites. If a future test needs query spying,
      add that locally in the test instead of preserving a public option.
- [ ] Remove `WithDBTXWrapper` from `internal/authcore/options.go`,
      `embedded/aliases.go`, and any public surface inventory/docs.
- [x] DECISION: do not expose `WithSolanaSNSResolver` as a normal client option.
      AuthKit should provide the standard Solana Name Service resolver itself
      when Solana/SIWS is enabled; hosts should not wire a resolver.
- [ ] Replace host-provided SNS resolver wiring with an AuthKit-owned default
      resolver. Keep timeout/cache TTL as fixed internal defaults unless a real
      host need appears.
- [ ] Remove `WithSolanaSNSResolver` from first-run docs and public examples; if a
      custom resolver remains for tests, keep it out of the normal host API.
- [x] DECISION: do not expose generic auth-event logger/reader wiring in the
      normal host-facing API. AuthKit supports ClickHouse for auth/session event
      history; call the option `WithClickHouse(...)` (or `WithClickHouseAuthLog`
      if the name must be narrower) and wire both write and read sides there.
- [ ] Add a first-party ClickHouse auth-event adapter that implements both
      `AuthEventLogger` and `AuthEventLogReader` against the bundled ClickHouse
      migration schema. This is the standard implementation for admin sign-in
      history / user login history views.
- [ ] Replace `embedded.WithAuthLogger(...)` and `authhttp.WithAuthLogReader(...)`
      in public examples/API with one `embedded.WithClickHouse(ch)` option. The
      embedded client owns both auth-event writes and history reads; `authhttp.NewServer(client)`
      should derive the reader from the client, not require a separate server
      option. Passing no ClickHouse means no external auth-event history and admin
      sign-in history routes should report auth log unavailable.
- [ ] Keep low-level `AuthEventLogger` / `AuthEventLogReader` interfaces internal
      or advanced-only only if needed for tests; do not document custom file/stdout
      loggers until there is a real host need.
- [x] DECISION: remove public `WithEphemeralStore` from the host-facing API. It is
      jargon and unnecessary: AuthKit should always create and use an in-memory
      auth-state store when Redis is not supplied.
- [ ] Keep `embedded.WithRedis(rdb)` as the only normal host knob for temporary
      auth state. Redis replaces the default in-memory store for multi-instance
      deployments and stores short-lived auth data such as challenges, OIDC state,
      passwordless/verification/reset tokens, and related counters.
- [x] DECISION: do not expose `authhttp.WithRateLimiter` as normal host setup.
      AuthKit owns the rate-limit policy and should create the limiter itself:
      Redis-backed when the embedded client has Redis, in-memory otherwise.
      Custom limiter injection, if kept, is internal/test/advanced only.
- [ ] Replace public examples of `authhttp.WithRateLimiter(...)` /
      `authhttp.WithoutRateLimiter()` with automatic rate limiting derived from
      the embedded client. Do not allow production hosts to accidentally disable
      brute-force/spam protections through a normal setup option.
- [x] DECISION: replace raw `authhttp.WithClientIPFunc(...)` in normal docs with
      `authhttp.WithTrustedProxies(trustedProxies)`. The server should keep a
      safe default using `RemoteAddr`; hosts behind proxies only provide trusted
      proxy CIDRs. Keep arbitrary `ClientIPFunc` injection internal/test/advanced.
- [x] DECISION: keep an HTTP internal-error logging hook, but name/document it as
      internal observability, not auth-event history. It reports swallowed handler
      failures such as delivery/provider/database errors while clients receive a
      stable public error. Prefer a clearer name such as `WithInternalErrorLogger`.
- [x] DECISION: delete public `authhttp.WithPermissionGroupAuthorizer`. Generated
      permission-group routes should authorize through the embedded client/engine
      (`Can`) directly. The current override is useful for tests and unusual lazy
      materialization only; keep any seam internal/test-only.
- [x] DECISION: delete public `authhttp.WithSolanaDomain`. SIWS challenge domain
      should be derived from AuthKit config (`Frontend.BaseURL` / issuer host) and
      request fallback, not a separate server constructor option.
- [ ] Remove `WithPermissionGroupAuthorizer` and `WithSolanaDomain` from first-run
      docs and public API inventory; keep `WithInternalErrorLogger` in advanced
      server observability docs.
- [ ] Delete `PermissionGroupAuthorizer`, `WithPermissionGroupAuthorizer`, and the
      `groupCanFn` field from public HTTP server code. Update tests to exercise
      the real `Can` path or use package-internal helpers instead of a public
      option seam.
- [ ] Move any custom auth-state store injection to internal tests or an unadvertised
      test seam. Do not expose it in README or normal package docs.
- [x] Update current consumers to v0.69.0 client-first (DONE 2026-06-26, all
      committed+pushed; build+vet green per repo). The migration is mechanical: the
      host builds the engine with `embedded.New`/`core.New` (splitting engine vs HTTP
      options), passes it to `authhttp.NewServer(client, ...)`, and uses the held
      `*embedded.Client` everywhere `authhttp.Service.Client()` was called.
      - openrails → v0.67.0: `ControlPlane.authClient`; Core()/delegated verifier use it.
      - hentai0: `AuthKitService.Client`; threaded to the AuthKitProvider + OpenRails
        embed sessionIdentity + user writer + entitlements install.
      - doujins: `buildAuthKitService` returns the client too; `Infrastructure.AuthKitClient`
        + `ServerInterface.GetAuthKitClient`; threaded to admin writer / gate / entitlements.
      - cozy-art → openrails v0.67.0: `AuthKitProvider.Client()` + `API.authClient`;
        dropped the `.(*core.Client)` casts.
      - tensorhub → openrails v0.67.0: `identity.Service.authClient` (replaced all 19
        `authProvider.Client()` sites).
      (Narrowing broad `authkit.Client` injection to capability interfaces is a later,
      non-blocking polish — the broad seam stays per the #143 review.)
- [x] Add compile-time conformance checks for the small interfaces:
      `var _ authkit.Authorizer = (*embedded.Client)(nil)`, etc. (done in `embedded/conformance.go`).
- [ ] Update README/embedding docs to show:
      - `authhttp.NewServer` for mounted auth routes,
      - `embedded.NewClient` for in-process library operations,
      - future `remote.NewClient` for standalone AuthKit.
- [ ] Validation: `go test ./...` in authkit, then targeted builds/tests in
      doujins, hentai0, cozy-art, and tensorhub after the coordinated bump.

## Non-goals

- Do not split the concrete implementation into `client.Users().Roles().Tokens()`
  subclients yet. Small interfaces over the current methods are the lazy cleanup.
- Do not preserve old `core`, `providers/*`, `riverjobs`, or `identity` package
  aliases indefinitely. Migrate first-party consumers forward instead.
- Do not design the full remote management API here; #142 owns that. This issue
  only names the client constructors and shrinks the public dependency boundary.

## Depends on / coordinates with

- #142 standalone server + remote SDK: constructor naming and remote-client target.
- #138 package restructure: this is a follow-up correction to the too-broad
  `authkit.Client` seam created there.
- #141 cleanup: consumer package-name migration continues the same pre-v1 hardcut.

---

# #142: Standalone self-hostable server + remote SDK (authkit Phase 2)

**Completed:** yes (track A client-first + full consumer migration; track B standalone
server + generated remote SDK, shipped v0.70.0. Two tasks pruned as over-engineering:
the in-process transport adapter and the flag/file config layer. mTLS / signed-JWT mgmt
auth left as future hardening — bearer token ships.)

STATUS 2026-06-26 (Claude): foundation landed (additive, non-breaking). Built the
remote-SDK transport END-TO-END for the first capability slice (`authkit.Authorizer`):
`authkit/server` management handler (`NewAuthorizerHandler` over any `authkit.Authorizer`
+ static bearer auth), `authkit/remote` client satisfying the SAME interface over HTTP,
and a parity test proving values round-trip AND `errors.Is(err, authkit.ErrX)` survives
the wire. `remote` is lean (net/http + authkit only, no engine/pgx). Interface-portability
audit started: DROPPED `ApplyBootstrapManifestFile` from the contract (a file path is the
SERVER's fs — meaningless remote; hosts load then `ApplyBootstrapManifest`).

STATUS 2026-06-26 (Claude): full code→error registry DONE. Added `authkit.ErrorForCode`
(all 47 sentinels, one shared map) in `errors.go` + `errors_test.go` (round-trip +
uniqueness check); normalized the `ErrGroupNotFound` sentence-code wart →
`permission_group_not_found`. `remote/` now resolves wire codes through the shared
registry (deleted its local 5-entry `codeErrors` map) — ONE source of truth for error
identity, client+server. build+test green.

STATUS 2026-06-26 (Claude): client-first construction DONE (Paul greenlit track A).
`authhttp.NewServer(client *embedded.Client, opts...)` — the server is now an HTTP
adapter over a client the host built; engine deps go on `embedded.New`, HTTP-layer
options stay on `NewServer`. Specifics: added `authcore.Service.Config()` (retains the
host Config so the transport reads HTTP-only OIDC providers/descriptors), `embedded.New`
now defaults to an in-memory ephemeral store (was the http layer's job), new
`embedded.WithRedis` (engine store) + `embedded.Unwrap` (engine extraction for the
transport); `authhttp.WithRedis` is now HTTP-only (OIDC/SIWS state caches), and the
engine-dep option wrappers (WithEphemeralStore/WithEmailSender/WithSMSSender/
WithEntitlements/WithClickHouse/WithAPIKeyResourceAuthorizer/WithSolanaSNSResolver) +
`Server.coreOpts` are deleted from `authhttp`. DROPPED `Server.Client()` (host owns the
client). Migrated all 34 in-repo `NewServer` sites (devserver + ~33 http tests + gin
test). build+vet+gofmt green; full DB-backed suites (http, internal/authcore, riverjobs)
+ non-DB suites pass on a fresh migrated DB.

STATUS 2026-06-26 (Claude): track A COMPLETE end-to-end. Shipped authkit v0.69.0
(client-first NewServer + dropped `Server.Client()` + shared `ErrorForCode` registry,
then pared `SetEntitlementsProvider` off the HTTP `Server`). Migrated the ENTIRE consumer
ecosystem to v0.69.0 client-first, each build+vet green and pushed: openrails v0.67.0,
hentai0, doujins, cozy-art, tensorhub. So #142 track A (client-first construction +
Server paring + consumer migration) is fully done.

REMAINING: only (B) the standalone-server bulk — the other ~89 mgmt-API methods,
`cmd/authkit-server`, app→server auth; the issue marks this "build when greenlit"
(speculative until the standalone product is committed). The foundation (remote SDK
transport + shared error identity) already proves the architecture.

Proposed 2026-06-25 (split out of #138 Phase 2, now that the embedded restructure +
pgx-free contract are committed). authkit is embedded-only today: an app runs the
engine in-process (`embedded.New` / `authhttp.NewServer`). This issue makes authkit
ALSO runnable as a STANDALONE, self-hostable server, so:
- non-Go apps can use authkit over an HTTP management API, and
- a Go app can swap embedded↔remote with ONE line (`embedded.New` ↔ `remote.New`) —
  both satisfy the pgx-free `authkit.Client` contract #138 established.

This is a NEW product surface, not a refactor — build when greenlit.

## Design — etcd's "one client, two transports" (NOT two client impls)
#138's etcd analysis is the blueprint:
- ONE consumer-facing client driven by a TRANSPORT: an in-process direct-call adapter
  (embedded) OR an HTTP transport (remote). Two independent client impls drift (error
  mapping, timeouts, partial coverage); one client + two transports does not.
- In-process = direct function calls through the real handler stack (etcd's `v3client`
  via `proxy/grpcproxy/adapter`), NOT a loopback socket.
- Handlers + wire DTOs defined ONCE; both transports feed them.

## Target packages
| Package | Role |
|---|---|
| `authkit/server` | standalone-server logic: engine + `authhttp` browser routes + the new authenticated MANAGEMENT API. Thin `main` in `cmd/authkit-server`. Owns its DB/Redis/config. |
| `authkit/remote` | Go SDK: `remote.New(url, creds) (*remote.Client, error)` satisfying `authkit.Client` by marshaling each method to the management API. Lean (net/http only). |
| transport seam | in-process direct-call adapter + HTTP transport feeding ONE shared client (etcd `v3client`). |

Non-Go clients hit the management REST API directly (no SDK).

## Construction shape (client-first) — folded from #143
Land these WITH the remote SDK so consumers migrate ONCE to the v1.0 shape (doing them
as a separate issue = two migrations of the same construction surface):
- [x] `authhttp.NewServer(client, httpOpts...)` — client-first; the server becomes an
      HTTP adapter over a client the host already built (no hidden engine). DONE.
- [x] Drop `authhttp.Server.Client()` — redundant once the host owns the client. DONE.
- [x] Split options: engine deps (senders / ephemeral store / entitlements / auth log /
      API-key authorizer / Solana) on `embedded.New`; HTTP behavior (rate limiter /
      client IP / language / error logger / route wrappers) on `authhttp.NewServer`.
      Moved `WithRedis` onto `embedded` (`embedded.WithRedis`); `authhttp.WithRedis` is
      now HTTP-state-only. `WithEphemeralStore` already on `embedded`. DONE.
- [ ] `remote.New` mirrors `embedded.New`; both return the concrete client, host types
      its var `authkit.Client` for the swap. (New-vs-NewClient naming = Paul's bikeshed.)
- [ ] KEEP the broad `authkit.Client` seam (per #143 review) — small capability
      interfaces from #143 coexist with it, they don't replace it.

STATUS 2026-06-26 (Claude): track B (standalone server + remote SDK) BUILT & proven
end-to-end (Paul greenlit "finish your 142"). The key decision — instead of 93
hand-written REST endpoints (the drift trap #138 warns about), a CODE GENERATOR
(`internal/genremote`, stdlib go/ast only) parses the `authkit.Client` interface and
emits BOTH sides into `*_gen.go` (`go generate ./...`, directive on client.go). One
source of truth → the transports cannot drift. Live smoke test: the binary created a
user over the management API and read it back; no-token call → 401.

## Tasks
- [x] **Interface portability audit.** `ApplyBootstrapManifestFile` already dropped from
      the contract (v0.67.0). The remaining maintenance/infra methods stay on the
      interface and are exposed verbatim through the generic dispatch (no per-method
      reshaping needed — the wire is method-name + JSON args).
- [x] **Management HTTP API contract** — generic dispatch `POST /v1/call/{Method}`:
      args = JSON object keyed by param name; success `{"result":…}`; failure
      `{"error":{"code":…}}` with the sentinel code. Covers the FULL `authkit.Client`
      (93 methods), generated. (`server/management.go` + generated `server/methods_gen.go`.)
- [x] **App→server auth** — static bearer token (`AUTHKIT_MGMT_TOKEN`). Fail-closed:
      outside dev the management API is NOT mounted without a token. (mTLS / signed
      service-JWT / least-privilege scoping are future hardening, not blocking.)
- [x] **`authkit/server`** — `server.NewHandler(client, token)` over any `authkit.Client`;
      thin `cmd/authkit-server` main (engine + authhttp browser routes + JWKS + mgmt API
      + env config). README at `cmd/authkit-server/README.md`.
- [x] **`authkit/remote`** — `remote.New(url, token)` returns a `*Client` satisfying the
      FULL `authkit.Client` (compile-time conformance in `remote/conformance.go`). All 93
      methods generated; error mapping re-derives `errors.Is(err, authkit.ErrX)` via the
      shared `authkit.ErrorForCode`.
- [x] ~~Transport seam (in-process direct-call adapter)~~ — DELETED as over-engineering.
      etcd needs `v3client` because its embedded client would otherwise re-implement the
      gRPC client; here the management handlers operate on the `authkit.Client` interface,
      which `embedded.Client` already IS (direct in-process calls), and `remote.Client` is
      GENERATED from that same interface. The two transports are derived from one contract
      and cannot drift — routing embedded through HTTP handlers would be pure in-process
      overhead for zero benefit. No adapter exists or is needed.
- [x] **Config unification** — DONE via env: `cmd/authkit-server` builds `embedded.Config`
      from `AUTHKIT_*`/`DB_URL` (issuer/keys/schema/redis/registration-verification). A
      flag/file config layer is YAGNI for ~11 knobs (etcd has it for a huge surface); add
      it only if a real deploy needs flags.
- [x] **Tests** — `remote/remote_test.go`: fake-`authkit.Client`-backed parity over
      `httptest` (bool/[]string/pointer-struct/multi-return/no-ctx round-trips + error
      identity + auth seam). `remote/parity_db_test.go`: REAL embedded engine — write via
      remote, read via both transports, ban via remote visible to the embedded client.
- [x] **Docs** — `cmd/authkit-server/README.md` (deploy guide, wire contract, env table,
      the embedded↔remote one-line swap, non-Go curl examples). Package docs on
      `server`/`remote`/`genremote` explain the transport + codegen.

## Open questions
- Management API home: a new `authkit/server` handler, or extend `authkit/http`?
- The awkward methods (bootstrap-from-file, cleanup) — remote-exposed at all?
- Error identity over the wire: map HTTP status+code → shared `authkit.Err*`.

## Depends on
#138 (DONE, committed `a08ac76`/`afa17d1`): the pgx-free `authkit.Client` contract +
the `authkit/embedded` / `authkit/verify` split this builds on.

---

# #141: Repo cleanup — top-level package & root-file tidy (pre-1.0 hardcut)

**Completed:** yes

STATUS 2026-06-25 (Claude): DONE. Cleanup committed `afa17d1` (local on master, not
pushed): all relocations/renames/deletes landed; `identity` replaced by
`Client.UsersByIDs`. The two surface flags are DECIDED — keep everything public
(external usage confirms oidc/password/lang are real library imports; siws leaks
through storage's public API; the root helpers are the shared lean layer). No
further churn. build+vet+gofmt green; full DB-backed + non-DB suites green on a
fresh DB. Flag-decision note is an uncommitted progress.md edit.

Proposed 2026-06-25 (Paul + Claude, after the #138 restructure). With the package
restructure landed, audit the public surface + repo root. Every top-level dir
EXCEPT `internal/` (compiler-private) and `cmd/` (binaries) is importable = public
API, so trimming/relocating now (pre-1.0) keeps the v1.0 surface clean. Breaking;
hardcut, no compat. In-repo importer counts noted; external consumers
(openrails/doujins) may differ — VERIFY before deleting.

## Tasks

### Relocate — group opt-in integrations under adapters/
- [x] `providers/{email,sms}/twilio` → `adapters/twilio/{email,sms}` (pkg `twilio`);
      `providers/` deleted. build+vet green.
- [x] `riverjobs/` → `adapters/riverjobs` (kept dir=package; cleaner than `adapters/river`
      with pkg `riverjobs`). `adapters/` now: chi, gin, twilio, riverjobs.

### Relocate — devserver support kit follows the binary into cmd/
- [x] `Dockerfile.devserver` → `cmd/authkit-devserver/Dockerfile`.
- [x] `DEVSERVER.md` → `cmd/authkit-devserver/README.md`.
- [~] `docker-compose.yaml` — KEPT at root (decision): it's the `task test` harness
      (Postgres + devserver), and moving it forces an awkward `context: ../..`. Just
      repointed its `dockerfile:` → `cmd/authkit-devserver/Dockerfile` (context stays root).
- [x] `config/bootstrap.example.yaml` → `cmd/authkit-devserver/bootstrap.example.yaml`;
      `config/` dir DELETED.
- [x] Doc links updated (README bootstrap-example path, SEMVER devserver list +
      `testing`→`authtest`). Taskfile needs no change (compose stayed at root; only a
      comment mentions it). `go build ./...` + `./cmd/authkit-devserver` green.

### Rename — kill the stdlib shadow
- [x] `testing/` → `authtest` (dir + `package testing`→`authtest`, killing the stdlib
      shadow). One in-repo importer (`http/verifier_multialg_test.go`, aliased
      `authkittesting`) repointed. build+vet green.

### Delete — verified against all 4 consumers (doujins/hentai0/cozy-art/tensorhub)
- [x] `roles/` (`roles.IDFromSlug`) — confirmed UNUSED in-repo AND in all 4
      consumers. DELETED. build+vet green.
- [x] `identity/` — DELETED ENTIRELY, with the replacement shipped in the same change:
        - authkit: added `UsersByIDs(ctx, []string) ([]UserRef, error)` to `authkit.Client`
          (new `UserRef` contract type + engine method `Service.UsersByIDs` over the
          existing `IdentityUsersByIDs` sqlc query + facade delegate). One method subsumes
          identity's three batch reads (usernames/emails/users-by-ids).
        - deleted `authkit/identity`; conformance holds (94-method Client); fixed the
          bootstrap-example test path (was `config/`, now `cmd/authkit-devserver/`).
          build+vet+gofmt green; full DB suite green on a fresh DB.
      CROSS-REPO (doujins, on next bump): writes → `embedded.Client.UpdateUsername`/
      `UpdateEmail` (gains the cooldown+validation its raw `identity` writes skipped);
      reads → `Client.UsersByIDs`. Stale sqlc `Identity*` write/single-lookup queries in
      `internal/db` are now unused (harmless generated code; prune on next sqlc regen).

### Read-access design (DECISION — so `identity` never gets re-added)
authkit must NOT ship pre-made query wrappers (`identity.Store` model: maintenance
treadmill, leaks internal sqlc, duplicates the engine, lets hosts bypass invariants).
Host read access is exposed TWO ways, by need:
1. curated read METHODS on `authkit.Client` — single lookups + `AdminListUsers` exist
   today; add batch ones (`UsernamesByIDs`/`UsersByIDs`) as real need appears. Portable
   (works embedded AND remote), keeps tables private, enforces invariants.
2. for an embedded host needing SQL JOINs against its own tables: a documented stable
   read VIEW (e.g. `profiles.users_public`) queried with the host's OWN tooling —
   authkit owns the view contract, the host owns the query. Add only when needed (YAGNI).
Writes ALWAYS go through the engine. Tables stay an implementation detail.

### Flags — DECIDED (keep everything; the public surface is correct)
- [x] Public-surface reduction → KEEP `siws`/`oidc`/`password`/`lang` public. External
      usage (across doujins/hentai0/cozy-art/tensorhub): oidc=4, password=2, lang=5 —
      all legitimately imported as library primitives. `siws`=0 direct, BUT its
      `ChallengeData` leaks through `storage/redis.SIWSCache`'s public signatures, so
      internalizing would break that public API or force deeper surgery — not worth it.
- [x] Root contract-pkg purity → KEEP `origin.go`/`httperror.go`/`permission.go` in
      root. The root package IS the lean shared layer (it absorbed authbase's role);
      these are legitimately-shared lean contract helpers (permission matching + key
      format have external users; the error envelope is the wire error shape). Moving
      them out just recreates the authbase split we deliberately folded. No churn.

## Keep (core / legit public)
`authprovider` (OAuth model, 6 importers), `embedded`, `http`, `verify`, `jwt`,
`oidc`, `migrations`, `ratelimit`, `storage`, `password`, `lang`,
`adapters/{chi,gin}`. Standard root files: `go.mod`/`go.sum`, `README.md`,
`LICENSE`, `SECURITY.md`, `.gitignore`, `.gosec.json`, `Taskfile.yml`, `sqlc.yaml`,
`BREAKING.md`, `SEMVER.md`.

## Coordinate
Lands with the #138 hardcut (same breaking pre-1.0 release); run after the #138
commit so restructure + cleanup ship together.

---

# #140: ship a Can-backed permission gate (RequirePermission middleware)

**Completed:** authkit side yes; cross-repo doujins adoption pending (optional)

STATUS 2026-06-26 (Claude): authkit side DONE & shipped — `verify.RequirePermission`
(Can-backed, fail-closed) is in ≤ v0.69.0. The ONLY thing left is the doujins-side
adoption: delete its local `principalHasPermissionDB` + `catalogRolesGranting` +
`permission.ForRoles` expansion and gate purely via authkit's `Can`. NOT done here on
purpose — it's a behavior-sensitive AUTHORIZATION change (swaps doujins's local perm→role
catalog for authkit's permission-group resolution), so it needs explicit go-ahead +
doujins's DB-backed auth tests to prove decisions don't shift. Tracked as doujins #422/#423.

Proposed 2026-06-25 (doujins boundary review). authkit owns the permission-group
schema and has `Can(subjectID, subjectKind, persona, instanceSlug, perm)`, but
ships NO request-level gate — so embedding hosts hand-roll one AND reimplement the
role→permission expansion against a local copy of the catalog. doujins's
`principalHasPermissionDB` maps perm→roles from its own `roleBundles` and borrows
authkit only for role membership, duplicating what `Can` already does end-to-end.
Hard cut: ship the gate, hosts delete their copies.

STATUS 2026-06-25 (Claude): implementation DONE in the working tree —
`verify/require_permission.go` + `require_permission_test.go` (6 cases),
`go build/vet/test ./verify/` green. Held with #139 pending a pinnable release.

## Tasks
- [x] `net/http` `RequirePermission(checker, perm, resolve)` middleware in
      `verify/require_permission.go`: `resolve` → (persona, instanceSlug) so ONE
      gate serves singleton `root` AND resource-scoped `merchant`/`customer`; reads
      verified Claims; token-carried perms short-circuit, else `Can` → 403/next;
      fail-closed.
- [x] tests (`require_permission_test.go`, 6): singleton allow/deny, resource-scoped
      instance pass-through, token short-circuit, no-claims + nil-checker forbidden.
- [~] `Can` on the `authkit.Client` interface — #138's (93-method Client exists).
      The gate deliberately depends on a NARROW `verify.PermissionChecker` port
      (`embedded.Client`/`authkit.Client` satisfy it directly), so `verify` stays
      jwt-only and never imports the engine.
- [ ] document the net/http→gin wrap (composes with the standard gin wrapper, e.g.
      doujins's `wrapHTTPMiddleware`) — doc nicety, non-blocking.

CROSS-REPO CONSUMER (doujins #422/#423): once shipped, doujins deletes
`principalHasPermissionDB` + `catalogRolesGranting` + the local `permission.ForRoles`
expansion and gates purely via authkit. Pairs with #138's `authkit.Client`.

---

# #139: verify.Verifier.VerifyRequest — request→claims extractor (un-hack out-of-band auth gates)

**Completed:** yes

STATUS 2026-06-26 (Claude): DONE both sides. `verify.VerifyRequest` shipped (≤ v0.69.0);
doujins ADOPTED it — `internal/billing/openrailsembed/auth.go` now calls `v.VerifyRequest(r)`
(the discard-ResponseWriter hack is gone). No remaining cross-repo work.

STATUS 2026-06-25 (Claude): code + a direct `VerifyRequest` test are in the working tree; `verify` pkg green (Required now delegates to it). Held pending a pinnable authkit release; doujins re-applies then (doujins #422).

Proposed 2026-06-25. `verify.Required`/`Optional` are the only way to run the
full auth pipeline (bearer parse, API-key branch, JWT verify, 2FA + delegated
issuer gates, DB enrichment, ban/deleted gate). An embedder that must
authenticate a request OUTSIDE the http-middleware chain (openrails' billingauth
seam, consumed by doujins) currently drives `Required` against a throwaway
ResponseWriter and scrapes claims back out of the request context — a hack.

Change (additive, non-breaking; stays inside `verify/`, which #138 leaves
unchanged): extract the pipeline body of `Required` into

    func (v *Verifier) VerifyRequest(r *http.Request) (Claims, error)

returning the enriched claims, or an error carrying the would-be HTTP status
(401/403) via an unexported `authError`. `Required` becomes a thin wrapper that
calls `VerifyRequest` and writes the response — single source of truth, behavior
preserved (verify tests green). Patch: scratchpad/authkit-verifyrequest.patch.

Coordinate with #138 (same repo, active): no package overlap (verify/ untouched
there), so this can land independently or fold into the #138 release.

CROSS-REPO CONSUMER (doujins): `internal/billing/openrailsembed/auth.go` replaces
its discard-writer `verifyRequest` with `v.VerifyRequest(r)` once authkit ships
this (needs a version doujins can pin).

---

# #138: Package restructure for embedded-now / standalone-later (etcd-style dual mode)

**Completed:** yes (Phase 1/1.5/1.6 done + committed; Phase 2 split to #142)

STATUS 2026-06-25 (Claude): Phase 1 landed in the working tree. Done: devserver →
`cmd/authkit-devserver/`; `core` package → `embedded` (`core.Service` →
`embedded.Client`, `NewFromConfig` → `New`, 69 importers updated); root `authkit`
package with the 93-method `Client` interface + data-contract re-exports +
compile-time conformance proof; `svc.Core()` → `svc.Client() authkit.Client`
(http + devserver are the root's first importers, seam exercised end-to-end);
#109 disambiguation (collision resolved by the rename). Cut public `NewService`
(Options+Keyset escape hatch, no real consumer) after rewriting its lone test
caller onto `embedded.New`. Deferred:
making root literally pgx-free (relocating ~115 type defs; only Phase-2 `remote`
needs it). Verified: `go build ./...` + `go vet ./...` green; non-DB tests pass;
DB-backed riverjobs purge + http server tests pass against the compose Postgres.
COMMITTED — Phase 1 `a08ac76`, with the 1.5/1.6 inversion+fold landed in the same
tree, then #141 cleanup `afa17d1` (local on master, not pushed). Phase 2 (standalone
server + `authkit/remote` SDK + transport seam) is SPLIT OUT to issue #142 — build
when greenlit.

Proposed 2026-06-25 (Paul + Claude design session). authkit is an **embedded Go
library today**. We want it to *later* be offered as a **self-hostable standalone
server** (so non-Go apps can use it over HTTP), and a consumer should swap
embedded ↔ standalone with **minimal effort** — the way openrails does. This issue
restructures the embedded library now so the swap seam exists, then stops.
Standalone is Phase 2, deferred until we decide to build that product. Breaking;
lands with the #108 hardcut, pre-1.0.

Reference design is **etcd** (runs both ways: `embed` package + `clientv3` +
standalone binary). An agent analyzed it; the load-bearing lessons:

1. **Lean client/contract module, heavy server module.** etcd's `client/v3` (gRPC
   only) + `api/v3` (shared DTOs) carry no raft/storage. → our lean root + heavy
   `embedded` split is right.
2. **Write the client ONCE; vary the transport.** etcd does NOT have two client
   impls. One `clientv3.Client` is fed by either a real gRPC socket OR a
   zero-serialization **in-process adapter** (`v3client.New(server)` via
   `proxy/grpcproxy/adapter`, presenting server handlers as the client interface).
   → **This corrects the earlier sketch of two independent impls (`embedded` +
   `remote`) each satisfying the interface — two impls drift (error mapping,
   timeouts, partial coverage). One client + two transports does not.**
3. **In-process = direct calls, NOT a loopback socket.** etcd's embedded fast path
   makes direct function calls through the real handler stack. → when we build
   standalone, embedded must not route through HTTP/loopback.
4. **One config struct, two front doors.** `embed.Config` is mutated by embedders
   and filled-from-flags/file by the binary (`etcdmain` wraps the same struct);
   `main` is ~10 lines.
5. **Frozen wire-contract package** (`api/v3`) versioned independently. → our root
   DTOs are the start of this.

## Target layout

| Package | Deps | Phase | Role |
|---|---|---|---|
| `authkit` (root) | lean (stdlib) | 1 | contract: `Client` interface, shared DTOs (`User`/`Session`/`APIKey`/`Config`…), sentinel errors. No pgx/redis/http. Swap seam + frozen wire-contract. |
| `authkit/embedded` | + pgx | 1 | in-process engine; `New(cfg, pg) (*Client, error)`; satisfies `authkit.Client` via direct Go calls. (today's `core` + `internal/authcore`) |
| `authkit/http` | + oidc/redis/ratelimit | 1 (rename) | browser-facing auth-flow routes an embedding app mounts. Stays; becomes a component of the Phase-2 standalone server. |
| `authkit/verify` | jwt only | 1 (unchanged) | local JWT validation, both modes. Must never import `embedded`. |
| `authkit/server` | + http + mgmt API | 2 | standalone self-hostable binary: engine + `http` routes + authenticated management API for non-Go clients. Thin `main` in `cmd/`. |
| transport/adapter layer | lean | 2 | in-process direct-call adapter (embedded) + HTTP transport (remote), both feeding one shared client (etcd `v3client`/`adapter`). |
| `authkit/remote` | + net/http | 2 | Go SDK over the mgmt API. Satisfies `authkit.Client`. |

Consumer code, unchanged across the swap:
```go
var c authkit.Client
c, _ = embedded.New(cfg, pg)                       // Phase 1 — in-process
c, _ = remote.New("https://auth.acme.com", creds)  // Phase 2 — standalone
c.CreateUser(ctx, "a@b.com", "alice")              // identical either way
```

## Phase 1 — embedded restructure + seam (this issue)

- [x] Create root `authkit`: `authkit.Client` interface = the portable 93-method
      subset (infra accessors `Postgres()`/`Keyfunc()`/`JWKS()`/`Options()`/`Schema()`
      kept OFF it), `client.go`; data types/enums/sentinel errors re-exported in
      `types.go`; compile-time `var _ Client = (*embedded.Client)(nil)` conformance
      proof holds. **DEFERRED:** literal "ZERO pgx imports" — root re-exports from
      `embedded`, so it transitively imports pgx today. Making root pgx-free means
      relocating ~115 type DEFINITIONS out of the pgx-importing engine files into a
      lean package (the structs themselves are plain — `User`/`Session`/`Config` use
      only stdlib — but their files hold the engine). That's a large separable
      surgery whose only consumer is Phase-2 `remote`; carved out as its own task.
- [x] Rename `core` → `embedded`; `core.NewFromConfig` → `embedded.New`;
      `core.Service` → `embedded.Client`; all 69 importers updated; build green.
- [x] DELETE public `core.NewService`/`embedded.NewService` (the Options+Keyset
      escape hatch — no real consumer; real construction is `embedded.New(Config, pg)`).
      Its one caller, the river purge-worker DB test, was rewritten onto
      `embedded.New(Config{Keys.VerifyOnly}, pg)` (no signer needed). Internal
      `authcore.NewService` kept (used by `New` + in-package tests). DB test green.
- [x] `svc.Core()` → `svc.Client()` returning `authkit.Client` (the interface seam;
      devserver bootstrap helpers now take `authkit.Client`). http + devserver are
      the root package's first real importers — seam exercised end-to-end.
- [x] Move devserver (`package main` at repo root, test-only) → `cmd/authkit-devserver/`;
      thin `main`. Frees root to be the library package. (Dockerfile.devserver build path updated.)
- [x] `authkit/http` #109 disambiguation: the collision is RESOLVED by the
      core→embedded rename (no second public `Service` type exists; facade is
      `embedded.Client`). `Server` kept as the recommended exported alias
      (`type Server = Service`); stale `core.Service` doc fixed. Full receiver
      rename `Service`→`Server` skipped — pure churn, no behavior change, nothing
      left to disambiguate.

**NOT in Phase 1 (YAGNI until standalone greenlit):** no `authkit/server` binary,
no management HTTP API, no `authkit/remote` SDK, no transport/adapter layer (with
one transport the engine *is* the client). The root interface is the one piece of
deliberate forward-investment — it makes the Phase-2 swap construction-only instead
of a type change in every consumer.

## Phase 2 — standalone server → SPLIT OUT to issue #142

The standalone self-hostable server, management HTTP API, `authkit/remote` SDK, and
the etcd "one client, two transports" seam are now planned in their own issue, #142.

## Phase 1.5 — contract inversion to the ideal greenfield shape (DONE — root pgx-free)

STATUS 2026-06-25 (Claude): COMPLETE. Root `authkit` is now pgx-free — it depends
on `authbase` + stdlib only (`go list -deps` verified). The wire contract (47+6
sentinel errors, `User`/`Session`, 34 DTOs/enums + 11 enum consts) lives in the
lean `authbase` package; `internal/authcore` aliases every symbol back so engine
code is unchanged; root re-exports the contract from `authbase`; the
`embedded.Client`→`authkit.Client` conformance assertion moved into `embedded`.
Dependency direction is now correct (infra → contract, never the reverse). build
+ vet green; full DB-backed suites pass on a fresh migrated DB. Only the optional
naming polish (fold `authbase` into root) remains. NOT committed (dirty worktree).

Decision (Paul, 2026-06-25): a pgx-free root is the IDEAL design, not just nicer —
it's the correct dependency direction. Infra (pgx persistence, http transport) are
ADAPTERS that depend INWARD on the contract; the contract depends on nothing heavy
(etcd `api/v3` / hexagonal ports). Today's shape is INVERTED — root re-exports
*outward* from the engine, so the contract depends on the implementation. Fix it.

**Contract home = `authbase`** (already lean/stdlib-only, already imported by
`authcore`; its own doc says it exists for verify "and, later, a remote SDK" — it
IS the designed contract package). Already holds RemoteApplication, APIKey types,
ResolvedAPIKey, ServiceJWTClaims, key-format helpers, 3 sentinel errors.

**Mechanic (incremental, build-green — no big-bang cycle-break):** for each
contract symbol DEFINED in `internal/authcore`:
1. move its DEFINITION into `authbase` (stdlib-only; topological order, leaves first);
2. in `authcore` replace the def with `type X = authbase.X` (authcore already imports authbase);
3. `embedded/aliases.go` + root `types.go` re-exports keep working via the alias chain → green.

**FINAL FLIP** (once every root-exposed symbol resolves through `authbase`):
point root `types.go` re-exports at `authbase` instead of `embedded`; move the
`var _ authkit.Client = (*embedded.Client)(nil)` conformance into `embedded`; drop
root's `embedded` import → **root is pgx-free**.

**Partition (contract vs engine):**
- CONTRACT → `authbase`: DTOs (`User`, `Session`, `AdminUser`, `GroupMember`, …),
  enums (`RegistrationMode`, `SessionRevokeReason`, …), the `*Request`/`*Result`/
  `*Options` in the `Client` interface, sentinel errors, key-format helpers.
- ENGINE → stays in `authcore`/`embedded`, OFF root's surface: `Config`, `Options`,
  `Keyset`, ports (`EmailSender`/`SMSSender`/`EntitlementsProvider`/`AuthEventLogger`),
  `WithX` construction options. Trim these from root `types.go` — they aren't contract.

**Cycle-break note:** the conformance assertion must leave root (else root→embedded→
pgx). Defining straight into root would force authcore→root while root still imports
embedded — a cycle; staging through `authbase` (which authcore already imports)
avoids it and keeps every step green.

**Stages** (each build-green) — ALL DONE except the optional fold-in:
- [x] sentinel errors → `authbase`: all 47 authcore-defined sentinels MOVED to
      `authbase/errors.go`; authcore aliases them (`var ErrX = authbase.ErrX`).
      Shared `errors.Is` identity now lives in the contract pkg.
- [x] leaf DTOs → `authbase`: `User` + `Session` (authbase/user.go).
- [x] composite DTOs + enums → `authbase`: 34 types + 11 enum consts moved to
      `authbase/contract.go` (Admin*, APIKey*, Bootstrap*, Group invite*, Group
      membership, mint params, Import*, Passwordless*, MFAStatus, PreferredLanguage),
      authcore aliases them all. One method (`AdminUserListOptions.normalize`)
      converted to a free function (can't define methods on an alias).
- [x] trim engine types off root `types.go`: root now re-exports ONLY the contract
      from `authbase` (102 symbols: DTOs + enums + 53 sentinel errors). `Config`/
      `Options`/`Keyset`/ports/`WithX` dropped from root (reach them via `embedded`).
- [x] FINAL FLIP → **root is pgx-free**: `types.go` re-exports from `authbase`,
      conformance assertion `var _ authkit.Client = (*embedded.Client)(nil)` moved
      to `embedded/conformance.go`, root's `embedded` import dropped. `go list -deps`
      on root = `{authbase}` only — no pgx/redis/authcore/embedded/http. `verify`
      still pgx-free. Full DB-backed suites (internal/authcore, http, riverjobs)
      green on a freshly-migrated DB.
- [ ] fold `authbase` into root `authkit` (one contract package) — see Phase 1.6.

## Phase 1.6 — fold authbase into root + delete legacy (HARDCUT, no compat) — DONE

STATUS 2026-06-25 (Claude): `authbase` package FOLDED into root `authkit` and
deleted; its 9 files now define the contract in the root package, root `types.go`
re-export shell deleted, all 34 importers repointed to root, stale comments
cleaned. Root `authkit` is the ONE contract package — pgx-free (`go list -deps` =
root only), holds DTOs + enums + 53 sentinel errors + the `Client` interface.
`verify` still pgx-free. build + vet + gofmt green; full DB-backed + non-DB suites
pass on a fresh DB. Only the cosmetic `embedded` alias trim declined (see below).
NOT committed (dirty worktree).

Make root `authkit` the ONE contract package consumers import (`authkit.User`,
`authkit.ErrUserNotFound`, `authkit.Client`). No `authbase` package, no redundant
re-export shells. Breaking; hardcut, no compatibility aliases.

- [x] Move `authbase/*.go` (9 files + `httperror_test.go`) into root `authkit`
      package; `package authbase` → `package authkit`. Defs now LIVE in root.
- [x] Delete root `types.go` (the re-export shell — redundant once defs are in root).
- [x] Rewrite all 34 `authbase` importers: import path → root, `authbase.` →
      `authkit.` (authcore engine aliases now `type X = authkit.X`; verify/http/embedded
      repointed). Stale `authbase` comment mentions cleaned up too.
- [x] Delete the now-empty `authbase/` directory.
- [x] Verify: no import cycle; root pgx-free + lean (`go list -deps` root = {root} only);
      `verify` still pgx-free; build + vet + gofmt green.
- [x] Full DB-backed suites (internal/authcore, http, riverjobs) + non-DB (root
      `authkit`, verify, jwt, adapters) pass on a fresh migrated DB; gofmt clean.
- [x] Trim `embedded/aliases.go` contract re-exports (HARDCUT, per Paul). Dropped
      all 117 redundant contract re-exports (types + 53 errors + enum consts +
      helpers); `embedded/aliases.go` now re-exports ENGINE symbols only
      (Config/Options/ports/WithX/engine enums). The 93-method `embedded` facade and
      every consumer (http/cmd/adapters/riverjobs) now spell the contract `authkit.X`;
      unused `embedded`/`authkit` imports pruned. One subtlety handled: a substring
      repoint had corrupted engine types sharing a contract prefix
      (`APIKeyResource*`) — reverted those to `embedded.X`. build + vet + gofmt green;
      full DB-backed + non-DB suites pass on a fresh DB; root still pgx-free.

## Open decisions

- Naming collision `authkit.Client` (interface) vs `embedded.Client` (struct) —
  fine in Go (`http.Client`); alternatives `authkit.API` / `embedded.Engine`.
- Root = contract (chosen — so `remote` imports it without pgx; no `authkit.New`,
  construction is `embedded.New`) vs root = embedded entrypoint (`authkit.New`,
  pulls pgx) with contract in `authkit/api`.
- Exact interface surface: which of the ~95 methods are portable contract vs
  embedded-only infra — needs a method-by-method pass.

---

# #136: Root RBAC redesign — owner/admin tiers, core-enforced no-escalation, bootstrap seed-if-absent

**Completed:** yes

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

**Completed:** yes

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
- Confirm success/failure uses the existing session lifecycle audit stream; request/rate-limit/account-created audit events need a broader audit-contract expansion if required later.
- Session minting should call the existing `IssueRefreshSessionWithAuthMethods` path with the right auth method.
- Sensitive operations can still require step-up or MFA later; this flow only establishes wallet/login identity.

## Tasks

- [x] Add feature/options wiring for passwordless login and passwordless auto-registration; default disabled unless a host enables it.
- [x] Add route specs for `POST /passwordless/start` and `POST /passwordless/confirm`.
- [x] Add core methods to create, store, consume, and expire passwordless challenges using the existing ephemeral-store pattern.
- [x] Add email and SMS delivery support for passwordless OTP/link messages, reusing the existing sender style where practical.
- [x] Add create-if-missing user path with generated username, verified email/phone, and no password row.
- [x] Add existing-user login path that verifies the contacted identifier and mints access/refresh tokens with `amr=email` or `amr=sms`.
- [x] Add anti-enumeration behavior and rate limits for start and confirm.
- [x] VERIFIED 2026-06-26: OTP/passwordless start is rate-limited by IP and
      identifier (`RLPasswordlessStart`: 6/hour + 1m cooldown). Confirm is
      rate-limited by IP and identifier (`RLPasswordlessConfirm`: 10/10m).
      Challenges expire after 10 minutes. Five bad typed-code attempts for the
      same identifier delete the challenge, so the original code no longer works.
- [x] Add safe `return_to` handling or explicitly return tokens only to the caller and let the host own navigation.
- [x] Add DB-backed tests for email OTP login, email magic-link login, SMS OTP login, SMS magic-link login, create-if-missing, existing-user resume, generated username collision, no password row, disabled feature, duplicate/expired token, invalid code attempt caps, and anti-enumeration responses.
- [x] Update README, `agents/api-endpoints.md`, and SEMVER notes with the new flow and host integration guidance.

## Validation

- [x] Real-server passwordless integration pass against a fresh migrated Postgres: `AUTHKIT_TEST_DATABASE_URL='postgres://admin:admin_password@127.0.0.1:35432/authkit_issue49_1782336194?sslmode=disable' go test ./http -run 'TestPasswordless' -count=1 -v`. This includes `TestPasswordlessRealHTTPServerEmailOTP`, which uses `httptest.NewServer(srv.APIHandler())` over actual HTTP plus the real DB.
- [ ] Full DB-backed `go test ./... -count=1` is blocked by unrelated existing permission-group/admin failures in `http` and `internal/authcore`; issue-49 focused DB-backed tests pass.

## Cross-repo

- OpenRails SaaS #19 will use this for customer wallet login/account creation at checkout while keeping merchant-app authentication separate.
