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
- [ ] Make `InviteOnly` real with first-class account-registration invites.
      A user can be invited to create an account without being invited to any
      permission group.
- [ ] Add a built-in root permission for standalone account-registration invites,
      `root:users:invite`. The root `owner` role gets it via `root:*`; hosts may
      add it to bounded operator roles when they want non-owner staff to invite
      new accounts.
- [ ] Keep account-registration invites and permission-group invites separate.
      A permission-group invite may also carry/attach a registration credential
      only when the recipient has no account and registration mode is
      `InviteOnly`.
- [ ] Authorize permission-group invites with that group's existing
      `<persona>:members:manage` no-escalation checks. A group owner/manager may
      attach a registration credential only for that group invite; this does not
      grant general `root:users:invite` authority.
- [ ] Registration invites must be high-entropy, time-bound URL tokens, not short
      OTP-style codes. Email-bound registration invites authorize account creation
      only for that email.
- [ ] Permission-group invite acceptance stays separate from account creation.
      If a group invite helped an unknown recipient register, the user still must
      manually accept/redeem the group invite before AuthKit adds the membership.
- [ ] Preserve the existing email-bound redemption rule in the onboarding flow:
      invite email must equal the redeemer account's verified email.
- [ ] Make the invite API/docs name invite kinds clearly: account-registration
      invite, permission-group shareable link, and permission-group email-bound
      invite.
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
      unexpired email-bound account-registration invite exists for the registering
      email.
- [ ] Update passwordless/OIDC/Solana auto-registration paths to honor the same
      invite-aware rule under `InviteOnly`.
- [ ] Update `internal/authcore/group_invite_links.go` defaults so both shareable
      and email-bound invite links are time-bound for a few days; keep explicit
      per-invite expiry overrides.
- [ ] Add the account-registration invite contract separately from group invites,
      including creation, email delivery, validation during registration, expiry,
      revocation, and consumption semantics.
- [ ] Update `CreateGroupInviteLink` / `CreateGroupInviteLinkRequest` /
      `GroupInviteLinkCreated` contract docs to name the two permission-group
      kinds: no-email shareable link vs email-bound invite.
- [ ] Update `http/permission_group_operations.go` add-member flow: existing
      `user_id` adds directly and silently; email with no account creates/sends an
      email-bound group invite instead of failing or auto-adding. If registration
      is not public, also create/attach an email-bound account-registration invite.
- [ ] Add invite-specific rate limits around invite creation/email sending,
      preferably keyed by actor user, target email, and group; return a stable
      rate-limit error instead of sending more mail.
- [ ] Add/adjust HTTP route support so an unauthenticated invite recipient can land
      on an account-registration invite or permission-group invite, register or
      log in, then manually redeem/accept any group invite. Do not auto-redeem a
      group invite after account creation.
- [ ] Add integration tests for: existing user direct add no notification; unknown
      email creates group invite; standalone account-registration invite works
      under `InviteOnly`; group invite for unknown email can authorize registration
      only through an attached account-registration invite; wrong verified email
      cannot register/redeem; manual group accept required; expired/revoked/
      exhausted invites rejected; shareable group link still obeys expiry/max-use
      but does not unlock invite-only registration by itself.
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
- [x] DECISION: delete public `authhttp.WithErrorLogger`. For swallowed internal
      handler failures, AuthKit should use Go's standard `slog.Default()` so the
      host controls output globally (`slog.SetDefault(...)`) and infrastructure
      captures stdout/stderr as usual.
- [x] DECISION: delete public `authhttp.WithPermissionGroupAuthorizer`. Generated
      permission-group routes should authorize through the embedded client/engine
      (`Can`) directly. The current override is useful for tests and unusual lazy
      materialization only; keep any seam internal/test-only.
- [x] DECISION: delete public `authhttp.WithSolanaDomain`. SIWS challenge domain
      should be derived from AuthKit config (`Frontend.BaseURL` / issuer host) and
      request fallback, not a separate server constructor option.
- [ ] Remove `WithPermissionGroupAuthorizer` and `WithSolanaDomain` from first-run
      docs and public API inventory.
- [ ] Delete `PermissionGroupAuthorizer`, `WithPermissionGroupAuthorizer`, and the
      `groupCanFn` field from public HTTP server code. Update tests to exercise
      the real `Can` path or use package-internal helpers instead of a public
      option seam.
- [ ] Delete `WithErrorLogger`, `InternalErrorEvent` as a public callback contract,
      and the server `errorLogger` field. Route swallowed internal handler errors
      to `slog.Default()` with structured attributes instead.
- [x] DECISION: route groups should be coarse host-mounted surfaces, not the main
      feature-toggle system. Hosts should turn features on/off in config
      (`Registration`, passkeys, passwordless, persona capabilities), and disabled
      features should not expose usable routes. Route-group mounting is for where
      a host places whole surfaces in its router.
- [ ] Rework/rename route groups around host decisions:
      `Auth` (login/token/logout/password reset/passwordless), `Registration`
      (account creation only), `Verification` if email/phone verification remains
      useful without registration, `Account` (current user/profile/MFA/passkeys),
      `Admin`, and `PermissionGroups`. Keep OIDC browser redirects and JWKS as
      separately mounted special cases.
- [ ] Replace current route constants with the new public route groups:
      `RouteAuth`, `RouteRegistration`, `RouteVerification`, `RouteAccount`,
      `RouteAdmin`, and `RoutePermissionGroups`. Delete `RoutePublic`,
      `RouteSession`, `RouteUser`, and `RoutePasskeys` from the host-facing API.
- [ ] Route mapping:
      `RouteAuth` gets `/identity-providers`, `/token`, `/sessions/current`,
      `/logout`, `/password/login`, password reset routes, passwordless routes,
      `/2fa/challenge`, `/2fa/verify`, Solana login/challenge, and passkey login
      begin/finish. `RouteRegistration` gets `/register`, `/register/availability`,
      `/register/resend-*`, and `/register/abandon`. `RouteVerification` gets
      `/email/verify/*` and `/phone/verify/*`. `RouteAccount` gets `/me`,
      `/user/*`, provider unlink/link/step-up routes, Solana link, 2FA enrollment
      and backup-code routes, and passkey register/list/update/delete routes.
      `RouteAdmin` remains admin user/operator routes. `RoutePermissionGroups`
      remains generated persona-group management plus group invite redemption.
- [x] INVESTIGATION: Doujins is the root-only case. It declares no non-root
      personas (`RBAC.Groups` is only `permission.RootGroupType()`), regular users
      belong to no group, and product admin role grants are app-owned
      (`POST /admin/roles/grant|revoke`) because Doujins needs entitlement side
      effects and product-specific response shapes. It still needs effective
      permission visibility for the SPA/admin nav and backend checks.
- [ ] Split permission visibility from permission-group management. Move
      `GET /me/permissions` to `RouteAccount` because apps without public group
      management still need it for UI gating. Keep the response rooted in the
      current principal and default to singleton `root`; if scoped permission
      checks are needed, prefer explicit scoped endpoints later over stuffing the
      full group-management surface into every app.
- [ ] Make `GET /me/groups` config-aware. It belongs in `RouteAccount` only when
      the deployment declares at least one non-root persona or otherwise enables
      user-visible memberships. Root-only apps like Doujins should not have to
      expose group discovery just to show admin permissions.
- [ ] Keep `POST /invites/redeem` under `RoutePermissionGroups` and mount it only
      when invite-link support is enabled for at least one persona. If invite-only
      account registration needs a public invite check/start route, that belongs
      to `RouteRegistration`, not the group-management route group.
- [ ] Make root management routes opt-in. `IntrinsicRootPersona(...)` should not
      automatically set `MemberAssignment: true`; hosts that want public root
      member/role management must explicitly enable it in root persona
      capabilities. The concrete client/core methods remain available for seed
      jobs, migrations, and app-owned admin routes.
- [ ] Stop generating role-catalog routes when every management capability is off.
      Today `GeneratedRoutes()` always emits `GET /<persona>/:instance_slug/roles`;
      that should be tied to custom role / member-management visibility rather
      than leaking a group-management endpoint into root-only deployments.
- [ ] Stop treating auth methods as primary route groups where config is better.
      Passkey login belongs to `RouteAuth`; passkey management belongs to
      `RouteAccount`; passkey availability should come from `PasskeyConfig`.
      Passwordless routes belong to `RouteAuth`, but are exposed/usable only when
      passwordless login is enabled. Registration routes belong to
      `RouteRegistration`, but are exposed/usable only when registration mode is
      not `Closed`; invite-only registration requires a valid invite token.
- [ ] Make route generation config-aware before mounting: disabled registration,
      passwordless, passkeys, 2FA methods, OIDC providers, Solana/SIWS, and persona
      capabilities should remove or fail-closed their routes by config. Hosts should
      not rely on omitting a route group as the security control.
- [x] DECISION: add one public, non-user auth capability/discovery endpoint instead
      of making frontends infer feature availability from mounted routes. Do not
      add a separate `/auth/availability`; service-level registration/login
      availability belongs in this one response.
- [ ] Replace/augment `GET /identity-providers` with `GET /auth/capabilities`
      under `RouteAuth`. Keep provider summaries there and include only
      non-sensitive booleans/enums. Do not expose secrets, internal sender health,
      or admin-only config.
- [ ] Define the `GET /auth/capabilities` response contract in root `authkit`
      types so embedded and remote/non-Go clients see the same shape. Include:
      registration mode plus invite-token requirement; enabled provider summaries;
      password login availability; passwordless enabled/channels/modes; passkey
      login availability; Solana/SIWS login availability; public verification
      requirements; and supported UI languages if language config remains mounted.
- [ ] Keep `GET /register/availability` separate and narrowly named for identifier
      checks (`username`, `email`, `phone_number`). It answers "is this value
      available?", not "which auth flows does this service support?".
- [ ] Keep `GET /identity-providers` only as a compatibility alias if needed during
      implementation, but do not make it the primary frontend discovery endpoint
      in new docs.
- [ ] Keep authenticated account-specific capability details on account endpoints:
      `/me` and `/user/2fa` should report user-specific MFA state, enrolled
      factors, allowed 2FA methods from config, backup-code status, linked
      providers, and available step-up methods.
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
