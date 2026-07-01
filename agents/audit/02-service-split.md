# Task 2: split internal/authcore/service.go

service.go is 4,924 lines. It holds the constructor, config validation, token
issuance, service accessors, phone change, password login, password reset, email
verification, phone verification, pending registration, and the sender wiring,
all in one file. We are breaking it into smaller files by topic.

## How we work (not "find problems")

Asking an LLM to "find problems" gives mostly false alarms. This is review-led
instead. For each area, before moving anything:

1. Read the functions in that area.
2. Ask what each one does and how it works.
3. Challenge the shape: is this the right shape, is it redundant, does it even
   need to exist?
4. Then extract the area into its own file, applying only the improvements the
   review actually justified.

## Non-breaking rule

A stage only moves methods between files inside the `internal/authcore` package
and tidies internals. It does NOT change the public surface: `authkit.Client`,
the exported `embedded` facade methods, or the HTTP routes. So every stage builds
and tests green, and pausing between any two stages is always safe.

Anything that would change the public surface (a constructor reshape like the
already-done NewServer(client) change) is its own explicitly-flagged stage, done
only when we can review it properly. Those wait for stage 4+.

## Stages

Today (non-breaking, safe to stop after any one):

- Stage 1: Links. The verification/reset/passwordless URL builders
  (`authkitURL`, `verificationURL`, `emailVerificationURL`,
  `phoneVerificationURL`, `emailPasswordResetURL`, `phonePasswordResetURL`,
  `passwordlessURL`) plus `VerificationMessage.Validate`. Move to `links.go`.
  Review: are all of these needed, are the thin wrappers worth keeping.

- Stage 2: Senders. Email/SMS sender wiring and the SMS health surface
  (`WithEmailSender`, `WithSMSSender`, `HasEmailSender`, `HasSMSSender`,
  `CheckSMSHealth`, `SMSHealthy`, `SMSHealthReason`, `SMSAvailable`,
  `*DeliveryError`, `ValidateVerificationConfiguration`, `PasskeysEnabled`).
  Move to `senders.go`. Review: the SMSHealthy/SMSHealthReason/SMSAvailable/
  CheckSMSHealth surface looks like four ways to ask one question.

- Stage 3: Passwords. Login, verify, and change
  (`PasswordLogin`, `PasswordLoginByUserID`, `VerifyUserPassword`,
  `CheckUserPassword`, `ChangePassword`, `SetPasswordAfterFreshAuth`,
  `errOrUnauthorized`). Move to `passwords.go`. Review: VerifyUserPassword vs
  CheckUserPassword, and the two login entry points.

Remaining stages. Each says what MOVES (relocate within the package, no
signature change) and what to REFACTOR/challenge (a behavior-preserving cleanup
the review justified). Same non-breaking rule until the last stage.

- Stage 4: Access-token issuance -> token_issue.go.
  MOVE: IssueAccessToken, issueAccessToken, Issue2FAEnrollmentToken.
  REFACTOR: is the public IssueAccessToken just a default-TTL wrapper over the
  private issueAccessToken; does Issue2FAEnrollmentToken need to be separate or
  is it issueAccessToken with a short TTL + one claim.

- Stage 5: Password reset -> password_reset.go.
  MOVE: RequestPasswordReset, BeginPasswordReset, ConfirmPasswordReset,
  ConfirmPasswordResetWithSession, finishPasswordReset, RequestPhonePasswordReset.
  REFACTOR: ConfirmPasswordReset vs ConfirmPasswordResetWithSession (is one a thin
  wrapper, like the login pair was).

- Stage 6: Email + phone verification -> verification.go.
  MOVE: RequestEmailVerification, sendEmailVerificationToUser,
  ConfirmEmailVerification(+ByToken), RequestPhoneVerification,
  SendPhoneVerificationToUser, ConfirmPhoneVerification(+UserID/+ByToken/
  +ByTokenUserID), GetUserByPhone, getUserByPhone, setPhoneVerified.
  REFACTOR: the four ConfirmPhoneVerification* variants look like a wrapper family
  to collapse; email and phone verify are near-symmetric.

- Stage 7: Pending registration -> fold into the existing registration.go.
  MOVE: CreatePendingRegistration(+WithLanguage), ConfirmPendingRegistration
  (+ByToken), CheckPendingRegistrationConflict and the phone equivalents, plus
  createEmail/PhoneRegistrationUser, createVerifiedRegistrationUser.
  REFACTOR: the non-WithLanguage funcs look like thin wrappers over the
  WithLanguage ones (dup); email vs phone pending-registration is near-symmetric.

- Stage 8: Account changes -> account_changes.go.
  MOVE: the email-change family (RequestEmailChange, ConfirmEmailChange(+ByToken),
  ResendEmailChangeCode, GetPendingEmailChange, CancelEmailChange) and the
  phone-change family (RequestPhoneChange, ConfirmPhoneChange(+ByToken),
  ResendPhoneChangeCode, CancelPhoneChange), SendPhone2FASetupCode,
  VerifyPhone2FASetupCode.
  REFACTOR: email-change and phone-change are near-identical request/confirm/
  resend/cancel state machines; biggest dup to challenge.

- Stage 9: User directory + lifecycle -> users.go.
  MOVE: getUserByEmail/Username/ID, ensureUserAccess(+ByID), autoUnbanIfExpired,
  isUserBanned, createUser, normalizeImportUserInput, ImportUser,
  UpdateImportedUser, setEmailVerified, setLastLogin, clearUserBan, BanUser,
  UnbanUser, SoftDeleteUser, RestoreUser, HostDeleteUser,
  updateUsername(+Force/Impl), updateEmail, updateBiography, the userFrom*Row
  mappers. REFACTOR: none expected, mostly a move.

- Stage 10: Small leftovers -> a few tiny files.
  MOVE: rand/hash helpers (randB64, randInt, randAlphanumeric, sha256Hex) ->
  rand.go; preferred-language (NormalizePreferredLanguage, Set/GetPreferredLanguage,
  context helpers) -> language.go; service accessors (JWKS, Options, Config,
  Postgres, Schema, dbSchema, qtx, Keyfunc, PublicKeysByKID, EntitlementsProvider,
  SetEntitlementsProvider, AdminSetPassword, isDevEnvironment) -> accessors.go;
  token storage (getPasswordHash, upsertPasswordHash, useEmailVerifyToken,
  useResetToken, createResetToken) -> token_store.go; root-role helpers
  (normalizeRootRoleSlug, splitConfiguredRootRoles, rootRoleSlugsByUser) ->
  roles.go.

- Stage 11 (may be breaking): the constructor.
  MOVE: NewService, NewFromConfig, the normalize* validators, isWellFormattedURL,
  validAPIKeyPrefix, the Options.* policy methods -> constructor.go.
  REFACTOR/CHALLENGE: this is the real audit of construction (the NewServer fix
  lived here). Done on its own, with full review, because it is the most likely to
  touch the public surface.

Added after stage 11 (the original plan ended at the constructor, but service.go
still held three large topic clusters it never enumerated). Same non-breaking,
review-led method: read the cluster, challenge its shape, then extract.

- Stage 12: Admin user directory -> admin_users.go.
  MOVE: the AdminUser/AdminListUsersResult/AdminUserStatus/AdminUserSort/
  AdminUserListOptions aliases + their consts, normalizeAdminUserListOptions,
  adminUserDirectoryQuery, adminUserOrderBy, AdminCountUsers, AdminListUsers,
  enrichEntitlements, AdminGetUser, AdminRecoverUserInput, AdminRecoverUser,
  AdminDeleteUser.
  REFACTOR/CHALLENGE: adminUserDirectoryQuery builds raw SQL from the list options;
  re-check the filter/sort whitelisting is airtight (injection surface), and whether
  AdminCountUsers and AdminListUsers share enough of that query construction to pull
  a common builder. enrichEntitlements vs the batch provider: is the per-call path
  still needed.

- Stage 13: Provider links -> providers.go.
  MOVE: the exported GetProviderLink, LinkProvider, SetProviderUsername,
  GetProviderUsername, GetDiscordUsername, GetProviderLinkByIssuer,
  LinkProviderByIssuer, UnlinkProvider, UnlinkProviderUnlessLast, CountProviderLinks,
  UserProfileLinks and their unexported impls (getProviderLinkByIssuerInternal,
  getProviderLinkBySlug, linkProvider, setProviderUsername, getProviderUsername,
  unlinkProvider, countProviderLinks), plus deriveUsername/DeriveUsername. Pull the
  provider wrappers and deriveUsername that stage 10 deliberately left in service.go
  for exactly this stage.
  REFACTOR/CHALLENGE: the exported/unexported pairs are thin pass-throughs (same
  pattern as the role wrappers); confirm each unexported impl has a real second
  caller, otherwise collapse. GetDiscordUsername is a provider-specific special-case
  over GetProviderUsername; check it earns its own method.

- Stage 14: Two-factor -> twofactor.go (joining the existing totp.go).
  MOVE: the 2FA settings/factor types (TwoFactorSettings, TwoFactorFactor,
  twoFactorFactorFromFields), Enable2FA(+Default/+impl), Disable2FA(+Factor/
  +WithRemovedRoles variants), SetDefault2FAFactor, Get2FASettings, List2FAFactors,
  the Require2FAForLogin/StepUp family, Verify2FA* family, Create/Verify/Clear2FA-
  Challenge, VerifyBackupCode, RegenerateBackupCodes, send2FACodeForFactor,
  verifyTOTPFactorCode, twoFactorFactor(+ByMethod), generateBackupCodes.
  REFACTOR/CHALLENGE: the biggest cluster and the most wrapper-dense. The
  Require2FAForLogin/StepUp/StepUpFactor/StepUpMethod and Verify2FAStepUpCode/
  FactorCode/MethodCode families look like wrapper fans over one factor-resolve +
  one send/verify core; challenge whether the by-default / by-factor / by-method
  entry points can share a resolver instead of each re-deriving the factor. Confirm
  which public variants actually have callers before keeping all of them.

After 14, service.go should be ~300 lines: the Service struct, the Options/Keyset/
EntitlementsProvider type decls, the package error catalog, and the few generic
helpers (requirePG, dedupeStrings). That is the natural floor; the constructor and
every topic now live in their own file.

## Progress

- Stage 14 (done): moved the two-factor machine to twofactor.go (joining totp.go):
  the TwoFactorSettings/TwoFactorFactor types, Enable2FA(+Default/+enable2FA),
  Disable2FA(+Factor and both WithRemovedRoles variants), SetDefault2FAFactor,
  Get2FASettings, List2FAFactors, Require2FAForLogin(+Factor), send2FACodeForFactor,
  Require2FAForStepUp(+Factor/+Method), Verify2FAStepUp(Code/FactorCode/MethodCode),
  Create/Verify/Clear2FAChallenge, Verify2FACode(+FactorCode), verifyTOTPFactorCode,
  VerifyBackupCode, RegenerateBackupCodes, twoFactorFactor(+ByMethod),
  twoFactorFactorFromFields, generateBackupCodes.
  Review of the planned "wrapper-fan" families produced two behavior-preserving
  dedups, both verbatim duplication:
  * RegenerateBackupCodes re-inlined the exact 10-code generate loop that
    generateBackupCodes already is (and that Enable2FA already calls). Replaced the
    inline loop with generateBackupCodes(). Pure function, identical result.
  * Verify2FAStepUpFactorCode and Verify2FAStepUpMethodCode were identical except
    the one factor-resolve line (by id vs by method): same session guard, same TOTP
    branch, same ephemeral guard, same consumeMFAStepUpCode. Extracted the shared
    tail into verifyStepUpForFactor(ctx, userID, sessionID, code, factor). Each caller
    still guards the session and resolves its own factor, then calls the shared tail.
  Challenged and deliberately kept: the thin one-line public wrappers
  (Require2FAForLogin/StepUp, Verify2FACode/StepUpCode) are real overloads with
  different return arities on the Client surface, not dead; twoFactorFactorByMethod
  already delegates to twoFactorFactor for the empty-method case; the Require-step-up
  pair's post-resolve tail is two lines, below the bar for a helper. No public method
  removed. service.go 1114 -> 462. gofmt/build/vet clean; authcore + http tests pass,
  only the pre-existing TOTP test fails.
  This finishes the split. service.go (462) now holds only the package's core
  surface: the Options/Keyset/entitlement-provider type decls, the error catalog, the
  Service struct, the session-event audit-log methods, hasPassword/ListEntitlements,
  the pending-registration peek helpers, and requirePG/dedupeStrings. The session-log
  and pending-peek blocks were never enumerated as stages; they could be their own
  files later, but that is optional tidy, not part of this plan.
- Stage 13 (done): moved the provider-link cluster to providers.go. Exported
  wrappers (GetProviderLink, LinkProvider, SetProviderUsername, GetProviderUsername,
  GetDiscordUsername, DeriveUsername, CountProviderLinks, UnlinkProvider,
  UnlinkProviderUnlessLast, GetProviderLinkByIssuer, LinkProviderByIssuer,
  UserProfileLinks) + their unexported impls (countProviderLinks, unlinkProvider,
  getProviderLinkByIssuerInternal, getProviderLinkBySlug, linkProvider,
  setProviderUsername, getProviderUsername) + the deriveUsername free func. Pure
  move, no signature changes; the public surface is untouched (facade/remote/server
  re-export LinkProvider/GetProviderUsername/UnlinkProvider/LinkProviderByIssuer, and
  http handlers call the rest). Left in service.go ON PURPOSE because they were only
  physically interleaved in the old provider block, not provider-link code:
  hasPassword/HasPassword (password-domain; live callers in passwords.go + http) and
  ListEntitlements (entitlements).
  Review of the planned challenges ("confirm each unexported impl has a real second
  caller; does GetDiscordUsername earn its own method"): every moved unexported impl
  still has a live caller, so none were collapsed. THREE exported methods are DEAD
  (zero callers repo-wide — verified across authkit, h0, openrails; none are in the
  client.go Providers interface): GetDiscordUsername (a one-liner over
  getProviderUsername(...,"discord")), DeriveUsername (superseded by
  DeriveUsernameForOAuth), and GetProviderLink. DELETED all three plus their
  now-orphaned sole-caller impls getProviderLinkBySlug and deriveUsername (the
  latter freed the strings import too). getProviderUsername stays (still used by
  GetProviderUsername); the usernameMinLen/MaxLen consts stay (still used by
  identity_validation.go + username.go).
  Separately, removed one UNRELATED pre-existing dead field to restore green
  staticcheck: http/service.go groupCanFn — an unwired test hook (groupCan never
  reads it, no test sets it), dead since eaae65b/#111 and failing U1000 at HEAD
  independent of this stage.
  service.go 1357 -> 1114; providers.go 207. gofmt/build/vet/staticcheck ./... all
  clean; http tests pass, authcore tests pass except the pre-existing TOTP env test
  (TestResolveTOTPSecretKey).
- Stage 12 (done): moved the admin user directory to admin_users.go: the
  AdminUser/AdminListUsersResult/AdminUserStatus/AdminUserSort/AdminUserListOptions
  aliases + their status/sort const blocks, ErrEntitlementFilterUnavailable,
  normalizeAdminUserListOptions, adminUserDirectoryQuery, adminUserOrderBy,
  AdminCountUsers, AdminListUsers, enrichEntitlements, AdminGetUser,
  AdminRecoverUserInput, AdminRecoverUser, AdminDeleteUser.
  Review of the planned injection surface: airtight. adminUserDirectoryQuery
  parameterizes every user-supplied value as a $N bind (role slug, search term,
  entitlement subject set); the list query binds OFFSET/LIMIT the same way; only
  static SQL fragments and the integer argIdx are ever concatenated. adminUserOrderBy
  picks the column from a closed enum (default u.created_at) and direction from a
  bool, so no user string reaches ORDER BY.
  Refactor applied (justified dedup): the count query
  `SELECT COUNT(DISTINCT u.id) FROM <from> WHERE <where>` + its RewriteSQL/QueryRow/
  Scan was byte-identical in AdminCountUsers and AdminListUsers. Extracted
  s.adminUserCount(ctx, from, where, args) as the single definition. AdminListUsers
  still calls adminUserDirectoryQuery ITSELF (not AdminCountUsers) so the entitlement
  filter provider is hit once per call, as its doc-comment promises; only the count
  execution is shared. Behavior identical.
  enrichEntitlements' per-user loop was challenged (the plan's "is the per-call path
  still needed") and kept: it is the fallback for providers that don't implement
  BatchEntitlementsProvider, not dead. service.go 1729 -> 1357. gofmt/build/vet
  clean; authcore + http tests pass, only the pre-existing TOTP test fails.
- Stage 11 (done): moved construction + Options/Config validation to constructor.go:
  NewService, NewFromConfig, validAPIKeyPrefix, normalizeRegistrationVerification,
  normalizeRegistrationMode, normalizeFrontendPath, the four Options registration-
  policy reads (RegistrationVerificationPolicy/Required/Enabled,
  PublicNativeUserRegistrationEnabled), isWellFormattedURL, and the default-path
  const block (defaultOIDCReturnPath etc., construction-only). The Service struct,
  Options/Keyset/EntitlementsProvider type decls, and the package error catalog
  stay in service.go as the package's core type surface.
  Review of construction (the planned "real audit") produced three behavior-
  preserving cleanups, all justified:
  * Both constructors duplicated the schema trim/default/ValidSchemaName guard, and
    NewFromConfig validated the schema then NewService validated it a second time.
    Extracted normalizeSchemaName(raw) (string, error) so the SQL-injection guard
    has ONE source; NewService panics on its error (the Options path, as before),
    NewFromConfig returns it. Panic message text unchanged (test only asserts that
    it panics, TestNewServicePanicsOnInvalidSchema).
  * NewFromConfig computed normalizeTwoFactorMode(cfg.TwoFactor.Mode) twice in the
    same Options literal (TwoFactorMode and RequireMFAEnrollment). Computed once
    into a local.
  * normalizeOIDCReturnPath was a single-use wrapper over normalizeFrontendPath and
    the only one of the five frontend-path normalizations with a wrapper. Inlined it
    so all five go through normalizeFrontendPath identically; deleted the wrapper.
  Public surface UNCHANGED despite this stage being allowed to touch it: NewService
  and NewFromConfig keep their signatures; no Client/facade/route change. service.go
  2053 -> 1731. gofmt/build/vet clean; authcore + http tests pass, only the
  pre-existing TOTP test fails.
  Not done (out of original plan scope, flagged for a decision): the plan enumerated
  stages through "the constructor" as the last, but service.go (1731) still holds
  three sizable topic clusters it never listed as stages: the admin user directory
  (normalizeAdminUserListOptions, adminUserDirectoryQuery, adminUserOrderBy,
  AdminCountUsers, AdminListUsers, enrichEntitlements, AdminGetUser, AdminRecoverUser,
  AdminDeleteUser, ~370 lines), the provider-link methods (~400 lines), and the whole
  2FA machine (Enable/Disable/StepUp/Challenge/backup-codes, ~650 lines). Finishing
  the god-file split cleanly wants stages 12-14 for those; left as a call to make.
- Stage 10 (done): moved the small leftovers into topic files. rand/hash helpers
  (randB64, randInt, randAlphanumeric, sha256Hex, randAlphanumericUppercase) ->
  rand.go; preferred-language (NormalizePreferredLanguage, Set/GetPreferredLanguage,
  the context helpers, the PreferredLanguage alias) -> language.go; service accessors
  (JWKS, AdminSetPassword, EntitlementsProvider, Options, Config, PublicKeysByKID,
  isDevEnvironment method + free func, Postgres, Schema, dbSchema, qtx,
  SetEntitlementsProvider, Keyfunc) -> accessors.go; password-hash + short-lived
  token storage (getPasswordHash, upsertPasswordHash + the UpsertPasswordHash wrapper,
  useEmailVerifyToken, useResetToken, createResetToken, emailVerifyToken type) ->
  token_store.go; the root-role cluster -> roles.go; the verificationSendTimeout/
  withSendTimeout pair -> senders.go (next to the send code it guards). Also moved
  SendPhone2FASetupCode/VerifyPhone2FASetupCode to totp.go (flagged in stage 8: they
  are 2FA setup, not contact changes).
  Re-review (the "you missed some things" pass) caught and fixed:
  * roles.go was half-done. The first cut moved only normalizeRootRoleSlug,
    splitConfiguredRootRoles, rootRoleSlugsByUser. The rest of the cluster was still
    in service.go after line 902: listRoleSlugsByUser, assignRoleBySlug,
    upsertRoleBySlug, removeRoleBySlug, the four exported wrappers (AssignRoleBySlug,
    UpsertRoleBySlug, RemoveRoleBySlug, ListRoleSlugsByUser), and the
    ErrUserRoleNotFound/ErrCannotRemoveLastAdminRole vars. All now in roles.go.
  * upsertRoleBySlug was genuinely redundant, not just misplaced: it computed `role`
    twice with the identical strings.ToLower(strings.TrimSpace(slug)) op (the second
    via normalizeRootRoleSlug), and carried two dead `_ = name`/`_ = description`
    lines (unused func params compile fine in Go). Cleaned, behavior identical.
  * Stage 9 had stranded public wrappers in service.go while their impls were in
    users.go: UpdateUsername, UpdateEmail, UpdateBiography, IsUserAllowed,
    GetUserByEmail, GetUserByUsername, CreateUser, SetEmailVerified. The tell was
    UpdateUsernameForce already sitting in users.go without its siblings. Moved all
    eight next to their impls.
  Deliberately left (decisions, not misses): the provider wrappers (LinkProvider,
  SetProviderUsername, GetProviderUsername, GetDiscordUsername, GetProviderLink) and
  deriveUsername/DeriveUsername stay because their impls are still in service.go; they
  belong to a future provider/username extraction. generateBackupCodes stays (2FA, not
  generic rand); dedupeStrings/requirePG stay as generic service helpers.
  service.go 2627 -> 2053. gofmt/build/vet clean; authcore + http + remote tests pass,
  only the pre-existing TOTP test fails.
- Stage 9 (done): moved user directory + lifecycle to users.go: the 4 userFrom*Row
  mappers, getUserByEmail/Username/ID, ensureUserAccess(+ByID), autoUnbanIfExpired,
  isUserBanned, createUser, normalizeImportUserInput, ImportUser, UpdateImportedUser,
  setEmailVerified, setLastLogin, clearUserBan, BanUser, UnbanUser, SoftDeleteUser,
  RestoreUser, HostDeleteUser, updateUsername(+Force/Impl), updateEmail,
  updateBiography, plus the User/ImportUserInput type aliases that sat right above
  the block. Review: no dup found (updateUsername/UpdateUsernameForce already
  correctly delegate to updateUsernameImpl(bypassCooldown), same pattern as the
  login dedup). Confirmed HardDeleteUser (the public Client method, in
  user_purge.go) is unrelated to HostDeleteUser (this file's internal soft/hard
  dispatcher) - a naming near-collision worth a rename later but out of scope here.
  Faithful move. service.go 3048 -> 2627. Build, vet, http tests green; only the
  pre-existing TOTP test fails.
- Bug fix (done, follow-up to 8b): ConfirmEmailChange was missing the
  `!useEphemeralStore()` guard that ConfirmPhoneChange and the cancel/get
  siblings have. Pending changes live only in the ephemeral store, so email
  confirm was relying on the loader to no-op instead of failing closed itself.
  Added the one-line guard + a regression test
  (TestConfirmContactChange_RequiresEphemeralStore) asserting both confirms
  return ErrTokenUnverifiable when no ephemeral store is configured.
- Stage 8b (done): deduped the email/phone contact-change families in
  account_changes.go. Extracted two byte-identical-across-channel helpers:
  newPendingContactChange (code+link-token generation + store, was copy-pasted in
  all 4 Request/Resend funcs) and sendContactChangeVerification (the send-or-
  unavailable tail, also 4x). The 4 Request/Resend funcs now share them.
  account_changes.go 375 -> 321. Build, vet, http tests green (those cover the
  email/phone change flows); only the pre-existing TOTP test fails.
  Deliberately NOT done, flagged instead: the Confirm funcs were left separate
  because ConfirmPhoneChange has an extra `!useEphemeralStore()` guard that
  ConfirmEmailChange lacks; collapsing them would silently change email-confirm
  behavior, so that inconsistency should be resolved as its own decision. The
  unused `phone` params on CancelPhoneChange and ResendPhoneChangeCode are
  signature changes (breaking), also left.
- Stage 8 (done): moved the email-change family (RequestEmailChange,
  ConfirmEmailChange, ConfirmEmailChangeByToken, ResendEmailChangeCode,
  GetPendingEmailChange, CancelEmailChange) and the phone-change family
  (RequestPhoneChange, ConfirmPhoneChange, ConfirmPhoneChangeByToken,
  ResendPhoneChangeCode, CancelPhoneChange) to account_changes.go. Faithful move,
  build + vet + http tests green; only the pre-existing TOTP test fails.
  service.go 3405 -> 3048.
  Review findings (NOT acted on here, on purpose):
  * The email and phone families are near-identical request/confirm/resend/cancel
    state machines on the same unified pending-change store. The dup is real but
    STRUCTURAL not verbatim (email vs SMS sender signatures differ, plus URL
    builder/error wrapper/TTL/kind/old-email-notification). A clean dedup needs a
    contact-channel abstraction, so it gets its own reviewed commit (stage 8b),
    not bundled into a move of security-sensitive code.
  * CancelPhoneChange takes a `phone` param it never uses (CancelEmailChange does
    not); a signature change is breaking, so left for the same follow-up.
  * SendPhone2FASetupCode / VerifyPhone2FASetupCode were left in service.go: they
    are 2FA setup, not contact changes, and belong with the 2FA files.
- Stage 7 (done): folded pending-registration into the existing registration.go.
  Moved 11 LIVE funcs: CreatePendingRegistrationWithLanguage, ConfirmPendingRegistration,
  ConfirmPendingRegistrationByToken, CheckPendingRegistrationConflict,
  CreatePendingPhoneRegistrationWithLanguage, ConfirmPendingPhoneRegistration,
  ConfirmPendingPhoneRegistrationByToken, CheckPhoneRegistrationConflict (the phone
  equivalent of the conflict check; it is named CheckPhoneRegistrationConflict, NOT
  CheckPendingPhoneRegistrationConflict — that name does not exist), plus the internal
  createVerifiedRegistrationUser, createEmailRegistrationUser, createPhoneRegistrationUser.
  Refactor outcome (the planned "non-WithLanguage funcs look like thin wrappers"):
  CreatePendingRegistration and CreatePendingPhoneRegistration are production-DEAD
  one-line delegations (zero non-test callers; every production path calls the
  *WithLanguage variant directly, verified by a non-test grep). Per decision, DELETED
  both wrappers and rewrote all 24 test call sites (across 9 files: ephemeral_test,
  policy_switches_test, account_registration_invites_test, phone_verify_cap_test,
  registration_optional_no_sender_test, email_verify_scope_test, pending_change_cancel_test,
  pending_abandon_test, verification_tokens_test, http/register_response_test) to call
  *WithLanguage(..., "") — behavior-identical by construction (that was the wrapper body).
  ConfirmPending* code vs byToken are distinct live entry points (kept, like the verify
  split); email vs phone are parallel but not mergeable (different policy gates + token
  stores), kept. Imports added to registration.go: context, fmt, strings, time, jwt, db
  (kept authkit); none orphaned in service.go. service.go 3854 -> 3416; registration.go
  23 -> 460. gofmt/build/vet clean; authcore 138 pass / 1 pre-existing TOTP fail / 76
  DB-gated skips; http tests pass.
- Stage 6 (done): moved the 11 LIVE email+phone verification funcs to
  verification.go: getUserByPhone, setPhoneVerified, RequestEmailVerification,
  sendEmailVerificationToUser, ConfirmEmailVerification, ConfirmEmailVerificationByToken,
  GetUserByPhone, RequestPhoneVerification, SendPhoneVerificationToUser,
  ConfirmPhoneVerificationUserID, ConfirmPhoneVerificationByTokenUserID. The
  planned refactor ("the four ConfirmPhoneVerification* variants look like a
  wrapper family to collapse") resolved the same way as stage 5: the two
  error-only wrappers ConfirmPhoneVerification and ConfirmPhoneVerificationByToken
  are DEAD (zero callers — the HTTP handlers call the *UserID variants directly).
  Per decision, deleted both wrappers (self-contained, no helper/test cascade).
  email vs phone confirm are NOT collapsible: email does a non-consuming peek +
  address re-scope + getUserByID; phone consumes atomically then writes — left
  as-is; deleting the wrappers already improves symmetry (both channels now
  expose only (userID, error)). Noted but untouched: getUserByPhone (unexported,
  full row) and GetUserByPhone (exported, nils ban fields, on the facade/Client)
  are near-duplicates but both live and the exported one is public API, so
  collapsing would change behavior/surface. Imports for verification.go:
  context, errors, fmt, strings, time, jwt, pgx, db; none orphaned in service.go.
  service.go 4154 -> 3854. Build, vet, http tests pass; only the pre-existing
  TOTP test fails.
- Stage 5 (done): moved the LIVE password-reset funcs (RequestPasswordReset,
  ConfirmPasswordReset, finishPasswordReset, RequestPhonePasswordReset) to
  password_reset.go. The planned refactor question ("ConfirmPasswordReset vs
  ConfirmPasswordResetWithSession — is one a thin wrapper, like the login pair")
  resolved differently than expected: the browser-session-handoff pair
  (BeginPasswordReset + ConfirmPasswordResetWithSession) is DEAD CODE, not a
  wrapper. Zero live callers — no HTTP route, not in the embedded facade, not on
  authkit.Client, only a doc-comment mention in a test. The shared tail was
  already extracted into finishPasswordReset, so the live ConfirmPasswordReset
  wraps nothing. Per decision to delete the full dead chain, removed:
  BeginPasswordReset + ConfirmPasswordResetWithSession (service.go); their only
  helpers storePasswordResetSession/consumePasswordResetSession plus the
  now-orphaned passwordResetSessionData type and keyPasswordResetSession const
  (ephemeral_data.go); and the unit test TestPasswordResetSessionOneTimeConsume
  (verification_tokens_test.go). Fixed a stale doc-comment ref in
  password_reset_required_test.go. service.go 4306 -> 4154. Build, vet, http
  tests pass; only the pre-existing TOTP test fails.
- Stage 4 (done): moved access-token issuance (IssueAccessToken,
  Issue2FAEnrollmentToken, issueAccessToken, reservedAccessTokenClaims) to
  token_issue.go. Review: the two public funcs are clean named wrappers over the
  private issueAccessToken (default TTL; 10-min + 2fa_enrollment claim), not
  redundancy, so pure move, no refactor. service.go 4446 -> 4306. Build, vet,
  http tests pass; only the pre-existing TOTP test fails.
- Stage 3 (done): moved the password block (PasswordLogin, PasswordLoginByUserID,
  VerifyUserPassword, CheckUserPassword, ChangePassword, SetPasswordAfterFreshAuth,
  errOrUnauthorized) to passwords.go. Review finding and fix: PasswordLogin and
  PasswordLoginByUserID duplicated ~30 lines of verify/rehash/issue logic that
  differed only in how they fetch the user; extracted a shared loginVerifiedUser
  helper (behavior-preserving, login tests pass). VerifyUserPassword vs
  CheckUserPassword are not redundant: bool form vs error form for reset-routing.
  service.go 4696 -> 4446. Build, vet, http tests pass; only the pre-existing TOTP
  test fails.
- Stage 2 (done): moved the senders block (VerificationMessage + Validate,
  EmailSender/SMSSender/SMSHealthChecker, the With/Has wiring, CheckSMSHealth and
  the SMS-health surface, delivery-error helpers, ValidateVerificationConfiguration)
  to senders.go. Also moved PasskeysEnabled to passkeys.go: it was mis-filed in
  the senders block but is a passkey capability, not a sender.
  Review finding: the SMS-health surface (CheckSMSHealth/SMSHealthy/
  SMSHealthReason/SMSAvailable) looked redundant but is not. They are distinct
  (run probe / read cached bool / read cached reason / composite gate), and
  SMSHealthy+SMSHealthReason are exposed through authhttp.Service, so they stay.
  I tried removing them as "dead" and the build caught it immediately. authcore
  builds and vets clean.
  Note (pre-existing, not from this change): the repo does not build whole because
  the last merge left adapters/clickhouse and http/server.go referencing dropped
  symbols (AuthEventLogger/WithAuthLogger, #143). TestResolveTOTPSecretKey also
  still fails. Both predate this stage.
- Stage 1 (done): moved the 7 URL builders (authkitURL, verificationURL, and the
  email/phone verify+reset wrappers, passwordlessURL) to links.go. Reviewed
  first: every thin wrapper is actually used (no dead code), so they stayed.
  Finding: VerificationMessage.Validate is the sender payload, not a link, so it
  moves with senders in stage 2. service.go 4924 -> 4867. Build + vet green.
  Note: TestResolveTOTPSecretKey fails, but it is pre-existing from the pull
  (new totp_key.go), unrelated to this move.
