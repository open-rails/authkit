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

- Stage 11 (LAST, may be breaking): the constructor.
  MOVE: NewService, NewFromConfig, the normalize* validators, isWellFormattedURL,
  validAPIKeyPrefix, the Options.* policy methods -> constructor.go.
  REFACTOR/CHALLENGE: this is the real audit of construction (the NewServer fix
  lived here). Done last, on its own, with full review, because it is the most
  likely to touch the public surface.

## Progress

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
