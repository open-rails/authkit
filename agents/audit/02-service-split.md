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

Tomorrow (stage 4+):

- Registration and pending-registration flows.
- Email and phone verification flows.
- The constructor area in authcore (NewService / NewFromConfig). The
  NewServer(client) shape fix is already done; this is auditing what's left here.
  Highest value and most likely to be breaking, so it gets its own careful stage.

## Progress

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
