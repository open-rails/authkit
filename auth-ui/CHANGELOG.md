# Changelog

## Unreleased

Speaks AuthKit's v1 routes (#407); breaking for every host.

- One sign-in result. Every sign-in call (password, 2FA, passwordless,
  verification, registration, wallet, OIDC, refresh) returns the wire
  `AuthResult`, narrowed by `status` as `SignInResult`: `complete` (the client
  has committed `token_set`), `second_factor_required`, `enrollment_required`,
  `verification_required` or `account_recovery_required`, each with its step
  (`second_factor`, `enrollment`, `verification`, `recovery`). Nothing is read
  from a 403/409 envelope any more. `LoginContinuation`, `AuthOutcome`,
  `continuationFrom`, `continuationFromParams` and `readContinuation` are
  gone; `session.continuation` and `SignInDialog`'s `continuation` are a
  `PendingSignIn`.
- `register` answers `null` when a code went to the identifier;
  `confirmVerification` answers `null` for a signed-in proof (204).
- OIDC results carry a one-time code, never a token: `signInWithPopup`,
  `completeRedirect()` (now async, `{ kind: "sign_in", result }`) and the new
  `completeStepUp()` trade it at `POST /oidc/exchange`. The step-up return is
  `#code=` on its page (`readStepUpReturn` is gone; `StepUpProvider` handles it).
  `oidcLoginStart` posts to `{api}/oidc/{provider}/login/start`.
- `accountInviteToken` is `inviteCode` everywhere (client, `useRegister`,
  `SignInDialog`/`SignInPanel`/forms).
- Self routes live under `/me`. Client changes: `updateProfile` replaces
  `updateUsername`/`updatePreferredLanguage`; `changeEmail`, `changePhone`,
  `removePhone` do contact changes (`requestVerification` only proves an
  address); `revokeOtherSessions` replaces `revokeAllSessions` (this session
  stays); `deleteAccount()` and `unlinkProvider(p)` take no password (step up
  first); `getSecurity`, `listSessionEvents` and `redeemInvitation` are new.
- 2FA is a factor resource: `setupTwoFactor` + `addTwoFactorFactor` (its
  `auth` is the finished sign-in with an enrollment token),
  `setDefaultTwoFactorFactor`, `removeTwoFactorFactor`, `disableTwoFactor()`.
  `enableTwoFactor`, `TwoFactorEnrollResult` and the removed-roles answer are
  gone. `useTwoFactorSettings` has `remove(id)`, `setDefault(id)`, `disable()`.
- Step-up: `sendStepUpCode` sends the email/SMS code; `stepUpWithPassword` and
  `stepUpWithTwoFactor({ code })` return `FreshAuth`. `useStepUp`'s
  `code_sent` state carries `destination`.
- Sign-in keys: `listSignInKeys`, `renameSignInKey`, `revokeSignInKey`,
  `registerPasskey`, `useSignInKeys` and `SignInKeysPanel` (in
  `AccountSecurity`, section `signInKeys`) manage passkeys and device keys.
- `useSessions` has `revokeOthers()` and `signOutEverywhere()` for `revokeAll()`.
  `ContactPanel` removes a phone number.
- `/me` is reshaped (`providers`, `solana_wallet`, `root_role`; no `security`:
  see `getSecurity`). Solana links with `PUT /me/solana-wallet`.
- `getPermissions` answers the `PermissionSet` (`role`, expanded
  `permissions`); `hasPermission` is set membership and `permMatches` is gone.
  `usePermissions` adds `role`.
- Error metadata is typed per code: `errorMetadata(err, code)`,
  `AuthErrorMetadata`. `SessionTokens`, `AccountRecovery` and the client's
  `ActionAvailability` copy are replaced by the generated wire types.
- `getUsers(ids)` and `getUserByUsername(name)` read public profiles
  (`GET /users`, no sign-in needed); `PublicUser` carries `created_at`.

## 0.133.0

- Moved into the AuthKit repo (`sdk/auth-ui`). Versions now follow AuthKit
  tags; install from `https://github.com/open-rails/authkit/releases/download/vX.Y.Z/openrails-auth-ui-X.Y.Z.tgz`.
- `AUTHKIT_VERSION` is removed: the package version is the AuthKit version.

## 0.3.2

- `SolanaSignInButton` (and `useSolanaAuth`) take `acquireSigner` for hosts
  that load their wallet stack on demand, like `SolanaLinkRow`. The wallet
  outcome feeds `renderSolana`'s `onOutcome`, so 2FA, account recovery and
  verification continue in the dialog. Rejecting with
  `SolanaWalletError("rejected")` (picker dismissed) ends the attempt quietly.

## 0.3.1

Requires AuthKit v0.132.0 or newer.

- "Send a new code" becomes the primary action on AuthKit's
  `2fa_code_expired` (5th miss, expired or used code) for login, step-up and
  enrollment codes. The client-side miss counter and 10-minute timer are gone.
- Contact-change codes get no spent signal from AuthKit, so they stay
  retryable with resend as a secondary action.
- `errors.2fa_code_expired` in all locales.

## 0.3.0

Requires AuthKit v0.131.0 or newer.

- A wrong email/SMS 2FA code no longer ends the attempt: the code input stays
  and resend is a secondary action. Sending a new code becomes the primary
  action only once AuthKit has invalidated the code (the 5th wrong guess, or
  10 minutes). Applies to login, step-up, enrollment and contact codes.
- Enabling a factor keeps the session signed in: the enroll response's
  `token_set` is adopted and the session is 2FA-verified, so the next refresh
  needs no continuation. `enabled` results carry `freshAuth`.
- Email 2FA enrollment sends a setup code and confirms it, like SMS.
- `ResetPasswordForm` and `PasswordPanel` validate against the `/capabilities`
  password policy instead of a fixed 8-character minimum.

## 0.2.2

- `SignInDialog` takes `modal={false}` while a host overlay such as a wallet
  picker is open above it, so the overlay stays clickable and outside clicks
  do not dismiss the dialog mid-sign-in.
- `SignInDialog` / `SignInPanel` take `continuation` to open on a pending
  step, e.g. `session.continuation` when a refresh now needs 2FA.

## 0.2.1

- `useVerifyLink`/`VerifyLink` confirm a link token once per client, across
  remounts. The confirm signs the user in, and a host that remounts its tree
  per session used to resend the single-use token and show "link expired".
- Built one file per module, and `@openrails/auth-ui/provider` exports
  `AuthUiProvider` alone: a host that lazy-loads the styled components keeps
  them out of its entry chunk.
- Solana sign-in and linking send `account.publicKey` beside the address (the
  full SIWS output shape).

## 0.2.0

- Sign-out race: requests that can set the refresh cookie wait for the
  logout response, which clears it. A sign-in answered first used to lose its
  cookie, so the next reload or refresh signed the user out.
- `VerifyLink` (and headless `useVerifyLink`) for the AuthKit verification
  link landing route: confirms the link token once and finishes any
  continuation in place.
- `SolanaLinkRow` takes `acquireSigner` instead of `wallet` for hosts that
  load their wallet stack only when Link is pressed.

## 0.1.0

First release: `client`, `react`, `solana`, styled sign-in and account security components, locales (en de es ja ko zh), tested against AuthKit v0.130.1.

- Styled account security: `AccountSecurity` and standalone `ContactPanel`,
  `PasswordPanel`, `LinkedProvidersPanel`, `TwoFactorPanel` (TOTP QR enrollment,
  email/SMS factors, default factor, backup codes), `SessionsPanel` (batch
  sign-out) and `DeleteAccountPanel`, sharing one `StepUpProvider` /
  `StepUpDialog`. A burned email/SMS code offers a new one. `solana` adds
  `SolanaLinkRow`. `useDeleteAccount` takes `onDeleted`.
- Styled sign-in: `SignInDialog`, `SignInPanel`, `LoginForm`, `RegisterForm`,
  `ForgotPasswordForm`, `ResetPasswordForm`, `TwoFactorChallenge`,
  `TwoFactorEnrollment`, `BackupCodes`, `TotpSetup` and `AuthCallback`;
  `SolanaSignInButton` in `./solana`. `onSignedIn` fires only after newly
  issued backup codes are acknowledged.
- AuthKit pin v0.130.1: `Capabilities` types the advertised `username` and
  `password` policy, `RegisterForm` validates and hints against it, and the new
  `password_too_long`, `password_too_common`, `password_requirements_unmet` and
  `password_contains_identifier` codes have messages in every locale.

## 0.1.0-alpha.1

Pre-release: `client`, `react`, `solana`, UI foundation and locales. Styled sign-in and account components follow in 0.1.0.

- UI primitives import `cn` from the [`cn`](https://github.com/shadcn-ui/cn)
  package (pinned `0.4.0`), replacing `clsx` and `tailwind-merge`.
- `react`: headless React bindings. `AuthProvider` (with `onSessionChange` for
  host cache resets), `useSession`, `useUser` (shared `/me`, refetched per
  session generation), `usePermissions`, `useCapabilities`, and flow state
  machines `useLogin` (every login continuation, popup sign-in),
  `useRegister`, `usePasswordReset`, `useChangePassword`, `useStepUp` (with a
  `guard` that steps up and retries a sensitive action), `useTwoFactorSettings`,
  `useContactVerification`, `useLinkedProviders`, `useSessions`,
  `useDeleteAccount` and `useOidcCallback`. Hook errors are `AuthKitError`s.
- `solana`: `createSolanaAuth(client)` with `signIn`, `link` and `unlink` over
  AuthKit's SIWS endpoints for any `{ publicKey, signMessage }` signer. Sign-in
  goes through `completeSignIn`, so 2FA and recovery continuations and
  session-change guards match password login; `link` refuses a wallet change
  before prompting and never links to an account that changed mid-signature.
  `useSolanaAuth` adapts wallet-adapter's `useWallet()` and resumes the action
  once a wallet connects. The wallet adapter is an optional peer that is never
  imported; the subpath is a separate bundle.
- Renamed the package to `@openrails/auth-ui`. Releases attach the packed
  `.tgz` to the GitHub release instead of publishing to npm.
- `client`: `createAuthClient`, a framework-free AuthKit browser client merged
  from two host apps' SDKs. It keeps the access token in memory with a
  session-generation guard, single-flights cookie refresh, and refreshes ahead
  of expiry with Retry-After backoff and a visibility catch-up. It also provides
  `authFetch`, typed methods for every browser flow, login-continuation
  parsing, the OIDC popup and redirect helpers, `readStepUpRequired`, and
  `permMatches`.
- Initial package scaffold and `client` error decoding.
