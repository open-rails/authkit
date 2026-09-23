# Changelog

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
  from the doujins and hentai0 SDKs. It keeps the access token in memory with a
  session-generation guard, single-flights cookie refresh, and refreshes ahead
  of expiry with Retry-After backoff and a visibility catch-up. It also provides
  `authFetch`, typed methods for every browser flow, login-continuation
  parsing, the OIDC popup and redirect helpers, `readStepUpRequired`, and
  `permMatches`.
- Initial package scaffold and `client` error decoding.
