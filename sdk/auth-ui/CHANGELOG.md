# Changelog

## Unreleased

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
