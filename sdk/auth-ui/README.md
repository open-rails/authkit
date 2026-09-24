# @openrails/auth-ui

Shared browser client, React hooks and UI for [AuthKit](https://github.com/open-rails/authkit).

Lives in the AuthKit repo and ships with it: package version = AuthKit tag, so
`@openrails/auth-ui` X.Y.Z speaks AuthKit vX.Y.Z's contract. Layers:

| Import                      | Contents                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------- |
| `@openrails/auth-ui/client` | Framework-free AuthKit client: session, refresh, every browser flow, OIDC, typed errors     |
| `@openrails/auth-ui/react`  | `AuthProvider`, `useSession` and flow hooks (login, register, 2FA, step-up, reset, linking) |
| `@openrails/auth-ui`        | Styled, themable components built on the hooks                                              |
| `@openrails/auth-ui/solana` | Optional wallet sign-in and linking                                                         |

Hosts supply `baseUrl`, `navigate`, messages and appearance tokens; the package
holds no router, i18n or query-cache dependency.

## Install

Each AuthKit GitHub release carries the package archive:

```json
"@openrails/auth-ui": "https://github.com/open-rails/authkit/releases/download/v0.133.0/openrails-auth-ui-0.133.0.tgz"
```

## Client

```ts
import { createAuthClient } from "@openrails/auth-ui/client"

const auth = createAuthClient({ baseUrl: "/api/v1" }) // the defaults
const stop = auth.start() // restore from the refresh cookie, keep it fresh

auth.subscribe(() => console.log(auth.getSnapshot())) // useSyncExternalStore-ready

const outcome = await auth.signInWithPassword({ identifier, password })
if (outcome.kind === "2fa_required") {
  await auth.verifyTwoFactor({ ...outcome, code })
}

const res = await auth.authFetch("/api/v1/things") // Bearer + one refresh retry
```

- The access token lives in memory only. Refresh is `POST /token` with the
  `authkit_rt` cookie; pass `storage` for mounts without the cookie.
- Each session boundary (login, sign-out, expiry) bumps a generation. Late
  refreshes, profiles, popups and sign-ins from an older generation are dropped.
- Continuations (`2fa_required`, `2fa_enrollment_required`,
  `account_recovery_required`, `verification_required`) are returned, not
  thrown. Other failures throw `AuthKitError` with the AuthKit `code`.
- `enableTwoFactor`: TOTP starts with a secret, email and SMS with a sent code
  (`code_sent`); resend the same call with `code` to confirm. Confirming
  re-issues the session token, so the session stays signed in and
  2FA-verified (`enabled` carries `freshAuth`).
- A wrong email/SMS 2FA code is `invalid_code` and can be retried. Once no
  code is live (the 5th miss, expiry, already used) AuthKit answers
  `2fa_code_expired`; resend to get a fresh code.
- `readStepUpRequired(err)` turns a `403 step_up_required` into the methods to
  offer; retry the action after `stepUpWithPassword` / `stepUpWithTwoFactor` /
  `startOidcStepUp`.
- OIDC: `signInWithPopup` (call from a click), `signInWithRedirect` and
  `completeRedirect()` on the callback route. With `accountInviteToken` both
  start the flow by POST (`oidcLoginStart`), so the invitation never enters a
  URL; `oidcLoginUrl` builds invitation-free login URLs.

## Session lifecycle

auth-ui owns the browser session, so an app writes no auth plumbing:

```tsx
import { ContactProofDialog, AuthUiProvider } from "@openrails/auth-ui"
import { createAuthClient } from "@openrails/auth-ui/client"
import { AuthProvider, useAuth } from "@openrails/auth-ui/react"

export const auth = createAuthClient({ baseUrl: "/auth/v1" })

const Root = () => (
  <AuthProvider
    client={auth}
    // Only on a different user (not a same-user session rotation).
    onUserChange={() => queryClient.resetQueries()}
  >
    <AuthUiProvider>
      <App />
      <ContactProofDialog />
    </AuthUiProvider>
  </AuthProvider>
)

function Header() {
  const { status, signedIn, user, hint, signOut } = useAuth()
  if (status === "loading") return null
  return signedIn ? (
    <UserMenu name={user?.username ?? hint?.username} onSignOut={signOut} />
  ) : (
    <SignInButton />
  )
}

// Host APIs: the session bearer, refresh-and-retry and contact proof.
const load = () => auth.authFetch("/api/things")
```

- **Restore:** `AuthProvider` restores the session from the HttpOnly refresh
  cookie on load. The refresh token never reaches script and the access token
  stays in memory.
- **Signed out:** a browser with no refresh cookie gets `401 no_session` from
  the restore and settles on `signed_out` quietly: no error, no retry. The
  restore always asks the server (a session may predate its hint).
- **No signed-out flash:** a non-secret hint (`userId`, `username`, expiry) is
  kept in `localStorage`. On reload `useAuth()` reports `status: "restoring"`
  (`signedIn: true`) with that hint until the restore settles. The client
  option `sessionHint: false` turns it off; `{ storage, key, ttlSeconds }`
  adjusts it.
- **Requests while restoring** (`authFetch` and every client call) wait for
  the restore, so they carry the restored session; `await auth.ready()` does
  the same for other code.
- **Tabs:** signing in, out or as another user in one tab follows in the
  others (the `storage` event on the hint).
- **Events:** `onUserChange(userId, previous)` fires only when the user
  changes; `onSessionChange` also fires on a same-user session rotation.
- **Contact proof:** AuthKit refuses new sign-in methods while no address is
  proven (`403 verification_required`, `reason: "contact_unproven"`).
  `<ContactProofDialog />` sends a code, confirms it and retries the refused
  request once. For custom UI, register
  `auth.onContactProofRequired(({ identifier, channel }) => Promise<boolean>)`;
  `<VerifyContactForm identifier onVerified />` is the form alone.

## React

```tsx
import {
  AuthProvider,
  useLogin,
  useStepUp,
  useTwoFactorSettings,
} from "@openrails/auth-ui/react"

const Root = () => (
  <AuthProvider client={auth} onSessionChange={() => queryClient.clear()}>
    <App />
  </AuthProvider>
)

function SignIn() {
  // state.step: credentials | two_factor | enrollment | recovery |
  // verification | backup_codes | done. error?.code is the AuthKit code.
  const login = useLogin({
    onSignedIn: ({ returnTo }) => navigate(returnTo ?? "/"),
  })
}

function Security() {
  // A 403 step_up_required opens stepUp.state; after withPassword or
  // withTwoFactor the original action is retried.
  const stepUp = useStepUp()
  const twoFactor = useTwoFactorSettings({ guard: stepUp.guard })
}
```

Hooks are headless: no styling, strings, router or query cache.

## Styled UI

```tsx
import { AuthUiProvider } from "@openrails/auth-ui"
import { de } from "@openrails/auth-ui/locales/de"

;<AuthUiProvider
  appearance={{ theme: "inherit", variables: { radius: "0.5rem" } }}
  messages={[de, { signIn: { title: "Willkommen" } }]}
  t={(key, vars) =>
    i18n.exists(`authUi.${key}`) ? i18n.t(`authUi.${key}`, vars) : undefined
  }
>
  {children}
</AuthUiProvider>
```

- Styles install from the entry and are scoped under `.authui`; `./styles.css`
  is the same sheet for SSR.
- Lazy-loading the components? Import `AuthUiProvider` from
  `@openrails/auth-ui/provider` in eager code so the root entry (and every
  component) stays out of the host's entry chunk.
- `theme`: `light`, `dark`, `auto` (OS) or `inherit` (host shadcn tokens and
  `.dark` class). `variables` override single `--authui-*` tokens.
- Messages: English is complete and the fallback for every key; locales
  (`en de es ja ko zh`) are lazy-loadable subpaths. Interpolation is `{name}`.
  `useMessages().error(err)` maps AuthKit error codes, with a generic fallback.

### Sign-in

```tsx
import {
  AuthCallback,
  ResetPasswordForm,
  SignInDialog,
} from "@openrails/auth-ui"
import { SolanaSignInButton } from "@openrails/auth-ui/solana"

;<SignInDialog
  open={open}
  onOpenChange={setOpen}
  initialTab="login" // or "register"
  returnTo={location.pathname}
  navigate={(to) => router.navigate(to)}
  onSignedIn={() => toast("Signed in")}
  defaultPhoneCountry="US" // numbers typed without +country
  providers={(list) =>
    list.map((p) => ({ ...p, icon: <BrandIcon id={p.id} /> }))
  }
  logo={<Logo />}
  termsUrl="/terms"
  privacyUrl="/privacy"
  renderSolana={({ mode, onOutcome, disabled }) => (
    <SolanaSignInButton
      wallet={wallet} // useWallet()
      onConnectRequest={() => setWalletModal(true)}
      {...{ mode, onOutcome, disabled }}
    />
  )}
/>
```

- `SignInDialog` (controlled) and `SignInPanel` (inline card) run the whole
  flow: password and popup provider sign-in, 2FA challenge (factor switch,
  resend, backup code), forced 2FA enrollment, account recovery, contact
  verification, registration with availability checks and code verification,
  and forgot password. `LoginForm`, `RegisterForm`, `ForgotPasswordForm`,
  `TwoFactorChallenge` and `TwoFactorEnrollment` are exported on their own.
- Close on `onSignedIn`, not on a session change: when 2FA enrollment issues
  backup codes the session is already live, and `onSignedIn` fires only after
  the user acknowledges them. The dialog closes itself then and can't be
  dismissed on that screen.
- `providers` replaces (array) or edits (function) the `/capabilities` list.
- `continuation` opens on a pending step: pass `session.continuation` (set
  when a refresh answered with one) so the user finishes signing in there.
- `modal={false}` while a host overlay (e.g. a wallet picker) is open above
  the dialog, so it stays clickable and does not dismiss the dialog.
- A host that loads its wallet stack lazily passes `SolanaSignInButton`
  `acquireSigner` (resolving a `SolanaSigner`) instead of `wallet`; 2FA and
  other continuations after the wallet signature still run in the dialog.
- Reset link route: `<ResetPasswordForm token={readLinkFragment(location.hash)?.token} onDone={openSignIn} />`.
- OIDC callback route: `<AuthCallback navigate={(to) => router.replace(to)} />`
  finishes 2FA and other continuations in place.
- Verification link route (AuthKit `Frontend.VerifyPath`, default `/verify`):
  `<VerifyLink token={readLinkFragment(location.hash)?.token} navigate={(to) => router.replace(to)} />`
  confirms the emailed/texted link once; `useVerifyLink` is the headless hook.

### Account security

```tsx
import { AccountSecurity } from "@openrails/auth-ui"
import { SolanaLinkRow } from "@openrails/auth-ui/solana"

;<AccountSecurity
  linkedAccountRows={<SolanaLinkRow wallet={useWallet()} />}
  onDeleted={() => navigate("/")}
/>
```

A host that loads its wallet stack lazily passes
`acquireSigner={() => connectWallet()}` (resolving a `SolanaSigner`) instead of
`wallet`.

`AccountSecurity` stacks `ContactPanel`, `PasswordPanel`,
`LinkedProvidersPanel`, `TwoFactorPanel`, `SessionsPanel` and
`DeleteAccountPanel` (pick with `sections`); each also works alone. Every
sensitive action runs through one `StepUpProvider`, whose `StepUpDialog` offers
password, TOTP/email/SMS code, backup code or OIDC re-authentication and then
retries the action. Wrap a page in your own `StepUpProvider` to share it, and
use `useStepUpGuard()` for host actions. A panel outside any provider brings its
own.

## Solana

```ts
import { createSolanaAuth, signerFromWallet } from "@openrails/auth-ui/solana"

const solana = createSolanaAuth(auth)
// Any { publicKey: base58, signMessage(bytes) } works; signerFromWallet adapts useWallet().
const outcome = await solana.signIn(signerFromWallet(wallet)) // same outcomes as password login
await solana.link(signer, { linkedAddress }) // needs a fresh session
await solana.unlink({ password })
```

React: `useSolanaAuth(auth, useWallet(), { onConnectRequest: () => setVisible(true) })`
returns `signIn`, `link`, `unlink`, `busy`, `error` and `awaitingWallet`; an
action started without a wallet resumes once it connects. Wallet-side failures
throw `SolanaWalletError` (`not_connected`, `unsupported`, `rejected`,
`invalid_signature`, `busy`); AuthKit rejections throw `AuthKitError`.
`@solana/wallet-adapter-react` is an optional peer and is never imported.

## Development

```sh
pnpm install
pnpm check
```

### UI primitives

`src/ui/*` is shadcn (`base-vega`, see `components.json`), managed with
`pnpm dlx shadcn@latest add <name> --overwrite`, importing `cn` from the
[`cn`](https://github.com/shadcn-ui/cn) package. After regenerating, re-apply the
local deltas, each marked with a `// Local:` comment.

### E2E

`pnpm test:e2e` builds `e2e/server` (a real AuthKit mount of this checkout, via
the `replace` in `e2e/server/go.mod`), starts it on a throwaway `postgres:18`
Docker container and runs Playwright against it (`pnpm exec playwright install
chromium` once). Needs Go and Docker. `pnpm contract` regenerates
`src/client/generated` from the same checkout; CI (`.github/workflows/sdk.yaml`)
runs `pnpm contract:check`, so an API change that moves the contract must
regenerate it in the same PR. Captured email/SMS: `GET /__test/outbox`.

`package.json` stays at `0.0.0`; publishing an AuthKit `vX.Y.Z` release stamps
`X.Y.Z` and attaches `openrails-auth-ui-X.Y.Z.tgz` (`sdk-release.yaml`).
