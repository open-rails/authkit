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

Each AuthKit release `vX.Y.Z` publishes `@openrails/auth-ui@X.Y.Z` to npm, with
provenance. Pair it with the AuthKit of the same version:

```sh
pnpm add @openrails/auth-ui@X.Y.Z
```

## Client

```ts
import { createAuthClient } from "@openrails/auth-ui/client"

const auth = createAuthClient({ baseUrl: "/api/v1" }) // the defaults
const stop = auth.start() // restore from the refresh cookie, keep it fresh

auth.subscribe(() => console.log(auth.getSnapshot())) // useSyncExternalStore-ready

const result = await auth.signInWithPassword({ identifier, password })
if (result.status === "second_factor_required") {
  const { user_id, challenge } = result.second_factor
  await auth.verifyTwoFactor({ userId: user_id, challenge, code })
}

const res = await auth.authFetch("/api/v1/things") // Bearer + one refresh retry, never on a step-up
```

- The access token lives in memory only. Refresh is `POST /token` with the
  `authkit_rt` cookie; pass `storage` for mounts without the cookie.
- Sessions are bearer by default. `createAuthClient({ dpop: true })` binds
  each sign-in's session to a non-extractable DPoP key in IndexedDB (RFC
  9449): every sign-in and refresh proves it, and the access tokens go as
  `DPoP` with a proof, never as bearer tokens. An AuthKit whose sign-ins
  require DPoP (capabilities `dpop: "required"`) refuses an unbound sign-in,
  and the client then binds anyway. Sign-out deletes the key.
- When a host routes multiple account directories at one API URL, give each
  client a stable, distinct `sessionKeyName` and `sessionHint.key`, alongside
  its directory-specific refresh credentials. This prevents one directory's
  sign-out from deleting another directory's DPoP key. The default key name
  remains `authkit:session-key:<baseUrl>`; changing it requires a new sign-in.
  The option selects browser storage, not the server's account directory.
- Each session boundary (login, sign-out, expiry) bumps a generation. Late
  refreshes, profiles, popups and sign-ins from an older generation are dropped.
- Every sign-in answers AuthKit's `AuthResult` (`SignInResult`, narrowed by
  `status`). `complete` is committed as the session; `second_factor_required`,
  `enrollment_required`, `verification_required`,
  `account_recovery_required` and `device_verification_required` carry their
  next step and are returned, not thrown. Failures throw `AuthKitError` with the AuthKit `code`
  (`errorMetadata(err, code)` reads its typed metadata).
- A password sign-in parked at `verification_required` carries a
  `password_proof`; `confirmVerification` sends it with that address's code,
  so the account keeps its password.
- A new device past the account's daily limit answers
  `device_verification_required`: a code went to the owner's email or phone.
  `confirmDeviceVerification` finishes the sign-in with it;
  `sendDeviceVerification` resends it, or to the other `channels` entry. Too
  many accounts from one device is `too_many_accounts` (429, `Retry-After`).
- 2FA factors: `setupTwoFactor` starts one (TOTP answers its secret, email and
  SMS send a code), `addTwoFactorFactor` confirms it and adopts the
  re-verified session. A forced enrollment passes the step's
  `enrollment.token_set` as `enrollmentToken` to both; the factor's `auth` is
  then the finished sign-in.
- A wrong email/SMS 2FA code is `invalid_code` and can be retried. Once no
  code is live (the 5th miss, expiry, already used) AuthKit answers
  `code_expired`; resend to get a fresh code.
- `readStepUpRequired(err)` turns a `401 step_up_required` into the methods to
  offer; retry the action after `stepUpWithPassword`, `sendStepUpCode` +
  `stepUpWithTwoFactor`, `sendContactStepUpCode` + `stepUpWithContactCode`
  (email, sms), `stepUpWithPasskey`, a wallet's
  `createSolanaAuth(auth).stepUp(signer)`, or `startOidcStepUp`.
- `signInWithPasskey()` (call from a click) signs in with a passkey the
  browser offers.
- OIDC: `signInWithPopup` (call from a click), `signInWithRedirect` and
  `completeRedirect()` on the callback route; the OIDC step-up returns with
  `#code=` to its page (`completeStepUp()`, run by `StepUpProvider`). Results
  carry a one-time code the client trades at `POST /oidc/exchange`, so no
  token enters a URL or a message. With `inviteCode` a sign-in starts by POST
  (`oidcLoginStart`), so the invitation never enters a URL either.

### Other services' APIs

A host frontend calls another service's API (a resource server of the
issuer's authorization server) with the user's identity, directly from the
browser:

```ts
const auth = createAuthClient({ resourceTokens: { clientId: "admin-ui" } })

const res = await auth.resourceFetch(
  "https://billing.example.com/v1/merchant/plans",
  {
    resource: "https://billing.example.com",
    scope: "billing:merchant",
  }
)
```

- `getResourceToken({ resource, scope })` trades the session's access token
  at the issuer's token endpoint (`tokenEndpoint`, default `/oauth2/token`;
  RFC 8693 token exchange) for an access token. Tokens stay in memory, cached
  until shortly before they expire, and are dropped at sign-out.
- `group` binds the token to one group, such as a merchant (`group_id`,
  [group-bound tokens](../docs/authorization-server.md#group-bound-tokens)):
  `getResourceToken({ resource, scope, group: merchantId })`. Each group's
  token is cached apart, so switching groups never reuses another group's
  token. AuthKit refuses a group the user holds no role in (`invalid_target`).
- Tokens are bearer tokens by default. `resourceTokens: { dpop: true }`
  binds them to this browser's DPoP key (RFC 9449), and so does an issuer
  that refuses an unbound exchange (`invalid_dpop_proof`). The key is a
  non-extractable P-256 key in IndexedDB, so it survives a reload; a bound
  token goes with a fresh proof on every request, and a `use_dpop_nonce`
  challenge is answered once. A DPoP-bound session (`createAuthClient({
dpop: true })`) is exchanged with its own key, the only one AuthKit
  accepts for it, and its resource tokens are bound to that key.
- `resourceFetch` retries once with a new token on a 401 `invalid_token`.
- Token endpoint refusals throw `OAuthError` (`error`, `description`).

### Signing in at another issuer

An app whose users belong to another deployment (any OIDC issuer; AuthKit's
[authorization server](../docs/authorization-server.md) included) signs them
in there and calls its API with that issuer's access tokens:

```ts
import { createIssuerClient } from "@openrails/auth-ui/client"

const issuer = createIssuerClient({
  issuer: "https://myapp.com",
  clientId: "billing-console",
  redirectUri: "/callback",
  resource: "https://billing.example.com",
  scope: "openid profile email billing:merchant",
  postLogoutRedirectUri: "/signed-out",
})

await issuer.completeSignIn() // on /callback: null elsewhere
issuer.start() // restores a kept session
await issuer.signIn({ returnTo: "/merchants" }) // or { popup: true } from a click
const res = await issuer.authFetch(
  "https://billing.example.com/v1/merchant/plans"
)
```

- Authorization code with PKCE S256, `resource` (RFC 8707), `iss` checked
  (RFC 9207), the ID token's `nonce`, `aud` and `exp` checked.
- Tokens are bearer tokens by default. `dpop: true` binds the session to a
  non-extractable DPoP key (RFC 9449), and so does an issuer that refuses an
  unbound token request (`invalid_dpop_proof`). The access token stays in
  memory. The rotating refresh token is kept in IndexedDB (with the key,
  when bound), so a reload restores the session without a redirect, and
  tabs rotate it one at a time (Web Locks).
- For a server-issued proof challenge, `signIn({ nonce: challenge.nonce })`
  binds the ID token to that nonce while state and PKCE remain independently
  random. `getIDToken()` returns the current unexpired ID token or `null`, and
  clears across new exchanges, identity changes and logout. The receiving server
  must verify the token and its expected nonce/client; an ID token is not an API
  access token. Use `persist: false` for a one-off proof flow.
- `stepUp()` re-authenticates (`max_age=0`); `signOut()` revokes the refresh
  token and ends the issuer session (`end_session_endpoint`); with
  `{ redirect: false }` it signs out here only.
- A popup sign-in ends on the app's own callback page, which hands the answer
  to its opener by `postMessage` (same origin, same window, same `state`).
- React: `<IssuerAuthProvider client={issuer}>` and `useIssuerAuth()`
  (`status`, `user` from the ID token, `session`, `fetch`, `signIn`, `stepUp`,
  `signOut`) from `@openrails/auth-ui/react`.

### The issuer's authorize page

A deployment that is an authorization server renders `<OAuthAuthorize />` at
`Frontend.AuthorizePath` (`/authorize`), inside `AuthProvider` and
`AuthUiProvider`. It signs the user in (second factors and step-ups
included), approves the client's request, and sends the browser back with the
code; `prompt=none` with nobody signed in returns `login_required`.

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
- **Temporary outages:** network errors, timeouts and server failures keep the
  current session or restoring hint and retry with backoff. Without a hint,
  the state stays `loading` until the server can confirm the session. A known
  invalid, revoked or absent session ends the restore; an outage does not.
- **Requests while restoring** (`authFetch` and every client call) wait for
  the restore, so they carry the restored session; `await auth.ready()` does
  the same for other code.
- **Tabs:** signing in, out or as another user in one tab follows in the
  others (the `storage` event on the hint).
- **Events:** `onUserChange(userId, previous)` fires only when the user
  changes; `onSessionChange` also fires on a same-user session rotation.
  `onRegistered({ userId })` fires only when the server confirms a newly
  created account's completed sign-in, including provider, wallet and MFA
  continuations. Credentials are ready, and this runs before ordinary
  session subscribers and `onUserChange`, so a host can stage guest settings
  for inheritance. Existing-account login, refresh and restore never fire
  it. Use the `AuthProvider` prop or `auth.onRegistered(listener)` (returns an
  unsubscribe function); the event is local and is not replayed.
  Bind deferred profile writes to their intended account with
  `auth.updateProfile({ preferredLanguage: "ja", expectedUserId: userId })`;
  a restore or account switch to someone else rejects before sending.
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
  // A 401 step_up_required opens stepUp.state; after withPassword or
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
  resend, backup code), forced 2FA enrollment, a new device's code, account
  recovery, contact verification, registration with availability checks and
  code verification, and forgot password. `LoginForm`, `RegisterForm`,
  `ForgotPasswordForm`, `TwoFactorChallenge`, `NewDeviceVerification` and
  `TwoFactorEnrollment` are exported on their own.
- Close on `onSignedIn`, not on a session change: when 2FA enrollment issues
  backup codes the session is already live, and `onSignedIn` fires only after
  the user acknowledges them. The dialog closes itself then and can't be
  dismissed on that screen.
- Registration follows `/capabilities` `registration.mode`: the
  "Create account" tab appears only when it is `open`, or `invite_only` with
  `inviteCode`; sign-in is never gated. Gate the host's own sign-up links the
  same way: `const { available } = useRegistration(inviteCode)` from
  `@openrails/auth-ui/react` (false until capabilities load).
- `providers` replaces (array) or edits (function) the `/capabilities` list.
- `continuation` opens on a pending step: pass `session.continuation` (set
  when a refresh answered with a next step) so the user finishes signing in
  there. A policy change uses session reason `verification_required`, rather
  than `expired`. Capture the continuation in local state and keep the dialog
  open until `onOpenChange(false)`; it must not close merely because the
  session becomes authenticated before backup-code acknowledgement.
  `inviteCode` carries an invitation into registration.
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

#### Contact-first sign-in

```tsx
import { ContactSignIn } from "@openrails/auth-ui"

;<ContactSignIn
  defaultPhoneCountry="US"
  initialIdentifier={loginHint} // pre-fills; proves nothing
  onSignedIn={() => router.navigate("/account")}
/>
```

- One field for an email or phone, then the 6-digit code sent there
  (AuthKit `Registration.PasswordlessLogin`). The field's autofill offers
  saved passkeys (`autocomplete="username webauthn"`, WebAuthn conditional
  mediation); a "Sign in with a passkey" button covers browsers without it.
- A new contact signs up (`PasswordlessAutoRegistration`): when AuthKit
  answers `agreement_required`, the user reads and accepts the documents and
  the same code creates the account. A code sign-up then offers a passkey.
- Any completed sign-in whose `agreements_due` is not empty asks the user to
  accept them (`POST /me/agreements`) or sign out. `RegisterForm` shows an
  "I agree" box when `/capabilities` lists `registration.agreements`, and a
  provider sign-up started there carries them. `OAuthAuthorize` asks for an
  OAuth client's agreements before approving it.
- `useLogin()` exposes the same steps headless: `sendCode`, `confirmCode`,
  `acceptSignUp`, `acceptAgreements`, `addPasskey`, `skipPasskey`, and
  `autofillPasskey(signal)`.

#### Consent to a group's app

`OAuthAuthorize` handles a group client (AuthKit's group OAuth clients) by
itself: when approval answers `consent_required` it shows the consent
screen from the request's `third_party` and the error's scopes, then
approves with `{ consent: true }`. Show `ConnectedAppsPanel` (or add
`"connectedApps"` to `AccountSecurity`'s `sections`) so users can
disconnect an app.

### Account security

```tsx
import { AccountProfile, AccountSecurity } from "@openrails/auth-ui"

;<>
  <AccountProfile
    avatar={<AvatarEditor />}
    nameAction={<EditUsername />}
    onSignOut={() => navigate("/")}
  >
    <MembershipDetails />
  </AccountProfile>
  <AccountSecurity
    acquireSolanaSigner={() => connectWallet()}
    onDeleted={() => navigate("/")}
  />
</>
```

`AccountProfile` owns the username row and red Logout action; avatar editing,
name editing and membership details are host-provided slots. `onSignOut` runs
before the local session is cleared, so a private page can navigate away first.

Social Logins lists linked providers and Solana wallets. Its plus button opens
`SignInDialog mode="link"`, offering only currently available, unlinked options
and never a password, registration or ordinary sign-in form. A host with wallet
support passes `acquireSolanaSigner` (resolving a `SolanaSigner`) to
`AccountSecurity`; this serves both linking and step-up. The legacy
`linkedAccountRows` slot remains available for custom rows.

`AccountSecurity` stacks `ContactPanel`, `PasswordPanel`,
`LinkedProvidersPanel`, `TwoFactorPanel`, `SignInKeysPanel` (passkeys and
device keys), `SessionsPanel` and `DeleteAccountPanel` (pick with
`sections`); each also works alone. Every
sensitive action runs through one `StepUpProvider`, whose `StepUpDialog` offers
each way the account can re-authenticate (password, second factor or backup
code, a code to its email or phone, a passkey, its wallet, a provider) and then
retries the action. The wallet needs `acquireSolanaSigner` on
`AccountSecurity` or `StepUpProvider`. Wrap a page in your own `StepUpProvider` to share it, and
use `useStepUpGuard()` for host actions. A panel outside any provider brings its
own.

A provider step-up leaves the page. To replay an action after it, pass a
resume and register its resumer:

```tsx
const guard = useStepUpGuard()
useEffect(
  () => guard.onResume?.(`refund:${id}`, (data) => refund(data as Refund)),
  [guard, id]
)
await guard(() => refund(input), {
  resume: { kind: `refund:${id}`, data: input },
})
```

The action is kept in `sessionStorage` with the signed-in person's id, a nonce
the return URL carries (`?authkit_step_up=`) and a 15-minute lifetime. On
return, the `StepUpProvider` replays it once through its resumer; another
person's, a stale one or a nonce that does not match is dropped.

## Admin

`@openrails/auth-ui/admin` is the staff side: a host composes its own admin
area from its components. Customer entries never import it.

```ts
import {
  createAdminClient,
  useGroupAdminAccess,
} from "@openrails/auth-ui/admin"

const admin = createAdminClient({ auth }) // auth: AuthClient, IssuerClient or anything with authFetch
await admin.setMemberRole(group, userId, "merchant:admin") // AuthKit's own routes, no host proxy
const access = useGroupAdminAccess({ auth, group }) // access.any hides a tab
```

The client covers AuthKit's group routes (members, invitations, roles, API
keys, OAuth clients, remote applications), its account routes
(`/admin/users…`) and `GET /me/permissions`; `ADMIN_ROUTES` names each call's
route. Every component takes `auth`, `baseUrl` (default `/api/v1`),
`basePath` (its views are deep links beneath it), `navigation` (the host
router as `{ pathname, search, navigate(to, { replace }) }`; the history API
without it), `guard` (`useStepUpGuard()`, which runs every write; without it a
stale sign-in fails the write with "sign in again"), `appearance` (default
`theme: "inherit"`), `language` (`ADMIN_LANGUAGES`) and `messages` (the admin
words under `admin`).

### Embedded console

`AuthAdmin` combines the existing panels into an optional reference console.
Import it from the separate admin entry; it does not start a server or add
administration routes to AuthKit.

```tsx
import { AuthAdmin } from "@openrails/auth-ui/admin"

;<AuthAdmin
  key={user.id}
  auth={auth}
  basePath="/admin/accounts"
  group={groupId}
  navigation={nav}
  guard={guard}
  sections={["users", "members", "roles", "api-keys"]}
  users={{ entitlements: ["premium"], userPanels, confirmWarnings }}
/>
```

**Key the console by the signed-in account id**, as above, so switching accounts
discards permission results, data and unfinished forms. The generic `authFetch`
interface does not expose an identity, so the console cannot detect that change
itself. Changes to `group`, `baseUrl` or `basePath` reset it automatically.

The host chooses the group (`root` by default); the console does not discover or
switch groups. The Users view uses root account permissions by default, or the
selected directory's account permissions when `users.tenantId` is supplied.
Group selection grants no access. Each view
uses the existing permission checks, and each write retains its panel's guard
and server authorization.

At `basePath`, the first permitted section opens. Section links are beneath it:
`users`, `members`, `roles`, `api-keys`, `oauth-clients` and `remote-applications`.
Their existing detail routes and query filters remain deep links, and browser
back/forward works with either the host's `navigation` or the history API. An
excluded or unauthorized deep link shows no access. Only the active panel is
mounted.

Omit `sections` to offer every permitted section, or select those enabled by your
deployment. `users={false}` excludes account administration entirely. `users`
otherwise accepts `userPanels`, `confirmWarnings` and `entitlements` from
`UsersAdmin`; `permissionHelp` is passed to `RolesAdmin`, and
`remoteApplications={{ scope, tokenEndpoint }}` configures
`RemoteApplicationsAdmin`. All the panels below remain independently usable.

### Group admins

Removing a member or changing a role so that it loses permissions shows a reminder
to review shared service keys. The reminder never revokes a key or claims that
the person possesses a particular secret. Promotions and equivalent permission
sets do not trigger it. Unknown role definitions are treated conservatively.

`MembersAdmin` and `UsersAdmin` accept
`onReviewServiceKeys={({ group, userId }) => ...}` to open the host's credential
inventory. Supply it only when that destination is available to the operator;
the destination must enforce its own authorization. Without it, the general
reminder still appears with a Done button. `AuthAdmin` connects the review button
to its API keys panel only when that panel is enabled, readable, and administers
the same group as the role change. A host may override the Users review action
through `users.onReviewServiceKeys` for its own inventory.

The reminder covers group-member removals and directory-role changes performed
through these panels. Host-owned role editors and command-line offboarding need
their own reminder; AuthKit cannot discover who received a shared secret from
the key's creator metadata.

```tsx
import {
  ApiKeysAdmin,
  MembersAdmin,
  OAuthClientsAdmin,
  RemoteApplicationsAdmin,
  RolesAdmin,
} from "@openrails/auth-ui/admin"

const guard = useStepUpGuard() // inside a StepUpProvider
const nav = { pathname: location.pathname, search: location.search, navigate } // React Router

<MembersAdmin auth={auth} group={merchantId} basePath="/settings/team" navigation={nav} guard={guard} />
<RolesAdmin auth={auth} group="root" basePath="/settings/roles" navigation={nav} guard={guard}
  permissionHelp={{ "billing:read": "Read customers and payments" }} />
<ApiKeysAdmin auth={auth} group={merchantId} basePath="/settings/keys" navigation={nav} guard={guard} />
<OAuthClientsAdmin auth={auth} group={merchantId} basePath="/settings/apps" navigation={nav} guard={guard} />
<RemoteApplicationsAdmin auth={auth} group={merchantId} basePath="/settings/backends" guard={guard} scope="openrails:self" />
```

| Component                 | Views                                 | Shows with                                                                         | Writes with          |
| ------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------- | -------------------- |
| `MembersAdmin`            | members (`?role=`), `invitations`     | `members:read` (the invite form: `members:manage`, or `root:users:invite` on root) | `members:manage`     |
| `RolesAdmin`              | roles, `new`, `<role>`, `<role>/edit` | `roles:read` or `members:read`                                                     | `roles:manage`       |
| `ApiKeysAdmin`            | keys (`?revoked=1`)                   | `credentials:read`                                                                 | `credentials:manage` |
| `OAuthClientsAdmin`       | clients, `new`, `<client_id>`         | `credentials:read`                                                                 | `credentials:manage` |
| `RemoteApplicationsAdmin` | keys and the assertion to sign        | `credentials:read`                                                                 | `credentials:manage` |

Permissions are the group persona's (`merchant:members:read`). Each component
reads the caller's own with `GET /me/permissions`: without them it shows a
no-access state, and with read alone no write controls. AuthKit still decides:
a role beyond the caller's own, the group's last owner or a self-change on
root is refused, and the refusal is shown. Writes that need a recent sign-in
(root changes, OAuth clients, signing keys) step up through `guard`, and replay after a
provider step-up. A secret (an API key, a client secret, an invitation link)
is shown once, at creation.

`RemoteApplicationsAdmin` registers a backend's signing keys (a JWKS URL, or a
PEM key with its kid) for the RFC 7523 assertions it trades for its users'
tokens, and shows what to sign. `tokenEndpoint` (default `/oauth2/token`
beside `baseUrl`) is the assertions' `aud`; `scope` adds one to the example.

### Users

```tsx
import { UserAccountSummary, UsersAdmin, useUsersAdminAccess } from "@openrails/auth-ui/admin"

<UsersAdmin auth={auth} basePath="/admin/users" navigation={nav} guard={guard}
  entitlements={["premium"]} // the directory's entitlement filter; needs Deps.EntitlementHolders
  userPanels={(user) => <BillingCustomerSummary customer={user.id} … />}
  confirmWarnings={async (user) => billingConfirmWarnings({ subscriptions: await subscriptionsOf(user.id) })} />
<UserAccountSummary auth={auth} user={customerId} href={`/admin/users/${customerId}`} navigation={nav} />
const access = useUsersAdminAccess({ auth }) // access.any hides the tab
```

`UsersAdmin` is the user directory and each account's page. Views: the
directory at `basePath` (`?q=` search over usernames, emails, phones, ids and
linked sign-ins; `?status=active|banned|deleted`, `?role=` a root role,
`?entitlement=`, `?sort=` and `?order=`; a total and cursor pages), an
account at `basePath/<user_id>` (`?kind=` filters its sign-in history), and
root invitations at `basePath/invitations`.

| Act                                     | Needs on root                                |
| --------------------------------------- | -------------------------------------------- |
| See the directory, sessions, history    | `root:users:read`                            |
| Ban (reason, an end) and unban          | `root:users:ban`                             |
| Delete and restore (typed confirmation) | `root:users:delete`                          |
| Edit the profile, sign out everywhere   | `root:users:manage`                          |
| See and change the root role (typed)    | `root:members:read`, `root:members:manage`   |
| Invite people to create an account      | `root:users:invite` or `root:members:manage` |

`root:users:manage` and `root:members:manage` need their holder to have a
second factor. AuthKit still decides: an account the caller does not outrank,
or the caller's own, is refused, and the refusal is shown. Every write steps
up through `guard`. `userPanels(user)` adds the host's panels to an account's
page; `confirmWarnings(user, "ban" | "delete")` adds warnings to those
confirmations (an array is one per item, a promise is awaited), and the act
still goes ahead. `UserAccountSummary` is one account's standing for another
page, such as a billing customer: status, root role, entitlements, ban, last
sign-in and a link.

For one tenant's account directory, pass its canonical group ID and the API
mount served by `Client.ForTenant(...).Handler`:

```tsx
;<UsersAdmin
  auth={auth}
  tenantId={tenantId}
  baseUrl={tenantAdminApi}
  basePath={`/admin/tenants/${tenantId}/users`}
  navigation={nav}
  guard={guard}
/>
const access = useUsersAdminAccess({ auth, tenantId, baseUrl: tenantAdminApi })
```

The `auth` client keeps the operator's original sign-in and refresh session.
Only admin requests use `tenantAdminApi`; the host supplies that trusted mount,
and AuthKit authorizes the target tenant. No tenant is inferred from an email
or added as an ambient request header. In this mode the role filter, editor,
and invitations use the tenant group and `tenant_role`; they never edit a
global root role. Account controls use `tenant:users:*` and separately load
`root:users:*` for global account administrators. Root membership, role and
credential permissions do not grant tenant role-management powers. Omitting
`tenantId` preserves the existing root UI.

Changing the target clears prior data, pagination, open forms and registered
action resumes. A returned account must have the expected `tenant_id`; a
missing or different owner produces a configuration error with retry, without
invalidating the operator's session. `createAdminClient` accepts the same
optional `tenantId` when used directly. Continue keying the admin mount by the
source account/session when that identity changes.

## Solana

```ts
import { createSolanaAuth, signerFromWallet } from "@openrails/auth-ui/solana"

const solana = createSolanaAuth(auth)
// Any { publicKey: base58, signMessage(bytes) } works; signerFromWallet adapts useWallet().
const result = await solana.signIn(signerFromWallet(wallet)) // an AuthResult, like password login
await solana.link(signer, { linkedAddress }) // PUT /me/solana-wallet
await solana.unlink() // needs a recent sign-in (step up first)
await solana.stepUp(signer) // the linked wallet's step-up
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
`src/client/generated` from the same checkout; CI (`.github/workflows/auth-ui.yaml`)
runs `pnpm contract:check`, so an API change that moves the contract must
regenerate it in the same PR. Captured email/SMS: `GET /__test/outbox`.

`package.json` stays at `0.0.0`; publishing an AuthKit `vX.Y.Z` release stamps
`X.Y.Z` and publishes it to npm as `@openrails/auth-ui@X.Y.Z`
(`.github/workflows/release.yaml`).

Password changes re-authenticate with the account's available sign-in methods
before opening the editor. The editor asks for one new password, with standard
username and `new-password` autocomplete metadata. If its authentication proof
expires while editing, the normal step-up guard still protects submission.

### Account notifications

Enable the inbox on the AuthKit backend, then render the widgets under the
existing `AuthProvider` and `AuthUiProvider`. They use that same client's
notification API and session; no ContentKit client or transport adapter is needed.

```tsx
import { NotificationBell, NotificationInbox } from "@openrails/auth-ui"

<NotificationBell />
<NotificationInbox />
```

The default renderer shows plain-text `data.title` / `data.message`, with a
localized fallback for an unknown payload. Use `renderItem(item)` and
`renderActions(item)` for domain-specific wording and approved destination links.
Return null/undefined from `renderItem` to retain the default for other kinds.
The inbox handles read/unread, archive/restore, cursor pagination and refresh;
producer withdrawal remains separate from those user actions. The bell reports
whether unread items exist, and all mounted views refresh after an inbox change.
Both widgets hide data immediately when the active session changes.
