# @openrails/auth-ui

Shared browser client, React hooks and UI for [AuthKit](https://github.com/open-rails/authkit).

Pre-release. Layers:

| Import                      | Contents                                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------- |
| `@openrails/auth-ui/client` | Framework-free AuthKit client: session, refresh, every browser flow, OIDC, typed errors     |
| `@openrails/auth-ui/react`  | `AuthProvider`, `useSession` and flow hooks (login, register, 2FA, step-up, reset, linking) |
| `@openrails/auth-ui`        | Styled, themable components built on the hooks                                              |
| `@openrails/auth-ui/solana` | Optional wallet sign-in and linking                                                         |

Hosts supply `baseUrl`, `navigate`, messages and appearance tokens; the package
holds no router, i18n or query-cache dependency.

## Install

Until the npm org is live, install the archive attached to each GitHub release:

```json
"@openrails/auth-ui": "https://github.com/open-rails/auth-ui/releases/download/v0.1.0/openrails-auth-ui-0.1.0.tgz"
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
- `readStepUpRequired(err)` turns a `403 step_up_required` into the methods to
  offer; retry the action after `stepUpWithPassword` / `stepUpWithTwoFactor` /
  `startOidcStepUp`.
- OIDC: `oidcLoginUrl`, `signInWithPopup` (call from a click) and
  `completeRedirect()` on the callback route.

## Development

```sh
pnpm install
pnpm check
```

### E2E

`pnpm test:e2e` builds `e2e/server` (a real AuthKit mount pinned in
`e2e/server/go.mod`), starts it on a throwaway `postgres:18` Docker container and
runs Playwright against it (`pnpm exec playwright install chromium` once).
Needs Go and Docker. `pnpm contract` regenerates `src/client/generated` from the
same pin; CI runs `pnpm contract:check`. Captured email/SMS: `GET /__test/outbox`.

Publishing a `vX.Y.Z` GitHub release matching `package.json` runs the checks and
attaches `openrails-auth-ui-X.Y.Z.tgz` to the release.
