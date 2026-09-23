# @open-rails/auth-ui

Shared browser client, React hooks and UI for [AuthKit](https://github.com/open-rails/authkit).

Pre-release. Planned layers:

| Import                       | Contents                                                                                    |
| ---------------------------- | ------------------------------------------------------------------------------------------- |
| `@open-rails/auth-ui/client` | Framework-free AuthKit client: tokens, refresh, login continuations, OIDC, typed errors     |
| `@open-rails/auth-ui/react`  | `AuthProvider`, `useSession` and flow hooks (login, register, 2FA, step-up, reset, linking) |
| `@open-rails/auth-ui`        | Styled, themable components built on the hooks                                              |
| `@open-rails/auth-ui/solana` | Optional wallet sign-in and linking                                                         |

Hosts supply `baseUrl`, `navigate`, messages and appearance tokens; the package
holds no router, i18n or query-cache dependency.

```ts
import { readAuthKitError } from "@open-rails/auth-ui/client"

const res = await fetch("/api/v1/password/login", init)
if (!res.ok) throw await readAuthKitError(res)
```

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

Releases are published to npm when a `vX.Y.Z` GitHub release matching
`package.json` is published.
