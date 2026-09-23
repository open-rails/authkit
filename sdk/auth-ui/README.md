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

Releases are published to npm when a `vX.Y.Z` GitHub release matching
`package.json` is published.
