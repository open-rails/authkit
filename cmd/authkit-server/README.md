# authkit-server

The standalone, self-hostable AuthKit server (#142). Runs the engine in-process
and exposes, on one listener:

- **Browser auth-flow routes** under `AUTHKIT_API_PREFIX` (default `/api/v1`) —
  register / login / OIDC / passwordless / 2FA, the same routes an embedding host
  mounts with `authhttp.NewServer`.
- **JWKS** at `/.well-known/jwks.json` — downstream verifiers fetch signing keys here.
- **Management API** at `POST /v1/call/{Method}` — the authenticated control surface
  for provisioning, management, and token minting. The `authkit/remote` Go SDK drives
  it (so a Go app swaps `embedded.New` ↔ `remote.New` with one line); non-Go clients
  call it directly.

## Wire contract (management API)

Generic method dispatch — `{Method}` is any method on `authkit.Client`:

```
POST /v1/call/CreateUser
Authorization: Bearer <AUTHKIT_MGMT_TOKEN>
Content-Type: application/json

{"email": "a@b.com", "username": "alice"}
```

Success → `200 {"result": <value>}`. Failure → `4xx/5xx {"error": {"code": "<code>"}}`,
where `code` is an AuthKit sentinel's code; the remote SDK re-derives it via
`authkit.ErrorForCode` so `errors.Is(err, authkit.ErrX)` holds across the network.

The handler and the SDK are **generated** from the `authkit.Client` interface
(`go generate ./...`, see `internal/genremote`), so the two transports cannot drift.

## Configuration (env)

| Var | Required | Default | Meaning |
|---|---|---|---|
| `AUTHKIT_ISSUER` | yes | — | Token issuer (`iss`) |
| `DB_URL` / `DATABASE_URL` | yes | — | Postgres DSN |
| `AUTHKIT_MGMT_TOKEN` | prod | — | Bearer credential for the management API. Outside dev, the management API is **disabled** unless set (fail-closed). |
| `AUTHKIT_LISTEN_ADDR` | no | `:8080` | Listen address |
| `AUTHKIT_AUDIENCES` | no | `authkit` | Comma-separated token audiences |
| `AUTHKIT_KEYS_PATH` | no | env/`/vault/auth` | JWT key directory (dev-generates one if absent and env=dev) |
| `AUTHKIT_SCHEMA` | no | `profiles` | Postgres schema |
| `AUTHKIT_ENV` | no | `dev` | `prod`/`production` requires Redis + a management token |
| `AUTHKIT_REDIS_ADDR` | no | — | Redis address (ephemeral store + OIDC/SIWS state) |
| `AUTHKIT_REGISTRATION_VERIFICATION` | no | `none` | `none`/`optional`/`required` (`required` needs a configured sender) |
| `AUTHKIT_API_PREFIX` | no | `/api/v1` | Mount prefix for browser routes |
| `AUTHKIT_MIGRATE_ON_START` | no | `false` | Apply the schema before serving. Prefer the one-shot `migrate` command in prod. |
| `AUTHKIT_API_KEY_PREFIX` | no | — | Branded prefix for issued API keys |

### Dev-only (honored only when `AUTHKIT_ENV` is a dev env)

The server folds in the integration-test affordances that used to live in the
separate `authkit-devserver` (#194). They are mounted **only** in a dev env and
are never reachable in production (fail-closed).

| Var | Default | Meaning |
|---|---|---|
| `AUTHKIT_DEV_MINT_SECRET` | — | Enables `POST {prefix}/dev/mint` (mint arbitrary access tokens) when set; shared-secret gated |
| `AUTHKIT_STATIC_ENTITLEMENTS` | — | Comma-separated entitlements seeded into every access token (billing/entitlement E2E) |

`GET {prefix}/dev/whoami` (reflect the resolved principal) is served whenever the
env is dev. In dev with no `AUTHKIT_MGMT_TOKEN`, the management API is also exposed
unauthenticated — `POST /v1/call/MintCustomJWT` is the production-grade way to mint
arbitrary-claim (non-`access`) tokens.

## Run

```sh
# Apply the schema (one-shot; needs only DB_URL):
DB_URL=postgres://... go run ./cmd/authkit-server migrate

# Then serve:
AUTHKIT_ISSUER=https://auth.example.com \
DB_URL=postgres://... \
AUTHKIT_MGMT_TOKEN=$(openssl rand -hex 32) \
go run ./cmd/authkit-server
```

A Go client then talks to it backend-agnostically:

```go
var c authkit.Client = remote.New("https://auth.example.com", mgmtToken)
u, _ := c.CreateUser(ctx, "a@b.com", "alice") // identical to the embedded call
```
