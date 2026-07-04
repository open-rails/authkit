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
| `AUTHKIT_KEYS_PATH` | no | `/vault/auth` | Directory containing `keys.json` (and `totp.key`) |
| `ACTIVE_KEY_ID` / `ACTIVE_PRIVATE_KEY_PEM` | no | — | Inline signing key material; wins over `keys.json` when set (both required together) |
| `PUBLIC_KEYS` | no | — | JSON map `kid -> public-key PEM` of extra verification keys kept in the JWKS (rotation) |
| `AUTHKIT_SCHEMA` | no | `profiles` | Postgres schema |
| `AUTHKIT_ENV` | no | `dev` | Only `dev`/`development`/`local`/`test` are dev; **everything else — incl. `staging` — is prod-like** (#231). Non-dev requires real keys, Redis, and a management token |
| `AUTHKIT_REDIS_ADDR` | no | — | Redis address (ephemeral store + OIDC/SIWS state); pair with `AUTHKIT_REDIS_PASSWORD` when the server requires auth |
| `AUTHKIT_REDIS_URL` | no | — | Full `redis://`/`rediss://` URL (password, TLS, and db ride in the URL); mutually exclusive with `AUTHKIT_REDIS_ADDR` |
| `AUTHKIT_REDIS_PASSWORD` | no | — | Password for `AUTHKIT_REDIS_ADDR` deployments (URL form carries its own) |
| `AUTHKIT_REGISTRATION_VERIFICATION` | no | `none` | `none`/`optional`/`required` (`required` needs a configured sender) |
| `AUTHKIT_API_PREFIX` | no | `/api/v1` | Mount prefix for browser routes |
| `AUTHKIT_MIGRATE_ON_START` | no | `false` | Apply the schema before serving. Prefer the one-shot `migrate` command in prod. |
| `AUTHKIT_API_KEY_PREFIX` | no | — | Branded prefix for issued API keys |
| `AUTHKIT_TRUSTED_PROXIES` | no | — | Comma-separated CIDRs of trusted reverse proxies / CDN egress. Client IP (rate limiting, auditing) is derived from `CF-Connecting-IP` / `X-Forwarded-For` **only** when the peer is inside one of these; otherwise `RemoteAddr` is used. Required for correct per-IP rate limiting behind a CDN. |
| `AUTHKIT_ACCESS_TOKEN_TTL` | no | `15m` | Access-token lifetime (Go duration) |
| `AUTHKIT_REFRESH_TOKEN_TTL` | no | — | Refresh-token lifetime (Go duration). Unset ⇒ indefinite sessions |
| `AUTHKIT_SESSION_MAX_PER_USER` | no | `3` | Max concurrent refresh sessions per user (evict-oldest). `-1` ⇒ unlimited |
| `AUTHKIT_VERIFICATION_SEND_TIMEOUT` | no | `15s` | Per email/SMS provider-send bound (verification codes, reset links, login codes) |
| `AUTHKIT_2FA_MODE` | no | `optional` | `disabled` / `optional` / `required` |
| `AUTHKIT_2FA_METHODS` | no | all | Comma-separated subset of `email,sms,totp` |
| `AUTHKIT_PASSKEY_RPID` | no | issuer host | WebAuthn relying-party ID |
| `AUTHKIT_PASSKEY_RP_DISPLAY_NAME` | no | issuer | WebAuthn relying-party display name |
| `AUTHKIT_PASSKEY_ORIGINS` | no | issuer origin | Comma-separated allowed WebAuthn origins (must match RPID or a subdomain) |
| `AUTHKIT_LANGUAGES` | no | `en` | Comma-separated supported UI languages (`?lang` / `Accept-Language` negotiation) |
| `AUTHKIT_DEFAULT_LANGUAGE` | no | `en` | Fallback language when the request carries none |
| `AUTHKIT_BOOTSTRAP_PATH` | no | — | Path to a bootstrap manifest (YAML; see `bootstrap.example.yaml` at the repo root). Applied **at most once** at startup (DB-marked apply-once); restarts skip it. It is a **genesis seed**: on a non-empty database without the marker (users/remote apps already exist) the server refuses to boot — unset the var for such deployments. |

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

## Env doctrine (#231)

The AuthKit **library reads no environment variables** — this binary is the one
place env is read, once, in `loadConfig`. It maps `AUTHKIT_ENV` through the
single classifier (`embedded.IsDevEnvironment`) and, in a dev env, sets
`Keys.AllowEphemeralDevKeys` so `go run ./cmd/authkit-server` still boots with
auto-generated dev signing keys (persisted under `.runtime/authkit/`). In any
non-dev env with no keys configured, the server **refuses to boot**.

JWT key material maps env → the explicit key-source config (#231): when
`ACTIVE_KEY_ID` / `ACTIVE_PRIVATE_KEY_PEM` (plus optional `PUBLIC_KEYS`) are
set, the binary builds a `jwtkit.NewStaticKeySourceFromPEM(...)` and passes it
as `Keys.Source`; otherwise it passes `AUTHKIT_KEYS_PATH` as `Keys.Path` and
the engine loads `<path>/keys.json` (hot-reloaded on rotation).

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
