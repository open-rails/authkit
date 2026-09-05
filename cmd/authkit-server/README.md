# authkit-server

The dev/CI harness, not a product: the AuthKit engine plus
`authhttp.MountHandler` on one listener, with `/healthz`. AuthKit ships as an
embedded library (root README); this binary exists so `docker compose` and CI
can boot a migrated database and exercise the real HTTP surface.

- Auth routes under `AUTHKIT_API_PREFIX` (default `/api/v1`), browser OIDC at
  `/oidc`, JWKS at `/.well-known/jwks.json` — exactly what an embedding host
  mounts with `authhttp.MountHandler`.
- `/healthz` — CI waits on it once `AUTHKIT_MIGRATE_ON_START` has applied the schema.

## The binary boundary

The library reads no environment variables. This binary is the one place env
is read, once, in `loadConfig`, and mapped onto explicit `embedded.Config`,
`embedded.Deps` and `authhttp.Config` fields. `AUTHKIT_ENV` is its own switch:
only `dev`/`development`/`local`/`test` are dev; everything else, including
`staging`, is prod-like. A dev value turns on the library's explicit opt-ins
(`Keys.AllowEphemeralDevKeys`, `Applications.AllowPrivateNetworkJWKS`,
`Registration.AllowMissingSenders`, `Ephemeral.AllowMemory` when no Redis is
set, `DirectPeerIP` when no proxies are set); a non-dev value requires real
keys, Redis and a declared IP posture or the server refuses to boot.

Every env var carries the `AUTHKIT_` prefix except the platform-conventional
`DB_URL`/`DATABASE_URL` pair (set exactly one); `env_doctrine_test.go` enforces
both rules.

## Configuration (env)

| Var | Required | Default | Meaning |
|---|---|---|---|
| `AUTHKIT_ISSUER` | yes | — | Token issuer (`iss`) |
| `DB_URL` / `DATABASE_URL` | yes | — | Postgres DSN |
| `AUTHKIT_ENV` | no | `dev` | See above |
| `AUTHKIT_LISTEN_ADDR` | no | `:8080` | Listen address |
| `AUTHKIT_AUDIENCES` | no | `authkit` | Comma-separated token audiences |
| `AUTHKIT_KEYS_PATH` | no | `/vault/auth` | Directory holding `keys.json` and `totp.key` |
| `AUTHKIT_ACTIVE_KEY_ID` / `AUTHKIT_ACTIVE_PRIVATE_KEY_PEM` | no | — | Inline signing key (both together); becomes `Keys.Source` and wins over `keys.json` |
| `AUTHKIT_PUBLIC_KEYS` | no | — | JSON map `kid -> public-key PEM` of extra verification keys (rotation) |
| `AUTHKIT_SCHEMA` | no | `profiles` | Postgres schema |
| `AUTHKIT_REDIS_URL` or `AUTHKIT_REDIS_ADDR` (+ `AUTHKIT_REDIS_PASSWORD`) | no | — | Redis for ephemeral state and rate limits; the two forms are mutually exclusive |
| `AUTHKIT_ALLOW_MEMORY_EPHEMERAL` | no | `false` | Let a non-dev boot run without Redis (single instance only) |
| `AUTHKIT_TRUSTED_PROXIES` / `AUTHKIT_CLOUDFLARE_PROXIES` / `AUTHKIT_DIRECT_PEER_IP` | non-dev | — | Client-IP posture: proxy CIDRs whose `X-Forwarded-For` is honoured (Cloudflare ranges also honour `CF-Connecting-IP`), or assert there is no proxy |
| `AUTHKIT_API_PREFIX` | no | `/api/v1` | JSON API mount prefix |
| `AUTHKIT_MIGRATE_ON_START` | no | `false` | Apply the schema before serving; prefer the one-shot `migrate` command |
| `AUTHKIT_API_KEY_PREFIX` | no | — | Brand prefix for issued API keys |
| `AUTHKIT_REGISTRATION_VERIFICATION` | no | `none` | `none`/`optional`/`required` (`required` needs a sender) |
| `AUTHKIT_ACCESS_TOKEN_TTL` | no | `15m` | Access-token lifetime |
| `AUTHKIT_REFRESH_TOKEN_TTL` | no | — | Refresh-session lifetime; unset ⇒ indefinite |
| `AUTHKIT_SESSION_MAX_PER_USER` | no | `3` | Concurrent refresh sessions per user; `-1` ⇒ unlimited |
| `AUTHKIT_REFRESH_ROTATION_GRACE` | no | `30s` | Window in which a just-rotated refresh token still answers with its successor; negative ⇒ strictly single-use |
| `AUTHKIT_VERIFICATION_SEND_TIMEOUT` | no | `15s` | Per email/SMS provider-send bound |
| `AUTHKIT_2FA_MODE` / `AUTHKIT_2FA_METHODS` | no | `optional` / all | `disabled`/`optional`/`required`; subset of `email,sms,totp` |
| `AUTHKIT_PASSKEY_RPID` / `AUTHKIT_PASSKEY_RP_DISPLAY_NAME` / `AUTHKIT_PASSKEY_ORIGINS` | no | from issuer | WebAuthn relying party |
| `AUTHKIT_LANGUAGES` / `AUTHKIT_DEFAULT_LANGUAGE` | no | `en` / `en` | Supported UI languages and the fallback (must be in the set) |
| `AUTHKIT_NAMING_*` | no | see `docs/naming-policy.md` | Rename policy |
| `AUTHKIT_BOOTSTRAP_PATH` | no | — | Bootstrap manifest (`bootstrap.example.yaml`); applied at most once, DB-marked. A database that already holds users but no bootstrap claim refuses to boot with it set |

Dev-only: the manifest's `dev.static_entitlements` section seeds entitlements
into every access token for billing E2E; it is read at every boot and a non-dev
boot with it set refuses to start.

## Run

```sh
DB_URL=postgres://... go run ./cmd/authkit-server migrate            # one-shot schema apply
AUTHKIT_ISSUER=https://auth.example.com DB_URL=postgres://... go run ./cmd/authkit-server
```
