# authkit-server

The dev/CI harness: the AuthKit engine plus `authhttp.MountHandler` on one
listener, with `/healthz`. AuthKit ships as an embedded library (root README);
this binary exists so `docker compose` and CI can boot a migrated database and
exercise the real HTTP surface.

- **Auth routes** under `AUTHKIT_API_PREFIX` (default `/api/v1`) — the same
  routes an embedding host mounts with `authhttp.NewServer`.
- **JWKS** at `/.well-known/jwks.json`.
- **`/healthz`** — CI waits on it once `AUTHKIT_MIGRATE_ON_START` has applied the schema.

## Configuration (env)

| Var | Required | Default | Meaning |
|---|---|---|---|
| `AUTHKIT_ISSUER` | yes | — | Token issuer (`iss`) |
| `DB_URL` / `DATABASE_URL` | yes | — | Postgres DSN. Set exactly one — both set refuses to boot (#266) |
| `AUTHKIT_LISTEN_ADDR` | no | `:8080` | Listen address |
| `AUTHKIT_AUDIENCES` | no | `authkit` | Comma-separated token audiences |
| `AUTHKIT_KEYS_PATH` | no | `/vault/auth` | Directory containing `keys.json` (and `totp.key`) |
| `AUTHKIT_ACTIVE_KEY_ID` / `AUTHKIT_ACTIVE_PRIVATE_KEY_PEM` | no | — | Inline signing key material; wins over `keys.json` when set (both required together) |
| `AUTHKIT_PUBLIC_KEYS` | no | — | JSON map `kid -> public-key PEM` of extra verification keys kept in the JWKS (rotation) |
| `AUTHKIT_SCHEMA` | no | `profiles` | Postgres schema |
| `AUTHKIT_ENV` | no | `dev` | Only `dev`/`development`/`local`/`test` are dev; **everything else — incl. `staging` — is prod-like** (#231). A dev value turns on the library's explicit dev opt-ins (`Keys.AllowEphemeralDevKeys`, `Applications.AllowPrivateNetworkJWKS`, `Registration.AllowMissingSenders`, `Ephemeral.AllowMemory` when no Redis is set, a direct-peer IP posture when no proxies are set); non-dev requires real keys, Redis and an IP posture |
| `AUTHKIT_REDIS_ADDR` | no | — | Redis address (ephemeral store + OIDC/SIWS state); pair with `AUTHKIT_REDIS_PASSWORD` when the server requires auth |
| `AUTHKIT_REDIS_URL` | no | — | Full `redis://`/`rediss://` URL (password, TLS, and db ride in the URL); mutually exclusive with `AUTHKIT_REDIS_ADDR` |
| `AUTHKIT_REDIS_PASSWORD` | no | — | Password for `AUTHKIT_REDIS_ADDR` deployments (URL form carries its own) |
| `AUTHKIT_ALLOW_MEMORY_EPHEMERAL` | no | `false` | Non-dev boot without Redis refuses (per-process 2FA codes, pending registrations and rate limits are wrong for replicas); set `true` only for a deliberate single-instance deployment |
| `AUTHKIT_REGISTRATION_VERIFICATION` | no | `none` | `none`/`optional`/`required` (`required` needs a configured sender) |
| `AUTHKIT_API_PREFIX` | no | `/api/v1` | Mount prefix for browser routes |
| `AUTHKIT_MIGRATE_ON_START` | no | `false` | Apply the schema before serving. Prefer the one-shot `migrate` command in prod. |
| `AUTHKIT_API_KEY_PREFIX` | no | — | Branded prefix for issued API keys |
| `AUTHKIT_TRUSTED_PROXIES` | no | — | Comma-separated CIDRs of your reverse proxies / load balancers. Client IP (rate limiting, auditing) is derived from `X-Forwarded-For` **only** when the peer is inside one of these; otherwise `RemoteAddr` is used. Required for correct per-IP rate limiting behind any proxy. |
| `AUTHKIT_DIRECT_PEER_IP` | no | `false` | Assert that no proxy sits in front (`RemoteAddr` is the end client). Production-like environments refuse to start without an IP posture: this, `AUTHKIT_TRUSTED_PROXIES`, or `AUTHKIT_CLOUDFLARE_PROXIES`. |
| `AUTHKIT_CLOUDFLARE_PROXIES` | no | — | Cloudflare's published egress CIDRs. A peer inside these also gets `CF-Connecting-IP` honoured when `X-Forwarded-For` is absent. Set it **only** where Cloudflare fronts the origin, and lock the origin to Cloudflare ingress. |
| `AUTHKIT_ACCESS_TOKEN_TTL` | no | `15m` | Access-token lifetime (Go duration) |
| `AUTHKIT_REFRESH_TOKEN_TTL` | no | — | Refresh-token lifetime (Go duration). Unset ⇒ indefinite sessions |
| `AUTHKIT_SESSION_MAX_PER_USER` | no | `3` | Max concurrent refresh sessions per user (evict-oldest). `-1` ⇒ unlimited |
| `AUTHKIT_REFRESH_ROTATION_GRACE` | no | `30s` | How long a just-rotated refresh token is still answered with the successor it rotated into, so two holders of one token do not revoke each other's family (ak#274). Negative ⇒ strictly single-use rotation |
| `AUTHKIT_VERIFICATION_SEND_TIMEOUT` | no | `15s` | Per email/SMS provider-send bound (verification codes, reset links, login codes) |
| `AUTHKIT_2FA_MODE` | no | `optional` | `disabled` / `optional` / `required` |
| `AUTHKIT_2FA_METHODS` | no | all | Comma-separated subset of `email,sms,totp` |
| `AUTHKIT_PASSKEY_RPID` | no | issuer host | WebAuthn relying-party ID |
| `AUTHKIT_PASSKEY_RP_DISPLAY_NAME` | no | issuer | WebAuthn relying-party display name |
| `AUTHKIT_PASSKEY_ORIGINS` | no | issuer origin | Comma-separated allowed WebAuthn origins (must match RPID or a subdomain) |
| `AUTHKIT_LANGUAGES` | no | `en` | Comma-separated supported UI languages (`?lang` / `Accept-Language` negotiation) |
| `AUTHKIT_DEFAULT_LANGUAGE` | no | `en` | Fallback language when the request carries none. Must be in `AUTHKIT_LANGUAGES` — an effective default outside the supported set refuses to boot (#266) |
| `AUTHKIT_BOOTSTRAP_PATH` | no | — | Path to a bootstrap manifest (YAML; see `bootstrap.example.yaml` at the repo root). Applied **at most once** at startup (DB-marked apply-once); restarts skip it. It is a **genesis seed**: a database that already holds users/remote apps but has NO recorded bootstrap claim at all refuses to boot — unset the var for such deployments. A database another bootstrap name already claimed is treated as already applied. |

### Dev-only (honored only when `AUTHKIT_ENV` is a dev env)

Static dev entitlements (seeded into every access token for billing/entitlement
E2E) live in the bootstrap manifest's `dev.static_entitlements` section (#266) —
reviewable YAML, read at every boot (not part of the apply-once seed). A
**non-dev boot with the section set refuses to start**. A fixtures-only manifest
(just `dev:`) seeds nothing and skips the apply-once genesis path.

## Env doctrine (#231)

The AuthKit **library reads no environment variables** — this binary is the one
place env is read, once, in `loadConfig`. The library carries no environment
notion (#314): every dev behaviour is an explicit config field, and this binary
maps a dev `AUTHKIT_ENV` onto those fields — among them
`Keys.AllowEphemeralDevKeys`, so `go run ./cmd/authkit-server` still boots with
auto-generated dev signing keys (in memory; set `AUTHKIT_KEYS_PATH` to persist
them as `keys.json` across restarts). In any
non-dev env with no keys configured, the server **refuses to boot**.

JWT key material maps env → the explicit key-source config (#231): when
`AUTHKIT_ACTIVE_KEY_ID` / `AUTHKIT_ACTIVE_PRIVATE_KEY_PEM` (plus optional
`AUTHKIT_PUBLIC_KEYS`) are set, the binary builds a
`jwtkit.NewStaticKeySourceFromPEM(...)` and passes it as `Keys.Source`;
otherwise it passes `AUTHKIT_KEYS_PATH` as `Keys.Path` and the engine loads
`<path>/keys.json` (hot-reloaded on rotation).

**Env naming (#266):** every env var this binary reads carries the `AUTHKIT_`
prefix — unprefixed names are collision magnets in shared-env containers. The
one exception is the platform-conventional `DB_URL`/`DATABASE_URL` DSN pair
(setting both refuses to boot). A guard test (`env_doctrine_test.go`,
`TestBinaryEnvNamesAreAuthkitPrefixed`) enforces the prefix.

**Policy stays env-owned (#266, item 5 decision):** runtime policy knobs —
`AUTHKIT_REGISTRATION_VERIFICATION`, `AUTHKIT_2FA_MODE`, `AUTHKIT_2FA_METHODS`
— remain env config on this binary (embedded hosts pass them as
`embedded.Config` fields). The bootstrap manifest stays genesis-scoped:
identity seed data (users, remote applications) plus dev fixtures. Policy does
NOT move into the manifest — the manifest is apply-once, policy is per-boot,
and blending the two lifetimes would make the manifest a second, stale config
channel.

## Run

```sh
# Apply the schema (one-shot; needs only DB_URL):
DB_URL=postgres://... go run ./cmd/authkit-server migrate

# Then serve:
AUTHKIT_ISSUER=https://auth.example.com DB_URL=postgres://... go run ./cmd/authkit-server
```
