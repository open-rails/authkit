# AuthKit Devserver (Local Issuer + JWT Minting)

This repo includes a **dummy/standalone devserver** that runs AuthKit against Postgres and can mint JWTs for end-to-end testing of downstream services (e.g. `~/doujins-billing`).

## What it provides

- `GET /.well-known/jwks.json` — public keys (JWKS) for JWT verification
- `POST /auth/dev/mint` — **dev-only** endpoint to mint JWTs (guarded by env + shared secret)
- AuthKit API routes under `/auth/*` (mounted for E2E testing AuthKit itself)

## Run with docker-compose

```bash
docker compose up --build
```

This starts:
- Postgres on `localhost:35432`
- AuthKit devserver on `localhost:38080`

The devserver applies AuthKit's Postgres migrations before it starts serving.

Generated dev signing keys are persisted via a docker volume mounted at `/.runtime/authkit`.

## Environment variables

Required:
- `DB_URL` (or `DATABASE_URL`) — Postgres connection string
- `DEVSERVER_ISSUER` — issuer URL embedded in tokens (e.g. `http://issuer:8080` in compose)

Dev minting (optional, but required for billing E2E):
- `DEVSERVER_DEV_MODE=true`
- `DEVSERVER_DEV_MINT_SECRET=...`

Registration behavior:
- `DEVSERVER_REQUIRE_VERIFIED_REGISTRATIONS=false` — when false, `/auth/register` creates users immediately (email_verified=true / phone_verified=true when phone registration) without requiring confirmation.

Bootstrap manifest:
- `AUTHKIT_BOOTSTRAP_PATH=/path/to/bootstrap.yaml` - strict YAML manifest declaring AuthKit users, trusted remote applications, root roles, and group-role assignments. Defaults to `/etc/authkit/bootstrap.yaml`.
- `AUTHKIT_BOOTSTRAP_ON_START=true` - opt-in startup hook. When enabled, the devserver applies the manifest after migrations and before serving traffic. Startup apply is once-only by default and records a marker in `profiles.bootstrap_applies`.
- `DEVSERVER_PERMISSION_CATALOG=repo:read,endpoint:deploy` - app permission catalog used when manifest roles include host-defined permissions.

For production-style deploys, the CLI command applies/reconciles by default:

```bash
DEVSERVER_ISSUER=https://auth.example \
DB_URL=postgres://... \
AUTHKIT_BOOTSTRAP_PATH=/manifests/bootstrap.yaml \
/authkit-devserver bootstrap apply --file /manifests/bootstrap.yaml
```

It updates declared users, trusted remote applications, and role assignments,
but it does not delete omitted users, groups, roles, or remote applications.
Use `--startup-only` only for first-boot guarded apply semantics.

## Mint a JWT

```bash
curl -fsS http://localhost:8080/auth/dev/mint \
  -H "Authorization: Bearer change-me" \
  -H "Content-Type: application/json" \
  -d '{"sub":"11111111-1111-1111-1111-111111111111","aud":"billing-app","email":"test@example.com"}'
```

Response:
- `token` — the JWT
- `expires_at` — expiry timestamp

## Use from doujins-billing E2E

Configure billing to trust the issuer:
- `AUTH_ISSUERS='["http://issuer:8080"]'` (from inside compose network)
- `AUTH_EXPECTED_AUDIENCE=billing-app`

Then mint tokens from the issuer and call billing endpoints with:
- `Authorization: Bearer <token>`

## Run AuthKit E2E tests (docker-compose)

These tests spin up `docker-compose.yaml` and hit the devserver over HTTP:

```bash
go test -tags=e2e ./testing -run DevserverE2E
```

## Run the DB-backed Go suite

Start the compose issuer so migrations run, then use the Taskfile test target:

```bash
docker compose up -d --build issuer
task test
```
