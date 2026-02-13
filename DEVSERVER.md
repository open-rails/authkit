# AuthKit Devserver (Local Issuer + JWT Minting)

This repo includes a **dummy/standalone devserver** that runs AuthKit against Postgres and can mint JWTs for end-to-end testing of downstream services (e.g. `~/doujins-billing`).

## What it provides

- `GET /.well-known/jwks.json` — public keys (JWKS) for JWT verification
- `POST /auth/dev/mint` — **dev-only** endpoint to mint JWTs (guarded by env + shared secret)
- AuthKit API routes under `/auth/*` (mounted for E2E testing AuthKit itself)

## Run with docker-compose

```bash
docker compose -f docker-compose.devserver.yaml up --build
```

This starts:
- Postgres on `localhost:5432`
- AuthKit devserver on `localhost:8080`

Generated dev signing keys are persisted via a docker volume mounted at `/.runtime/authkit`.

## All-in-one image (embedded Postgres)

For downstream E2E testing, it can be convenient to run **a single container** that bundles:
- Postgres 17
- AuthKit devserver

This is published as an image (no `../authkit` checkout required) and is intended for local/E2E use only:
- Docker Hub: `openrails/authkit-test-issuer` (tags: `latest`, `v*`)

```bash
docker compose -f docker-compose.devserver.all-in-one.yaml up
```

Notes:
- The all-in-one image enables the dev mint endpoint by default with `AUTHKIT_DEV_MINT_SECRET=change-me` to stay zero-config for E2E.
- Postgres is bound to `127.0.0.1` inside the container (not exposed to other containers).
- Persisted volumes:
  - Postgres data: `/var/lib/postgresql/data`
  - Dev signing keys: `/.runtime/authkit` (JWKS stability across restarts)

## Environment variables

Required:
- `DB_URL` (or `DATABASE_URL`) — Postgres connection string
- `AUTHKIT_ISSUER` — issuer URL embedded in tokens (e.g. `http://issuer:8080` in compose)

Dev minting (optional, but required for billing E2E):
- `AUTHKIT_DEV_MODE=true`
- `AUTHKIT_DEV_MINT_SECRET=...`

Registration behavior:
- `AUTHKIT_SKIP_EMAIL_VERIFICATION=true` — when set, `/auth/register` creates users immediately (email_verified=true) without requiring confirmation.

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

These tests spin up `docker-compose.devserver.yaml` and hit the devserver over HTTP:

```bash
go test -tags=e2e ./testing -run DevserverE2E
```
