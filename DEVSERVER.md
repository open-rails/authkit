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

## Environment variables

Required:
- `DB_URL` (or `DATABASE_URL`) — Postgres connection string
- `DEVSERVER_ISSUER` — issuer URL embedded in tokens (e.g. `http://issuer:8080` in compose)

Dev minting (optional, but required for billing E2E):
- `DEVSERVER_DEV_MODE=true`
- `DEVSERVER_DEV_MINT_SECRET=...`

Registration behavior:
- `AUTH_REQUIRE_VERIFIED_REGISTRATIONS` (bool, default `true`) — the standard
  first-party embedder knob (issue #67). `true` maps to
  `core.RegistrationVerificationRequired` (verification gates login); `false`
  maps to `core.RegistrationVerificationOptional` (a verification email/SMS is
  still sent when a sender is configured but never blocks login; with no sender
  configured, users are created verified and nothing is sent). With no sender,
  the devserver logs verification codes to stdout (`[authkit/dev-email] ...`).
  The legacy `DEVSERVER_REGISTRATION_VERIFICATION` tri-state is rejected at
  boot with a migration hint; the `none` tier is no longer reachable from the
  devserver env (library embedders can still pass
  `core.RegistrationVerificationNone`).

Tenant manifest bootstrap:
- `DEVSERVER_TENANT_MANIFEST_PATH=/path/to/tenants.yaml` - strict YAML manifest declaring tenants, trusted tenant issuers, roles, and optional service token outputs.
- `DEVSERVER_RECONCILE_TENANT_MANIFEST_ON_START=true` - opt-in startup hook. When enabled, the devserver applies the manifest after migrations and before serving traffic.
- `DEVSERVER_PERMISSION_CATALOG=repo:read,endpoint:deploy` - app permission catalog used when manifest roles include host-defined permissions.
- `DEVSERVER_TOKEN_PREFIX=cozy` - brand prefix for opaque service tokens minted by the manifest reconciler.

For production-style deploys, prefer the one-shot command below as a Kubernetes
Job or release step, using a deploy identity with DB write access and secret
output access:

```bash
DEVSERVER_ISSUER=https://auth.example \
DB_URL=postgres://... \
DEVSERVER_TENANT_MANIFEST_PATH=/manifests/tenants.yaml \
/authkit-devserver tenant-manifest apply
```

The bundled command supports local file token outputs through AuthKit's
`FileTenantManifestTokenStore`. Hosts that write to Vault, Kubernetes Secrets,
or another backend should call `core.ReconcileTenantManifest` with their own
`TenantManifestTokenStore` implementation.

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
