# HTTP

This page covers how AuthKit's HTTP surface is mounted and what sits around it. The routes and their schemas are in [`api/openapi.json`](../api/openapi.json), and the wire conventions are in [Stability](stability.md#http-api).

## Mounting

Setting `Config.HTTP` gives the Client one handler for the whole surface. There are four ways to mount it:

- `Client.Handler()`, mounted at the host's root, because its paths already include `BasePath`;
- `Client.Mount(mux)` on a `ServeMux`;
- `adapters/gin.Mount`;
- `adapters/fiber.Mount`.

Every route lives beneath `HTTPConfig.BasePath`:

| Path | Serves |
|---|---|
| `{BasePath}{APIPath}/v1/…` | the JSON API; `APIPath` defaults to `/api`, and AuthKit owns `/v1` |
| `{BasePath}/oidc/{provider}/…` | browser sign-in with an identity provider |
| `{BasePath}/.well-known/jwks.json` | the public signing keys |

`BasePath` defaults to the path of `TokenConfig.Issuer`. When the issuer is a URL, `BasePath` must equal that path, because verifiers look for JWKS at the issuer plus `/.well-known/jwks.json`. Serve the paths unchanged, with no prefix stripping in front. If a proxy changes the origin or the path clients see, set `HTTPConfig.PublicURL`; DPoP proofs name it.

## Which routes are mounted

- A route is mounted only when its feature is on. Each feature has its switch, such as `Passkeys`, `TwoFactor`, `DeviceKeys.Enabled`, `Delegated.Audiences`, `SolanaNetwork` or `Deps.Providers`. The OpenAPI entry's `x-authkit-mounted-when` names the feature.
- `Invitations.Disabled` turns invitations off: the four invitation routes go, `/capabilities` reports `invitations.enabled` false, and issuing or redeeming one is `invitations_disabled`.
- `HTTPConfig.Groups` limits the surface to route groups (`iam.RouteGroup`); nil mounts them all.
- `HTTPConfig.Exclude` drops individual routes the host serves itself.
- `Client.Routes()` lists what is mounted.
- `Deps.Wrap` decorates each handler: logging, tracing, CORS. AuthKit sets no CORS headers of its own.

## Browsers

- With `HTTPConfig.RefreshCookie`, the refresh token lives only in an `HttpOnly` `__Host-authkit_rt` cookie, and never in a response body.
- The single-page app and AuthKit must then share an origin. Cookie mounts refuse cross-site requests (by `Origin` and `Sec-Fetch-Site`) and refresh tokens sent in bodies.
- Links in emails and the OIDC return go to the host's frontend routes (`Config.Frontend`). `BaseURL` defaults to the issuer.
- Register one redirect URI at each identity provider: `{BasePath}/oidc/{provider}/callback` as clients reach it (under `PublicURL` when set). Sign-in, linking and step-up all return there.

## Client addresses and rate limits

- `New` requires you to declare what sits in front of AuthKit: `HTTPConfig.TrustedProxies`, `CloudflareProxies` or `DirectPeerIP`, or `Deps.ClientIP`. Forwarded-address headers count only from the declared proxies.
- Every route has a rate-limit bucket (`x-authkit-rate-limit` in the OpenAPI). Budgets are per client address; an IPv6 address counts per /64. Emailed and texted codes also have per-account and per-destination budgets.
- `DefaultRateLimits()` holds the defaults. `HTTPConfig.RateLimits` overrides buckets by name; an unknown name is an error.
- Counters live in each process's memory. Set `Deps.Redis` when you run more than one replica, to share them.
- If Redis fails, each process counts on its own with the same limits until Redis answers again, so no budget is ever lifted. A request waits on Redis for at most 250ms, and AuthKit logs the fallback and the recovery once each.
- A 429 is `rate_limited` with `Retry-After`, the `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` headers, and the budget in `metadata`.
