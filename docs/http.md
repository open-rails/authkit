# HTTP

This page covers how AuthKit's HTTP surface is mounted and what sits around it. The routes and their schemas are in [`api/openapi.json`](../api/openapi.json), and the wire conventions are in [Stability](stability.md#http-api).

## Mounting

Setting `Config.HTTP` gives the Client one handler for the whole surface. There are four ways to mount it:

- `Client.Handler()`, mounted at the host's root, because its paths already include the issuer's path;
- `Client.Mount(mux)` on a `ServeMux`;
- `adapters/gin.Mount`;
- `adapters/fiber.Mount`.

Every route lives beneath the issuer's path, `{path}` (empty for an issuer at its origin's root):

| Path | Serves |
|---|---|
| `/auth/v1/…`, or `{path}/v1/…` beneath an issuer's path | the JSON API |
| `{path}/oidc/{provider}/…` | browser sign-in with an identity provider |
| `{path}/.well-known/jwks.json` | the public signing keys |

`Config.Issuer` is an https URL; `http://` is accepted only on a loopback host (`localhost`, `127.0.0.1`, `[::1]`, any port) for local development. `Config.FrontendURL` (the issuer's origin when empty) follows the same rule, and its scheme decides whether cookies are `Secure` and `__Host-`. Serve the paths unchanged, with no prefix stripping in front. A proxy in front keeps the issuer's URL: DPoP proofs and assertions name it.

## Which routes are mounted

- `HTTPConfig.Groups` selects the route groups (`iam.RouteGroup`); nil is `iam.DefaultRouteGroups()`, every group but the opt-in ones: passwordless sign-in (`iam.RoutePasswordless`), device keys (`iam.RouteDeviceKeys`) and personal access tokens (`iam.RoutePersonalAccessTokens`). Each of those features is on exactly when its group is mounted.
- Without `iam.RouteInvitations` invitations are off: the four invitation routes go, `/capabilities` reports `invitations.enabled` false, and issuing or redeeming one is `invitations_disabled`.
- Within a mounted group, a route is mounted only when its feature is on, such as `Registration`, `TwoFactor`, `AuthorizationServer.Clients`, `SolanaNetwork` or `Deps.Providers`. The OpenAPI entry's `x-authkit-mounted-when` names the feature.
- `Client.Routes()` lists what is mounted.
- `Deps.Wrap` decorates each handler (logging, tracing, CORS), or replaces one the host serves itself, JWKS included. AuthKit sets no CORS headers of its own.
- Every answer is `Cache-Control: no-store`, refusals and unknown paths included, except the successful answers of the public metadata: JWKS (`public, max-age=300, must-revalidate`), `/capabilities` and the authorization server's metadata documents (`public, max-age=300`).

## Browsers

- The refresh token lives only in an `HttpOnly` issuer-specific `__Host-authkit_rt_<issuer-hash>` cookie, and never in a response body.
- The single-page app and AuthKit must share an origin. Cookie mounts refuse cross-site requests (by `Origin` and `Sec-Fetch-Site`) and refresh tokens sent in bodies.
- Links in emails and the OIDC return go to fixed routes beneath `Config.FrontendURL`: `/verify`, `/reset`, `/passwordless`, `/invite`, `/authorize` and `/login/callback`.
- Register one redirect URI at each identity provider: `{issuer}/oidc/{provider}/callback`. Sign-in, linking and step-up all return there.

## Client addresses and rate limits

- `New` requires you to declare what sits in front of AuthKit, once: its proxies (`HTTPConfig.TrustedProxies`, with `CloudflareProxies` where Cloudflare fronts the origin), `DirectPeerIP` for none, or `Deps.ClientIP` for your own extraction. It refuses none, and more than one. Forwarded-address headers count only from the declared proxies; with `DirectPeerIP` the client is the TCP peer.
- Every route has a rate-limit bucket (`x-authkit-rate-limit` in the OpenAPI). Budgets are per client address; an IPv6 address counts per /64. Emailed and texted codes also have per-account and per-destination budgets.
- A code typed before anything is proven belongs to the start that sent it. `POST /passwordless/start`, `/verify/request`, `/register` and `PUT /me/email`, `/me/phone` answer 202 `{"challenge": "…"}`, a random 128-bit handle, and the code is confirmed with it: `{"challenge", "code"}` at `POST /passwordless/confirm` or `/verify/confirm`; an `identifier` sent beside it must be the address the code went to. A code is checked only against the challenge it names, and five wrong codes burn that challenge alone. A start never replaces another, so nobody else's start or guesses spend your code. A link keeps its own token (`{"token"}`). A sign-in parked at `verification_required` carries its code's `verification.challenge`.
- Each email or phone a start sends to also has a send quota, beside the route's per-client-address budget: `passwordless_start_identifier` (30 an hour), `verify_request_identifier` (45, shared by `/verify/request` and the contact changes), `register_create_identifier` (12), `password_reset_request_identifier` (12) and `device_key_enroll_begin_identifier` (30, per email and per public key). It never refuses: past it nothing is stored or sent, and the answer is the one a sent code gets, whether or not the address has an account. Each allows at least twice what one client address may send there and has no cooldown, so one client cannot spend another account's codes. Confirming has no budget per email or phone, only the route's per-client-address one (`passwordless_confirm`, `verify_confirm`); guessing is bounded by five per challenge times the send quota. `sms_number` and `sms_account` (30 an hour) are quotas of the same kind on every text message: a code start past them answers alike and sends nothing, and any other send is refused with `rate_limited`.
- Password sign-in also has a failed-attempt budget per identifier (email, username or phone, in any case): `password_login_identifier`, 20 an hour, beside the route's per-address `password_login`. It is spent before the account is looked up, so an identifier with no account is refused the same way, and given back when the account's own password proves right and the sign-in goes on; a pending sign-up's password does not count as that. Each identifier has its own budget, so an account's email, phone, username and forwarding former names each get one; a refusal never shows which identifiers share an account. Once it is spent the right password is refused too, until the window frees an attempt; a password reset does not lift it. Codes, passkeys and provider sign-in do not use it.
- The budgets are fixed; only tests lift them (`authtest.LiftLimits`).
- Counters live in each process's memory. Set `Deps.Redis` when you run more than one replica, to share them.
- If Redis fails, each process uses its own counters with the same limits until Redis answers again. Shared and local counter history is not transferred: a process can admit its local allowance after the shared budget was spent, and replicas have separate allowances during the outage. The fallback remains bounded, but it does not preserve a global budget across the transition. A request waits on Redis for at most 250ms, and AuthKit logs the fallback and the recovery once each.
- Spent DPoP proofs (the token endpoint, userinfo, SCIM and `Client.NewVerifier`) and spent JWT-bearer and client assertions (RFC 7523) are kept in `Deps.Replays` when the host gives one, else in `Deps.Redis`, else in memory. Unlike counters they have no fallback: while that store fails, a proof or assertion is refused (5xx, or 503 `temporarily_unavailable` at the token endpoint), since a spend another replica cannot see would let the same proof pass there. A host with several replicas and no Redis implements `verify.ReplayStore` on the store they share (an insert-if-absent with an expiry). A capability's `jti` is a grant record and stays in PostgreSQL.
- A 429 is `rate_limited` with `Retry-After`, the `RateLimit-Limit`, `RateLimit-Remaining` and `RateLimit-Reset` headers, and the budget in `metadata`.

## Sign-in limits

AuthKit counts distinct accounts and devices over a rolling 24 hours. Rate limits count requests per address, and failed passwords per identifier; these count who signs in where, which only AuthKit knows.

- **A device** is a browser's `__Host-authkit_device` cookie (`authkit_device` over plain HTTP): random, `HttpOnly`, `SameSite=Lax`, kept 400 days, granting nothing. Routes that sign in, and browser OIDC starts, set it when it is missing. A client without one is known by its address (per /64 for IPv6). A provider sign-in counts against the device that started it.
- **Accounts per device** (5; 20 per address without the cookie): distinct accounts that sign in or register from one device. Signing back into one of them is always allowed. The next account gets 429 `too_many_accounts`, and registration creates no account.
- **New devices per account** (10): new devices that sign in to one account. A device that signed in to it within 30 days is not new. Past the limit, a new device answers `device_verification_required`: a code went to the account's proven email (else its phone), telling the owner someone is signing in. `POST /device-verification/confirm` with the code finishes the sign-in (or asks for the second factor), and `/device-verification/send` sends another, at most 10 an hour. A sign-in that proved the owner's email or phone, or that a second factor finishes, needs no code. An account with no proven address gets 429 `too_many_devices`.
- Both 429s carry `Retry-After`, and `limit` and `retry_after_seconds` in `metadata`.
- The counts live in the short-lived store every replica shares (Postgres, with or without `Deps.Redis`). They hold only hashes of a device with an account, so they never list which accounts share a device, and they expire on their own.
- `authtest.New` turns the limits off, and `authtest.LiftLimits` lifts them for a Client a host's test rig builds itself.

Refresh cookie names are derived from the complete issuer, including its port, so multiple apps on one browser host keep independent sessions. Legacy unscoped cookies are accepted and retired only after their token is attributed to this issuer; foreign legacy cookies are left untouched.
