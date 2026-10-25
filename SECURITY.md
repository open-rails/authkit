# Security

## Reporting a vulnerability

Report it privately. Don't open a public issue, pull request or discussion.

Email the contact address on the [Open Rails GitHub organization](https://github.com/open-rails). Include the version or commit, what an attacker can do, and a reproduction if you have one. We'll confirm we got it, ship the fix in a release, and agree a disclosure date with you.

## Supported versions

Only the latest v1 release gets security fixes. Upgrades within v1 are additive ([stability](docs/stability.md)).

## Security contracts and regression coverage

The critical suite uses real PostgreSQL, Redis, HTTP servers and public clients. Its named scenarios and initial scope are described in [critical/README.md](critical/README.md). CI rejects skipped or missing selected scenarios and retains govulncheck and Trivy. The table distinguishes implemented regression coverage from expansion work; it is not a claim that every input or optional protocol has been tested.

| Contract | Critical regression coverage |
|---|---|
| Host operations such as bootstrap/import are trusted embedded capabilities. A fabricated identity does not gain request authority; unverified imported contacts cannot be adopted for privileged provisioning. | AK-J02, AK-J15 |
| With verification required, an account with no proven contact never signs in on its password alone: while no channel can send its code the sign-in is refused and logged. | AK-J04-C06 |
| Public identity projections exclude private contact and credential data. Tenant-bound lookups retain the selected directory and do not reidentify an actor. | AK-J02-C01/C05 |
| Permissions come from live authority, not role claims supplied by the caller. Group and personal credentials stay within their issuer, scope and permission ceiling. | AK-J15, AK-J16, AK-J17 |
| Asymmetric JWT verification rejects wrong keys, algorithms, token profiles, issuer, audience and expired/future time bounds. DPoP binds proofs to key, request and token, with replay protection. | AK-J13, AK-J14 |
| Stateless `Verify` and `verify.Required` can admit an unexpired token after logout. Live session/permission gates and `Client.Authenticator()` refuse it. Refresh concurrency returns one successor; password changes, ban, deletion and revocation retire authority. | AK-J05; AK-J31-C01/C02 |
| Cookie refresh transport keeps refresh tokens out of JSON. Cookies are HttpOnly, Secure on HTTPS, SameSite=Lax, scoped by issuer/tenant; origin and fetch-site checks reject cross-site mutations. | AK-J31-C05 and the browser suite |
| Route budgets apply before authentication. Forwarded client-address headers are trusted only from configured proxies. Redis failure falls back to per-process replay protection, so replicas no longer provide a shared replay guarantee during that outage. | AK-J04-C05; AK-J14-C06; AK-J31-C05/C06 |
| Password, contact, device and MFA proofs do not issue authority for the wrong account, scope, expired proof or replay. Required MFA cannot be satisfied by email-only elevation. Sensitive mutations require recent proof tied to the active session. | AK-J03, AK-J04, AK-J06, AK-J07, AK-J08, AK-J33 |
| Group-owned API keys survive their creator's departure or deletion. Revocation, expiry, role deletion and group lifecycle retire them. User-owned personal tokens remain limited by their owner's live authority and never become an interactive account session. | AK-J16, AK-J17 |
| Account deletion remains recoverable only within its allowed lifecycle. Due cleanup retries failures, fences restoration while purging, catches up on restart and preserves live credentials during maintenance. | AK-J25, AK-J32 |
| The retained event log contains committed events, supports independent readers and explicit cursor expiry, and enforces current scoped read authority. | AK-J26 |
| Malformed/oversized JSON and unsupported body media types fail without changing the account. Real store outages remain distinct from known-invalid credentials; external sender/provider failure does not issue a session. | AK-J31-C04/C06 |

Optional provider, passkey, device-key, OAuth federation/consent and directory synchronization have selected admission probes in the initial suite; their full successful protocol journeys are expansion work. Password hashing/storage algorithms and memory-budget protection remain runtime contracts of `internal/password`, `internal/apikey` and `internal/engine`; the initial suite does not claim complete load, cryptographic implementation or log-redaction auditing.

## Your part

- Serve AuthKit over HTTPS.
- Declare exactly what sits in front of it (`HTTPConfig.TrustedProxies`, `CloudflareProxies` or `DirectPeerIP`). A wrong answer puts every client in one rate-limit budget, or lets clients choose their own address.
- Running more than one replica, set `Deps.Redis`. Otherwise, and while Redis is down, each process keeps its own rate-limit budgets.
- Keep the key directory (`KeysConfig.Path`: `keys.json` and `totp.key`) readable only by your server. See [keys](docs/keys.md).
