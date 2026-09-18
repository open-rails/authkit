# AuthKit workflow qualification

Run `scripts/check.sh` for the same checks as CI. The script starts local
PostgreSQL/Redis through Compose when `AUTHKIT_TEST_DATABASE_URL` is unset.
To use existing disposable services, set that variable and
`AUTHKIT_TEST_REDIS_URL`. Tests create isolated databases and Redis keyspaces.
Install the browser dependency once with:

```sh
pnpm --dir authhttp/testdata install --frozen-lockfile
pnpm --dir authhttp/testdata exec playwright install chromium
```

`workflows` and `contracts` select either half of the command. CI has one
workflow with those two qualification jobs plus a required security job and no
scheduled performance matrix. Go test results live in `.reports/`; a failing
test, skipped test or missing principal workflow fails the run. Packages with
no tests are compiled, not reported as skipped behavioral checks. Go modules
are released through Git tags; this change adds no publishing machinery.

## Six workflow groups

| Group | Retained behavior |
| --- | --- |
| Account admission | Password/passwordless registration through delivered email/SMS proofs, invitations, unknown-account nondisclosure, atomic code/link winner, replay and target/purpose binding, expiry/reissue and rollback. |
| Credentials and recovery | TOTP/SMS/backup factors, passkey/device/Solana signatures, restricted enrollment, step-up, password reset and provider-link grant invalidation, refresh race/grace/reuse, cross-issuer revocation. |
| Browser and provider authentication | Real two-site Chromium cookie workflow, OIDC/OAuth discovery/token exchange and browser state, MFA continuation, verified account linking and unverified/email-less identity refusal. |
| Authority and isolation | Group lifecycle, custom-role escalation, last-owner protection under concurrent departure, human/application authority, application trust withdrawal and namespace isolation. |
| Delegation | Host-authorized DPoP and certificate-bound grants, audience/key policy, exact sender and request binding, signed documents, key rotation, issuer withdrawal and proof replay. |
| Persistence and recovery | Fresh/custom schema migration, host bootstrap, erasure acknowledgements and purge, backend failure without partial enrollment, configured memory/Redis limits and fail-closed limiter outage. |

The main account journeys share the public `MountHandler`, real PostgreSQL and
real configured memory/Redis limiters. Their high per-IP allowance permits a
long legitimate lifecycle; `TestWorkflowRateLimits` separately proves a small
limit with wrong passwords, a correct password after exhaustion, forged
forwarding headers and a Redis client outage. Focused concurrency cases may
hold database locks or deny a backend command to make the race deterministic.
Fake identity providers are configured before mounting, as a host configures
its providers; there is no test-only per-request route reconstruction.

Small focused tests remain for password-hash input bounds, JWT key/algorithm
policy, DPoP and SIWS signatures, SSRF/network restrictions, document
canonicalization, stored issuer authority, the verify-only dependency boundary,
and the Gin/River adapters. Their fixtures are shared; the old per-handler and
per-private-helper repetitions are removed. Fixtures and helpers count toward
the test-maintenance budget.

The contracts job runs vet, SQLC generation/vet and the existing published
Go/migration/route/wire compatibility check. Compatibility alone is not an
authorization proof. These workflows do not qualify external identity or
message-delivery services, and they do not declare v1.
