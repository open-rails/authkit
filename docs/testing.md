# AuthKit workflow qualification

The test consolidation tracked in open-rails-tracker #1013 replaces repeated
handler and implementation tests with six maintained workflow groups:

1. Account admission: password/passwordless registration, invitations, contact
   verification and atomic, target-bound, single-use proofs.
2. Credentials and recovery: factors, native credentials, refresh families,
   step-up, password reset and revocation.
3. Browser authentication: real cookie origins, provider login/linking and
   browser return paths.
4. Authority and isolation: groups, roles, final owners, application identities
   and independent issuers sharing storage.
5. Delegation: DPoP and certificate-bound grants, document authority, key
   rotation, withdrawal and replay refusal.
6. Persistence and recovery: fresh/custom schemas, host bootstrap, lifecycle
   maintenance and backend failures.

Qualification uses PostgreSQL, the production HTTP mount and rate limiter, and
Redis where configured. Memory and Redis both exercise single-use proofs.
Crypto, encoding and concurrency boundaries retain small focused tests where a
workflow cannot reliably isolate the invariant. External delivery and identity
providers are local test servers; these tests do not qualify live providers.

The consolidation removes superseded tests only after the retained workflow
asserts their required behavior. CI will run these workflows and a small set of
critical guards, with no weekly performance matrix or duplicated scanners.
