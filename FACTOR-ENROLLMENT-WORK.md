# AuthKit #281 work record

Owner: Codex authkit_enrollment_fix agent
Purpose: require fresh authentication for 2FA enrollment and prevent factor replacement.
Branch: fix/ak281-factor-enrollment
Base: 364740b (origin/master)
Worktree: /home/fidika/cozy/.worktrees/authkit/ak281-factor-enrollment

PR: https://github.com/open-rails/authkit/pull/81

Implemented behavior:
- All full-session POST /user/2fa requests require fresh authentication, with the account's current factor state determining whether MFA is needed.
- Restricted 2fa_enrollment tokens may add the first factor only. The restriction is checked again under the user-row lock when persisting the factor.
- Existing methods cannot be replaced, including concurrent enrollment. Insert-only storage and serialized factor mutations preserve the original secret, default, and backup codes.
- Enrollment does not update the session authentication time or authentication methods. Sensitive actions still require the appropriate step-up.

Client contract:
- Handle 403 step_up_required using the returned step-up methods, obtain the fresh access token, then retry enrollment with that token.
- Handle 409 2fa_factor_exists by showing the existing factor. Replacing a method requires explicit authenticated deletion before enrollment.
- The restricted enrollment token is also issued when refresh discovers mandatory enrollment. It is not universally evidence of a newly verified password; first-factor scope applies regardless of issuance path.

Consumer census:
- Doujins frontend/src/queries/twoFactorQueries.ts calls POST /user/2fa.
- Doujins frontend/src/components/account/TwoFactorAuth.tsx currently presents failures as generic messages; adding its step-up interaction remains a frontend follow-up.
- The login enrollment dialog calls the same route with the restricted enrollment token and remains supported by the first-factor flow.
- No public Go Client/facade enrollment methods changed; changed signatures belong to the internal engine and its in-repository test callers.

Validation uses an isolated ak281 database on the audit-owned PostgreSQL 15434 server, with memory KV and no live providers or external notification delivery. Tracker owner coordinates merge and frontend follow-up tracking.


Completed checks:
- Full race suites passed: authhttp, internal/authcore, internal/db/querytest, embedded, verify, and root package.
- PostgreSQL concurrency regressions passed for simultaneous same-method and different-method first enrollment.
- HTTP regressions passed for stale sessions, immutable TOTP factors, unchanged session assurance, protected-route denial after enrollment, and refresh-issued first-factor tokens.
- sqlc generation and database-backed vet passed; git diff --check passed.
