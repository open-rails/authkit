# Security tests

`securitytest/` attacks AuthKit as a host embeds it: `embedded.New` with the
`authhttp` surface under `/auth/v1`, a scratch PostgreSQL database and real
memory/Redis stores. Every test runs in the `workflows` CI job;
`scripts/check.sh` fails the job if any listed test is skipped or missing.
Add a row and a test for every new attack class.

| Threat | Test |
|---|---|
| JWT forgery: `alg=none`, HS256 keyed with the RSA public key, attacker key under the real `kid`, unlisted alg, `kid` traversal, `jku`/embedded `jwk`, swapped payload, wrong/missing `aud`/`iss`, expired, missing `exp`, future `nbf`/`iat`, token-type confusion | `TestSecurityAccessTokenForgery` |
| Bearer token in query string or non-Bearer scheme | `TestSecurityBearerTransport` |
| Stolen refresh token replayed after rotation (either party) revokes the family | `TestSecurityRefreshTokenTheft` |
| Rotation grace window forks a session | `TestSecurityRefreshGraceDoesNotFork` |
| Refresh after logout, revoke-all, admin password set, emergency revoke, ban, soft delete, including on a second replica | `TestSecuritySessionRevocationEvents` |
| Stolen session survives the owner's password change | `TestSecurityPasswordChangeEndsOtherSessions` |
| Revoked session's access token sets a password, adds a passkey or factor, or deletes the account | `TestSecurityRevokedSessionCannotChangeCredentials` |
| Delegated token minted from a logged-out session or banned/deleted account | `TestSecurityDelegationOutlivingRevocation` |
| Stranger locks a user out of 2FA by user id | `TestSecuritySecondFactorLockout` |
| 2FA guesses reset by resend or address rotation | `TestSecuritySecondFactorGuessBudget` |
| Self-unban or unban of a more privileged account | `TestSecurityUnbanRequiresAuthority` |
| Credentials manager swaps keys of, disables or deletes an owner application | `TestSecurityRemoteApplicationTakeover` |
| Role, custom-role, invite-link and API-key escalation; cross-group action; root routes with a group role | `TestSecurityRoleEscalation` |
| Per-process limits/state in a multi-replica deployment | `TestSecurityMultiReplicaStores` |
| Forged `X-Forwarded-For`/`CF-Connecting-IP` resets rate limits | `TestSecurityClientAddressSpoofing` |
| Removed signing key still accepted or published; new key not published | `TestSecurityKeyRotationIsPublished` |
| Cross-site refresh-cookie use, cookie tossing, body tokens on cookie mounts, cross-site cookie login | `TestSecurityRefreshCookieCSRF` |
| Oversized, malformed, unknown-field and SQL-metacharacter bodies; CORS reflection; internal detail in errors | `TestSecurityRequestBoundary` |
| Account enumeration through login and reset responses | `TestSecurityAccountEnumeration` |
| Unproven account adds a provider link, passkey, factor or wallet | `TestSecurityUnprovenContactCannotAddLoginMethods` |
| Pre-registration takeover: attacker's sessions, password, links, device keys or factors survive the owner's first proof (reset, email code, verification on another device) | `TestSecurityPreRegistrationTakeover` |
| Registration marks an address verified without proof | `TestSecurityRegistrationNeverSelfVerifies` |
| Untrusted provider's `email_verified` stores or matches an address | `TestSecurityProviderEmailTrust` |

Covered by the workflow suites (see [testing](testing.md)): OIDC state
binding, single use, provider mix-up, nonce and PKCE
(`TestOIDCCallbackStateIsBoundAndSingleUse`); `return_to` sanitising; no
auto-link by email and unverified provider email (`TestProviderAuthenticationWorkflow`);
code/link single winner and reset-grant invalidation
(`TestAccountAdmissionWorkflow`, `TestCredentialTransactionsResetGrantsExpireOnCredentialChanges`);
2FA code retry semantics (`TestTwoFactorCodeSurvivesWrongGuess`); last-owner
and role-owner races (`TestRoleOwnerWorkflow`); DPoP and delegated scope
(`TestBrowserDelegationWorkflow`); rate-limit backend outage (`TestWorkflowRateLimits`).

Known open risks are tracked in the AuthKit tracker (#392 and its follow-ups).
