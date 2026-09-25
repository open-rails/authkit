# Security tests

`securitytest/` attacks AuthKit as a host embeds it: `embedded.New` with the
`authhttp` surface under `/auth/v1`, a scratch PostgreSQL database and a real
Redis for shared rate limits. Every test runs in the `workflows` CI job;
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
| Demoted creator redeems their own invite link or keeps their API key | `TestSecurityDemotedCreatorCredentials` |
| Bounded manager revokes a higher role's API key or invite link | `TestSecurityRevokeAboveOwnRole` |
| Group binds a reserved issuer or squats an unregistered one against its domain | `TestSecurityRemoteApplicationIssuerSquat` |
| Group or domain claims a shared-account peer issuer; peer user tokens replayed as delegations or sessions | `TestSecurityAccountPeerRemoteApplication` |
| Delegated grant carries AuthKit authority the user lacks, or keeps it after the user loses it | `TestSecurityDelegatedGrantClamp` |
| Issuer registered without an audience accepts every audience | `TestSecurityIssuerWithoutAudience` |
| Sibling subdomain plants or shadows the OIDC state cookie | `TestSecurityOIDCStateCookieIsHostPrefixed` |
| Providers sharing an issuer, or claiming this deployment's | `TestSecurityProviderIssuerCollisions` |
| Account invitation carried in a login URL; cross-site login start | `TestSecurityInviteTokenNotInURL` |
| Built-in provider without PKCE | `TestSecurityProviderPKCE` |
| Oversized form_post callback body | `TestSecurityFormPostCallbackIsBounded` |
| Outbound fetch to reserved ranges, including NAT64/6to4 | `TestSecurityOutboundAddressGuard` |
| Purged user's username re-registered | `TestSecurityPurgedUsernameStaysReserved` |
| A token or code issued on one replica replayed or guessed across replicas; replicas share Redis rate-limit budgets | `TestSecurityMultiReplicaStores` |
| Stranger locks an account out with wrong passwords; guessing address keeps guessing; IPv6 address rotation within a /64 | `TestSecurityPasswordLimitIsPerAddress` |
| Forged `X-Forwarded-For`/`CF-Connecting-IP` resets rate limits | `TestSecurityClientAddressSpoofing` |
| Removed signing key still accepted or published; new key not published | `TestSecurityKeyRotationIsPublished` |
| Cross-site refresh-cookie use, cookie tossing, body tokens on cookie mounts, cross-site cookie login | `TestSecurityRefreshCookieCSRF` |
| Upgrade strands a browser holding an earlier release's refresh cookie (legacy path, plain name on HTTPS); sign-out leaves a historical variant; same-path duplicates | `TestSecurityRefreshCookieUpgrade` |
| Oversized, malformed, unknown-field and SQL-metacharacter bodies; CORS reflection; internal detail in errors | `TestSecurityRequestBoundary` |
| Account enumeration through login and reset responses | `TestSecurityAccountEnumeration` |
| Unproven account adds a provider link, passkey, factor or wallet | `TestSecurityUnprovenContactCannotAddLoginMethods` |
| Pre-registration takeover: attacker's sessions, password, links, device keys or factors survive the owner's first proof (reset, email code, verification on another device) | `TestSecurityPreRegistrationTakeover` |
| Registration marks an address verified without proof | `TestSecurityRegistrationNeverSelfVerifies` |
| Untrusted provider's `email_verified` stores or matches an address | `TestSecurityProviderEmailTrust` |

The cookie compatibility guard `TestCookieRegistry` (authhttp) pins the cookies
AuthKit sets to the append-only registry ([cookies](security/cookies.md)).

Covered by the workflow suites (see [testing](testing.md)): OIDC state
binding, single use, provider mix-up, nonce and PKCE
(`TestOIDCCallbackStateIsBoundAndSingleUse`); `return_to` sanitising; no
auto-link by email and unverified provider email (`TestProviderAuthenticationWorkflow`);
code/link single winner and reset-grant invalidation
(`TestAccountAdmissionWorkflow`, `TestCredentialTransactionsResetGrantsExpireOnCredentialChanges`);
2FA code retry semantics (`TestTwoFactorCodeSurvivesWrongGuess`); last-owner
and role-owner races (`TestRoleOwnerWorkflow`); DPoP and delegated scope
(`TestBrowserDelegationWorkflow`); per-address password limits and rate-limit
backend outage (`TestWorkflowRateLimits`).

Known open risks are tracked in the AuthKit tracker (#392 and its follow-ups).
