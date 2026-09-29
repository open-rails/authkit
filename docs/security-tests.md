# Security tests

`internal/securitytest/` attacks AuthKit as a host embeds it: `authkit.New`
with its HTTP surface under `/auth/v1`, a scratch PostgreSQL database and a real
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
| Banned or deleted creator's API key or invite link keeps working | `TestSecurityDeadCreatorCredentials` |
| Bounded manager revokes a higher role's API key or invite link | `TestSecurityRevokeAboveOwnRole` |
| Group binds a reserved issuer or squats an unregistered one against its domain | `TestSecurityRemoteApplicationIssuerSquat` |
| Group or domain claims a shared-account peer issuer; peer user tokens replayed as delegations or sessions | `TestSecurityAccountPeerRemoteApplication` |
| Delegated grant carries AuthKit authority the user lacks, or keeps it after the user loses it | `TestSecurityDelegatedGrantClamp` |
| Go-path delegated mint for another user, by a machine actor, or with authority the user lacks | `TestSecurityDelegatedMintAuthority` |
| Delegated token used on AuthKit's own management routes, or keeping a banned user's authority at host gates | `TestSecurityDelegatedPrincipalManagementPlane` |
| Token shape (typ, subject claims, sender binding, issuer kind) verifies as another actor or an operator | `TestSecurityTokenMatrix` |
| Credentials manager re-keys or deletes an operator-registered application, or one holding roles they don't cover | `TestSecurityOperatorApplicationRekey` |
| Group registers an application above tier `registered`, or a re-key keeps an approval | `TestSecurityGroupApplicationTier` |
| Application holds an MFA-required role (assignment, bootstrap or a leftover row) or stands in for an MFA owner | `TestSecurityApplicationMFARoles` |
| Unproven issuer claim, left as last owner, blocks the domain that proves the issuer | `TestSecurityIssuerSquatLastOwner` |
| Application list paging repeats or skips rows, or accepts a forged cursor | `TestSecurityRemoteApplicationPaging` |
| OAuth `scope` claim on a service JWT grants permissions | `TestSecurityServiceJWTPermissionsOnly` |
| Issuer registered without an audience accepts every audience | `TestSecurityIssuerWithoutAudience` |
| Sibling subdomain plants or shadows the OIDC state cookie | `TestSecurityOIDCStateCookieIsHostPrefixed` |
| Providers sharing an issuer, or claiming this deployment's | `TestSecurityProviderIssuerCollisions` |
| Account invitation carried in a login URL; cross-site login start | `TestSecurityInviteTokenNotInURL` |
| Built-in provider without PKCE | `TestSecurityProviderPKCE` |
| Oversized form_post callback body | `TestSecurityFormPostCallbackIsBounded` |
| Outbound fetch to reserved ranges, including NAT64/6to4 | `TestSecurityOutboundAddressGuard` |
| Purged user's username re-registered | `TestSecurityPurgedUsernameStaysReserved` |
| Account edit, ban, delete, restore or session revoke by an actor lacking the `root:users` permission, or not covering the target's roles in root and every group | `TestSecurityAccountAuthority` |
| Email change plus reset strips MFA while MFA-required roles remain | `TestSecurityContactChangeKeepsMFARoles` |
| Host marks a squatter's address verified and the squatter's credentials survive | `TestSecurityVerifiedOnlyByProof` |
| Inline password clears the fresh-auth gate for an account with a second factor | `TestSecurityInlinePasswordNeedsSecondFactor` |
| API keys and invite links outlive their issuer's ban or deletion | `TestSecurityAccountLifecycleRevokesCredentials` |
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
| Bootstrap manifest adopts a squatted username, alias (live or expired) or unverified address, or marks its contacts verified | `TestSecurityBootstrapNeverAdoptsSquatters` |
| First-admin seed adopts a pre-registered account, binds by username, or lets its unproven account sign in without proof | `TestSecurityEnsureUserRole` |
| Import reports a row without its account, stores an invalid hash, or merges into an account bound by username or unverified address | `TestSecurityImportUsers` |
| Imported wallet becomes a login method or moves between accounts | `TestSecurityImportSolanaLinks` |
| Non-operator links a provider identity; an operator link reaches another account | `TestSecurityLinkProvider` |
| Stolen session plus password on an account with a second factor: password step-up, or a password-refreshed session, clears the fresh-auth gate (backup codes, passkey, factor, provider link, address change, host `Sensitive` route) | `TestSecurityPasswordStepUpNeedsSecondFactor` |
| Device key enrolled before MFA signs in without it; an MFA-required role holder without a factor enrolls one; a password change leaves device keys | `TestSecurityDeviceKeyMFAGate` |
| API key registers an application; an application outranks, or outlives the authority of, the user who registered it | `TestSecurityApplicationRegistrar` |
| Squatter's invite links and account invitations survive the owner's first proof | `TestSecurityFirstProofRevokesSquatterInvitations` |
| Signing in restores an account staff deleted | `TestSecurityDeletionRecoveryIsSelfOnly` |
| Differently cased id slips a self-edit, self-ban or self-unban past the self rule | `TestSecuritySelfRulesUseCanonicalIDs` |
| Enrollment-only token acts as the user through `Verify` and `Allow` | `TestSecurityEnrollmentTokenOutsideMiddleware` |
| API key or application keeps a role after the host makes it need MFA | `TestSecurityMFARequirementRevokesMachineCredentials` |
| Adding a member by email reveals the account or adds it without consent; a failed verification link reveals the address's state | `TestSecurityMemberEmailIsAnInvitation` |
| Staff email change plus reset strips the second factor of an account holding no MFA role | `TestSecurityContactChangeKeepsEnrolledMFA` |
| Banned account's live token creates a group | `TestSecurityBannedTokenCreatesNoGroup` |
| API key minted for a persona that does not enable keys | `TestSecurityAPIKeysNeedPersonaOptIn` |

The cookie compatibility guard `TestCookieRegistry` (`internal/engine`) pins the cookies
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
backend outage (`TestWorkflowRateLimits`); adding a member by email is an invitation
only the proven address accepts (`TestAddMemberByEmailNeverBindsAnUnprovenAccount`);
custom-role changes need the holders' authority
(`TestCustomRoleChangesNeedHolderAuthority`); MFA follows permissions
(`TestMFAFollowsPermissions`); no credential outlives its issuer, including
across a role-catalog change at boot (`TestNoCredentialOutlivesItsIssuer`,
`TestRoleCatalogChangesAtBoot`).

Known open risks are tracked in the AuthKit tracker (#392 and its follow-ups).
