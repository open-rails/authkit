# Security

## Reporting a vulnerability

Report it privately. Don't open a public issue, pull request or discussion.

Email the contact address on the [Open Rails GitHub organization](https://github.com/open-rails). Include the version or commit, what an attacker can do, and a reproduction if you have one. We'll confirm we got it, ship the fix in a release, and agree a disclosure date with you.

## Supported versions

AuthKit is pre-v1. Only the latest release gets security fixes.

## What AuthKit guarantees

Each guarantee names the test or package that enforces it. The `TestSecurity*` tests live in `internal/securitytest` and attack a real AuthKit: its HTTP surface, PostgreSQL and Redis. CI fails when any test fails or is skipped, and runs govulncheck and a Trivy scan.

| Guarantee | Enforced by |
|---|---|
| **Only host code is trusted.** No request, token or body can build the system actor or reach a host operation (`CreateGroup`, `EnsureUserRole`, `ImportUsers`, …). | `TestRequestSurfaceCannotBuildActors` |
| **Authorization fails closed.** A user's authority is read live from the database on every operation and permission check; their token can't claim roles or permissions. The zero actor, an unknown or missing group, and a failed check all deny. Gating a route on an unregistered permission panics when the route is built. | `verify.RequirePermission`, `TestNativeUserTokenCannotSupplyRoleOrPermissionAuthority`, `TestSecurityRoleEscalation`, `TestSecurityAccountAuthority` |
| **Forged tokens don't verify.** Tokens are signed with asymmetric keys. Verifiers accept only RS256, ES256, ES384, ES512 and EdDSA (never `none` or HS*), and check the key id, `iss`, `aud`, `exp`, `nbf` and the token type. Bearer tokens are read only from the `Authorization` header. | `TestSecurityAccessTokenForgery`, `TestSecurityTokenMatrix`, `TestSecurityBearerTransport` |
| **Revocation is bounded.** Access tokens last 15 minutes by default, so a revoked session's token dies within that window. Refresh tokens rotate on every use; reusing a rotated one ends the session (a 30-second grace re-sends the same successor, never a second session). Logout, ban and deletion end refresh sessions, and a password change ends every other session. Refresh sessions last until revoked unless `TokenConfig.RefreshTokenDuration` is set. | `TestSecurityRefreshTokenTheft`, `TestSecurityRefreshGraceDoesNotFork`, `TestSecuritySessionRevocationEvents`, `TestSecurityPasswordChangeEndsOtherSessions` |
| **Browser refresh cookie.** With `HTTPConfig.RefreshCookie`, the refresh token lives only in `__Host-authkit_rt`: `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/`. Cookie mounts refuse cross-site requests (by `Origin` and `Sec-Fetch-Site`) and refresh tokens in bodies. | `TestSecurityRefreshCookieCSRF`, `TestCookieRegistry` |
| **Guessing is rate-limited.** Every route has a budget per client address (IPv6 per /64). Emailed and texted codes also have a budget per account or destination, and die after 5 wrong guesses. Passwords are limited per address only, so a stranger can't lock the owner out. If the limiter's backend fails, password, reset, verification and second-factor checks are refused. Forwarded-address headers count only from declared proxies. | `TestSecurityPasswordLimitIsPerAddress`, `TestSecuritySecondFactorGuessBudget`, `TestWorkflowRateLimits`, `TestSecurityClientAddressSpoofing` |
| **Secrets are stored hashed.** Passwords use Argon2id (bcrypt hashes are accepted on import), and common passwords are refused by default. Refresh tokens, API-key secrets, invite codes and one-time codes are stored only as SHA-256 digests. Authenticator-app secrets are encrypted with AES-GCM. | `internal/password`, `internal/apikey`, `internal/engine` |
| **Secrets stay out of events and errors.** An event never carries a password, hash, token or code. Error responses carry no internal detail. | `TestSecurityEventsCarryNoSecrets`, `TestSecurityRequestBoundary` |
| **Sensitive changes need a recent sign-in.** Managing second factors, backup codes, passkeys and linked sign-ins, changing an email or phone, and deleting the account need a recent sign-in. On an account with a second factor, that includes the factor: a stolen session plus the password is not enough. | `TestSecurityPasswordStepUpNeedsSecondFactor`, `TestSecurityInlinePasswordNeedsSecondFactor` |
| **Addresses are proven, never assumed.** An email or phone counts as verified only after its owner proves it. The first proof removes every password, session and login method a squatter added. | `TestSecurityVerifiedOnlyByProof`, `TestSecurityPreRegistrationTakeover`, `TestSecurityRegistrationNeverSelfVerifies` |
| **Sign-in and recovery don't reveal accounts.** Password sign-in, password reset and verification requests answer the same for known and unknown addresses. Registration does say when an email, phone or username is taken. | `TestSecurityAccountEnumeration`, `TestSecurityVerifyRequestRevealsNothing` |
| **Credentials don't outlive their creator's authority.** An API key or invite link stops working when its creator is demoted, removed, banned or deleted. | `TestNoCredentialOutlivesItsIssuer`, `TestSecurityDemotedCreatorCredentials`, `TestSecurityDeadCreatorCredentials` |
| **Social sign-in.** Built-in providers use PKCE wherever the identity provider supports it. OIDC state is single-use and bound to a `__Host-` cookie on HTTPS. A provider's `email_verified` counts only when the provider is trusted to verify email. | `TestSecurityProviderPKCE`, `TestOIDCCallbackStateIsBoundAndSingleUse`, `TestSecurityProviderEmailTrust` |
| **No server-side request forgery.** Fetches of JWKS and other host-supplied URLs refuse private and reserved addresses. | `internal/netguard`, `TestSecurityOutboundAddressGuard` |
| **Bounded requests.** JSON bodies are limited to 1 MiB and unknown fields are rejected. | `TestSecurityRequestBoundary` |

## Your part

- Serve AuthKit over HTTPS.
- Declare exactly what sits in front of it (`HTTPConfig.TrustedProxies`, `CloudflareProxies` or `DirectPeerIP`). A wrong answer puts every client in one rate-limit budget, or lets clients choose their own address.
- Running more than one replica, set `HTTPConfig.Redis`. Otherwise each process keeps its own rate-limit budgets.
- Keep the key directory (`KeysConfig.Path`: `keys.json` and `totp.key`) readable only by your server. See [key rotation](jwtkit/KEY_ROTATION.md).
