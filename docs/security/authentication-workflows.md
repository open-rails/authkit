# Authentication workflows

The embedded flows own authentication policy; HTTP presents `LoginOutcome`.
`PasswordLogin`, `PasswordlessLogin`, `ConfirmVerification`, and
`CompleteExternalLogin` return a session, a second-factor challenge, or a restricted
enrollment grant. Hosts must handle every outcome; a first-factor user ID alone
is not permission to issue a session. Passkey login uses the same completion path
with actual UV proof. See the [wire contract](../api-endpoints.md#authentication-continuation).

The final account lock checks the credential version captured before password or
passkey verification, and the provider/passkey/session that supplied the proof.
MFA completion retains that provenance and locks the live source row through
commit. Provider grants bind the immutable link-row ID, so unlinking and
recreating the same issuer/subject cannot revive an old grant. Revoke-all takes
the account lock before selecting sessions, including a concurrently completed
derived session. Password recovery, contact changes,
provider unlink and source-session revocation invalidate in-flight authority.
A restricted enrollment JWT carries first-factor assurance for continuation,
but cannot perform freshness-gated account/factor management.

Public registration uses one transaction for account/contact state, password,
language, provider binding, invitation consumption and any invitation role.
Invitation consumption locks its group before its own row, matching group
lifecycle operations. Email and SMS accept the same unbound invitation token.

Codes and links share one canonical record. `EphemeralStore.CompareAndConsume`
claims the exact bytes that were checked: a stale reader cannot consume a newer
issuance, and at most one code/link completion can win. Custom ephemeral stores
must implement the same atomic semantics as the memory mutex and Redis Lua
implementations. There is no old challenge-format fallback.

## Workflow coverage and consolidation

Each of the three HTTP suites in `authhttp/account_workflow_test.go` uses actual
HTTP requests, a scratch PostgreSQL database and both memory and isolated Redis
state. Only message delivery and the external identity provider are substituted.
The existing cookie/browser suite supplies actual browser transport coverage.

| Suite | Assertions |
| --- | --- |
| `TestAccountAdmissionWorkflow` | Email/SMS, password/passwordless, invitation admission and consumption, pending-password recovery, generated usernames, disabled/unknown-contact behavior, one code/link winner, replay and purpose/identifier binding, attempt budget across reissue, injected invitation-consume rollback after account/password/provider writes, and an older blocked completion preserving a new issuance. |
| `TestAuthenticationContinuationWorkflow` | Delivered registration/passwordless links through restricted enrollment, TOTP to full session, password/passwordless MFA and backup completion with actual AMR, replay, recovery invalidation, a password check queued behind completed recovery, same-channel factor rejection, UV passkey login under Required mode with an MFA-required role, controlled passkey deletion, and revoke-all racing a refresh-derived completion. |
| `TestProviderAuthenticationWorkflow` | OIDC and OAuth2 discovery/token exchange, browser state cookie and fragment metadata, SMS enrollment to session, subsequent enrolled-user challenge to session, retained `oauth` provenance, controlled provider unlink, and rejection of a grant after its provider link is deleted and recreated. |

These replace the standalone passwordless test matrix, four engine outcome
matrices in `embedded/login_outcomes_test.go`, the registration atomic happy-path
fixtures, pending-store shape tests, the standalone four-channel verification
confirmation matrix, invitation admission duplicates, URL-builder tests, and the
bare MFA-challenge/passkey-identifier probes. The profile projection assertions
moved unchanged in scope to `embedded/profile_projection_test.go`; reusable
passwordless fixture code remains for credential/cookie suites.

The two obsolete GET landing-bridge test groups were deleted with their routes.
Delivered-fragment-to-POST tests cover the current producer/consumer contract.
The dummy browser enrollment-fragment test was replaced by real provider
continuation; provider-error escaping/state/nonce tests remain. Optional signup
with/without delivery shares one database in `TestOptionalRegistrationWorkflow`.

Focused cryptographic, forced-code-collision, atomic storage, TTL, query-contract,
contact-mutation and credential-rollback regressions remain where they establish
invariants that a normal workflow cannot force reliably.

The final consolidation extends these workflows through native-credential
management and factor management. Every removed fixture's unique assertions
are recorded below before deletion; fault and concurrency tests stay separate.
