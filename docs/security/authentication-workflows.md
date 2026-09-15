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

The lifecycle spine additionally includes:

| Suite | Assertions |
| --- | --- |
| `TestFactorManagementWorkflow` | A stale password session cannot enroll/change factors; password step-up returns fresh assurance; TOTP enrollment keeps the existing session's time/AMR unchanged; factor/default/status and step-up method projections; actual TOTP step-up and selected-factor login; password re-auth preserves MFA; duplicate enrollment preserves secret/backup material; client IP capture; backup login, stale-MFA retry and backup regeneration. Both memory and Redis run the entire sequence. |
| `TestNativeCredentialWorkflow` | Both stores run real WebAuthn registration, login, replay/counter rejection, list/rename/delete and rejected post-deletion login; Ed25519 device registration/login, domain separation, enumeration resistance, notices, independent machine identity, recovery-root authorization, selective revocation, self-logout retry and tombstone refusal. No dummy SQL credential is inserted. |
| `TestDelegatedTokenRoute_CertificateBoundEndToEnd` and `TestDelegatedTokenRoute_KIDRotationReconciliation` | Existing HTTP/PG/mTLS delegation, audience/TTL/authority restrictions, certificate proof, document claims and live signing-key reconciliation. Focused issuer/scope matrices retain local versus external identity and revocation invariants. |
| `TestGroupLifecycleWorkflow` | Existing group subtree deletion/name retention, custom-role deletion/reuse, inherited grants and simultaneous assignment/deletion ordering. Role authorization and usable-owner regressions remain explicit adjacent suites. |
| `TestBootstrapWorkflow` and `TestFreshSchemaWorkflow` | Existing manifest dry-run/reconcile/global-once behavior and actual fresh/custom-schema installation, concurrent replicas, repeat validation, host pool/record isolation and invalid ledger refusal. Per-stage transaction failures and cancellation races remain separate. |
| `TestCookieLoginBrowserTwoSites` | Actual browser cookie login, refresh/logout and cross-site refusal; runs separately under the browser build tag. |

Final assertion transfers (the original fixtures are deleted, not wrapped):

| Superseded fixtures | Replacement and preserved differences |
| --- | --- |
| `TestPasskeyHTTPIntegrationFullCeremonyAndAssurance`, `TestPasskeyManagementHTTPIntegration` | Native passkey sequence retains creation/backup flags, resident/discoverable options, excluded credentials, malformed/removed identifier input, token AMR/time, counter/replay refusal and last-use timestamp. Management now renames/deletes that genuinely enrolled key and checks subsequent login refusal. |
| `TestDeviceKeyEmailEnrollmentAndRefreshlessLogin`, `TestDeviceKeyLoginBeginDoesNotRevealKnownKey`, `TestDeviceKeyEmailEnrollmentAddsIndependentMachineToExistingAccount`, `TestDeviceKeyManagementRevokesExactlyTheRequestedMachines`, `TestDeviceKeyEnrollmentNotifiesExistingAccountOnly` | Native device sequence reuses the first account/key through login, a second machine and revocation. It retains no-refresh-session/token-shape assertions, wrong-code retry, expiry, single-use ceremonies, indistinguishable unknown-key challenges, account binding, exact key counts, new/existing-owner notice distinction and every revocation retry/refusal. |
| Both `TestTOTP…HTTPIntegration` fixtures, `TestFactorEnrollmentRequiresFreshAuthAndPreservesFactor`, and the five fixtures in `step_up_token_integration_test.go` | Factor management retains their listed behavior with actual HTTP/PG/session proof. It replaces injected MFA methods with successful factor verification and removes the TOTP replay-counter reset. The stale session is aged explicitly; a backup proof refreshes it after selected TOTP login. The former SMS-only `mfa_enrolled` smoke becomes before/after enrollment JWT assertions in this workflow; SMS enrollment itself remains in the provider/refresh/backend-failure matrices. |
| `TestPasskeyLoginRejectsValidNonUVAssertion` | `TestPasskeyVerificationProvesIdentityWithoutSession` already rejects non-UV verification; it now also pins `ErrPasskeyUserVerificationRequired` for login on both stores, retaining the precise engine error and adding Redis coverage. |

Run the full suite with `task test-ci`; it rejects any skip and requires pass
events for the core lifecycle suites, both store legs, and each native credential
scenario. `task test-browser` additionally requires the named browser pass event.
A focused lifecycle run (after the test services/schema are ready) is:

```sh
AUTHKIT_TEST_REQUIRE_DB=1 go test -race -p 1 -count=1 ./authhttp ./embedded ./authkitmigrate \
  -run 'Test(AccountAdmissionWorkflow|AuthenticationContinuationWorkflow|ProviderAuthenticationWorkflow|FactorManagementWorkflow|NativeCredentialWorkflow|DelegatedTokenRoute_(CertificateBoundEndToEnd|KIDRotationReconciliation)|GroupLifecycleWorkflow|BootstrapWorkflow|FreshSchemaWorkflow)$'
```

The focused command complements the full run; it does not replace the retained
cryptographic/fuzz, input-bound, state-machine, fault, contention, credential
mutation, enrollment-revocation and provider-linking regressions.

Measured against `c0aadd8` at workflow revision `511a87d`, on the same PG18/Redis7 host with
`GOMAXPROCS=2 go test -race -p 1 -count=1 -json ./authhttp ./embedded`:

| Measurement | Before | After |
| --- | ---: | ---: |
| Passing test events (including subtests) | 916 | 908 |
| Skipped / failed tests | 0 / 0 | 0 / 0 |
| `authhttp` package duration | 111.774 s | 159.438 s |
| `embedded` package duration | 56.360 s | 61.806 s |

This change removes 798 and adds 310 Go test lines (**net -488**); production
code is unchanged. Sixteen standalone test roots become two workflow roots and
one added assertion in the retained passkey matrix. These shared-host timings
show no speedup; the gains are fewer fixtures, actual session/credential proof,
and memory/Redis parity for the consolidated workflows.

The final TOTP boundary correction retries enrollment only when an invalid-code
response coincides with expiry of the captured prior counter, using a fresh
current counter. Subsequent proofs use an unused real counter, waiting at most
35 seconds when it is not yet accepted; no replay state or assurance is injected.
The final memory/Redis native+factor matrix passed in 4.144 s. An uncommitted
forced-expiry probe also passed in 26.967 s, including an observed 24.439 s wait,
and was removed after validation. Normal execution need not wait.
