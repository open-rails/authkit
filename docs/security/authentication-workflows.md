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

## Workflow qualification

The retained account, credential and provider workflows use a scratch
PostgreSQL database and both memory and isolated Redis state. They mount the
public HTTP handler with configured rate limits. Identity providers are local
servers with real signed responses; email/SMS delivery is captured at its
external boundary. The browser workflow uses Chromium and two real origins.

[Testing](../testing.md) names the six workflow groups, focused security checks
and the single local/CI command. These tests exercise public behavior rather
than the retired routes or duplicate private-handler layouts.
