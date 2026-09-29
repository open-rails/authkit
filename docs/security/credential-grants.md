# Credential and recovery grants

Password changes, administrative password replacement, successful password reset,
and changes to an account's recovery email or phone invalidate outstanding
password-reset grants. These operations use a durable per-account credential
version. The password, version and session revocations commit together.

Reset grants contain the account UUID, credential version, recovery channel and
contact as observed at issuance. Contact verification, ban/unban, account deletion
and reserved-placeholder transitions also advance this version. Ordinary metadata
and last-login updates do not. MFA remains an independent login requirement; a
password reset never disables or replaces it. Completion checks the current version and contact
while holding the account row lock. Completing one reset invalidates sibling
reset grants. Grants issued before versioning fail closed after upgrade.

Provider-link continuations require the initiating session to remain live and
fresh at completion. Linking and session revocation serialize on the initiating
session row; a revoked continuation cannot become a new login.

## Provider links

A link is authorized by the initiating session (user, session id and its
authentication time, kept in browser state), never by a bare account UUID. A
successful link issues no access token, refresh token or cookie: JSON callbacks
answer `204`, browser callbacks redirect to the frontend callback with
`#flow=link&provider=<provider>&result=success`, and failures keep the
`error`/`flow=link` result. Clients keep their session and reload the account.
Host code links with `LinkProvider(ctx, iam.SystemActor(), ...)`, trusted
authority that must never take a user-supplied UUID.
