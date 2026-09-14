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

## Provider-link API change before v1

`ExternalLoginInput.LinkUserID` becomes `Link *ExternalLinkAuthorization`, carrying
`UserID`, `SessionID`, and the session's `AuthenticatedAt` from `SessionFreshness`.
A bare account UUID is not sufficient authorization. The server stores these
fields in browser state and rejects legacy link state without session authority.

A successful `CompleteExternalLogin` link returns `ExternalProviderLinked` and a
nil `Session`. JSON link callbacks return HTTP 204 with an empty body. Browser
callbacks redirect to the configured frontend callback with
`#flow=link&provider=<provider>&result=success`. They issue no access token, refresh
token, or refresh cookie. Existing login and step-up contracts are unchanged.
Consumers retain their current session and refresh account/provider data after
success. Failed callbacks retain the documented `error`/`flow=link` result.

The fetched Doujins/Hentai0 `frontend/src/pages/AuthCallback.tsx` callbacks only
store tokens when present; their link popup completion already works without a
token. Cozy-art `frontend/src/services/auth.ts` (`consumeAuthCallback`) and
`frontend/src/store/authStore.ts` (`completeAuthCallback`) likewise retain the
existing session and reload the user. Custom clients consuming JSON link callbacks
must accept 204 rather than requiring a login token set. Direct host/import code
can still use `LinkProviderByIssuer`; it is trusted administrative authority and
must never be exposed as a user-supplied UUID command.
