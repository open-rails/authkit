# Subject, Invoker, Credential

Every request AuthKit verifies has three parts, and its authkit/auth `Identity` (`verify.Claims.Identity`) names each one:

- **Subject**: the account, native to `Issuer`, whose authority and money the request uses. It is a `user` or an `application`.
- **Invoker**: who actually acts. It is always set. It equals the subject (`{Issuer, Subject}`) unless someone acts on the subject's behalf: the actor an RFC 8693 `act` claim names (delegation), such as a workload acting for a user.
- **Credential**: how the request was proven: `session`, `device_key`, `api_key`, `personal_access_token` or `access_token`, with its own id. A credential is never the subject, so rotating keys or signing in on another device never changes who the subject is.

Authorization is the subject's grants, narrowed by what the credential carries (a token's permissions within its resource's ceiling). Limits and budgets are per invoker within the subject. Audit records all three.

| Request | Subject | SubjectKind | Invoker | Credential |
|---|---|---|---|---|
| a user signed in (browser) | the user | user | the subject | `session` |
| a user's device key | the owning user | user | the subject | `device_key` |
| a group API key | the group's account (its id) | application | the subject | `api_key` |
| a personal access token | its owning user | user | the subject | `personal_access_token` |
| an OAuth client's client-credentials token | the client | application | the subject | `access_token` |
| an OAuth client's token for a user (`at+jwt`) | the user | user | the subject; the `act` actor when it names one | `access_token` |

A group API key belongs to its group's account: every key of a group has the group's id as its subject, and the key is the credential. A personal token is a separate, optional user credential with a live permission ceiling; it carries no interactive sign-in or MFA assurance.

`Identity.SelfInvoked` reports whether the subject acts for itself. Only RFC 8693's actor claim (`act.sub`) names another invoker; the client a token was issued to (`client_id`) is the user's agent, not an invoker. Token exchange without an `actor_token` is impersonation (RFC 8693 §1.1) and carries no `act`; a jwt-bearer workload is named in `act` when the host's grant decision sets `Invoker`; with an empty `Invoker` the token carries no `act`.

## Authority comes from the credential's state

Every operation that depends on who acts (`Client.Can`, `SetGroupRole`, `Ban`, …) takes an `auth.Identity`, and reads its authority only from the credential's state (`Credential.State`): an `iam.CredentialState` that only AuthKit builds. It records the account the credential acts as, the sign-in it must stay signed in with, the ceilings a token carries and the group it is pinned to. Narrowing (`iam.Within`, `iam.PinnedTo`, `iam.InSession`) only shrinks it.

- verify's gates attach it to the identity of a request they verified.
- Your own code builds one with `iam.SystemIdentity()` (your code, with host authority), `iam.UserIdentity(id)`, `iam.APIKeyIdentity(id)` or `iam.ApplicationIdentity(id)` (checked at account level, with no sign-in), and never from request input.
- An `Identity` built as a literal, decoded from JSON, or stored by `verify.SetClaims` has no state and is refused, `Credential.Kind` `"system"` included, as is the zero `Identity`. Editing an identity's exported fields changes nothing it may do.

## Reading it

Behind a gate (`verify.Required`, `RequireSession`, `RequirePermission`, `Sensitive` and their adapters), `verify.VerifiedIdentity(ctx, client)` is the request's identity. It reads only what a gate over that authenticator verified: claims a host stored with `verify.SetClaims`, or a gate over another authenticator, prove nothing. `verify.IdentityFromContext` is the identity of whatever claims the context holds.

A library that guards its own routes takes `client.Authenticator()` instead ([RBAC](rbac.md#a-library-that-guards-its-own-routes)): its `Authenticate(r)` returns the request's `Verified`, whose `Identity()` this is. Native session access tokens carry no contact details, so it reads a local user's email and username from the account when the user is the subject, acts for itself, and the token carries neither. An OAuth client's access token may already carry them: `email` with the `email` scope or a resource's `ContactClaims`, and `username` with `ContactClaims`.

Events (`Client.ListEvents`) record who made a change the same way: `subject_kind` and `subject_id`, `invoker_issuer` and `invoker_id`, `credential_kind` and `credential_id`.

## Registration verification

`Config.Registration.Verification` (YAML `registration.verification`) is `none`
(the default), `optional` or `required`. Contacts stay unverified until proven.
`optional` sends a code at registration; `required` keeps a new sign-up pending
until its code is confirmed, before creating an account.

With `required`, password sign-in also asks an existing account with an unverified
email or phone to confirm a code. Hosts can set
`Config.Registration.UnprovenPasswordSignIn = true` (YAML
`registration.unproven_password_sign_in: true`) to skip that sign-in check for
existing accounts with an unproven contact, such as imported ones. It defaults to
false. The correct password is still required, and normal sign-in checks,
including 2FA and restoring a deleted account, still apply. Password sign-in sends
no contact verification code for this check, and the account stays unproven:
proof-dependent restrictions, including adding sign-in methods, still apply.
New sign-ups and pending-registration recovery still require their code.

## Network accounts

A network account, such as a shopper's at openrails.dev, is an ordinary user who proved an email or phone and accepted the network's agreements. The id merchants see is its `sub`, the user id: public (OIDC Core §8), stable, never reassigned.

**Agreements.** `Config.Agreements` declares documents (`key`, `version`, `url`); `Registration.Agreements` names those every sign-up accepts. A sign-up by password (`agreements` on `POST /register`), code (`agreements` on `POST /passwordless/confirm`; the code stays good for the retry) or identity provider (`agreements` on the JSON start) without them is `agreement_required` (409), whose metadata names each one with its version and URL. Each acceptance is kept, append-only, with its channel (`registration`, `account` or `host`), address and user agent. A signed-in user accepts with `POST /me/agreements`; a completed sign-in's `agreements_due` lists what is due now: a required document the account never accepted, or a new version marked `reaccept`. An OAuth client's `Agreements` must be accepted before its approval. Hosts read acceptances with `Client.UserAgreements` and gate their own features on a document's current version; `Client.AcceptAgreements` records one accepted in the host's own flow. Each newly accepted version is a `user.agreement_accepted` event (`agreement`, the version as `current`).

**How it signed in** (`amr`, RFC 8176): `email` for a code sent to a proven email, `sms` for one sent to a proven phone, `swk` with `mfa` for a passkey (user-verified), `swk` alone for a Solana wallet, `pwd` for a password, `oauth` for an identity provider, `device_key` with `email`, `otp` and `mfa` for a device-key sign-in; a second factor adds its method with `otp` and `mfa`.

**One account per contact.** An email or phone is tied to one account at a time within a tenant, by a unique constraint, whether proven or not. Uniqueness is per tenant: apps that share a tenant share accounts, while the same address in two tenants is two separate accounts. Proving one an account holds (a code sign-in) signs into that account, never into a second one, and registering with it is `email_in_use` or `phone_in_use` when registration does not require verification. When it does, a taken address answers like a free one (so the answer reveals no account) and its owner is notified instead. Changing to another contact (`PUT /me/email`, `PUT /me/phone`, once the new one is proven) releases the old one at once: another account may then sign up with it or move to it by proving it. Of two accounts moving to one contact at once, exactly one gets it. A number its carrier gives someone else stays its account's until the account changes it, as a mailbox would: whoever proves it signs into that account.

**Phone-only accounts.** An account whose only proven contact is a phone, and that holds no passkey, proves the phone again on every new device: a password or provider sign-in there is `device_verification_required` with a code by SMS, whatever `SignIn.NewDevicesPerAccount` says; an SMS code or passkey sign-in already is that proof. A device it proved is recognized for 30 days. Adding a proven email or a passkey makes it an ordinary account.

**Devices in iframes.** On HTTPS the device cookie is issued twice: `SameSite=Lax`, and `SameSite=None; Partitioned` (CHIPS). Inside a third-party iframe only the partitioned one comes back, keyed to the top-level site, so a device signs in there once and is recognized there again.

**Text messages.** `SMS.AllowedCountries` (ISO 3166-1 alpha-2, by the number's real region: `+1 876` is Jamaica, not the US) refuses any other number with `phone_country_not_allowed` before anything is looked up or sent. Every message also spends the `sms_number`, `sms_account`, `sms_address` and `sms_country` rate-limit buckets (`HTTPConfig.RateLimits`; Redis when configured), whatever route sends it, with two exceptions: a `contact_changed` notice to a number the account just replaced is never withheld, and a headless Client (no HTTP surface) applies no send limits. A code message carries `Domain`, `Frontend.BaseURL`'s host: the Twilio adapter's built-in bodies end with the origin-bound line `@<domain> #<code>` (WICG origin-bound one-time codes), and a host's own `Render` adds `SMSMessage.OriginBoundLine()`.

**Deletion.** `DELETE /me` is recoverable deletion: 30 days, then `Deps.OnPurge` on every account issuer, then the purge. Deadlines live in the account database. Each issuer has one `authkit_account_delete_due` batch job, scheduled at the earliest `purge_at` of the deletions it receives: the transaction that deletes an account (or `PurgeUsers`, which moves `purge_at` to now) schedules every account issuer's batch in that issuer's own queue and fleet. A batch reads due records in batches of 100, performs that issuer's pending required cleanup, and snoozes until the next `purge_at`; with no deletion pending there is no job. `Start` schedules the batch for deletions an earlier release recorded. A restore before `purge_at` leaves that run nothing to do. A failed or offline issuer leaves its receipt pending, preventing hard deletion. The final completed cleanup purges the account; a failed cleanup or purge is retried after as long as it has been overdue, from a minute up to a day. Accounts are never purged before their deadline, and each failed account is isolated from the rest of the batch. Permanent deletion begins within seconds of the recovery window closing. `Deps.DeletionCheck` runs first and may refuse with `iam.RefuseDeletion(reason)`, such as while the user's cards still pay subscriptions: `deletion_refused` (409) with `metadata.reason`. It is never asked about a staff or host deletion. A network host revokes what the account linked (merchant links, wallet cards) in `OnPurge`, idempotently on the deletion's `ID`.

**Restoring.** Someone who deleted their own account comes back by signing in, inside the 30 days. Every sign-in ends at `status: account_recovery_required` once its proof is complete: a code to the account's contact, a passkey, a provider or a wallet, plus any second factor. A password alone is not a proof here, so it gets the code step first (`verification_required`), the same answer an unverified account gets; nothing about the deletion shows before that proof.

`recovery.token` is opaque and is no session. It works once, only at `POST /account/recovery/confirm`, and lasts 10 minutes or until `purge_at`. Confirming restores the account and answers the rest of the sign-in as an `AuthResult`, which is `complete` unless a step such as a new-device code is due. `204` means the account is back but this answer signed nobody in: the client signs in again. Not confirming leaves the account deleted. auth-ui's sign-in steps do all of this.

`POST /device-keys/enroll/finish` refuses with `account_recovery_required` (409), its metadata the same `token`, `expires_at` and `purge_at`. No key is enrolled, and the ceremony stays live: confirm the token (`204`), then repeat the same finish.

An account deleted by staff or the system, or banned, gets `account_disabled` or `user_banned`, and only `RestoreUsers` brings the first back. Past `purge_at`, sign-in answers `account_recovery_expired` and queues the issuer's batch now, so once it has purged the account its address signs up fresh.

## Host provider reconciliation

`Client.LinkProvider` adds an external sign-in identity as trusted host code.
`Client.ReconcileProvider` conditionally adds, removes or replaces one issuer's
identity, for example when synchronizing identities from a source system:

```go
err := client.ReconcileProvider(ctx, userID, oldSubject, iam.ProviderLink{
    Issuer: issuer, Subject: newSubject, Provider: slug, Email: email,
})
```

An empty `oldSubject` expects no link; an empty `newSubject` removes the link.
Issuer and subject values are trimmed as in `LinkProvider`. If the desired
subject already matches (including no link), the operation succeeds without
writes, even with a stale expectation. Metadata is left alone on that no-op. Otherwise, the current subject must equal the expected subject:
`iam.ErrProviderSubjectMismatch` (`provider_subject_mismatch`, 409) refuses a
stale change. Hosts should keep their imported subject as the expectation;
this operation does not establish source provenance or authorize an overwrite
of a different subject.

Replacement commits atomically under the account lock. Other issuers are
untouched. An issuer/subject held by another account is
`iam.ErrProviderAlreadyLinked`; a missing, deleted or other-tenant account is
`iam.ErrUserNotFound`. Removing a verified link refuses
`iam.ErrCannotUnlinkLastLoginMethod` when no sign-in method would remain,
using the same rules as self-service unlink: configured verified providers,
a password, a passkey, an enabled device key, or a passwordless contact with its
sender configured. An unverified imported claim is removable. A replacement can
replace the sole sign-in method, provided the resulting account can still sign
in. Include the configured provider name when linking or replacing.

Like `LinkProvider`, this is a trusted tenant Client operation, takes no
operation options, and has no HTTP route. Hosts must never expose it directly
to untrusted request input. Browser linking and unlinking keep their existing
session and recent-sign-in requirements.

Provider reconciliation emits no events, matching self-service link and unlink.
