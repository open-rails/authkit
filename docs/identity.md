# Subject, Invoker, Credential

Every request AuthKit verifies has three parts, and its helpers/auth `Identity` (`verify.Claims.Identity`) names each one:

- **Subject**: the account, native to `Issuer`, whose authority and money the request uses. It is a `user` or an `application`.
- **Invoker**: who actually acts. It is always set. It equals the subject (`{Issuer, Subject}`) unless someone acts on the subject's behalf: the actor an RFC 8693 `act` claim names (delegation), such as a workload acting for a user.
- **Credential**: how the request was proven: `session`, `device_key`, `api_key` or `access_token`, with its id (the session, device key or API key, or the token's `jti`). A credential is never the subject, so rotating keys or signing in on another device never changes who the subject is.

Authorization is the subject's grants, narrowed by what the credential carries (a token's permissions within its resource's ceiling). Limits and budgets are per invoker within the subject. Audit records all three.

| Request | Subject | SubjectKind | Invoker | Credential |
|---|---|---|---|---|
| a user signed in (browser) | the user | user | the subject | `session` |
| a user's device key | the owning user | user | the subject | `device_key` |
| a group API key | the group's account (its id) | application | the subject | `api_key` |
| an OAuth client's client-credentials token | the client | application | the subject | `access_token` |
| an OAuth client's token for a user (`at+jwt`) | the user | user | the subject; the `act` actor when it names one | `access_token` |

A group API key belongs to its group's account for now: every key of a group has the group's id as its subject, and the key is the credential. API keys owned by a user or an application come next.

`Identity.SelfInvoked` reports whether the subject acts for itself. Only RFC 8693's actor claim (`act.sub`) names another invoker; the client a token was issued to (`client_id`) is the user's agent, not an invoker. Token exchange without an `actor_token` is impersonation (RFC 8693 §1.1) and carries no `act`; a jwt-bearer workload is named in `act`.

## Authority comes from the credential's state

Every operation that depends on who acts (`Client.Can`, `SetGroupRole`, `Ban`, …) takes an `auth.Identity`, and reads its authority only from the credential's state (`Credential.State`): an `iam.CredentialState` that only AuthKit builds. It records the account the credential acts as, the sign-in it must stay signed in with, the ceilings a token carries and the group it is pinned to. Narrowing (`iam.Within`, `iam.PinnedTo`, `iam.InSession`) only shrinks it.

- verify's gates attach it to the identity of a request they verified.
- Your own code builds one with `iam.SystemIdentity()` (your code, with host authority), `iam.UserIdentity(id)`, `iam.APIKeyIdentity(id)` or `iam.ApplicationIdentity(id)` (checked at account level, with no sign-in), and never from request input.
- An `Identity` built as a literal, decoded from JSON, or stored by `verify.SetClaims` has no state and is refused, `Credential.Kind` `"system"` included, as is the zero `Identity`. Editing an identity's exported fields changes nothing it may do.

## Reading it

Behind a gate (`verify.Required`, `RequireSession`, `RequirePermission`, `Sensitive` and their adapters), `verify.VerifiedIdentity(ctx, client)` is the request's identity. It reads only what a gate over that authenticator verified: claims a host stored with `verify.SetClaims`, or a gate over another authenticator, prove nothing. `verify.IdentityFromContext` is the identity of whatever claims the context holds.

A library that guards its own routes takes `client.Authenticator()` instead ([RBAC](rbac.md#a-library-that-guards-its-own-routes)): its `Authenticate(r)` returns the request's `Verified`, whose `Identity()` this is. Access tokens carry no contact details, so it reads a local user's email and username from the account when the user is the subject and acts for itself.

Events (`Deps.OnEvent`) record who made a change the same way: `subject_kind` and `subject_id`, `invoker_issuer` and `invoker_id`, `credential_kind` and `credential_id`.

## Network accounts

A network account, such as a shopper's at openrails.dev, is an ordinary user who proved an email or phone and accepted the network's agreements. The id merchants see is its `sub`, the user id: public (OIDC Core §8), stable, never reassigned.

**Agreements.** `Config.Agreements` declares documents (`key`, `version`, `url`); `Registration.Agreements` names those every sign-up accepts. A sign-up by password (`agreements` on `POST /register`), code (`agreements` on `POST /passwordless/confirm`; the code stays good for the retry) or identity provider (`agreements` on the JSON start) without them is `agreement_required` (409), whose metadata names each one with its version and URL. Each acceptance is kept, append-only, with its channel (`registration`, `account` or `host`), address and user agent. A signed-in user accepts with `POST /me/agreements`; a completed sign-in's `agreements_due` lists what is due now: a required document the account never accepted, or a new version marked `reaccept`. An OAuth client's `Agreements` must be accepted before its approval. Hosts read acceptances with `Client.UserAgreements` and gate their own features on a document's current version; `Client.AcceptAgreements` records one accepted in the host's own flow. Each newly accepted version is a `user.agreement_accepted` event (`agreement`, the version as `current`).

**How it signed in** (`amr`, RFC 8176): `email` for a code sent to a proven email, `sms` for one sent to a proven phone, `swk` with `mfa` for a passkey (user-verified), `swk` alone for a Solana wallet, `pwd` for a password, `oauth` for an identity provider; a second factor adds its method with `otp` and `mfa`.

**Phone-only accounts.** An account whose only proven contact is a phone, and that holds no passkey, proves the phone again on every new device: a password or provider sign-in there is `device_verification_required` with a code by SMS, whatever `SignIn.NewDevicesPerAccount` says; an SMS code or passkey sign-in already is that proof. A device it proved is recognized for 30 days. Adding a proven email or a passkey makes it an ordinary account.

**Devices in iframes.** On HTTPS the device cookie is issued twice: `SameSite=Lax`, and `SameSite=None; Partitioned` (CHIPS). Inside a third-party iframe only the partitioned one comes back, keyed to the top-level site, so a device signs in there once and is recognized there again.

**Text messages.** `SMS.AllowedCountries` (ISO 3166-1 alpha-2, by the number's real region: `+1 876` is Jamaica, not the US) refuses any other number with `phone_country_not_allowed` before anything is looked up or sent. Every message also spends the `sms_number`, `sms_account`, `sms_address` and `sms_country` rate-limit buckets (`HTTPConfig.RateLimits`; Redis when configured), whatever route sends it. A code message carries `Domain`, `Frontend.BaseURL`'s host: the Twilio adapter's built-in bodies end with the origin-bound line `@<domain> #<code>` (WICG origin-bound one-time codes), and a host's own `Render` adds `SMSMessage.OriginBoundLine()`.

**Deletion.** `DELETE /me` is recoverable deletion: 30 days, then `Deps.OnPurge` on every account issuer, then the purge. `Deps.DeletionCheck` runs first and may refuse with `iam.RefuseDeletion(reason)`, such as while the user's cards still pay subscriptions: `deletion_refused` (409) with `metadata.reason`. It is never asked about a staff or host deletion. A network host revokes what the account linked (merchant links, wallet cards) in `OnPurge`, idempotently on the deletion's `ID`.
