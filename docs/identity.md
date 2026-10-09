# Subject, Invoker, Credential

Every request AuthKit verifies has three parts, and its helpers/auth `Identity` (`verify.Claims.Identity`) names each one:

- **Subject**: the account, native to `Issuer`, whose authority and money the request uses. It is a `user` or an `application`.
- **Invoker**: who actually acts. It is always set. It equals the subject (`{Issuer, Subject}`) unless someone acts on the subject's behalf, such as an OAuth client acting for a user.
- **Credential**: how the request was proven: `session`, `device_key`, `api_key` or `access_token`, with its id (the session, device key or API key, or the token's `jti`). A credential is never the subject, so rotating keys or signing in on another device never changes who the subject is.

Authorization is the subject's grants, narrowed by what the credential carries (a token's permissions within its resource's ceiling). Limits and budgets are per invoker within the subject. Audit records all three.

| Request | Subject | SubjectKind | Invoker | Credential |
|---|---|---|---|---|
| a user signed in (browser) | the user | user | the subject | `session` |
| a user's device key | the owning user | user | the subject | `device_key` |
| a group API key | the group's account (its id) | application | the subject | `api_key` |
| an OAuth client's client-credentials token | the client | application | the subject | `access_token` |
| an OAuth client's token for a user (`at+jwt`) | the user | user | the client | `access_token` |

A group API key belongs to its group's account for now: every key of a group has the group's id as its subject, and the key is the credential. API keys owned by a user or an application come next.

`Identity.SelfInvoked` reports whether the subject acts for itself. An OAuth token from token exchange names its invoker in RFC 8693's actor claim (`act.sub`); AuthKit reads it as the Invoker.

## Authority comes from the credential's state

Every operation that depends on who acts (`Client.Can`, `SetGroupRole`, `Ban`, …) takes an `auth.Identity`, and reads its authority only from the credential's state (`Credential.State`): an `iam.CredentialState` that only AuthKit builds. It records the account the credential acts as, the sign-in it must stay signed in with, the ceilings a token carries and the group it is pinned to. Narrowing (`iam.Within`, `iam.PinnedTo`, `iam.InSession`) only shrinks it.

- verify's gates attach it to the identity of a request they verified.
- Your own code builds one with `iam.SystemIdentity()` (your code, with host authority), `iam.UserIdentity(id)`, `iam.APIKeyIdentity(id)` or `iam.ApplicationIdentity(id)` (checked at account level, with no sign-in), and never from request input.
- An `Identity` built as a literal, decoded from JSON, or stored by `verify.SetClaims` has no state and is refused, `Credential.Kind` `"system"` included, as is the zero `Identity`. Editing an identity's exported fields changes nothing it may do.

## Reading it

Behind a gate over the Client (`verify.Required`, `RequireSession`, `RequirePermission`, `Sensitive` and their adapters), `Client.Identity(ctx)` is the request's identity. It reads only what a gate over this Client verified: claims a host stored with `verify.SetClaims`, or a gate over another authenticator, prove nothing. `verify.VerifiedIdentity(ctx, authenticator)` is the same read for any authenticator, and `verify.IdentityFromContext` the identity of whatever claims the context holds.

Access tokens carry no contact details. `Client.Identity` reads a local user's email and username from the account when the user is the subject and acts for itself.

Events (`Deps.OnEvent`) record who made a change the same way: `subject_kind` and `subject_id`, `invoker_issuer` and `invoker_id`, `credential_kind` and `credential_id`.
