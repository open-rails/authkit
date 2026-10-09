# Subject, Invoker, Credential

Every request AuthKit verifies has three parts, and its helpers/auth `Identity` (`verify.Claims.Identity`) names each one:

- **Subject**: the account, native to `Issuer`, whose authority and money the request uses. It is a `user` or an `application`.
- **Invoker**: who actually acts. It is always set. It equals the subject (`{Issuer, Subject}`) unless someone acts on the subject's behalf, such as an application's own user, who may be foreign to this deployment.
- **Credential**: how the request was proven: `session`, `device_key`, `api_key`, `signed_token` or `access_token`, with its id (the session, device key or API key, or the token's `jti`). A credential is never the subject, so rotating keys or signing in on another device never changes who the subject is.

Authorization is the subject's grants, narrowed by what the credential carries (a token's permissions, an application's registered ceiling). Limits and budgets are per invoker within the subject: an application's users each spend within the application's budget. Audit records all three.

| Request | Subject | SubjectKind | Invoker | Credential |
|---|---|---|---|---|
| a user signed in (browser) | the user | user | the subject | `session` |
| a user's device key | the owning user | user | the subject | `device_key` |
| a group API key | the group's account (its id) | application | the subject | `api_key` |
| a registered application's own token | the application | application | the subject | `signed_token` |
| an application's token for one of its users | the application | application | the user, in the application's namespace | `signed_token` |
| a token AuthKit delegated from a user | the user | user | the subject | `access_token` |
| an OAuth client's client-credentials token | the client | application | the subject | `access_token` |
| an OAuth client's token for a user (`at+jwt`) | the user | user | the client | `access_token` |

A group API key belongs to its group's account for now: every key of a group has the group's id as its subject, and the key is the credential. API keys owned by a user or an application come next.

`Identity.SelfInvoked` reports whether the subject acts for itself. `iam.Actor` is the authorization handle `Client.Can` and the gates take: the subject bound to its credential (the session it must stay signed in with, the ceiling a token carries).

## Reading it

Behind a gate over the Client (`verify.Required`, `RequireSession`, `RequirePermission`, `Sensitive` and their adapters), `Client.Caller(ctx)` is the request's identity. It reads only what a gate over this Client verified: claims a host stored with `verify.SetClaims`, or a gate over another authenticator, prove nothing. `verify.CallerFromContext(ctx, authenticator)` is the same read for any authenticator.

Access tokens carry no contact details. `Client.Caller` reads a local user's email and username from the account when the user is the subject and acts for itself.
