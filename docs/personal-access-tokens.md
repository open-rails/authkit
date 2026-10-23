# Personal access tokens

Organization API keys belong to a permission group, such as a merchant, tenant
or app. Their creator is audit metadata; demotion, departure or account deletion
does not revoke the group's automation. Explicit revocation, expiry, group
deletion and current role policy still apply. Previously revoked keys stay
revoked. Creating or changing a group key still requires group authority.

Personal access tokens are separate, optional credentials for an individual
user. Enable `Config.PersonalAccessTokens.Enabled` explicitly. No personal-token
UI is installed, and existing applications do not enable this feature.
`DefaultTTL` is 30 days and `MaxTTL` is 90 days unless configured otherwise.

An interactive, recently authenticated user creates a token with
`POST /me/personal-access-tokens`, naming `name`, `group_id`, `permissions` and
optional `expires_at`. The owner is always the authenticated user. Permission
names must be registered and concrete: no wildcards, credential management or
MFA-protected operations. The user must currently hold every requested grant.

`GET /me/personal-access-tokens` lists only that user's tokens.
`DELETE /me/personal-access-tokens/{id}` revokes only their own token and requires
recent authentication. Native clients expose `CreatePersonalAccessToken`,
`ListPersonalAccessTokens`, `RevokePersonalAccessToken` and
`ResolvePersonalAccessToken`; the browser client exposes matching lower-case
methods. Routes are relative to the configured AuthKit API prefix.

The secret uses a separate `pat_` prefix and is returned only at creation. It is
stored as a hash, excluded from lists and logs, and cannot be recovered.
Tokens are bound to their issuing application and one permission group.

Ban, soft deletion and the first verified contact proof permanently retire the
account's existing personal tokens. Unbanning or restoring the account does not
revive them. Ordinary password changes and web-session logout keep their
separate existing policies.

Each permission check intersects the stored ceiling with the owner's current
authority. Losing one permission removes that access without destroying
unaffected grants. Revocation, expiration, account disablement or deletion, and
group deletion take effect on subsequent checks, including a retained Verified
object. Expired and revoked rows are pruned by existing auth maintenance.

A personal token is **not an interactive sign-in or an MFA proof**. AuthKit
refuses it on its own identity-only account/session routes, personal-token
management, and sensitive credential operations. Hosts opting in must likewise
use explicit permission checks for their APIs; an identity alone is not a
permission ceiling. `auth.CredentialPersonalAccessToken` identifies this distinct
credential kind, while the authenticated subject remains the owning user.
