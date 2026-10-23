# Remote client parity

**DESIGN ONLY / DEFERRED — 2026-10-23.** The owner explicitly stopped general
remote AuthKit implementation. The runtime prototype is preserved on
`feat/remote-client-parity` for reference, not approved for merging or release.
The narrow event reader remains separate in PR #445.

Prototype source through `ef69c26c` includes 24 internal methods. The first
17-method tests passed, but the later group-operation tranche and lossless
remote-application result have not been compiled or validated. Generated
contracts currently cover the earlier tranche and must be regenerated if
runtime implementation is explicitly authorized again. No compiler is running.

Do not treat the source-call matrix or preserved prototype as a requirement
to implement a general remote client now. The remaining work is design only.

This map starts from `internal/ops/ops.go` and traces HTTP handlers in
`internal/httpapi/catalog.go`. A route that calls an operation is evidence of a
possible transport, not proof of equivalent semantics. Handlers may expose only
the signed-in user, project a different response, or add mandatory authorization.

The event reader is implemented and tested in PR #445. A general remote
`*Client` remains withheld until every declared supported operation has real
transport, error, scope and authorization tests; engine lifecycle stays local.

| Native operation | Existing HTTP call paths | Status |
|---|---|---|
| `ListEvents` | `GET /events` | Internal transport implemented; real HTTP tests |
| `User` | `POST /token`<br>`POST /password/login`<br>`POST /2fa/verify`<br>`POST /device-verification/confirm`<br>`POST /passwordless/confirm`<br>`POST /passkeys/login/finish`<br>`POST /solana/login`<br>`POST /device-keys/enroll/finish`<br>`POST /device-keys/login/finish`<br>`POST /register`<br>`POST /verify/confirm`<br>`POST /me/step-up/password`<br>`POST /me/step-up/2fa`<br>`POST /me/step-up/code`<br>`POST /me/step-up/solana`<br>`POST /me/step-up/passkey`<br>`POST /me/passkeys/enroll/finish`<br>`POST /me/2fa/factors`<br>`GET /{provider}/callback`<br>`POST /{provider}/callback` | By-ID admin route returns UserEntry; email/phone/username reference mapping still missing |
| `Users` | — | No sensitive bulk-user route; public users are not equivalent |
| `PublicUsers` | `GET /users` | Mapping and parity test required |
| `ListUsers` | `GET /admin/users` | Internal transport implemented; real HTTP tests |
| `UserAgreements` | `GET /me/agreements`<br>`POST /me/agreements` | Existing endpoint is self-only; arbitrary target ownership mapping missing |
| `AgreementsDue` | `POST /token`<br>`POST /password/login`<br>`POST /2fa/verify`<br>`POST /device-verification/confirm`<br>`POST /passwordless/confirm`<br>`POST /passkeys/login/finish`<br>`POST /solana/login`<br>`POST /device-keys/enroll/finish`<br>`POST /device-keys/login/finish`<br>`POST /register`<br>`POST /verify/confirm`<br>`GET /me/agreements`<br>`POST /me/agreements`<br>`POST /me/step-up/password`<br>`POST /me/step-up/2fa`<br>`POST /me/step-up/code`<br>`POST /me/step-up/solana`<br>`POST /me/step-up/passkey`<br>`POST /me/passkeys/enroll/finish`<br>`POST /me/2fa/factors`<br>`GET /{provider}/callback`<br>`POST /{provider}/callback` | Internal sign-in response calls and self-only view are not arbitrary-target reads |
| `AcceptAgreements` | — | No direct catalog path; inspect projection/native semantics |
| `OAuthConsents` | `GET /me/oauth-consents` | Self-only route; arbitrary native target needs explicit contract |
| `RevokeConsent` | — | No direct catalog path; inspect projection/native semantics |
| `CreateGroupOAuthClient` | `POST /groups/{group_id}/oauth-clients` | Mapping and parity test required |
| `GroupOAuthClients` | `GET /groups/{group_id}/oauth-clients` | Internal transport implemented; real HTTP tests |
| `GroupOAuthClient` | `GET /groups/{group_id}/oauth-clients/{client_id}` | Internal transport implemented; real HTTP tests |
| `UpdateGroupOAuthClient` | `PATCH /groups/{group_id}/oauth-clients/{client_id}` | Mapping and parity test required |
| `RotateGroupOAuthClientSecret` | `POST /groups/{group_id}/oauth-clients/{client_id}/secret` | Mapping and parity test required |
| `DeleteGroupOAuthClient` | `DELETE /groups/{group_id}/oauth-clients/{client_id}` | Mapping and parity test required |
| `ResolveUsername` | `GET /users` | Mapping and parity test required |
| `CheckUsername` | `GET /usernames/availability` | Mapping and parity test required |
| `GenerateUsername` | `GET /usernames/generate` | Internal transport implemented; real HTTP tests |
| `DeviceKeys` | `GET /me/sign-in-keys` | Self-only sign-in-key projection differs from native DeviceKey list |
| `CreateUser` | — | Public registration is not trusted native account creation |
| `UpdateUser` | `PATCH /me`<br>`PATCH /admin/users/{user_id}` | Admin wire omits native password/hash and verified-contact flags |
| `PatchPublicMetadata` | — | No direct catalog path; inspect projection/native semantics |
| `Ban` | `PUT /admin/users/{user_id}/ban` | Mapping and parity test required |
| `Unban` | `DELETE /admin/users/{user_id}/ban` | Mapping and parity test required |
| `DeleteUsers` | `DELETE /me`<br>`DELETE /admin/users/{user_id}` | HTTP is one target and rejects self; native bulk result mapping needs review |
| `RestoreUsers` | `POST /admin/users/{user_id}/restore` | HTTP is one target; native bulk result mapping needs review |
| `PurgeUsers` | — | No direct catalog path; inspect projection/native semantics |
| `ResetAccountMFA` | — | No direct catalog path; inspect projection/native semantics |
| `Sessions` | `GET /me/sessions`<br>`GET /admin/users/{user_id}/sessions` | Internal transport implemented; real HTTP tests |
| `ListSessionEvents` | `GET /me/session-events`<br>`GET /admin/users/{user_id}/session-events` | Internal transport implemented; real HTTP tests |
| `RevokeSession` | — | No direct catalog path; inspect projection/native semantics |
| `RevokeAccountSessions` | `DELETE /admin/users/{user_id}/sessions` | HTTP returns204; native method returns issuer/count report |
| `MintAccessToken` | — | No direct catalog path; inspect projection/native semantics |
| `CheckSession` | — | No direct catalog path; inspect projection/native semantics |
| `CheckRecentSignIn` | `POST /me/2fa/setup`<br>`POST /me/2fa/factors` | Mapping and parity test required |
| `Group` | `GET /me/permissions`<br>`POST /invitations/redeem` | Only internal group-gate calls; no group-detail result endpoint |
| `Groups` | — | No direct catalog path; inspect projection/native semantics |
| `ListGroups` | — | No direct catalog path; inspect projection/native semantics |
| `ListGroupMembers` | `GET /groups/{group_id}/members` | Mapping and parity test required |
| `ListMemberships` | `GET /me/groups` | Existing endpoint is self-only; native subject can differ |
| `GroupRoles` | `GET /me/permissions` | Self permission projection is not arbitrary subject-role map |
| `CreateGroup` | — | No direct catalog path; inspect projection/native semantics |
| `DeleteGroup` | — | No direct catalog path; inspect projection/native semantics |
| `PurgeGroup` | — | No direct catalog path; inspect projection/native semantics |
| `SetGroupRole` | `PUT /groups/{group_id}/members/{kind}/{id}` | HTTP path currently supports user subjects only; native also supports applications |
| `RemoveGroupMember` | `DELETE /groups/{group_id}/members/{kind}/{id}` | HTTP path currently supports user subjects only; native also supports applications |
| `Can` | `GET /events` | Internal authorization calls are not an authorization-query endpoint |
| `CanDirect` | `GET /me/permissions` | Self permissions do not expose arbitrary actor direct-grant checks |
| `EffectivePermissions` | `GET /me/permissions` | Self-only projection; arbitrary actor/group-list contract missing |
| `KnownPermission` | — | No direct catalog path; inspect projection/native semantics |
| `Persona` | — | No direct catalog path; inspect projection/native semantics |
| `Permission` | — | No direct catalog path; inspect projection/native semantics |
| `Role` | `GET /admin/users`<br>`GET /groups/{group_id}/members`<br>`PUT /groups/{group_id}/members/{kind}/{id}`<br>`POST /groups/{group_id}/invitations`<br>`POST /groups/{group_id}/api-keys` | Internal parsing only; remote declared-catalog lookup missing |
| `RolePermissions` | — | No direct catalog path; inspect projection/native semantics |
| `ListGroupRoles` | `GET /groups/{group_id}/roles` | Internal transport implemented; real HTTP tests |
| `GroupRole` | `GET /groups/{group_id}/roles/{role}` | Internal transport implemented; real HTTP tests |
| `CreateGroupRole` | `POST /groups/{group_id}/roles` | Mapping and parity test required |
| `UpdateGroupRole` | `PATCH /groups/{group_id}/roles/{role}` | Mapping and parity test required |
| `DeleteGroupRole` | `DELETE /groups/{group_id}/roles/{role}` | Mapping and parity test required |
| `CreateAPIKey` | `POST /groups/{group_id}/api-keys` | Mapping and parity test required |
| `ListAPIKeys` | `GET /groups/{group_id}/api-keys` | Internal transport implemented; real HTTP tests |
| `RevokeAPIKey` | `DELETE /groups/{group_id}/api-keys/{id}` | HTTP intentionally hides not-found; native error identity differs |
| `ResolveAPIKey` | — | No direct catalog path; inspect projection/native semantics |
| `CreatePersonalAccessToken` | `POST /me/personal-access-tokens` | Mapping and parity test required |
| `ListPersonalAccessTokens` | `GET /me/personal-access-tokens` | Mapping and parity test required |
| `RevokePersonalAccessToken` | `DELETE /me/personal-access-tokens/{id}` | Mapping and parity test required |
| `ResolvePersonalAccessToken` | — | No direct catalog path; inspect projection/native semantics |
| `CreateInvitation` | `POST /groups/{group_id}/invitations` | Email mode returns202 without native creation result; link mode differs |
| `ListInvitations` | `GET /groups/{group_id}/invitations` | Internal transport implemented; real HTTP tests |
| `RevokeInvitation` | `DELETE /groups/{group_id}/invitations/{id}` | HTTP intentionally hides not-found; native error identity differs |
| `UpsertRemoteApplication` | `POST /groups/{group_id}/remote-applications`<br>`PATCH /groups/{group_id}/remote-applications/{id}` | Mapping and parity test required |
| `DeleteRemoteApplication` | `DELETE /groups/{group_id}/remote-applications/{id}` | Mapping and parity test required |
| `RemoteApplication` | `POST /groups/{group_id}/remote-applications`<br>`PATCH /groups/{group_id}/remote-applications/{id}` | Mapping and parity test required |
| `ListRemoteApplications` | `GET /groups/{group_id}/remote-applications` | Internal transport implemented; real HTTP tests |
| `DeclareRemoteApplications` | — | No direct catalog path; inspect projection/native semantics |
| `RemoteUserRoles` | — | No direct catalog path; inspect projection/native semantics |
| `RemoveRemoteUserRole` | — | No direct catalog path; inspect projection/native semantics |
| `ApplyBootstrapManifest` | — | No direct catalog path; inspect projection/native semantics |
| `EnsureUserRole` | — | No direct catalog path; inspect projection/native semantics |
| `ImportUsers` | — | No direct catalog path; inspect projection/native semantics |
| `ImportSolanaLinks` | — | No direct catalog path; inspect projection/native semantics |
| `LinkProvider` | — | No direct catalog path; inspect projection/native semantics |
| `ProvisioningTargets` | `GET /admin/provisioning/targets` | Internal transport implemented; real HTTP tests |

## Implementation boundary

Never serialize `auth.Identity` from trusted native arguments as proof of
authority. Mutations derive their actor from verified HTTP credentials on the
server. Native `InTx` cannot cross HTTP. Tenant selection must use the host’s
actual tenant dispatch contract, never a cursor or a new client-invented header.
A missing route requires a separately reviewed server endpoint or an explicit
local-only classification before a general remote constructor is exposed.

## Actor-bearing mutations

The remote OAuth-client mutation adapter sends `AuthKit-Expected-Actor` as a
post-authentication precondition on distinct `/operations/groups/...` routes.
Older servers return 404 instead of silently ignoring the constraint and
executing a mutation. The header is mandatory on these new routes; ordinary
existing routes remain unchanged. Its subject, issuer, tenant, invoker and
credential identity must exactly match the identity independently verified by
the server. A mismatch is 403. Credential state, roles and contact metadata are
never transferred as authority. Credentials must represent the expected actor;
there is no automatic service-account impersonation or delegation. Existing
permission, MFA and recent-sign-in gates still run on the actual credential.
Native operation options are refused until explicitly mapped; a local
transaction cannot cross HTTP.

The directory adapter passes `with_entitlements` explicitly. Omitting that
HTTP parameter retains the admin UI's existing behavior (include entitlements),
while a native query requesting no enrichment causes no provider work through
either transport.

## Group-operation tranche

The next tranche adds ListGroupMembers (including LiveOnly), custom-role
create/update/delete, API-key create/revoke and remote-application deletion.
API-key revocation uses a distinct native-result operation so a missing key
retains its native error; the existing browser route remains idempotent.
Remote-application listing uses a lossless authenticated operation result,
because the browser projection omits JWK, role-map and permission fields.
Nonempty fixtures cover these differences before qualification.

## Host-extension boundary awaiting owner decision

The disputed operations are `ApplyBootstrapManifest`, `EnsureUserRole`,
`ImportUsers`, `ImportSolanaLinks`, `LinkProvider`, `DeclareRemoteApplications`,
`MintAccessToken`, `ResolveAPIKey`, `ResolvePersonalAccessToken`, `CheckSession`
and `CheckRecentSignIn`. They accept trusted host assertions, import/issuance
capabilities, raw credentials or verified claims rather than an ordinary
actor-bound domain request. No new remote privilege is invented for them here.

`CreateUser` verified-contact flags and `UpdateUser` password-hash/verified-contact
fields also require an explicit capability boundary; the existing admin wire
does not expose them. Ordinary account/group administration is not automatically
classified as local-only. The pending decision is whether the domain facade has
explicit local host extensions or these capabilities get separately authorized
remote endpoints. The final public remote facade must have no unsupported stubs.
