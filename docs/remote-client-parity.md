# Remote client parity

This map starts from `internal/ops/ops.go` and traces HTTP handlers in
`internal/httpapi/catalog.go`. A route that calls an operation is evidence of a
possible transport, not proof of equivalent semantics. Handlers may expose only
the signed-in user, project a different response, or add mandatory authorization.

The event reader is implemented and tested in PR #445. A general remote
`*Client` remains withheld until every declared supported operation has real
transport, error, scope and authorization tests; engine lifecycle stays local.

| Native operation | Existing HTTP call paths | Status |
|---|---|---|
| `ListEvents` | `GET /events` | Implemented event reader |
| `User` | `POST /token`<br>`POST /password/login`<br>`POST /2fa/verify`<br>`POST /device-verification/confirm`<br>`POST /passwordless/confirm`<br>`POST /passkeys/login/finish`<br>`POST /solana/login`<br>`POST /device-keys/enroll/finish`<br>`POST /device-keys/login/finish`<br>`POST /register`<br>`POST /verify/confirm`<br>`POST /me/step-up/password`<br>`POST /me/step-up/2fa`<br>`POST /me/step-up/code`<br>`POST /me/step-up/solana`<br>`POST /me/step-up/passkey`<br>`POST /me/passkeys/enroll/finish`<br>`POST /me/2fa/factors`<br>`GET /{provider}/callback`<br>`POST /{provider}/callback` | Mapping and parity test required |
| `Users` | — | No direct catalog path; inspect projection/native semantics |
| `PublicUsers` | `GET /users` | Mapping and parity test required |
| `ListUsers` | `GET /admin/users` | Mapping and parity test required |
| `UserAgreements` | `GET /me/agreements`<br>`POST /me/agreements` | Mapping and parity test required |
| `AgreementsDue` | `POST /token`<br>`POST /password/login`<br>`POST /2fa/verify`<br>`POST /device-verification/confirm`<br>`POST /passwordless/confirm`<br>`POST /passkeys/login/finish`<br>`POST /solana/login`<br>`POST /device-keys/enroll/finish`<br>`POST /device-keys/login/finish`<br>`POST /register`<br>`POST /verify/confirm`<br>`GET /me/agreements`<br>`POST /me/agreements`<br>`POST /me/step-up/password`<br>`POST /me/step-up/2fa`<br>`POST /me/step-up/code`<br>`POST /me/step-up/solana`<br>`POST /me/step-up/passkey`<br>`POST /me/passkeys/enroll/finish`<br>`POST /me/2fa/factors`<br>`GET /{provider}/callback`<br>`POST /{provider}/callback` | Mapping and parity test required |
| `AcceptAgreements` | — | No direct catalog path; inspect projection/native semantics |
| `OAuthConsents` | `GET /me/oauth-consents` | Mapping and parity test required |
| `RevokeConsent` | — | No direct catalog path; inspect projection/native semantics |
| `CreateGroupOAuthClient` | `POST /groups/{group_id}/oauth-clients` | Mapping and parity test required |
| `GroupOAuthClients` | `GET /groups/{group_id}/oauth-clients` | Mapping and parity test required |
| `GroupOAuthClient` | `GET /groups/{group_id}/oauth-clients/{client_id}` | Mapping and parity test required |
| `UpdateGroupOAuthClient` | `PATCH /groups/{group_id}/oauth-clients/{client_id}` | Mapping and parity test required |
| `RotateGroupOAuthClientSecret` | `POST /groups/{group_id}/oauth-clients/{client_id}/secret` | Mapping and parity test required |
| `DeleteGroupOAuthClient` | `DELETE /groups/{group_id}/oauth-clients/{client_id}` | Mapping and parity test required |
| `ResolveUsername` | `GET /users` | Mapping and parity test required |
| `CheckUsername` | `GET /usernames/availability` | Mapping and parity test required |
| `GenerateUsername` | `GET /usernames/generate` | Mapping and parity test required |
| `DeviceKeys` | `GET /me/sign-in-keys` | Mapping and parity test required |
| `CreateUser` | — | No direct catalog path; inspect projection/native semantics |
| `UpdateUser` | `PATCH /me`<br>`PATCH /admin/users/{user_id}` | Mapping and parity test required |
| `PatchPublicMetadata` | — | No direct catalog path; inspect projection/native semantics |
| `Ban` | `PUT /admin/users/{user_id}/ban` | Mapping and parity test required |
| `Unban` | `DELETE /admin/users/{user_id}/ban` | Mapping and parity test required |
| `DeleteUsers` | `DELETE /me`<br>`DELETE /admin/users/{user_id}` | Mapping and parity test required |
| `RestoreUsers` | `POST /admin/users/{user_id}/restore` | Mapping and parity test required |
| `PurgeUsers` | — | No direct catalog path; inspect projection/native semantics |
| `ResetAccountMFA` | — | No direct catalog path; inspect projection/native semantics |
| `Sessions` | `GET /me/sessions`<br>`GET /admin/users/{user_id}/sessions` | Mapping and parity test required |
| `ListSessionEvents` | `GET /me/session-events`<br>`GET /admin/users/{user_id}/session-events` | Mapping and parity test required |
| `RevokeSession` | — | No direct catalog path; inspect projection/native semantics |
| `RevokeAccountSessions` | `DELETE /admin/users/{user_id}/sessions` | Mapping and parity test required |
| `MintAccessToken` | — | No direct catalog path; inspect projection/native semantics |
| `CheckSession` | — | No direct catalog path; inspect projection/native semantics |
| `CheckRecentSignIn` | `POST /me/2fa/setup`<br>`POST /me/2fa/factors` | Mapping and parity test required |
| `Group` | `GET /me/permissions`<br>`POST /invitations/redeem` | Mapping and parity test required |
| `Groups` | — | No direct catalog path; inspect projection/native semantics |
| `ListGroups` | — | No direct catalog path; inspect projection/native semantics |
| `ListGroupMembers` | `GET /groups/{group_id}/members` | Mapping and parity test required |
| `ListMemberships` | `GET /me/groups` | Mapping and parity test required |
| `GroupRoles` | `GET /me/permissions` | Mapping and parity test required |
| `CreateGroup` | — | No direct catalog path; inspect projection/native semantics |
| `DeleteGroup` | — | No direct catalog path; inspect projection/native semantics |
| `PurgeGroup` | — | No direct catalog path; inspect projection/native semantics |
| `SetGroupRole` | `PUT /groups/{group_id}/members/{kind}/{id}` | Mapping and parity test required |
| `RemoveGroupMember` | `DELETE /groups/{group_id}/members/{kind}/{id}` | Mapping and parity test required |
| `Can` | `GET /events` | Mapping and parity test required |
| `CanDirect` | `GET /me/permissions` | Mapping and parity test required |
| `EffectivePermissions` | `GET /me/permissions` | Mapping and parity test required |
| `KnownPermission` | — | No direct catalog path; inspect projection/native semantics |
| `Persona` | — | No direct catalog path; inspect projection/native semantics |
| `Permission` | — | No direct catalog path; inspect projection/native semantics |
| `Role` | `GET /admin/users`<br>`GET /groups/{group_id}/members`<br>`PUT /groups/{group_id}/members/{kind}/{id}`<br>`POST /groups/{group_id}/invitations`<br>`POST /groups/{group_id}/api-keys` | Mapping and parity test required |
| `RolePermissions` | — | No direct catalog path; inspect projection/native semantics |
| `ListGroupRoles` | `GET /groups/{group_id}/roles` | Mapping and parity test required |
| `GroupRole` | `GET /groups/{group_id}/roles/{role}` | Mapping and parity test required |
| `CreateGroupRole` | `POST /groups/{group_id}/roles` | Mapping and parity test required |
| `UpdateGroupRole` | `PATCH /groups/{group_id}/roles/{role}` | Mapping and parity test required |
| `DeleteGroupRole` | `DELETE /groups/{group_id}/roles/{role}` | Mapping and parity test required |
| `CreateAPIKey` | `POST /groups/{group_id}/api-keys` | Mapping and parity test required |
| `ListAPIKeys` | `GET /groups/{group_id}/api-keys` | Mapping and parity test required |
| `RevokeAPIKey` | `DELETE /groups/{group_id}/api-keys/{id}` | Mapping and parity test required |
| `ResolveAPIKey` | — | No direct catalog path; inspect projection/native semantics |
| `CreatePersonalAccessToken` | `POST /me/personal-access-tokens` | Mapping and parity test required |
| `ListPersonalAccessTokens` | `GET /me/personal-access-tokens` | Mapping and parity test required |
| `RevokePersonalAccessToken` | `DELETE /me/personal-access-tokens/{id}` | Mapping and parity test required |
| `ResolvePersonalAccessToken` | — | No direct catalog path; inspect projection/native semantics |
| `CreateInvitation` | `POST /groups/{group_id}/invitations` | Mapping and parity test required |
| `ListInvitations` | `GET /groups/{group_id}/invitations` | Mapping and parity test required |
| `RevokeInvitation` | `DELETE /groups/{group_id}/invitations/{id}` | Mapping and parity test required |
| `UpsertRemoteApplication` | `POST /groups/{group_id}/remote-applications`<br>`PATCH /groups/{group_id}/remote-applications/{id}` | Mapping and parity test required |
| `DeleteRemoteApplication` | `DELETE /groups/{group_id}/remote-applications/{id}` | Mapping and parity test required |
| `RemoteApplication` | `POST /groups/{group_id}/remote-applications`<br>`PATCH /groups/{group_id}/remote-applications/{id}` | Mapping and parity test required |
| `ListRemoteApplications` | `GET /groups/{group_id}/remote-applications` | Mapping and parity test required |
| `DeclareRemoteApplications` | — | No direct catalog path; inspect projection/native semantics |
| `RemoteUserRoles` | — | No direct catalog path; inspect projection/native semantics |
| `RemoveRemoteUserRole` | — | No direct catalog path; inspect projection/native semantics |
| `ApplyBootstrapManifest` | — | No direct catalog path; inspect projection/native semantics |
| `EnsureUserRole` | — | No direct catalog path; inspect projection/native semantics |
| `ImportUsers` | — | No direct catalog path; inspect projection/native semantics |
| `ImportSolanaLinks` | — | No direct catalog path; inspect projection/native semantics |
| `LinkProvider` | — | No direct catalog path; inspect projection/native semantics |
| `ProvisioningTargets` | `GET /admin/provisioning/targets` | Mapping and parity test required |

## Implementation boundary

Never serialize `auth.Identity` from trusted native arguments as proof of
authority. Mutations derive their actor from verified HTTP credentials on the
server. Native `InTx` cannot cross HTTP. Tenant selection must use the host’s
actual tenant dispatch contract, never a cursor or a new client-invented header.
A missing route requires a separately reviewed server endpoint or an explicit
local-only classification before a general remote constructor is exposed.
