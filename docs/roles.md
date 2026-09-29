# Roles and permissions

A **persona** is a type of permission group (channel, org, merchant). A
**permission group** is one instance of a persona, addressed by its ID. It only
holds roles: the thing it guards (the channel /c/golang, its name and its data)
lives in your app, which stores the group's ID. **root** is the persona with
exactly one group, the whole site; it always exists.

A **permission** is `<persona>:<resource>:<action>` (`channel:posts:edit`). `*`
may replace the action (`channel:posts:*`) or everything after the persona
(`channel:*`, the owner).

A **role** bundles permissions. Where a role is held is its scope: a role held
on a group applies there, and a role held on root applies in every group.

## Config

```go
Roles: authkit.RoleConfig{
	Personas: map[string]authkit.Persona{
		"channel": {
			Permissions: []string{"channel:posts:edit", "channel:posts:delete"},
		},
	},
	Roles: []authkit.Role{
		{Persona: "channel", Name: "moderator", Permissions: []string{"channel:posts:*"}},
		{Persona: iam.RootPersona, Name: "admin", Permissions: []string{"channel:*", "root:users:*"}},
	},
}
```

- `Persona.Permissions` is the persona's complete app catalog. A `"root"` entry
  is optional and only adds app root permissions.
- `Persona.CustomRoles` lets group owners define roles at run time from the
  catalog. `APIKeys` and `RemoteApplications` mount those group routes.
- `Role.Includes` names roles of the same persona whose permissions the role
  also holds.
- Every persona gets an `owner` role holding `<persona>:*`.
- `Persona.RequireMFA` lists permissions that need a second factor. A role
  whose grants reach one (directly, through `Includes`, or as a root role)
  can be held only by a user with MFA enrolled; applications and API keys never
  hold it. `root:members:manage` and `root:users:manage` always need MFA, so
  root's owner, and any role editing other people's accounts, does. With 2FA
  disabled deployment-wide the rule is inert.
- An account that needs MFA and has a passkey but no factor signs in only with
  the passkey (`passkey_required`). When the passkey is lost, verify the person
  out of band and call `ResetAccountMFA(ctx, iam.OperatorActor(), userID)`: it
  removes the account's passkeys, factors, backup codes, device keys and
  sessions, keeps its roles, and the next sign-in enrolls a factor.

## Built-in permissions

AuthKit adds these to each persona's catalog:

| Permission | Registered | Gates |
|---|---|---|
| `<p>:members:read`, `<p>:members:manage` | always | member lists and the role catalog; role assignment, invite links |
| `<p>:roles:manage` | `CustomRoles` | defining and deleting custom roles (also reads the role catalog) |
| `<p>:credentials:read`, `<p>:credentials:manage` | `APIKeys` or `RemoteApplications` | API keys, remote applications |

Root also has `root:users:read` (accounts and sign-ins), `root:users:ban`,
`root:users:delete` (delete and restore), `root:users:manage` (edit an account,
revoke its sessions) and `root:users:invite`.

## Validation at New

- Catalog entries are three-part and start with their persona.
- A role's permissions must match its persona's catalog; a wildcard must cover
  at least one registered permission. Persona roles hold only their own
  persona's permissions; root roles may hold any persona's.
- An unknown persona, a duplicate (persona, name), or an include cycle fails.
- A catalog role that shadows a custom role stored in a live group fails.

`New` stores a fingerprint of the role catalog. When it changes, `New` re-checks
every live API key, invite link and account invite against its creator's
authority and revokes what the creator can no longer issue.

## Groups

Your app creates and deletes groups, because it owns what they guard. It
decides who may make a channel and which names are allowed, then calls AuthKit
with the operator:

```go
tx, err := db.Begin(ctx)
// ...
owner := iam.UserSubject(userID)
g, err := auth.CreateGroup(ctx, iam.OperatorActor(), iam.NewGroup{Persona: "channel", Owner: &owner}, authkit.InTx(tx))
// ...
_, err = tx.Exec(ctx, `INSERT INTO channels (name, group_id) VALUES ($1, $2)`, name, g.ID)
// ...
err = tx.Commit(ctx)
```

- `CreateGroup`, `DeleteGroup` (soft) and `PurgeGroup` refuse every actor but
  `iam.OperatorActor()`. Before deleting, the app checks its own permission,
  for example `RequirePermission(iam.RootGroup(), "root:channels:delete")`.
- `NewGroup.Owner`, when set, must be a live account; it gets the `owner` role.
- `authkit.InTx(tx)` runs the operation in a savepoint of your transaction, so
  the group and your row commit or roll back together. `tx` must be READ
  COMMITTED and on the database of `Deps.Postgres`; AuthKit sets its own
  search_path inside the savepoint. The authority lock, the credential sweep
  and event records join your transaction, and the lock is held until it ends.
- Routes address a group by ID: `/api/v1/groups/{group_id}/members` and so on
  ([routes](api-endpoints.md)). `GET /me/groups` lists the caller's groups.

## Actors

Every mutation on `*authkit.Auth` takes an `iam.Actor` right after `ctx`;
reads take none (the host is the trust boundary). The zero actor is refused.

| Actor | Authority |
|---|---|
| `iam.UserActor(id)` | the user's roles on the group and on root |
| `iam.APIKeyActor(id)` | the key's role, only in the key's group |
| `iam.RemoteApplicationActor(id)` | the application's roles, only in its group |
| `iam.DelegatedActor(grant)` | its local user or application, capped by the grant's permissions |
| `iam.OperatorActor()` | everything; host code only |

Every actor but the operator is resolved live: a banned or deleted user, a
revoked or expired key, or a disabled application covers nothing. `Within`
narrows an actor to a permission ceiling. The operator skips the permission
rules but not the invariants: the last usable owner and MFA-required roles
bind it too. Only users and the operator issue credentials (API keys, invite
links, account invites, group-registered applications); a user's credentials
die with the user's authority, the operator's never. The user who supplies a
group application's keys is its registrar: the application holds only roles
the registrar could issue, and loses them with the registrar's authority. `verify.ActorFromClaims` derives the actor of a request
([verification](verification.md)).

Assigning or removing a role needs `<p>:members:manage` for a user subject and
`<p>:credentials:manage` for an application, and the actor must cover every
permission of the role it grants or takes away. Account operations need the
named `root:users:*` permission and coverage of the target's grants on root and
in every group it holds a role in.

## Checks

`Can` considers the actor's roles on the group and on root; a `root:`
permission counts only on root and never stands in for a persona permission. An
unregistered permission returns `iam.ErrUnknownPermission`, never a silent
false. `RequirePermission` (on `*authkit.Auth`, `verify`, and the gin and fiber
adapters) authenticates the request and panics when the route is built with an
unregistered permission. AuthKit's own routes refuse delegated tokens.
