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

The app declares its model once with `authkit.NewRoles`, typically in a
package-level `var` block, and passes it as `Config.Roles`. Every declaration
returns a typed value (`iam.Persona`, `iam.Perm`, `iam.Role`) that the app then
hands to AuthKit; a string never converts to one, so a misspelled name is a
compile error.

```go
var (
	rbac = authkit.NewRoles()

	Channel     = rbac.Persona("channel")
	PostsEdit   = Channel.Permission("posts", "edit")
	PostsDelete = Channel.Permission("posts", "delete")

	Moderator = Channel.Role("moderator", Channel.Resource("posts").All())
	Admin     = rbac.Root.Role("admin", Channel.All(), rbac.Root.Users.All())
)

cfg := authkit.Config{Roles: rbac /* ... */}
```

- `Persona(name, opts...)` declares a persona; `Permission(resource, action)`
  adds to its catalog. `rbac.Root` is root, which always exists;
  `rbac.Root.Permission` adds app root permissions.
- Options `authkit.CustomRoles` (group owners define roles at run time from
  the catalog), `authkit.APIKeys` and `authkit.RemoteApplications` (mount those
  group routes). Root's options go to `NewRoles`.
- Patterns: `Channel.All()` is `channel:*`, `Channel.Resource("posts").All()`
  is `channel:posts:*`.
- `Role(name, grants...)` takes permissions, patterns, and roles of the same
  persona whose permissions it includes.
- Every persona has `Owner`, the role holding `<persona>:*`.
- `RequireMFA(perms...)` marks permissions that need a second factor. A role
  whose grants reach one (directly, through an included role, or as a root
  role) can be held only by a user with MFA enrolled; applications and API keys
  never hold it. `root:members:manage` and `root:users:manage` always need MFA,
  so root's owner, and any role editing other people's accounts, does. With 2FA
  disabled deployment-wide the rule is inert.
- An account that needs MFA and has a passkey but no factor signs in only with
  the passkey (`passkey_required`). When the passkey is lost, verify the person
  out of band and call `ResetAccountMFA(ctx, userID)`: it
  removes the account's passkeys, factors, backup codes, device keys and
  sessions, keeps its roles, and the next sign-in enrolls a factor.

Names read at run time (a request parameter, a config file) resolve through
the schema: `Client.Persona(name)`, `Client.Permission(text)` and
`Client.Role(persona, name)` return the typed value or an error
(`iam.ErrUnknownGroupPersona`, `iam.ErrUnknownPermission`,
`iam.ErrRoleNotAssignable`). A role is `<persona>:<name>` in its text form
(`MarshalText`); rows and AuthKit's routes use the bare name.

## Built-in permissions

AuthKit adds these to each persona's catalog, as fields of its definition:

| Permission | Field | Registered | Gates |
|---|---|---|---|
| `<p>:members:read`, `<p>:members:manage` | `Members.Read`, `Members.Manage` | always | member lists and the role catalog; role assignment, invite links |
| `<p>:roles:manage` | `Roles.Manage` | `CustomRoles` | defining and deleting custom roles (also reads the role catalog) |
| `<p>:credentials:read`, `<p>:credentials:manage` | `Credentials.Read`, `Credentials.Manage` | `APIKeys` or `RemoteApplications` | API keys, remote applications |

Root also has `rbac.Root.Users`: `Read` (`root:users:read`, accounts and
sign-ins), `Ban`, `Delete` (delete and restore), `Manage` (edit an account,
revoke its sessions) and `Invite`. A built-in that is not registered fails
`New` wherever a role holds it.

## Validation at New

- Names are `[a-z][a-z0-9-]*`; a permission declared twice, or one AuthKit
  already registers, fails.
- A role's permissions must match its persona's catalog; a wildcard must cover
  at least one registered permission. Persona roles hold only their own
  persona's permissions; root roles may hold any persona's.
- An unknown persona, a duplicate (persona, name), or an include cycle fails.
- A catalog role that shadows a custom role stored in a live group fails.

`New` stores a fingerprint of the role catalog. When it changes, `New` re-checks
every live API key, invite link and account invite against its creator's
authority and revokes what the creator can no longer issue.

## Groups

Your app creates and deletes groups, because it owns what they guard. These
are host operations: your code decides who may make a channel and which names
are allowed, so they take no actor.

```go
tx, err := db.Begin(ctx)
// ...
owner := iam.UserSubject(userID)
g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: Channel.Persona, Owner: &owner}, authkit.InTx(tx))
// ...
_, err = tx.Exec(ctx, `INSERT INTO channels (name, group_id) VALUES ($1, $2)`, name, g.ID)
// ...
err = tx.Commit(ctx)
```

- `CreateGroup`, `DeleteGroup` (soft) and `PurgeGroup` check no permission.
  Before deleting, the app checks its own; see [who deletes a channel](#who-deletes-a-channel).
- `NewGroup.Owner`, when set, must be a live account; it gets the `owner` role.
- `authkit.InTx(tx)` runs the operation in a savepoint of your transaction, so
  the group and your row commit or roll back together. `tx` must be READ
  COMMITTED and on the database of `Deps.Postgres`; AuthKit sets its own
  search_path inside the savepoint. The authority lock, the credential sweep
  and event records join your transaction, and the lock is held until it ends.
- Routes address a group by ID: `/api/v1/groups/{group_id}/members` and so on
  ([routes](api-endpoints.md)). `GET /me/groups` lists the caller's groups.

## Who deletes a channel

Two models, both app permissions:

- Per channel: `SelfDelete = Channel.Permission("self", "delete")`, checked in
  the channel's own group (`RequirePermission(auth, SelfDelete, …)` with the
  channel's group). Its owner holds it through `Owner`, and a root role holding
  `Channel.All()` holds it in every channel. Owners can delete their own
  channel.
- Global: `ChannelsDelete = rbac.Root.Permission("channels", "delete")`,
  checked on `iam.RootGroup()`. Only root roles hold it; a channel owner never
  does, since `root:` permissions count only on root. Only site admins delete.

## Actors

A mutation whose rules depend on who acts takes an `iam.Actor` right after
`ctx`; the zero actor is refused. Host operations take none: your code decides
(`CreateGroup`, `DeleteGroup`, `PurgeGroup`, `EnsureUserRole`, `CreateUser`,
`PurgeUsers`, `ResetAccountMFA`, `MintAccessToken`, `ApplyBootstrapManifest`,
`ImportUsers`, `ImportSolanaLinks`, `LinkProvider`), and they keep every
invariant. Reads take none either: the host is the trust boundary.

| Actor | Authority |
|---|---|
| `iam.UserActor(id)` | the user's roles on the group and on root |
| `iam.APIKeyActor(id)` | the key's role, only in the key's group |
| `iam.RemoteApplicationActor(id)` | the application's roles, only in its group |
| `iam.DelegatedActor(grant)` | its local user or application, capped by the grant's permissions |
| `iam.SystemActor()` | your app's own code acting, with no user: everything; host code only |

Every actor but the system is resolved live: a banned or deleted user, a
revoked or expired key, or a disabled application covers nothing. `Within`
narrows an actor to a permission ceiling. The system skips the permission
rules but not the invariants: the last usable owner and MFA-required roles
bind it too. Only users and the system issue credentials (API keys, invite
links, account invites, group-registered applications); a user's credentials
die with the user's authority, the system's never. The user who supplies a
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
false. `RequirePermission` (on `*authkit.Client`, `verify`, and the gin and fiber
adapters) authenticates the request and panics when the route is built with an
unregistered permission. AuthKit's own routes refuse delegated tokens.
