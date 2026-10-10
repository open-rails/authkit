# RBAC

How AuthKit decides who may do what. The [README](../README.md) shows the setup; this page covers the model and what happens when you change it.

## The model

- A **persona** is a type of permission group: `channel`, `org`, `merchant`.
- A **group** is one instance of a persona: an id and a persona. Your app creates one per entity (`Client.CreateGroup` for the channel `/c/golang`) and stores its id. The channel's name and data live in your tables, not AuthKit's.
- **`root`** is the persona with exactly one group: the whole site. It always exists. HTTP routes address it as `root`, and Go code as `iam.RootGroup()`.
- A **permission** is `<persona>:<resource>:<action>`, such as `channel:posts:edit`. A grant can be a pattern: `channel:posts:*` covers every action on posts, and `channel:*` covers every channel permission. The persona is never a wildcard.
- A **role** is a named bundle of permissions, scoped to one persona. Its text is always qualified, as in `channel:moderator` and `root:admin`, in Go, on the wire and in the database. A role may include other roles of the same persona.
- A member holds **one role per group**. Giving someone a new role there replaces the old one.

### Owner

Every persona has an `owner` role (`channel:owner`) that holds `<persona>:*`. `iam.NewGroup.Owner` seeds a new group's owner. AuthKit refuses to remove or demote a group's last owner (`409 last_owner`).

`root:owner` holds `root:*` and every other persona's `<persona>:*`, so the site owner can act in every group, like a root role holding `Channel.All()` (below).

### Root roles reach every group

A persona's role may hold only that persona's permissions. A root role may hold any persona's permissions, and holding it on root applies them in every group of that persona. The README's `Admin` is `rbac.Root.Role("admin", Channel.All(), …)`: it can do everything in every channel. `root:` permissions count only on root itself.

### Built-in permissions

AuthKit registers these itself; you never declare them. `<persona>` means every persona, root included.

| Built-in | Registered | Lets you |
|---|---|---|
| `<persona>:members:read` | always | see who holds which role, the group's roles and its invitations |
| `<persona>:members:manage` | always | give someone a role, change it or take it away; invite people |
| `<persona>:credentials:read` | with `APIKeys` or `RemoteApplications` | list the group's API keys |
| `<persona>:credentials:manage` | with `APIKeys` or `RemoteApplications` | create and revoke API keys; give remote applications roles |
| `<persona>:directory:read` | with `RemoteApplications` | read the group's [directory](scim.md#directory) of its remote applications' users |
| `<persona>:directory:manage` | with `RemoteApplications` | provision that directory over SCIM |
| `root:users:read` | always | look through accounts and their sign-in history |
| `root:users:ban` | always | ban and unban |
| `root:users:delete` | always | delete an account, or restore it within 30 days |
| `root:users:manage` | always | edit someone else's account and sign them out everywhere |
| `root:users:invite` | always | invite someone to create an account |

Handing out a role takes `members:manage` in that group, and the grantor's own grants must cover every permission of the role being given and of the role it replaces. A removed role grants nothing, so taking it away or replacing it needs no cover. Account actions (`root:users:*`) also require covering every role the target holds in each of their groups and, on root, outranking it: staff can't ban, delete or edit a peer or anyone above them, so demote first. Signing someone out everywhere needs only cover, so a peer can contain a compromised account.

### Roles that need MFA

`PersonaDef.RequireMFA(perms...)` marks permissions that need a second factor. A role needs MFA when its grants reach one of them, whether directly, through an include or through a root role. Such a role:

- goes only to users with a second factor enrolled;
- is never held by an API key or a remote application;
- is taken away from users who turn their own 2FA off.

`root:members:manage` and `root:users:manage` always need MFA, so `root:owner` does too. The requirement is off while `TwoFactor.Mode` is disabled. `New` fails when a role needs MFA but no second factor can be enrolled.

## Declaring the catalog

`authkit.NewRoles()` returns a builder that you fill at package init, usually in a `var (...)` block like the README's. Each call registers something and returns a typed value: `rbac.Persona("channel")` returns `Channel`, `Channel.Permission("posts", "edit")` returns `PostsEdit`, and `Channel.Role("moderator", …)` returns `Moderator`. Includes and MFA look like this:

```go
Senior = Channel.Role("senior", Moderator, Channel.Members.Manage) // Moderator's grants, plus managing members

func init() { Channel.RequireMFA(Channel.Members.Manage) }
```

Pass the builder as `Config.Roles` (nil means root only). The builder collects every declaration mistake, such as a bad name or a duplicate. `authkit.New` reports them all at once, then validates and compiles the catalog once. The compile step checks that every grant matches a registered permission, that no persona role holds another persona's permissions, that includes don't form a cycle, and that every `RequireMFA` pattern matches something. The compiled catalog is fixed for that client's life: changing the builder after `New` does nothing to it, and only a client built later would see the change.

Typed values are the point: `iam.Persona`, `iam.Perm` and `iam.Role` aren't strings, so a misspelled role or permission is a compile error, not a silent deny. Text from outside, such as a request body or a config file, goes through `Client.Role`, `Client.Permission` and `Client.Persona`, which reject anything the catalog doesn't declare.

## What's stored where

| In Postgres | Only in your code |
|---|---|
| each group's id and persona name | the personas and their permissions |
| who holds which role in each group, as role text (`channel:moderator`) | what each role grants |
| the role each API key, invitation and remote application carries | which permissions need MFA |
| per app: a fingerprint of the compiled catalog, and the role names it declares | |

Postgres never stores a permission or what a role grants.

A check (`Client.Can`, or `RequirePermission` in `verify` and the adapters) combines the two. Postgres answers "is this identity still signed in and usable, and which role does it hold in this group and on root?" The in-memory catalog answers "what do those roles allow?" This runs live on every gated request, so a role change, ban or sign-out applies at the next request. `Required` alone, meaning signed in with no permission check, verifies a user's token without the database.

## Changing the catalog

| Change | What you do | What happens at the next deploy |
|---|---|---|
| Add a permission or role | code | It's available as soon as it ships. |
| Rename or remove a permission | code; the compiler finds every use | No stored data names a permission, so there's nothing to migrate. Resource access tokens carry permission text, so those minted earlier lack the new name until they expire. |
| Change what a role grants | code | Every holder gets the new grants. No migration. |
| Remove a role | code | Its assignments stay in Postgres but grant nothing. At startup AuthKit logs `authkit: rbac drift detected` with counts. The credential sweep revokes API keys and invitations users issued for it. Anyone with `members:manage` in a group can remove its holders there or give them another role. |
| Rename a role or persona | code, plus a data fix | Stored rows keep the old text. Until they're fixed, the old name's holders hold nothing, as if the role were removed. AuthKit has no rename operation. |

**The credential sweep.** AuthKit fingerprints the compiled catalog: every role's grants, the permissions that need MFA, and whether 2FA is on. Each app's fingerprint is stored. When `New` sees a different one, it re-checks every API key, invitation and application role that this app issued, against the creator's authority under the new catalog. It revokes what the creator no longer covers, plus any machine credential whose role now needs MFA, and logs each one. The sweep never fails startup. It is why renaming a permission or changing a role can revoke credentials.

## Apps sharing an account store

Apps that share one account store (the same schema, listed in `TokenConfig.AccountIssuers`) share membership, root included: who holds which role. Each app declares its own `Roles`, so a role means what that app's catalog says. A role only a peer declares grants nothing in this app, and doesn't count as drift here. This app can't take it away or replace it either, since it can't tell what it grants; do that through the peer.

Fingerprints and sweeps are per app. Each app judges only the API keys, invitations and applications issued through it, and an API key works only at the app that minted it. When a change through one app demotes a user, every other app sweeps its own credentials from that user.

## A library that guards its own routes

A library that serves routes inside your app, such as OpenRails' billing routes, takes `client.Authenticator()`, a helpers/auth `Authenticator`. It says who a request is; the library decides what to admit and answers its own refusals. People and applications (API keys) both authenticate, checked live. The Client itself is not one.

| Method | Is |
|---|---|
| `Authenticate(r)` | `verify.AuthenticateSession` over the Client: a revoked sign-in or a banned or deleted account is refused. Behind a gate over the Client it reuses the gate's verification, so a DPoP proof is spent once. A DPoP refusal is an `*auth.Challenge` carrying `WWW-Authenticate` and `DPoP-Nonce` |
| `Verified.Can(ctx, scope, p)` | `Client.Can`: exactly `p`, in the group `scope.ID` names, live |
| `Verified.CheckRecentSignIn(ctx)` | `verify.Sensitive`'s check. A stale sign-in is an `*auth.Challenge` with `auth.ErrStepUpRequired`, `MaxAge` (15 minutes) and the account's step-up methods as `Metadata`; a credential with no sign-in of its own (an API key) is `auth.ErrForbidden` |
| `KnownPermission(p)` | `p` is one registered permission, so the library refuses a misspelled one when it mounts |

A user acting for themself carries their email and username, read from the account. `client.Scope(ctx, ref)` is the group where the library checks its permissions, `{Authority: Config.Token.Issuer, ID: <the group's id>}`; root roles hold theirs in `client.Scope(ctx, iam.RootGroup())`. The library names no permissions: the host passes its own.

```go
rbac := authkit.NewRoles()
customersRead := rbac.Root.Permission("customers", "read")
customersUpdate := rbac.Root.Permission("customers", "update")
rbac.Root.Role("support", customersRead, customersUpdate)

staff, err := client.Scope(ctx, iam.RootGroup()) // where the roles above are held
if err != nil {
	return err
}
err = openrailsgin.Mount(r, bill, openrails.Routes{
	Auth:        client.Authenticator(), // says who a request is; OpenRails decides what to admit
	Scope:       staff,
	RouteGroups: openrails.RouteGroups{Admin: true},
	Permissions: openrails.Permissions{AdminRead: customersRead, AdminUpdate: customersUpdate},
})
```

A group API key holds its role only in its own group, so it acts where a library is mounted with that group's scope (one group per merchant: `client.Scope(ctx, iam.GroupByID(id))`); a root API key (`NewRoles(authkit.APIKeys)`) acts in root's. Like AuthKit's own API, `client.Authenticator()` refuses resource access tokens (`at+jwt`). For a library that is also a resource server, `client.NewVerifier(audiences)` with its resource among them gives a `Verifier` whose `Authenticator()` takes them too: an OAuth client's own token (client credentials) authenticates as an application, holding nothing in a group (its `permissions` are the resource server's to read).

## Related

- **`verify.Claims.RootRole`** is the user's root role when the token was minted. It is for display only, can be stale for the token's lifetime, and must never authorize anything.
- **`Client.RolePermissions(role)`** returns a role's grants, with includes flattened. `Client.EffectivePermissions` and `GET /api/v1/me/permissions` return what an identity holds, for UIs.
- **`PersonaDef.Permissions()`** lists a persona's catalog, built-ins included. **`PersonaDef.Expand(grants)`** lists the catalog permissions some grant covers, as `GET /api/v1/me/permissions` does, with no database read: `Roles.Root.Expand(grants)` over a token's `RootRole` and `Client.RolePermissions` shows a user's permissions.
- **Members over HTTP:**
  - `PUT /api/v1/groups/{group_id}/members/users/{id}` with `{"role": "channel:moderator"}` gives a role.
  - `DELETE` on the same path takes it away.
  - `GET /api/v1/groups/{group_id}/roles` lists the group's roles.

  `{group_id}` may be `root`, and changes on root need a recent sign-in.
