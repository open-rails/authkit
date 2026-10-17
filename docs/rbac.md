# RBAC

How AuthKit decides who may do what. The [README](../README.md) shows the setup; this page covers the model and what happens when you change it.

## The model

- A **persona** is a type of permission group: `channel`, `org`, `merchant`.
- A **group** is one instance of a persona: an id and a persona. Your app creates one per entity (`Client.CreateGroup` for the channel `/c/golang`) and stores its id. The channel's name and data live in your tables, not AuthKit's.
- **`root`** is the persona with exactly one group: the whole site. It always exists. HTTP routes address it as `root`, and Go code as `iam.RootGroup()`.
- A **permission** is `<persona>:<resource>:<action>`, such as `channel:posts:edit`. A grant can be a pattern: `channel:posts:*` covers every action on posts, and `channel:*` covers every channel permission. The persona is never a wildcard.
- A **role** is a named bundle of permissions, scoped to one persona. Its text is always qualified, as in `channel:moderator` and `root:admin`, in Go, on the wire and in the database. A role may include other roles of the same persona. Your code declares roles; a persona can also let each group define [custom roles](#custom-roles) of its own.
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
| `<persona>:credentials:read` | with `APIKeys`, `RemoteApplications` or `OAuthClients` | list the group's API keys, [OAuth clients](authorization-server.md#group-clients) and [remote applications](resource-server.md#trusted-issuers) |
| `<persona>:credentials:manage` | with `APIKeys`, `RemoteApplications` or `OAuthClients` | create and revoke API keys; register remote applications and give them roles; register and change OAuth clients |
| `<persona>:directory:read` | with `RemoteApplications` | read the group's [directory](scim.md#directory) of its remote applications' users |
| `<persona>:directory:manage` | with `RemoteApplications` | provision that directory over SCIM |
| `<persona>:roles:read` | with `CustomRoles` | see what each of the group's roles grants (the role list also admits `members:read`) |
| `<persona>:roles:manage` | with `CustomRoles` | define, change and delete the group's custom roles |
| `root:users:read` | always | look through accounts and their sign-in history |
| `root:users:ban` | always | ban and unban |
| `root:users:delete` | always | delete an account, or restore it within 30 days |
| `root:users:manage` | always | edit someone else's account and sign them out everywhere |
| `root:users:invite` | always | invite someone to create an account |

Handing out a role takes `members:manage` in that group, and the grantor's own grants must cover every permission of the role being given and of the role it replaces. A removed role grants nothing, so taking it away or replacing it needs no cover. Account actions (`root:users:*`) also require covering every role the target holds in each of their groups and, on root, outranking it: staff can't ban, delete or edit a peer or anyone above them, so demote first. Signing someone out everywhere needs only cover, so a peer can contain a compromised account.

### Roles that need MFA

`PersonaDef.RequireMFA(perms...)` marks permissions that need a second factor. A role needs MFA when its grants reach one of them, whether directly, through an include or through a root role. Such a role:

- can be assigned before a user enrolls, but its holder must finish MFA before using authenticated access;
- is never held by an API key or a remote application;
- prevents its holder from removing their last second factor while the requirement applies.

`root:members:manage` and `root:users:manage` always need MFA, so `root:owner` does too. The requirement is off while `TwoFactor.Mode` is disabled. When a role needs MFA but no second factor can be enrolled, `New` logs it and the `authkit_two_factor` probe fails: those accounts can't sign in until a method works.

## Requiring MFA after a promotion

Role assignment and MFA enrollment are separate. `SetGroupRole`, `EnsureUserRole`,
invitation acceptance and custom role changes may assign a protected role to an
unenrolled user. Their next sign-in returns `enrollment_required`; an already
issued token cannot keep using protected access. The role remains assigned.

For an individual account, an account administrator may set or clear an explicit
requirement:

```go
required := true
_, err := client.UpdateUser(ctx, administrator, userID, iam.UserUpdate{
    MFARequired: &required,
})
```

The HTTP equivalent is `PATCH /admin/users/{user_id}` with
`{"mfa_required":true}`. The shared UsersAdmin editor exposes the same control.
This field is administrator-only; clearing it does not waive a deployment or
role requirement. `GET /me/security` returns the effective requirement as
`two_factor.required`.

Requirements use current policy rather than a queued job. Existing sessions are
checked when used: a recent first-factor proof can continue into enrollment; an
older session returns `reauthentication_required` and must sign in again first.
AuthUI handles both continuations. An enrollment token grants only enrollment
access, and a verified user-verifying passkey already satisfies MFA. Required
policy accepts configured TOTP/SMS or UV passkeys; email does not qualify for
privileged authority. A delivery outage does not erase a registered factor or
allow a weaker proof to replace it. Required first-passkey enrollment uses the
short-lived pending primary proof and never grants a full session first.
Creation is bound to account, tenant, RP, nonce and credential generation;
key insertion and its UV-authenticated session commit together. Existing keys
on another RP still protect the account against password-only enrollment. A required
last factor cannot be removed (`2fa_required_by_policy`); enroll its replacement
first, or use the system's account-recovery operation for a lost factor.

## Custom roles

A persona declared with `authkit.CustomRoles` lets each of its groups define roles at run time, for least privilege your code didn't plan: a merchant's `storefront` role holding only `merchant:entitlements:read`, given to an API key.

```go
Merchant = rbac.Persona("merchant", authkit.APIKeys, authkit.CustomRoles)

storefront, err := client.CreateGroupRole(ctx, who, iam.GroupByID(id), iam.NewGroupRole{
	Name: "storefront", Permissions: []iam.Perm{EntitlementsRead},
}) // storefront.Name is merchant:custom-storefront
```

- **Name.** `<persona>:custom-<name>`. No declared role may start with `custom-`, so the two never clash, even when a later deploy declares a name a group already uses. A custom role exists only in its group: no other group sees or holds it.
- **Grants.** 1 to 256 permissions or patterns that a declared role of the persona may hold: its own persona's, and on root any persona's. No includes. A group defines at most 100 (`iam.MaxGroupRoles`).
- **Holders.** Assign it like a declared role, in its group: members, API keys, remote applications, invitations and `role_map`. MFA follows its permissions, as for a declared role.
- **Live.** A check reads the definition in the same query as the assignment, so a change applies to every holder at their next request. Resource access tokens keep the permissions they were minted with until they expire, as after any role change.
- **Authority.** Creating one takes `roles:manage` and covering every grant. Changing or deleting one also takes covering its current grants and, while it is held, what hands it out: `members:manage` for members and invitations, `credentials:manage` for API keys and applications. A change needing MFA is refused while an API key or application holds the role (`role_not_assignable`). Human holders without a second factor must finish enrollment on their next sign-in or authenticated request. Changes on root need a recent sign-in.
- **Removing a permission** needs nothing more: holders lose it at their next request and, as after any demotion, the credentials whose issuers no longer cover their role are revoked (the credential sweep). Adding one can revoke too: a key, invitation or application holding the role whose issuer doesn't cover the addition.
- **Deleting** takes the role from every holder in the same transaction: members and applications lose it (`role.revoked` events), the API keys and invitations carrying it are revoked and `role_map` entries naming it dropped. A later role of the same name starts with no holders.
- **Audit.** `group.role_created`, `group.role_updated` and `group.role_deleted` events carry the role and its grants before and after.

Over HTTP:

| Route | Needs | Does |
|---|---|---|
| `GET /groups/{group_id}/roles` | `members:read` or `roles:read` | every role the group can assign: declared, then custom |
| `GET /groups/{group_id}/roles/{role}` | `members:read` or `roles:read` | one, with its `grants` and the `permissions` they cover |
| `POST /groups/{group_id}/roles` | `roles:manage` | `{name, permissions}` defines one: 201 |
| `PATCH /groups/{group_id}/roles/{role}` | `roles:manage` | `{permissions}` replaces what it grants |
| `DELETE /groups/{group_id}/roles/{role}` | `roles:manage` | deletes it: 204 |

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
| who holds which role in each group, as role text (`channel:moderator`) | what each declared role grants |
| the role each API key, invitation and remote application carries | which permissions need MFA |
| per app: a fingerprint of the compiled catalog, and the role names it declares | |
| each group's custom roles and what they grant | |

Postgres stores no permission, nor what a role grants, except a group's custom roles.

A check (`Client.Can`, or `RequirePermission` in `verify` and the adapters) combines the two. Postgres answers "is this identity still signed in and usable, and which role does it hold in this group and on root?" The in-memory catalog answers "what do those roles allow?" This runs live on every gated request, so a role change, ban or sign-out applies at the next request. `Required` alone, meaning signed in with no permission check, verifies a user's token without the database.

## Changing the catalog

| Change | What you do | What happens at the next deploy |
|---|---|---|
| Add a permission or role | code | It's available as soon as it ships. |
| Rename or remove a permission | code; the compiler finds every use | No stored data names a permission, so there's nothing to migrate. Resource access tokens carry permission text, so those minted earlier lack the new name until they expire. |
| Change what a role grants | code | Every holder gets the new grants. No migration. |
| Remove a role | code | Its assignments stay in Postgres but grant nothing. At startup AuthKit logs `authkit: rbac drift detected` with counts. The credential sweep revokes API keys and invitations users issued for it. Anyone with `members:manage` in a group can remove its holders there or give them another role. |
| Turn `CustomRoles` off for a persona | code | Its groups' custom roles grant nothing, members' assignments count as drift, and the credential sweep revokes the keys and invitations carrying them. Turning it back on restores the roles and members' assignments. |
| Rename a role or persona | code, plus a data fix | Stored rows keep the old text. Until they're fixed, the old name's holders hold nothing, as if the role were removed. AuthKit has no rename operation. |

**The credential sweep.** AuthKit fingerprints the compiled catalog: every role's grants, the permissions that need MFA, and whether 2FA is on. Each app's fingerprint is stored. When `New` sees a different one, it re-checks every API key, invitation and application role that this app issued, against the creator's authority under the new catalog. It revokes what the creator no longer covers, plus any machine credential whose role now needs MFA, and logs each one. The sweep never fails startup. It is why renaming a permission or changing a role can revoke credentials.

## Apps sharing an account store

Apps that share one account store (the same schema, listed in `TokenConfig.AccountIssuers`) share membership, root included: who holds which role. Each app declares its own `Roles`, so a role means what that app's catalog says. A role only a peer declares grants nothing in this app, and doesn't count as drift here. This app can't take it away or replace it either, since it can't tell what it grants; do that through the peer.

Fingerprints and sweeps are per app. Each app judges only the API keys, invitations and applications issued through it, and an API key works only at the app that minted it. When a change through one app demotes a user, every other app sweeps its own credentials from that user.

## A library that guards its own routes

A library that serves routes inside your app, such as OpenRails' billing routes, takes `client.Authenticator()`, a authkit/auth `Authenticator`. It says who a request is; the library decides what to admit and answers its own refusals. People and applications (API keys) both authenticate, checked live. The Client itself is not one.

| Method | Is |
|---|---|
| `Authenticate(r)` | `verify.AuthenticateSession` over the Client: a revoked sign-in or a banned or deleted account is refused. Behind a gate over the Client it reuses the gate's verification, so a DPoP proof is spent once. A DPoP refusal is an `*auth.Challenge` carrying `WWW-Authenticate` and `DPoP-Nonce` |
| `Verified.Can(ctx, scope, p)` | `Client.Can`: exactly `p`, in the group `scope.ID` names, live |
| `Verified.CheckRecentSignIn(ctx)` | `verify.Sensitive`'s check. A stale sign-in is an `*auth.Challenge` with `auth.ErrStepUpRequired`, `MaxAge` (15 minutes) and the account's step-up methods as `Metadata`; a credential with no sign-in of its own (an API key) is `auth.ErrForbidden` |
| `KnownPermission(p)` | `p` is one registered permission, so the library refuses a misspelled one when it mounts |
| `RootScope(ctx)` | `client.Scope(ctx, iam.RootGroup())` (authkit/auth `Root`): where root roles hold their `root:` permissions, which the library checks there |

A user acting for themself carries their email and username, read from the account. A permission's persona says where the library checks it: a `root:` permission in the Authenticator's `RootScope`, so the host passes no scope; a group persona's in the group it serves, `client.Scope(ctx, ref)` (`{Authority: Config.Token.Issuer, ID: <the group's id>}`).

A credential bound to a group (`BoundScope`) acts only there:

- A group API key holds its role only in its own group; a root API key (`NewRoles(authkit.APIKeys)`) acts in root's.
- A person's token exchanged for one group (RFC 8693 `group_id`, [authorization server](authorization-server.md#group-bound-tokens)) holds what the person holds in that group, and keeps the person's `root:` permissions on root: a person keeps their root role whatever group a token names (authkit/auth `Bound`).
- A host's group-bound mint (`iam.AccessTokenOptions.Group`) is a customer token: bound, holding nothing.

Like AuthKit's own API, `client.Authenticator()` refuses resource access tokens (`at+jwt`) unless `Config.Resource` names their resource. For a library that is also a resource server, `client.NewVerifier(audiences)` with its resource among them gives a `Verifier` whose `Authenticator()` takes them too: an OAuth client's own token (client credentials) authenticates as an application, holding nothing in a group (its `permissions` are the resource server's to read).

### A library's permissions in two personas

A library acting on one tenant at a time, such as OpenRails acting on one merchant, checks each route's permission in two places: its `merchant:` name in that merchant's group, or its `root:` twin on root. The library exports both, full `persona:resource:action` names. A role belongs to one persona, so the host defines one role per persona, from the same constants:

```go
rbac := authkit.NewRoles()
Merchant := rbac.Persona("merchant", authkit.APIKeys)
grants := func(perms []iam.Perm) (out []iam.Grant) {
	for _, p := range perms {
		out = append(out, p)
	}
	return out
}
// lib.MerchantPermissions: merchant:billing:read, …; lib.RootPermissions: root:billing:read, …
Merchant.Role("billing", grants(Merchant.Declare(lib.MerchantPermissions...))...) // in a merchant's group: that merchant
rbac.Root.Role("billing", grants(rbac.Root.Declare(lib.RootPermissions...))...)   // on root: every merchant
```

Staff of every merchant hold the `root:` names on root. A root role holding `merchant:` names also reaches every merchant group (above), but a library that checks `root:` on root, as OpenRails does, never relies on that.

## Related

- **`verify.Claims.RootRole`** is the user's root role when the token was minted. It is for display only, can be stale for the token's lifetime, and must never authorize anything.
- **`Client.RolePermissions(role)`** returns a declared role's grants, with includes flattened; `Client.GroupRole` and `Client.ListGroupRoles` read a group's roles, custom ones included. `Client.EffectivePermissions` and `GET /api/v1/me/permissions` return what an identity holds, for UIs.
- **`PersonaDef.Permissions()`** lists a persona's catalog, built-ins included. **`PersonaDef.Expand(grants)`** lists the catalog permissions some grant covers, as `GET /api/v1/me/permissions` does, with no database read: `Roles.Root.Expand(grants)` over a token's `RootRole` and `Client.RolePermissions` shows a user's permissions.
- **Members over HTTP:**
  - `PUT /api/v1/groups/{group_id}/members/users/{id}` with `{"role": "channel:moderator"}` gives a role.
  - `DELETE` on the same path takes it away.
  - `GET /api/v1/groups/{group_id}/roles` lists the group's roles, its [custom roles](#custom-roles) included.

  `{group_id}` may be `root`, and changes on root need a recent sign-in.
