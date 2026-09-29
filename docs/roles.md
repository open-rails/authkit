# Roles and permissions

A **persona** is a type of permission group (channel, org, merchant). A
**permission group** is one instance of a persona (/c/golang), created at run
time. **root** is the persona with exactly one group, the whole site; it always
exists.

A **permission** is `<persona>:<resource>:<action>` (`channel:posts:edit`). `*`
may replace the action (`channel:posts:*`) or everything after the persona
(`channel:*`, the owner). The resource `self` is the group itself.

A **role** bundles permissions. Where a role is held is its scope: a role held
on a group applies there, and a role held on root applies in every group.

## Config

```go
Roles: authkit.RoleConfig{
	Personas: map[string]authkit.Persona{
		"channel": {
			Permissions: []string{"channel:posts:edit", "channel:posts:delete"},
			Creation:    authkit.GroupCreation{Enabled: true, ReservedSlugs: []string{"announcements"}},
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
- Every persona gets an `owner` role holding `<persona>:*`. Root's owner
  requires MFA.
- Reserved slugs of persona p are creatable only by actors holding `p:*` on root.

## Built-in permissions

AuthKit registers these in every catalog:

| Permission | Gates |
|---|---|
| `<p>:members:read`, `<p>:members:manage` | member lists, role assignment, invite links |
| `<p>:roles:read`, `<p>:roles:manage` | role catalog, custom roles |
| `<p>:credentials:read`, `<p>:credentials:manage` | API keys, remote applications |
| `<p>:self:read`, `<p>:self:update`, `<p>:self:delete` | the group's descriptor, slug and display name, soft delete (not on root) |

Root also has `root:users:{ban,recover,delete,invite}`, `root:roles:manage`,
`root:credentials:manage` and `root:resources:read`.

## Validation at New

- Catalog entries are three-part, start with their persona, and never use `self`.
- A role's permissions must match its persona's catalog; a wildcard must cover
  at least one registered permission. Persona roles hold only their own
  persona's permissions; root roles may hold any persona's.
- An unknown persona, a duplicate (persona, name), or an include cycle fails.

## Checks

`Can` and `CanOnGroup` consider the subject's roles on the group and on root.
An unregistered permission returns `iam.ErrUnknownPermission`, never a silent
false. `RequirePermission` (on `*authkit.Auth`, `verify`, and the gin and fiber
adapters) panics when the route is built with an unregistered permission.
