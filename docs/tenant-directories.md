# Tenant account directories

One AuthKit deployment can store several independent account directories in
the same PostgreSQL schema. Every account belongs to one tenant. Apps owned by
that tenant can share its accounts; a different tenant has a separate
registration, credentials, profile and sessions, even when the email or
username is identical.

`iam.TenantID` is the stable business UUID. When using ContentKit, pass the
same UUID to both libraries. An app UUID identifies one app within that
business. A billing merchant can have a different UUID with an explicit
association to the tenant. None of these identifiers is a database schema,
storage path, role or authentication credential.

## Select a directory

For an app serving one tenant, set its persisted tenant ID in configuration:

```go
tenantID, err := iam.ParseTenantID(configuredTenantID)
if err != nil {
	return err
}
cfg.DefaultTenantID = tenantID
```

Use an existing ID from trusted provisioning or configuration. Do not call
`iam.NewTenantID()` on every startup. Changing a default does not move accounts
to a new business.

A deployment serving several tenants can leave `DefaultTenantID` zero, create
tenants explicitly, and select an existing directory for each operation:

```go
if err := authority.CreateTenant(ctx, iam.Tenant{ID: tenantID, Slug: "acme"}); err != nil {
	return err
}
directory, err := authority.ForTenant(ctx, tenantID)
if err != nil {
	return err
}
user, err := directory.User(ctx, iam.UserByEmail(email))
```

`CreateTenant` creates the tenant and its canonical permission group, without
an account, owner assignment, app or key. Repeating matching provisioning is
safe; the same ID under another name (`iam.ErrTenantConflict`) and conflicting
group ownership or persona are errors. `ForTenant` requires
an existing tenant and returns a lightweight view that borrows the original
engine, pools, keys and workers. Closing the view does not close the authority.
Start and stop shared workers through their owning client.

Use an explicit `ForTenant` view for callbacks that resolve an account in a
fixed target directory, such as an avatar owner or notification recipient.
Pass that view's `UserInfo` rather than the owning client's method so an
incoming operation context cannot select a different directory.
When the caller already holds a PostgreSQL transaction, use the lookup's
optional `TransactionalUserInfo.GetTx` capability. It uses the supplied
transaction and restores its search path; calling ordinary `Get` can wait
for a second connection and exhaust a shared pool.

An unbound client is useful for explicit tenant provisioning and global
authority operations. Its account operations require a selected tenant; it
does not search every directory for a matching email or infer a business from
an account name. Resolve tenant routing from trusted app/domain configuration
before dispatching a request. A tenant selector chooses a target; it does not
authorize the caller to access it.

`directory.Handler()` binds login and personal account operations to that
directory. Authorized administration can still admit a root operator from
another tenant; the shared authenticator verifies their source identity
independently. Tenant-qualified cookies prevent one mounted directory's
refresh cookie from overwriting another's, including when they share a
configured cookie basename. A wrong directory cannot redeem another tenant's
refresh, recovery or verification proof.

For one HTTP mount serving host-selected directories, set
`Deps.RequestTenant` to a function with signature
`func(*http.Request) (iam.TenantID, error)`. Resolve only registered host-owned
assignments, such as a ready merchant's immutable tenant ID. The callback runs
before credentials, DPoP proofs and rate limits are consumed, including when a
framework mounts the route catalog. The original URL and headers stay intact.
`Deps.Wrap` runs inside those guards and must not recursively dispatch to a
tenant handler.

Return zero when no selector is present: this keeps `DefaultTenantID` or an
explicit `ForTenant` view. Unknown nonzero IDs return 404; an attempt to select
a different directory on a fixed view returns 403. `auth.ErrForbidden` refuses
a host selector with 403, and other errors use AuthKit's error envelope without
falling back to the default. A zero default remains an unbound authority.

Native browser clients sharing a URL must use distinct, stable
`sessionKeyName` and `sessionHint.key` values per account directory. These
isolate the browser's DPoP keys and cross-tab session state; the trusted host
callback still chooses the directory. Clients omitting those options retain
the existing storage names.

A shared, unbound frontend can remember the last successfully authenticated
directory for cookie-only refresh. This routing hint grants no authority: the
selected refresh secret still has to belong to that directory. Bind an
application to its tenant so a login in another tab cannot switch the app's
account. A configured OAuth client or an existing authorization request also
keeps its own tenant selection rather than following the shared hint.

For AuthKit's authorization server, `OAuthClientConfig.TenantID` selects the
client's native account directory. An omitted value uses only the explicitly
configured `DefaultTenantID`. A static SCIM client is not a global directory
reader merely because several tenants share an issuer. Dynamic group clients
use their group's recorded ownership. Shared callbacks recover their tenant
from immutable proof state; an explicitly mounted directory still rejects a
proof belonging to another tenant.

## Tenant names

A tenant's `Slug` is its public name for display, URLs and operator lookup,
following the OpenRails merchant-name rules. It is stored trimmed and
lowercased and must match `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`
(`iam.ValidateTenantSlug`). Names a hosted product reserves, such as `www` or
`admin`, are that product's policy; AuthKit accepts them.

The name is never an identity. Tokens, scopes, keys, grants and storage paths
use the UUID, so a rename changes none of them.

```go
renamed, err := authority.RenameTenant(ctx, tenantID, "acme-labs")
tenant, err := authority.ResolveTenant(ctx, "acme") // tenant.ID == tenantID, tenant.Slug == "acme-labs"
```

The old name becomes a former name. It keeps resolving to the tenant, and no
other tenant may claim it, until it expires. `Config.Tenants.FormerNames` sets
the lifetime: 90 days by default (`FormerNamesFinite`), `FormerNamesForever`,
or `FormerNamesImmediate` for none. A tenant may take its own former name back.
A name another tenant holds, live or former, is `iam.ErrTenantNameTaken`, and
concurrent claims of one name have exactly one winner. Tenants are permanent;
AuthKit has no tenant deletion, so nothing else releases a name.

`root:tenants:read` and `root:tenants:manage` gate the same operations over
HTTP: `POST /admin/tenants`, `GET` and `PATCH /admin/tenants/{tenant_id}`, and
`GET /admin/tenants/by-slug/{slug}`.

Migration 0026 names each existing tenant `tenant-<its UUID's 32 hex digits>`.
Rename it to its real name once; the placeholder then forwards like any
former name.

## Permissions and ownership

Keep capabilities and role bundles in typed Go declarations. For example:

```go
roles := authkit.NewRoles()
app := roles.Persona("app")
writeContent := app.Permission("content", "write")
editor := app.Role("editor", writeContent)
accountReader := roles.Tenant.Role("account-reader", roles.Tenant.Users.Read)
```

Use the built-in `roles.Tenant`; do not declare another `tenant` persona.
A persona is the type of permission group. The concrete group UUID determines
which business or app a role assignment covers.

| Assignment | Effective scope |
|---|---|
| `root:owner` on the root group | All registered capabilities across this authority |
| A limited root role | Its declared capabilities across this authority |
| `tenant:owner` on a tenant UUID | That tenant's account administration and non-root groups |
| A limited tenant role | Its declared capabilities in that tenant's groups |
| `app:editor` on an app UUID | The declared editing capability in that app |

Every non-root permission group records its immutable owning tenant. The
canonical tenant group's ID equals its tenant ID. App and merchant groups keep
their own stable IDs and reference that tenant. An app slug can change without
changing grants.

`Client.Can` evaluates effective authority, including applicable tenant and
root inheritance. `CanDirect` asks only for authority held directly in the
named group; it is not the usual admin-access check. API key bindings,
revocation, session validity, MFA requirements and token permission ceilings
still apply to inherited authority. Root ownership is not a bypass for a
credential restricted to a single app.

Native client methods are trusted host operations unless their contract takes
an acting identity. A host accepting untrusted input must perform the relevant
permission check before invoking those trusted methods.

## A global operator is not a tenant member

A root operator may administer a different tenant while keeping their source
account and sign-in session. Use `ResolveTenantActor` with the verified
credential to obtain the live source account ID and tenant. Selecting a target
through `ForTenant` does not change those facts.

Do not create a target-tenant audience account just to let an operator perform
administration. Personal operations, such as profile changes, reading history
and content ownership, require an actual account in the target tenant. Keep
the source actor available for audit records and check the requested target
scope for administration.

A root-owned remote directory is global, not an audience directory for a
particular tenant. Read it deliberately through an unbound coordinator;
tenant-selected `RemoteUserInfo` lookups refuse it. This does not remove a
global operator's administrative authority or change remote authentication.

Likewise, an admin UI can select a target tenant and API mount without
replacing the authentication client used for its source session, refresh or
step-up. Include the target in request/cache state so switching tenants cannot
reuse another directory's results or pending writes.

`iam.Event.TenantID` and `iam.UserDeletion.TenantID` identify the affected
tenant, including after the target account or group has been removed. Delivery
restores that tenant in the hook's context from the durable record. Global
events have a zero tenant rather than inheriting a worker's default directory.
The event's subject and invoker fields still identify the acting operator;
they must not be substituted for the affected tenant.

## Upgrade an existing directory

Take a verified backup and coordinate the writer upgrade first. Migration adds
non-null tenant ownership and tenant-scoped uniqueness; old unscoped writers
must be retired before serving the upgraded schema or provisioning additional
businesses.

Choose the tenant that already owns the accounts. Pass it explicitly to the
migration entry point:

```go
err := authkit.Migrate(ctx, pool, database, authkit.MigrationOptions{
	LegacyTenantID: tenantID,
})
```

The migration refuses a populated unowned directory without that choice. It
preserves account and group IDs, password hashes, enrolled factors and existing
role/key bindings. Repeating the same migration is safe. Runtime configuration
then uses that same `DefaultTenantID`; hosts running migrations through a
separate command set `Database.SkipMigrations = true` for normal startup.

Account ownership and permission-persona names are separate changes. The SQL
migration does not silently rename a legacy app or tenant group. During an
explicit persona transition, retain both old and new typed role declarations
until stored bindings have been migrated; ordinary role-catalog reconciliation
must not retire still-needed legacy credentials.

Map each old role to an equivalent grant set. In particular, a legacy
content-only tenant owner must not automatically become the built-in
`tenant:owner`, which also controls accounts and associated app/merchant
groups. Preserve the old limits with an explicitly declared compatibility
role, or stop for a deliberate authority decision. Existing signed permission
ceilings are not rewritten to grant broader access.

Use `Client.MigrateGroupPersona` for the explicit transition. The application
supplies typed mappings from its old declarations to the new declarations;
see the [full migration contract](group-persona-migration.md):

```go
migration := iam.GroupPersonaMigration{
	Group:       iam.GroupByID(appID),
	From:        legacyApp.Persona,
	To:          app.Persona,
	Roles:       map[iam.Role]iam.Role{legacyEditor: editor},
	Permissions: map[iam.Perm]iam.Perm{legacyWrite: writeContent},
}
report, err := authority.MigrateGroupPersona(ctx, migration)
if err != nil {
	return err
}
// Review the report and persist its fingerprint before the apply step.
migration.Apply = true
migration.ExpectedFingerprint = report.Fingerprint
_, err = authority.MigrateGroupPersona(ctx, migration)
```

Include every referenced role and its concrete permissions; omitted,
incompatible or wider mappings are refused. The dry-run does not write data.
Apply requires the reviewed fingerprint and table-owner privileges, briefly
locks the permission-group table, and retains the group's ID, tenant and
credential secrets. Run it as coordinated maintenance, not on normal startup.
The report identifies existing token claims that need reissuing; it cannot
rewrite already-signed credentials. An already migrated group is validated
as a no-op.

A migration client can verify only its own compiled catalog. Bindings marked
as belonging to another issuer are refused rather than translated on an
assumption about that issuer's roles. Coordinate the owning issuer's migration
for those groups.

Before cutover, rehearse with a copied database and verify account IDs, hashes,
factors, roles, key bindings, pending proof behavior and application readiness.
Source tests, published dependency versions and the live migration are
separate delivery steps.
