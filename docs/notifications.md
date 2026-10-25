# Account notification inbox (AuthKit #470)

This optional add-on moves the authenticated account
inbox from ContentKit to AuthKit while retaining Helpers' shared storage model.
The general retained event log remains an independent host-integration interface.

## Ownership and publication

AuthKit owns the inbox alongside the account directory. Helpers owns the generic
mutation/storage contract. Producers decide which facts deserve a user notice;
the frontend owns presentation and action destinations.

A configured producer handle is bound to an account tenant, source system/scope,
and application visibility. It accepts exact deterministic notification IDs and
positive producer revisions. Publish/update and withdrawal are the two states of
one mutation. Withdrawal can arrive first; older delayed publications remain
hidden. Equal retries preserve read/archive state. A higher-revision publication
can explicitly reopen an item. No prefixes, ranges, dependency graphs or inbox
searches are required. Producers can submit bounded batches of exact identities.

The producer revision is separate from the revision used for inbox read/archive
updates. Reading a notification does not resolve the source's underlying issue.
Resolved/withdrawn notifications leave the active inbox and unread count whether
or not the user saw them.

## Embedded and remote delivery

The embedded AuthKit client exposes a producer handle implementing
`notify.Sink.Apply` and `notify/postgres.TxSink.ApplyTx`. Ordinary `Apply` returns
after the inbox commit. `ApplyTx` joins the caller's same-database transaction,
so the domain mutation and notification are committed or rolled back together.

A narrow remote notification publisher uses the same mutation interface over an
authenticated AuthKit endpoint. Its `Apply` succeeds after the destination commit.
Its transactional `ApplyTx` records a River delivery obligation in the producer's
database. A common worker sends available obligations immediately and retries
failures; it never scans the general event log. The stable identity/revision
makes response loss and replay safe. Credentials and destination URLs remain in
trusted configuration, not in queued notification payloads.

## Account interface

When enabled, AuthKit exposes authenticated list/get/read/unread/archive/restore
operations for the current account. Recipient identity comes from the verified
session and native tenant directory. Application views are fixed by trusted host
configuration. Producer publication has a distinct authenticated machine surface;
it cannot select arbitrary producer identities or publish outside its declared
account tenant/application. Domain resolution remains producer-owned.

Permanent account erasure removes inbox data and retains the Helpers recipient
fence before the account row is removed. Delayed delivery cannot recreate it.
Soft deletion continues AuthKit's existing recovery policy.

## Migration and qualification

Enabling the add-on installs/validates the Helpers notification schema using the
host's PostgreSQL pool. Existing `account_notifications` data is adopted in place using an explicit
`Scopes` mapping from canonical account tenant UUID to the existing logical scope
(for example `contentkit:accounts`). Notification IDs, read/archive state and
recipient/app erasure fences remain in the same rows. Unmapped tenants use
`authkit:<tenant UUID>`. The addon persists scope ownership (canonical tenant plus account schema) in
`account_inbox_scopes`, with a unique tenant home within that notification
schema. Two separately configured replicas cannot map different account
directories to the same scope. Startup validates the persisted claim; explicit
migration claims existing legacy scopes, and tenant creation binds new canonical
scopes transactionally. Changing an already-bound tenant home is refused. The add-on never
silently merges account namespaces during startup.

`Client.AdoptNotifications` performs a separate, operator-invoked exact-identity
migration for producers changing legacy event IDs to stable issue IDs. Each
`notify.Adoption` contains exact `Previous` origins and one `Current` mutation.
Run it with old writers stopped. An existing canonical receipt wins; otherwise
the newest matching previous receipt (created_at, ID descending) retains its ID,
read/archive state and becomes canonical. Redundant prior receipts remain hidden.
Conflicting visibility or producer scope refuses the batch. Replay cannot lower
a canonical producer revision. An active current issue with no previous/current
receipt is skipped; a withdrawn issue can create a hidden ordering tombstone.
This never replays unconsumed history into a new visible inbox.

## Host wiring

```go
cfg.Notifications = &authkit.NotificationsConfig{
    Schema: "account_notifications",
    AppID: appID,
    Scopes: map[string]string{tenantID.String(): "contentkit:accounts"},
    Producers: []authkit.NotificationProducer{{
        Name: "contentkit", TenantID: tenantID,
        Origin: notify.OriginScope{System: "contentkit", Scope: catalogKey},
        Visibility: notify.VisibilityApp, AppID: appID,
    }},
}
// With SkipMigrations, call MigrateNotifications during explicit migration.
publisher, err := accounts.Notifications("contentkit")
// Pass publisher as the producer module's notification dependency.
```

A remote-enabled producer additionally declares `PermissionGroupID` and a
concrete `Permission` from the host's existing role model. The HTTP operation
requires a live direct grant in that group and verifies it belongs to the bound
tenant. An in-process-only producer omits both. Source origin and visibility are
fixed by this binding; a request cannot broaden them.

The browser client exposes `client.notifications.list`, `get`, `setRead`,
`setDismissed`, `subscribe`, and `refresh`. The React `useNotifications` hook
loads an account-scoped page and hides prior-account state on a session switch.
The HTTP endpoints are `GET /me/notifications`, `GET /me/notifications/{id}`,
`PUT/DELETE /me/notifications/{id}/read` and `PUT/DELETE
/me/notifications/{id}/dismiss`. Producer batches use `POST
/notifications/{producer}`. All paths are below the configured AuthKit API base.


Required qualification covers local transaction rollback, authenticated HTTP
isolation, producer/source spoofing denial, stale and out-of-order mutations,
withdrawal before publication, account erasure, preserved migrated inbox state,
and durable remote delivery/retry. Frontend coverage must exercise listing and
receipt state independently from domain resolution. Optional-disabled
installations retain their existing AuthKit interface and worker inventory.

AuthKit and application code can obtain their own declared native publisher with
`accounts.Notifications("authkit")` or `accounts.Notifications("application")`.
The channel does not invent new security notices or mirror every email; concrete
notification policy remains explicit in the producer.
