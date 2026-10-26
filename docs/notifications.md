# Account notification inbox (AuthKit #470)

This optional add-on owns the authenticated account inbox in AuthKit, including
its types, PostgreSQL persistence, producer client and frontend API. Existing
inbox tables and receipt identities are adopted in place.
The general retained event log remains an independent host-integration interface.

## Ownership and publication

AuthKit owns the inbox alongside the account directory and provides its publisher
contract. Producers decide which facts deserve a user notice;
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

The embedded AuthKit client returns `notify.Publisher` from
`accounts.Notifications("contentkit")`. Producers use only two operations:

```go
err := publisher.Publish(ctx, []notify.Publication{{
    RecipientID: userID, ID: "comment.reply:" + replyID, Revision: revision,
    Kind: "comment.reply", Data: replyReferences, CreatedAt: createdAt,
}})
err = publisher.Withdraw(ctx, []notify.Withdrawal{{
    RecipientID: userID, ID: "comment.reply:" + replyID, Revision: nextRevision,
}}, sourceTx)
```

AuthKit fixes origin, tenant and application visibility in the configured producer.
Each batch accepts at most100 exact identities. Omit the transaction to commit
acceptance in a new transaction, or supply exactly one non-nil `pgx.Tx` to join
source writes. The host must supply a transaction from the account database for
a local publisher, or the configured source database for a remote publisher.
Passing a transaction from another database is unsupported. Local publishers
write the inbox; a failed batch rolls back to a savepoint without discarding the
caller's independent work. Publication uses the supplied transaction without
opening another database connection.

Remote publishers use the same two operations and always insert a source River
delivery obligation, including when no transaction is supplied. Only the worker
sends authenticated HTTP to AuthKit. An unavailable destination cannot turn a
successful producer mutation into lost delivery. Response loss/restart/replay are
safe through stable exact IDs and producer revisions. Credentials and destination
URLs stay in trusted configuration, never in queued notification payloads.

## Account interface

When enabled, AuthKit exposes authenticated list/get/read/unread/archive/restore
operations for the current account. Recipient identity comes from the verified
session and native tenant directory. Application views are fixed by trusted host
configuration. Producer publication has a distinct authenticated machine surface;
it cannot select arbitrary producer identities or publish outside its declared
account tenant/application. Domain resolution remains producer-owned.

Permanent account erasure removes inbox data and retains the AuthKit recipient
fence before the account row is removed. Delayed delivery cannot recreate it.
Soft deletion continues AuthKit's existing recovery policy.

## Migration and qualification

Enabling the add-on installs/validates the AuthKit notification schema using the
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
Conflicting visibility or producer scope refuses the batch. Only unversioned
legacy receipts may acquire classification; versioned unclassified records are
refused rather than silently changing their producer identity/hash. Replay cannot lower
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

## Existing revisioned producer envelopes

Previously queued AuthKit delivery jobs retain their full mutation envelopes.
The worker forwards their existing origin subject and workflow status unchanged;
the destination still applies the complete content hash. The new narrow
publication contract emits notices with no origin-subject override.

A previously revisioned receipt with nonempty source subject or workflow status
therefore cannot be rewritten by a minimal publication at the same revision.
That is a semantic change and still returns `ErrConflict`; producers must
deliberately advance their durable revision and drain old obligations during
cutover. Canonical notice envelopes replay unchanged. Explicit adoption of
unversioned legacy receipts sets the chosen canonical current envelope before
new publishers resume, preserving receipt ID/read/archive state. The package
move alone does not waive ordering or content-conflict checks.
