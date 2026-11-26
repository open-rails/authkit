# Account notification inbox

AuthKit owns the authenticated account inbox: its types, PostgreSQL persistence, producer client and frontend API. It is always on. The general retained event log remains an independent host-integration interface.

## Ownership and publication

AuthKit owns the inbox alongside the account directory and provides its publisher
contract. Producers decide which facts deserve a user notice;
the frontend owns presentation and action destinations.

A registered producer is bound to its Client's tenant, a source system/scope and a visibility. It accepts exact deterministic notification IDs and positive producer revisions. Publish/update and withdrawal are the two states of one mutation. Withdrawal can arrive first; older delayed publications remain hidden. Equal retries preserve read/archive state. A higher-revision publication can explicitly reopen an item. No prefixes, ranges, dependency graphs or inbox searches are required. Producers can submit bounded batches of exact identities.

The producer revision is separate from the revision used for inbox read/archive
updates. Reading a notification does not resolve the source's underlying issue.
Resolved/withdrawn notifications leave the active inbox and unread count whether
or not the user saw them.

## Embedded and remote delivery

`Client.Notifications(producer)` registers a producer in the Client's tenant and returns its `notify.Publisher`. Producers use only two operations:

```go
err := publisher.Publish(ctx, []notify.Publication{{
    RecipientID: userID, ID: "comment.reply:" + replyID, Revision: revision,
    Kind: "comment.reply", Data: replyReferences, CreatedAt: createdAt,
}})
err = publisher.Withdraw(ctx, []notify.Withdrawal{{
    RecipientID: userID, ID: "comment.reply:" + replyID, Revision: nextRevision,
}}, sourceTx)
```

AuthKit fixes origin, tenant and application visibility in the registered producer.
Each batch accepts at most 100 exact identities. Omit the transaction to commit
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

AuthKit exposes authenticated list/get/read/unread/archive/restore operations for the current account. Recipient identity comes from the verified session and native tenant directory. The view is tenant-wide notices plus this deployment's app's, the app being `Config.Issuer`. Producer publication has a distinct authenticated machine surface; it cannot select arbitrary producer identities or publish outside its registered tenant and app. Domain resolution remains producer-owned.

Permanent account erasure removes inbox data and retains the AuthKit recipient
fence before the account row is removed. Delayed delivery cannot recreate it.
Soft deletion continues AuthKit's existing recovery policy.

## Storage and migration

The inbox lives in `Database.Schema`: `Migrate` (and `New`) creates it with the rest of AuthKit's tables, recording its migrations in migratekit's ledger as app `authkit_notify`. A tenant's notifications are scoped `authkit:<tenant UUID>` (`Client.NotificationScope`).

## Host wiring

```go
publisher, err := accounts.Notifications(authkit.NotificationProducer{
    Name:   "contentkit",
    Origin: notify.OriginScope{System: "contentkit", Scope: catalogKey},
    // Visibility defaults to notify.VisibilityApp: this deployment's inbox.
})
// Pass publisher as the producer module's notification dependency.
```

A remote-enabled producer additionally declares `PermissionGroupID` and a concrete `Permission` from the host's existing role model. The HTTP operation requires a live direct grant in that group and verifies it belongs to the bound tenant, and the replica serving it must have registered the producer with that permission. An in-process-only producer omits both. Source origin and visibility are fixed by this binding; a request cannot broaden them.

The browser client exposes `client.notifications.list`, `get`, `setRead`,
`setDismissed`, `subscribe`, and `refresh`. The React `useNotifications` hook
loads an account-scoped page and hides prior-account state on a session switch.
The HTTP endpoints are `GET /me/notifications`, `GET /me/notifications/{id}`,
`PUT/DELETE /me/notifications/{id}/read` and `PUT/DELETE
/me/notifications/{id}/dismiss`. Producer batches use `POST
/notifications/{producer}`. All paths are below the JSON API base.


Required qualification covers local transaction rollback, authenticated HTTP
isolation, producer/source spoofing denial, stale and out-of-order mutations,
withdrawal before publication, account erasure and durable remote delivery/retry. Frontend coverage must exercise listing and
receipt state independently from domain resolution.

AuthKit's host and each engine it embeds register their own producer with `Client.Notifications`. The channel does not invent new security notices or mirror every email; concrete notification policy remains explicit in the producer.

## Existing revisioned producer envelopes

Previously queued AuthKit delivery jobs retain their full mutation envelopes.
The worker forwards their existing origin subject and workflow status unchanged;
the destination still applies the complete content hash. The new narrow
publication contract emits notices with no origin-subject override.

A previously revisioned receipt with nonempty source subject or workflow status
therefore cannot be rewritten by a minimal publication at the same revision.
That is a semantic change and still returns `ErrConflict`; producers must
deliberately advance their durable revision and drain old obligations during
cutover. Canonical notice envelopes replay unchanged.
