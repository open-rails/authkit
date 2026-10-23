# Reading committed events

AuthKit records each account/group change once in its mutation transaction,
even when no reader exists. `ListEvents` reads retained events; it creates no
subscription, job or acknowledgement. Each application stores its own cursor.

```go
tenant, err := client.ForTenant(ctx, tenantID)
if err != nil { return err }
page, err := tenant.ListEvents(ctx, iam.EventQuery{After: savedCursor, Limit: 100})
if err != nil { return err }
// Apply every page.Events entry, idempotently by event.ID, then save
// page.NextCursor in the reader's own store. Retry the page on failure.
```

The HTTP equivalent is `GET /events?after=<cursor>&limit=100` beneath AuthKit's
configured API prefix. The tenant comes from trusted host dispatch. It requires
current `tenant:users:read` for that tenant or `root:users:read` on every request.
An API key/identity's existing capability ceiling still applies. The explicit
`authority=true` option reads only changes without a tenant-owned target and
requires `root:users:read`; it does not merge every tenant's log.

The response has `events`, `next_cursor`, `has_more`, and `retention_seconds`.
Events use the existing typed `iam.Event` shape (`kind`, `id`, `tenant_id`, actor
and affected-subject fields) with payload `version: 1`. Unknown kinds and
additive payload fields may appear. `kind` is an optional repeated/comma-separated
filter; the cursor is bound to its normalized kind set and scope. The browser
SDK exposes the same single request as `client.listEvents(...)`.

Omitting `after` starts at the oldest retained event. An empty page still returns
a usable cursor. A reader may poll it at its own interval; AuthKit starts no
poller. Save the returned cursor only after processing the page. The publisher
does not store reader identities, progress, retries or dead letters.

Positions are allocated under a per-scope transaction lock, held through commit.
Multi-scope mutations lock scopes in sorted order. Other scopes remain
independent. A read uses one repeatable-read snapshot, including the committed
head and retention floor. This prevents a faster transaction from causing a
reader to skip an earlier transaction that has not committed yet.

`Config.EventRetention` defaults to 90 days and must be at least one second.
The existing auth-state cleanup tick removes old rows in bounded batches;
request-time retention applies even before that tick runs. Retention is
independent of every reader. `410 event_cursor_expired` means history is missing
or its stream incarnation changed: resynchronize from current account state,
then begin a new traversal. A cursor at the retained boundary is still usable
when it has missed no events.

Restore procedures must invalidate saved cursors by rotating the restored
schema's stream epoch before serving:

```sql
UPDATE profiles.event_log_instance SET epoch = gen_random_uuid();
```

Use the configured AuthKit schema instead of `profiles` where it differs.
Boundary event IDs also detect incompatible restored history. Restores must not
reuse a stream epoch merely because numeric positions happen to match.

The migration copies any still-retained legacy event once, deduplicated across
issuer deliveries. Previously delivered/deleted history is unavailable and is
not invented. `Deps.OnEvent` is a temporary compatibility transport while hosts
migrate; it still owns its old delivery records/jobs. It will be removed after
all hosts adopt reader-owned cursors. Required `OnPurge` cleanup is separate:
each issuer’s daily/startup sweep runs its required cleanup before hard deletion, while the subsequent `user.purged` event describes
what committed. Reading the log never satisfies or delays that cleanup.
