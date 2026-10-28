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
Events use the existing typed `iam.Event` shape (`type`, legacy `kind`, `id`, `tenant_id`, actor
and affected-subject fields) with payload `version: 1`. Unknown kinds and
additive payload fields may appear. `kind` is an optional repeated/comma-separated
filter; the cursor is bound to its normalized kind set and scope. The browser
SDK exposes the same single request as `client.listEvents(...)`.

Omitting `after` starts at the oldest retained event. An empty page still returns
a usable cursor. A reader may poll it at its own interval; AuthKit starts no
poller. Save the returned cursor only after processing the page. The publisher
does not store reader identities, progress, retries or dead letters.

Facts queue inside the domain transaction. The shared deferred flush locks every
affected scope in sorted order at commit and then allocates positions. Other scopes remain
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
not invented. It removes the old ordinary-event table and subscriber flag,
and retires pending ordinary-event and account-cleanup River jobs while
preserving their required domain cleanup receipts. Stop old account writers
before migrating every participating fleet; migration refuses active legacy
workers. `Deps.OnEvent` is removed: migrate hosts to `ListEvents` before adopting
this version.

Required `OnPurge` cleanup is separate. Each issuer's daily sweep (or overdue startup catch-up) runs
its required cleanup before hard deletion, while the subsequent `user.purged`
event describes what committed. Reading the log never satisfies or delays
that cleanup.

Libraries can consume the common `github.com/open-rails/helpers/eventlog.Reader`
through `client.EventReader()` (or `client.EventReader(true)` for authority-wide
facts). `NewRemoteEventReader(RemoteEventConfig{BaseURL: apiURL, HTTPClient: httpClient,
Headers: headers})` reads the same events over HTTP; configure a tenant-routed
API URL and authenticated transport. Both expose `eventlog.Query{After, Types,
Limit}` and the same cursor/expiry semantics. Remote errors retain AuthKit's
`iam.Error` codes and `errors.Is(err, iam.ErrEventCursorExpired)` identity.

Hosts that apply account events to their own data can compose
`tenantClient.AccountEventJobs(AccountEventConsumer{Schema, Handle, Reconcile})`
into the same River fleet as `RiverJobs`. The host migrates two tables in
`Schema`; the exact SQL is on `AccountEventConsumer`:
`auth_event_cursors(stream, cursor, updated_at)` and
`auth_event_parked(event_id, event, attempts, due_at, last_error, parked_at)`.

A periodic tick (every thirty seconds) tries to take the `reader:lease` row in
`auth_event_cursors`. Only the holder works, so one `Handle` runs at a time for
the whole stream. The holder renews the lease before every `Handle` or
`Reconcile` call, and a lease not renewed for `HandleTimeout` plus one minute
(six minutes by default) is taken over, so a killed pod delays the stream by
minutes, not by River's stuck-job rescue time. Each pass first retries due parked
events, then reads the tenant stream and the authority stream from the
`tenant:<tenant UUID>` and `authority` rows, calling `Handle` in log order. The
cursor moves only from the value the pass read; if anything else wrote it, the
pass fails and the next one starts from the written value.

A `Handle` that fails or exceeds `HandleTimeout` (five minutes by default, the
deletion budget) parks its event in `auth_event_parked` in the same transaction
as the cursor move. Parked events are retried after 1, 5 and 15 minutes and
then hourly, without a limit, and removed once applied. `Handle` must therefore
be idempotent and act on current state. Parking and every failed retry log at
Warn; a failed pass, including an expired cursor, logs at Error and keeps the
cursor. `AccountEventsProbe(pool, schema)` fails when no pass has succeeded for
five minutes or a parked event has failed four times or is fifteen minutes
overdue; it reads only the host tables, so any process can run it.

The shared envelope uses source `authkit`, scope equal to the tenant UUID or
`authority`, and the affected user/application/group as its subject. `Data`
contains the complete original `iam.Event`; actor identity stays in that payload.
`RecordedAt` is the log's storage timestamp and is also returned additively in
`iam.Event`. `Types`/HTTP `type` are the common filter spelling; legacy
`Kinds`/HTTP `kind` remain accepted. Filters are combined, normalized and bound
to the cursor, with at most 100 supplied types and a 100 default/500 maximum page.
Native Kinds-only queries retain their historical exact strings, including outer
whitespace; Types queries use the common trimmed normalization.

Migration0025 moves the existing facts into the shared PostgreSQL engine,
keeping recorded times, positions, IDs and deployment epoch unchanged. Old read
names remain compatibility views; the former allocator/write queries are gone.
Shared paging uses the historical AuthKit cursor codec and missing-floor-ID
compatibility; it does not reissue historical facts. Existing empty-scope cursors
retain the singleton epoch when their first shared stream is created. There is
no new tenant foreign key that could delete retained historical facts.

Imported recording times may be nonmonotonic. Retention preserves every younger
row and excludes individually expired rows, even when they appear after a younger
position. This is the existing retained-only contract, not lossless catch-up of
expired history; migration copies the physical rows and timestamps unchanged.
Pruning deletes only an expired prefix. New shared writes have monotonic recording
timestamps, so this historical gap case does not arise for them.

Stop older writers and keep a database backup before applying0025. It changes
writer storage and must be coordinated across the fleet; rolling back the binary
alone does not restore the retired writer tables.

The remote constructor is deliberately an event reader, not a general remote
`*Client`. General client transport readiness is design-only for future work,
tracked in [AuthKit #468](https://github.com/open-rails/tracker/blob/master/authkit/future/468-remote-client-transport-parity.md).
The current task adds no general remote operation facade or new operation routes.
Future work must map actor/tenant semantics to credential-authorized requests and
preserve domain errors without exposing trusted host functions implicitly.

`iam.Event.Type` is the discriminator for new code. `Kind` remains a compatible
alias: JSON reads accept either spelling, writes emit both with the same value,
and conflicting nonempty values are rejected. Historical kind-only records and
older HTTP responses therefore retain their exact event type.
