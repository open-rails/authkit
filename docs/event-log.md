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
JSON API base. The tenant comes from trusted host dispatch. It requires
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

Events are retained for 90 days.
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

Hosts that apply account events can run AuthKit's loop instead of their own.
`tenant.StartAccountEvents(ctx, authkit.AccountEventOptions{Pool, Schema, Handle, Sync, Reconcile})`
reads the tenant stream and then the authority stream into `Handle`, every
`Interval` (30 seconds by default). One process per schema and tenant reads at
a time, under the session advisory lock `<schema>:auth-events:<tenant UUID>`
held on its own connection. Cursors stay in the host's
`<schema>.auth_event_cursors` under `tenant:<tenant UUID>` and `authority`, so
use one tenant per schema.

Each `Handle` and `Sync` call has its own deadline, `HandlerTimeout` (five
minutes by default), and must return when its context ends. When `Handle`
fails, overruns or panics, the event's account is parked in
`<schema>.account_resyncs` and the stream moves on. `Sync(userID)` reapplies the
account's current state after 1, 5 and 15 minutes, then hourly, until it
succeeds, and a failed `Sync` parks the same way.
`ScheduleAccountResync` queues a check for state that records no event, such
as a temporary ban ending; a check `Sync` reschedules while it runs is kept.
An empty tenant cursor first syncs every account in the `Reconcile` statuses,
which may only be deleted and banned. That first sync is not parked: when
`Sync` fails there, the pass fails and the next pass starts it again.

Any other error ends the pass and keeps its cursor. The tenant stream is read
first, so an error there, including an expired tenant cursor, also stops the
authority stream until it is fixed. `Probe` fails after a failed pass, after
five minutes without a good pass, or while a parked account is 15 minutes
overdue or has failed four times. `Stop` ends the loop and parks nothing: the
unfinished page is delivered again on the next start, so `Handle` must tolerate
repeats. The host migrates both tables:

```sql
CREATE TABLE app.auth_event_cursors (stream text PRIMARY KEY, cursor text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE app.account_resyncs (user_id uuid PRIMARY KEY, due_at timestamptz NOT NULL,
    attempts integer NOT NULL DEFAULT 0, last_error text,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE INDEX account_resyncs_due_at_idx ON app.account_resyncs (due_at);
```

Required `OnPurge` cleanup is separate. Each issuer's batch, scheduled at the deletion's `purge_at`, runs
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

The shared envelope uses source `authkit`, scope equal to the tenant UUID or
`authority`, and the affected user/application/group as its subject. `Data`
contains the complete original `iam.Event`; actor identity stays in that payload.
`RecordedAt` is the log's storage timestamp and is also returned additively in
`iam.Event`. `Types`/HTTP `type` are the common filter spelling; legacy
`Kinds`/HTTP `kind` remain accepted. Filters are combined, normalized and bound
to the cursor, with at most 100 supplied types and a 100 default/500 maximum page.
Native Kinds-only queries retain their historical exact strings, including outer
whitespace; Types queries use the common trimmed normalization.

Events live in Helpers' shared PostgreSQL engine (`eventlog_events`,
`eventlog_streams`). Every stream takes the deployment's epoch
(`event_log_instance`), so a cursor issued before its stream's first event stays
valid. There is no tenant foreign key that could delete retained facts. Pruning
deletes only an expired prefix.

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
