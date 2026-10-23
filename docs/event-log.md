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
not invented. It removes the old ordinary-event table and subscriber flag,
and retires pending ordinary-event and account-cleanup River jobs while
preserving their required domain cleanup receipts. Stop old account writers
before migrating every participating fleet; migration refuses active legacy
workers. `Deps.OnEvent` is removed: migrate hosts to `ListEvents` before adopting
this version.

Required `OnPurge` cleanup is separate. Each issuer's daily/startup sweep runs
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

This adoption retains the existing tables, writer transaction, recorded times,
positions, IDs and deployment epoch. Shared paging uses the historical AuthKit
cursor codec and its floor-boundary behavior; it does not reissue historical
facts. AuthKit's legacy retention adapter also handles nonmonotonic imported
recorded times by pruning only an expired prefix.

The remote constructor is deliberately an event reader, not a general remote
`*Client`. Full public-client transport parity is still open: the route catalog
has HTTP request/response shapes but no operation-to-route mapping, and domain
methods include trusted actor, transaction options, tenant dispatch and native
operations without an equivalent authorized HTTP route. Completing that facade
requires explicit mappings and authorization/error parity tests for each supported
operation. No general remote client with silent unsupported methods is provided.
