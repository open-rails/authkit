# Account notification inbox (AuthKit #470)

This optional add-on is under implementation. It moves the authenticated account
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
host's PostgreSQL pool. Existing `account_notifications` data must be explicitly
adopted without changing notification IDs, read/archive state, producer identity,
or recipient/app erasure fences. Migration is operator-invoked with writers
stopped; it never silently merges account namespaces during startup.

Required qualification covers local transaction rollback, authenticated HTTP
isolation, producer/source spoofing denial, stale and out-of-order mutations,
withdrawal before publication, account erasure, preserved migrated inbox state,
and durable remote delivery/retry. Frontend coverage must exercise listing and
receipt state independently from domain resolution. Optional-disabled
installations retain their existing AuthKit interface and worker inventory.
