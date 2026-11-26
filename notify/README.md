# AuthKit account inbox

`github.com/open-rails/authkit/notify` owns account notification types and the
producer-facing `Publisher` interface. AuthKit provides the configured publisher;
applications pass it to ContentKit, OpenRails or their own domain services.

Use `Publish(ctx, []Publication, tx...)` and `Withdraw(ctx, []Withdrawal, tx...)`.
The exact deterministic ID and positive producer revision identify source state.
AuthKit binds the account tenant, source origin and application visibility.
Neither operation requires an inbox read. Omit the transaction for independent
durable acceptance, or supply one non-nil same-source-database transaction.
Remote publishers always queue a durable source delivery job; only workers send
HTTP. Local publication and withdrawal join the account database transaction.

The `postgres` subpackage contains the inbox persistence and its explicit
migration. `Migrate` applies the inbox's migrations
through migratekit (app `authkit_notify`); a released migration never changes,
so an inbox built before AuthKit v1.58.0 is refused and rebuilt. It is not
another service or an application-owned inbox. Host-facing API and
client behavior belong to AuthKit; producers use the small publisher contract.

Read/archive state remains separate from producer resolution. Withdrawals hide
unread items and retain a revision tombstone; delayed old delivery cannot revive
them. A newer explicit publication can reopen unread. Batches are atomic and
bounded at100 exact identities; no ranges or prefix deletion are supported.

See [the configuration, delivery and migration guide](../docs/notifications.md).
