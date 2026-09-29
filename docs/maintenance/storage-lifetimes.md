# AuthKit storage lifetimes

Group assignments are current state: at most one row per group and subject.
Replacing a role updates that row; revoking it deletes the row. Assignment rows
are not an audit log.

AuthKit installs `citext` and uses PostgreSQL 18's native UUID functions. It does
not install `pgcrypto`; hosts that use it provision it themselves. AuthKit never
drops an existing extension.

Account deletion is recoverable for 30 days. `account_deletions` holds one
generation per deletion (`deleted`, `restored`, `finalizing`, `purged`) and
`account_deletion_deliveries` one receipt per account issuer and stage. A
restored or purged generation whose receipts all completed is deleted 90 days
after it ended; pending callbacks are never collected.

API keys and invitations keep terminal metadata for 90 days after their first
expiry, revocation or redemption. Each maintenance run (`Config.River.CleanupInterval`)
deletes at most 5,000 eligible rows per table, using indexed terminal timestamps,
and the next run resumes. Live rows and permanent name reservations stay.
