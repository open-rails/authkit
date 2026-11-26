# PostgreSQL and PgBouncer

AuthKit works through one pool, `Deps.Postgres`. Behind PgBouncer in transaction mode, give it the PgBouncer pool and set `Deps.PostgresSession` to a direct configuration of the same database and role: AuthKit dials from it, and closes, only the few connections a transaction-pooled server connection cannot carry.

```go
pooled, err := pgxpool.ParseConfig(os.Getenv("DATABASE_URL")) // PgBouncer, pool_mode = transaction
pooled.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeCacheDescribe
pool, err := pgxpool.NewWithConfig(ctx, pooled)
direct, err := pgxpool.ParseConfig(os.Getenv("DATABASE_DIRECT_URL")) // PostgreSQL itself
auth, err := authkit.New(ctx, cfg, authkit.Deps{Postgres: pool, PostgresSession: direct /* … */})
```

Without `PostgresSession` nothing changes: everything runs through `Postgres`, which must then reach PostgreSQL directly, or through PgBouncer in session mode.

## What runs where

| Work | Connection | Why |
|---|---|---|
| Requests, jobs, short-lived auth state, River's queries | `Postgres` | Every lock it takes is transaction-scoped (`pg_advisory_xact_lock`, `FOR UPDATE`), and every transaction ends before its connection returns. |
| Migrations (`New`, `Migrate`) | a pool dialed from `PostgresSession`, closed when they finish | The migrators serialize replicas on session advisory locks. `authkit.Migrate` and `riverhelpers.ApplyMigrations` called on their own take a direct pool. |
| River's `LISTEN` | one connection from `PostgresSession` | A notification goes to the server connection that listened, which PgBouncer has since handed to another client. |
| Provisioning's `LISTEN` (`Config.Provisioning`) | one connection from `PostgresSession` | As River's. |
| An account's cleanup callback (`Deps.OnPurge`) | one connection from `PostgresSession` while it runs | Its per-account session lock is held while host code runs; a transaction would pin a pooled connection for that time. |
| The account-event reader election (`StartAccountEvents`) | one connection from `AccountEventOptions.Session` per pass | As the callback's. |

An instance with its own River and provisioning targets holds two direct connections, three while a cleanup callback runs, plus a transient migration pool at boot.

## What the pooler must do

- **No prepared statements across round trips.** `Postgres`'s `DefaultQueryExecMode` is `cache_describe`, `exec` or `simple_protocol`; `New` refuses another when `PostgresSession` is set.
- **Keep each client's `search_path`.** AuthKit resolves its tables through a `search_path` it sends as a startup parameter, which the pooler sets on whichever server connection runs the client's transaction. PgBouncer 1.26 does; an earlier one from 1.20 needs `track_extra_parameters = search_path`. Never list it in `ignore_startup_parameters`. `New` connects once with a `search_path` no other client uses and refuses a pooler that loses or mangles it.
- **Room for AuthKit's statements beside its transactions.** A flow reads short-lived state on a second pool while its transaction is open. Size PgBouncer's pool for the database and role above `Postgres`'s `MaxConns` and a quarter of it (plus `Database.RiverConns` with AuthKit's own River); otherwise both wait on each other until `query_wait_timeout`.

## Notifications are wake-ups

The tables are the truth; a notification only says to look now. River's producers poll every 10 seconds (AuthKit's own River) or the fleet's `FetchPollInterval`, and River pings and redials its listener. The provisioning listener queues every target's due run when it connects and every 30 seconds, pinging its connection then; a connection that fails the ping is redialed. A lost notification delays work; it never loses it.

## A host River fleet

A fleet that runs `auth.RiverJobs()` through the PgBouncer pool listens on a direct connection: build it with `riverhelpers.NewWithSession(ctx, pool, direct, riverConfig, auth.RiverJobs(), …)` (Helpers v1.23), or set `river.Config.PollOnly`.
