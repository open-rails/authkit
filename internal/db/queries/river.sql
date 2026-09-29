-- River database identity witness (requireSameRiverDatabase): the producer
-- pool takes two random transaction advisory locks; the worker pool must see
-- them held by that backend in the same database.

-- name: RiverIdentityProbeLock :one
SELECT pg_catalog.pg_backend_pid()::integer AS pid,
       pg_catalog.pg_try_advisory_xact_lock(sqlc.arg(key1)::integer, sqlc.arg(key2)::integer)::boolean AS first,
       pg_catalog.pg_try_advisory_xact_lock(sqlc.arg(key3)::integer, sqlc.arg(key4)::integer)::boolean AS second;

-- name: RiverIdentityProbeSeen :one
SELECT (pg_catalog.count(*) = 2)::boolean AS seen FROM pg_catalog.pg_locks
WHERE locktype = 'advisory' AND pid = sqlc.arg(pid)::integer AND granted AND mode = 'ExclusiveLock' AND objsubid = 2
  AND database = (SELECT oid FROM pg_catalog.pg_database WHERE datname = pg_catalog.current_database())
  AND ((classid = sqlc.arg(class1)::bigint::pg_catalog.oid AND objid = sqlc.arg(obj1)::bigint::pg_catalog.oid)
    OR (classid = sqlc.arg(class2)::bigint::pg_catalog.oid AND objid = sqlc.arg(obj2)::bigint::pg_catalog.oid));
