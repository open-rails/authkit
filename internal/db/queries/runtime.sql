-- Connection setup and migration locks. The schema identifier in CREATE
-- SCHEMA stays inline in the engine.

-- name: SetSearchPath :exec
-- is_local false sets it for the session, true until the transaction (or
-- savepoint) ends.
SELECT set_config('search_path', sqlc.arg(search_path)::text, sqlc.arg(is_local)::boolean);

-- name: AdvisoryXactLock :exec
-- Transaction-scoped advisory lock on key, released when the transaction ends.
SELECT pg_advisory_xact_lock(hashtextextended(sqlc.arg(key)::text, 0));

-- name: AdvisoryLock :exec
-- Session-scoped advisory lock on key in this database: hold it on one
-- dedicated connection, whose close releases it.
SELECT pg_advisory_lock(hashtext(current_database()), hashtext(sqlc.arg(key)::text));
