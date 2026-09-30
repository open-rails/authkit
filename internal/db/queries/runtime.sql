-- Connection setup, migrations and runtime-role provisioning. The schema
-- identifiers in CREATE SCHEMA and the GRANTs stay inline in the engine.

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

-- name: RuntimeIdentity :one
SELECT current_user::text AS user_name, current_database()::text AS database_name;

-- name: CurrentDatabase :one
SELECT current_database()::text;

-- name: RuntimeAccessLock :exec
-- Shared with OpenRails: ACL writes can touch the same public objects.
SELECT pg_advisory_xact_lock(hashtextextended('open-rails:runtime-access', 0));

-- name: MigrationSchemaHasUsers :one
SELECT EXISTS (
  SELECT 1 FROM information_schema.tables WHERE table_schema = sqlc.arg(schema_name)::text AND table_name = 'users'
)::boolean;
