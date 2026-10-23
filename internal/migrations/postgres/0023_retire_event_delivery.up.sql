-- Retire ordinary event delivery after migrating pending rows into the log.
-- Stop old account writers before this coordinated migration.
SET LOCAL lock_timeout = '10s';
LOCK TABLE account_events IN SHARE ROW EXCLUSIVE MODE;

DO $$
DECLARE fleet record;
DECLARE running boolean;
BEGIN
  FOR fleet IN SELECT DISTINCT river_schema FROM account_delivery_fleets ORDER BY river_schema LOOP
    IF to_regclass(format('%I.river_job',fleet.river_schema)) IS NULL THEN CONTINUE; END IF;
    EXECUTE format('LOCK TABLE %I.river_job IN SHARE ROW EXCLUSIVE MODE',fleet.river_schema);
    EXECUTE format('SELECT EXISTS(SELECT 1 FROM %I.river_job WHERE kind IN (''authkit_account_event'',''authkit_account_delivery'') AND args->>''schema''=$1 AND state=''running'')',fleet.river_schema)
      INTO running USING current_schema();
    IF running THEN
      RAISE EXCEPTION 'stop old AuthKit event/account workers before migrating schema %',current_schema() USING ERRCODE='55000';
    END IF;
  END LOOP;
  IF EXISTS(SELECT 1 FROM account_events e JOIN event_log l ON l.event_id=e.event_id
            WHERE l.scope<>coalesce(e.tenant_id::text,'authority')) THEN
    RAISE EXCEPTION 'legacy event identity has conflicting scope' USING ERRCODE='55000';
  END IF;
END;
$$;

WITH pending AS (
    SELECT DISTINCT ON (e.event_id) e.* FROM account_events e
    WHERE NOT EXISTS(SELECT 1 FROM event_log l WHERE l.event_id=e.event_id)
    ORDER BY e.event_id,e.id
), numbered AS (
    SELECT *, coalesce(tenant_id::text, 'authority') AS event_scope,
           coalesce((SELECT position FROM event_log_scopes s WHERE s.scope=coalesce(pending.tenant_id::text,'authority')),0) +
           row_number() OVER (PARTITION BY tenant_id ORDER BY id) AS event_position
    FROM pending
)
INSERT INTO event_log(scope, position, event_id, kind, recorded_at, payload)
SELECT event_scope, event_position, event_id::uuid, kind, occurred_at,
       jsonb_build_object(
           'version', 1, 'id', event_id, 'kind', kind, 'tenant_id', tenant_id,
           'occurred_at', occurred_at, 'subject_kind', subject_kind,
           'subject_id', subject_id, 'invoker_issuer', invoker_issuer,
           'invoker_id', invoker_id, 'credential_kind', credential_kind,
           'credential_id', credential_id, 'user_id', coalesce(user_id::text, ''),
           'group_id', coalesce(group_id::text, ''), 'persona', persona,
           'application_id', coalesce(application_id::text, ''), 'role', role,
           'client_id', client_id, 'agreement', agreement,
           'previous', previous_value, 'current', current_value,
           'reason', reason, 'until', until)
FROM numbered;
INSERT INTO event_log_scopes(scope, position)
SELECT scope, max(position) FROM event_log GROUP BY scope
ON CONFLICT(scope) DO UPDATE SET position=greatest(event_log_scopes.position,excluded.position);


DO $$
DECLARE fleet record;
BEGIN
  FOR fleet IN SELECT DISTINCT river_schema FROM account_delivery_fleets ORDER BY river_schema LOOP
    IF to_regclass(format('%I.river_job',fleet.river_schema)) IS NULL THEN CONTINUE; END IF;
    EXECUTE format('DELETE FROM %I.river_job WHERE kind IN (''authkit_account_event'',''authkit_account_delivery'') AND args->>''schema''=$1 AND state IN (''available'',''pending'',''retryable'',''scheduled'')',fleet.river_schema)
      USING current_schema();
  END LOOP;
END;
$$;
DROP TABLE account_events;
ALTER TABLE account_delivery_fleets DROP COLUMN events;
COMMENT ON TABLE account_delivery_fleets IS 'Configured account issuer destinations for required cleanup and credential operations; not event readers.';
