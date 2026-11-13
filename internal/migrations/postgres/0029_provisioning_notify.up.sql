-- A recorded provisioning change wakes its target's run (#478): the users
-- triggers NOTIFY authkit_provisioning with the schema, issuer and target,
-- folded per transaction, and each AuthKit's listener queues that run. One
-- channel for every schema: "<schema>.provisioning" can pass a channel
-- name's 63 bytes.
SET LOCAL lock_timeout = '10s';
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

CREATE OR REPLACE FUNCTION provisioning_record_change() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE owner uuid; subject_id uuid; recorded record;
BEGIN
 IF TG_OP='DELETE' THEN owner:=OLD.tenant_id; subject_id:=OLD.id;
 ELSE owner:=NEW.tenant_id; subject_id:=NEW.id; END IF;
 FOR recorded IN
  INSERT INTO provisioning_changes(issuer,target,user_id,tenant_id)
  SELECT issuer,name,subject_id,tenant_id FROM provisioning_targets WHERE tenant_id=owner
  RETURNING issuer,target
 LOOP
  PERFORM pg_notify('authkit_provisioning',
   json_build_object('schema',TG_TABLE_SCHEMA,'issuer',recorded.issuer,'target',recorded.target)::text);
 END LOOP;
 RETURN NULL;
END;
$$;
