-- parent: 10 sha256:f96c9a1ca80d63547d30d32c626d12847bf7474076f740fc85d0d41ad163a6d6
-- A permission group is an id, a persona and its role holders. The entity it
-- guards (a channel and its name) lives in the host app, keyed by group id, so
-- groups lose their slug, display name, renames and former-name aliases.
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

DROP TRIGGER groups_name_claim ON permission_groups;
DELETE FROM name_claims WHERE owner_kind = 'group';
ALTER TABLE name_claims
  DROP CONSTRAINT name_claims_owner_kind_check,
  DROP CONSTRAINT name_claims_check,
  ADD CONSTRAINT name_claims_user_chk CHECK (owner_kind = 'user' AND persona = '');

CREATE OR REPLACE FUNCTION enforce_canonical_name_claim() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE handle text; previous text;
BEGIN
 IF TG_OP='UPDATE' AND NEW.id <> OLD.id THEN RAISE EXCEPTION 'identity UUID is immutable' USING ERRCODE='23514'; END IF;
 IF TG_OP = 'DELETE' THEN
  -- A deleted user's username stays reserved forever as an alias of the dead
  -- UUID, so nobody can re-register it and impersonate the purged account.
  UPDATE name_claims SET canonical=false, expires_at=NULL WHERE owner_kind='user' AND owner_id=OLD.id AND canonical;
  RETURN OLD;
 END IF;
 handle := NEW.username::text;
 IF TG_OP = 'INSERT' THEN
  PERFORM claim_canonical_name('user', '', handle, NEW.id, clock_timestamp());
 ELSE
  previous := OLD.username::text;
  IF lower(COALESCE(handle,'')) <> lower(COALESCE(previous,'')) AND (COALESCE(handle,'') = '' OR NOT EXISTS (
   SELECT 1 FROM name_claims WHERE owner_kind = 'user' AND persona = ''
    AND name = lower(handle) AND owner_id = NEW.id AND canonical
  )) THEN RAISE EXCEPTION 'rename requires an atomic name claim' USING ERRCODE = '23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;

DROP INDEX permission_groups_persona_instance_uidx;
ALTER TABLE permission_groups
  DROP CONSTRAINT pg_root_singleton_shape_chk,
  DROP CONSTRAINT pg_instance_slug_format_chk,
  DROP COLUMN instance_slug,
  DROP COLUMN display_name,
  DROP COLUMN last_renamed_at,
  DROP COLUMN updated_at;

CREATE FUNCTION permission_group_identity_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
 RAISE EXCEPTION 'a permission group''s id and persona are immutable' USING ERRCODE = '23514';
END;
$$;
CREATE TRIGGER permission_group_identity_immutable BEFORE UPDATE OF id, persona ON permission_groups
 FOR EACH ROW WHEN (NEW.id IS DISTINCT FROM OLD.id OR NEW.persona IS DISTINCT FROM OLD.persona)
 EXECUTE FUNCTION permission_group_identity_immutable();
