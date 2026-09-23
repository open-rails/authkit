-- parent: 1 sha256:c5e953e22e2b79c840c691d5b80e440df4ab14b7df1a21e04d01e489762f51bd
-- Retain inactive groups without changing existing hard-delete behavior.
ALTER TABLE permission_groups ADD COLUMN deleted_at timestamptz;
ALTER TABLE permission_groups ADD CONSTRAINT permission_groups_root_active CHECK (persona <> 'root' OR deleted_at IS NULL);
COMMENT ON COLUMN permission_groups.deleted_at IS 'Retained inactive subtree state; the trusted host owns retention and purge.';

CREATE OR REPLACE FUNCTION trg_permission_group_containment() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
DECLARE
  actual_parent_persona text;
BEGIN
  IF NEW.persona = 'root' THEN
    RETURN NEW;
  END IF;

  SELECT persona INTO actual_parent_persona FROM permission_groups WHERE id = NEW.parent_id AND deleted_at IS NULL FOR KEY SHARE;
  IF actual_parent_persona IS NULL THEN
    RAISE EXCEPTION 'permission_groups.parent_id % does not exist', NEW.parent_id
      USING ERRCODE = 'foreign_key_violation';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM group_persona_parents
    WHERE persona = NEW.persona AND parent_persona = actual_parent_persona
  ) THEN
    RAISE EXCEPTION 'a % group may not have a % parent',
      NEW.persona, actual_parent_persona USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;
