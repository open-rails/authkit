-- parent: 9 sha256:1684703aeee000231fffed4f8560e79ab9186bfd30368fcb9b265e59695e4146
-- SCIM 2.0 provisioning (Config.Provisioning). A change to what a SCIM User
-- shows (email and its verification, username, deletion, ban) records one
-- provisioning_changes row per target in the change's own transaction,
-- whoever writes users: the triggers below are the only writers. A target's
-- periodic batch sends each pending user's current state and deletes the rows
-- the target accepted. profile_updated_at is when those fields last changed:
-- SCIM meta.lastModified and the OIDC updated_at claim.
SET LOCAL lock_timeout = '10s';
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

ALTER TABLE users ADD COLUMN profile_updated_at timestamptz NOT NULL DEFAULT now();
COMMENT ON COLUMN users.profile_updated_at IS 'When email, its verification, username, deletion or ban last changed';

CREATE TABLE provisioning_targets (
  issuer text NOT NULL,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  -- The initial sync queues every account in id order; sync_after is how far
  -- it got, synced_at when it finished.
  sync_after uuid,
  synced_at timestamptz,
  reconciled_at timestamptz,
  -- A reconciliation spans runs: when it began, the next startIndex of its
  -- listing of the target's users, and when that listing finished (the
  -- resources it did not see are then checked one by one).
  reconcile_started_at timestamptz,
  reconcile_next_index integer,
  reconcile_listed_at timestamptz,
  last_success_at timestamptz,
  failing_since timestamptz,
  failures integer NOT NULL DEFAULT 0,
  retry_at timestamptz,
  last_error text,
  PRIMARY KEY (issuer, name)
);
COMMENT ON TABLE provisioning_targets IS 'SCIM targets of each issuer''s Config.Provisioning; a target no longer configured is deleted at its issuer''s Start.';

-- The outbox: a user with a row is pending for the target. Rows reference no
-- user: a purge must leave its own row behind.
CREATE TABLE provisioning_changes (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  issuer text NOT NULL,
  target text NOT NULL,
  user_id uuid NOT NULL,
  due_at timestamptz NOT NULL DEFAULT now(),
  attempts integer NOT NULL DEFAULT 0,
  last_error text,
  FOREIGN KEY (issuer, target) REFERENCES provisioning_targets ON DELETE CASCADE
);
CREATE INDEX provisioning_changes_due_idx
  ON provisioning_changes (issuer, target, due_at, id);
CREATE INDEX provisioning_changes_user_idx
  ON provisioning_changes (issuer, target, user_id, id);
COMMENT ON COLUMN provisioning_changes.due_at IS 'Not sent before: a retry''s backoff, or a temporary ban''s end';

-- What each target holds: the id it gave the user and the digest of the
-- state it last accepted.
CREATE TABLE provisioning_resources (
  issuer text NOT NULL,
  target text NOT NULL,
  user_id uuid NOT NULL,
  remote_id text NOT NULL,
  state_digest text NOT NULL,
  synced_at timestamptz NOT NULL DEFAULT now(),
  seen_at timestamptz,
  PRIMARY KEY (issuer, target, user_id),
  FOREIGN KEY (issuer, target) REFERENCES provisioning_targets ON DELETE CASCADE
);
COMMENT ON COLUMN provisioning_resources.state_digest IS 'SHA-256 of the resource the target last accepted; empty when reconciliation found it drifted';
COMMENT ON COLUMN provisioning_resources.seen_at IS 'When reconciliation last found the resource at the target';

CREATE FUNCTION provisioning_touch_profile() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  NEW.profile_updated_at := statement_timestamp();
  RETURN NEW;
END;
$$;
CREATE TRIGGER users_profile_updated
  BEFORE UPDATE OF email, email_verified, username, deleted_at, banned_at, banned_until ON users
  FOR EACH ROW
  WHEN (ROW(OLD.email, OLD.email_verified, OLD.username, OLD.deleted_at, OLD.banned_at, OLD.banned_until)
        IS DISTINCT FROM ROW(NEW.email, NEW.email_verified, NEW.username, NEW.deleted_at, NEW.banned_at, NEW.banned_until))
  EXECUTE FUNCTION provisioning_touch_profile();

CREATE FUNCTION provisioning_record_change() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  INSERT INTO provisioning_changes (issuer, target, user_id)
  SELECT issuer, name, CASE WHEN TG_OP = 'DELETE' THEN OLD.id ELSE NEW.id END FROM provisioning_targets;
  RETURN NULL;
END;
$$;
CREATE TRIGGER users_provisioning_insert
  AFTER INSERT ON users
  FOR EACH ROW EXECUTE FUNCTION provisioning_record_change();
CREATE TRIGGER users_provisioning_update
  AFTER UPDATE OF email, email_verified, username, deleted_at, banned_at, banned_until ON users
  FOR EACH ROW
  WHEN (ROW(OLD.email, OLD.email_verified, OLD.username, OLD.deleted_at, OLD.banned_at, OLD.banned_until)
        IS DISTINCT FROM ROW(NEW.email, NEW.email_verified, NEW.username, NEW.deleted_at, NEW.banned_at, NEW.banned_until))
  EXECUTE FUNCTION provisioning_record_change();
CREATE TRIGGER users_provisioning_delete
  AFTER DELETE ON users
  FOR EACH ROW EXECUTE FUNCTION provisioning_record_change();
