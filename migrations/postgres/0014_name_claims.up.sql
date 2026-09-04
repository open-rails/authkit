-- Canonical names and active former names share one unique ownership key.
-- No FK: deletion must not free a surviving former-name reservation.
CREATE TABLE profiles.name_claims (
  owner_kind text NOT NULL CHECK (owner_kind IN ('user', 'group')),
  persona text NOT NULL,
  name text NOT NULL CHECK (name = lower(name) AND name <> ''),
  owner_id uuid NOT NULL,
  canonical boolean NOT NULL,
  expires_at timestamptz,
  PRIMARY KEY (owner_kind, persona, name),
  CHECK ((owner_kind = 'user' AND persona = '') OR (owner_kind = 'group' AND persona <> '')),
  CHECK (NOT canonical OR expires_at IS NULL)
);
CREATE UNIQUE INDEX name_claims_canonical_owner ON profiles.name_claims(owner_kind, owner_id) WHERE canonical;
CREATE INDEX name_claims_owner ON profiles.name_claims(owner_kind, owner_id);
ALTER TABLE profiles.users ADD COLUMN last_renamed_at timestamptz;
ALTER TABLE profiles.permission_groups ADD COLUMN last_renamed_at timestamptz;

-- Current development records retain their UUIDs. Historical records are history,
-- not active reservations: this is the pre-launch replacement, not a dual reader.
INSERT INTO profiles.name_claims(owner_kind, persona, name, owner_id, canonical)
 SELECT 'user', '', lower(username::text), id, true FROM profiles.users WHERE COALESCE(username::text, '') <> '';
INSERT INTO profiles.name_claims(owner_kind, persona, name, owner_id, canonical)
 SELECT 'group', persona, lower(instance_slug), id, true FROM profiles.permission_groups WHERE COALESCE(instance_slug, '') <> '';
DROP TABLE profiles.permission_group_slug_tombstones;

-- All namespace writers share 256 lock stripes. The bound permits bulk import
-- without one shared-memory advisory lock per account. Collisions serialize
-- unrelated claims only. Multi-name operations acquire stripe IDs in order.
CREATE FUNCTION profiles.lock_name_claims(kind text, scope text, handles text[]) RETURNS void LANGUAGE plpgsql AS $$
DECLARE stripe integer;
BEGIN
 FOR stripe IN SELECT DISTINCT (hashtextextended(kind || ':' || scope || ':' || lower(handle),631335) & 255)::integer
  FROM unnest(handles) AS handle WHERE COALESCE(handle,'')<>'' ORDER BY 1
 LOOP
  PERFORM pg_advisory_xact_lock(631335,stripe);
 END LOOP;
END;
$$;

CREATE FUNCTION profiles.claim_canonical_name(kind text, scope text, handle text, owner uuid, at_time timestamptz)
RETURNS void LANGUAGE plpgsql AS $$
BEGIN
 IF COALESCE(handle, '') = '' THEN RETURN; END IF;
 PERFORM profiles.lock_name_claims(kind, scope, ARRAY[handle]);
 INSERT INTO profiles.name_claims(owner_kind, persona, name, owner_id, canonical)
 VALUES (kind, scope, lower(handle), owner, true)
 ON CONFLICT (owner_kind, persona, name) DO UPDATE
 SET owner_id = EXCLUDED.owner_id, canonical = true, expires_at = NULL
 WHERE name_claims.owner_id = owner
    OR (NOT name_claims.canonical AND name_claims.expires_at <= at_time);
 IF NOT FOUND THEN
  RAISE EXCEPTION 'name is unavailable' USING ERRCODE = '23505', CONSTRAINT = 'name_claims_pkey';
 END IF;
END;
$$;

-- Inserts include generated, imported and trusted low-level creation. Renames
-- must first prepare the owner-locked claim transition in the same transaction;
-- direct UPDATEs cannot silently discard the outgoing reservation.
CREATE FUNCTION profiles.enforce_canonical_name_claim() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE kind text := TG_ARGV[0]; scope text; handle text; previous text;
BEGIN
 IF TG_OP='UPDATE' AND NEW.id <> OLD.id THEN RAISE EXCEPTION 'identity UUID is immutable' USING ERRCODE='23514'; END IF;
 IF kind = 'user' THEN
  scope := '';
  IF TG_OP = 'DELETE' THEN handle := OLD.username::text; ELSE handle := NEW.username::text; END IF;
  IF TG_OP = 'UPDATE' THEN previous := OLD.username::text; END IF;
 ELSE
  IF TG_OP = 'DELETE' THEN scope := OLD.persona; handle := OLD.instance_slug;
  ELSE scope := NEW.persona; handle := NEW.instance_slug; END IF;
  IF TG_OP = 'UPDATE' THEN
   previous := OLD.instance_slug;
   IF NEW.persona <> OLD.persona THEN RAISE EXCEPTION 'group persona is immutable' USING ERRCODE = '23514'; END IF;
  END IF;
 END IF;
 IF TG_OP = 'DELETE' THEN
  -- Canonical deletion reserves forever by default. Explicit group release
  -- deletes this one claim after deletion; previous aliases keep their deadlines.
  IF kind='user' THEN
   -- Existing user hard-delete semantics release the final canonical username.
   DELETE FROM profiles.name_claims WHERE owner_kind=kind AND owner_id=OLD.id AND canonical;
  ELSE
   UPDATE profiles.name_claims SET canonical = false, expires_at = NULL
    WHERE owner_kind = kind AND owner_id = OLD.id AND canonical;
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP = 'INSERT' THEN
  PERFORM profiles.claim_canonical_name(kind, scope, handle, NEW.id, clock_timestamp());
 ELSIF lower(COALESCE(handle,'')) <> lower(COALESCE(previous,'')) THEN
  IF COALESCE(handle,'') = '' OR NOT EXISTS (
   SELECT 1 FROM profiles.name_claims WHERE owner_kind = kind AND persona = scope
    AND name = lower(handle) AND owner_id = NEW.id AND canonical
  ) THEN RAISE EXCEPTION 'rename requires an atomic name claim' USING ERRCODE = '23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
CREATE TRIGGER users_name_claim AFTER INSERT OR UPDATE OF id, username OR DELETE ON profiles.users
 FOR EACH ROW EXECUTE FUNCTION profiles.enforce_canonical_name_claim('user');
CREATE TRIGGER groups_name_claim AFTER INSERT OR UPDATE OF id, instance_slug, persona OR DELETE ON profiles.permission_groups
 FOR EACH ROW EXECUTE FUNCTION profiles.enforce_canonical_name_claim('group');
