-- parent: 2 sha256:f224a2cb39a8134f5c869e27f16baadcaf964b56884f89f97cc6d9e33303c21e
-- Reserve a purged user's username permanently, as deleted groups' slugs are.
-- Explicit pg_temp keeps temporary tables from shadowing AuthKit relations
-- inside the captured function search path (as in 0001).
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

CREATE OR REPLACE FUNCTION enforce_canonical_name_claim() RETURNS trigger LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
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
  -- A deleted user's username stays reserved forever as an alias of the dead
  -- UUID, so nobody can re-register it and impersonate the purged account.
  -- Raw group deletion keeps canonical-release semantics; the explicit group
  -- lifecycle primitive first turns the claim into a permanent alias when
  -- reservation is requested. Earlier rename aliases always survive.
  IF kind = 'user' THEN
   UPDATE name_claims SET canonical=false, expires_at=NULL WHERE owner_kind=kind AND owner_id=OLD.id AND canonical;
  ELSE
   DELETE FROM name_claims WHERE owner_kind=kind AND owner_id=OLD.id AND canonical;
  END IF;
  RETURN OLD;
 END IF;
 IF TG_OP = 'INSERT' THEN
  PERFORM claim_canonical_name(kind, scope, handle, NEW.id, clock_timestamp());
 ELSIF lower(COALESCE(handle,'')) <> lower(COALESCE(previous,'')) THEN
  IF COALESCE(handle,'') = '' OR NOT EXISTS (
   SELECT 1 FROM name_claims WHERE owner_kind = kind AND persona = scope
    AND name = lower(handle) AND owner_id = NEW.id AND canonical
  ) THEN RAISE EXCEPTION 'rename requires an atomic name claim' USING ERRCODE = '23514'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
