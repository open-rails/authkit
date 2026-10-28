-- #471: a tenant's public name (slug) beside its stable UUID, as OpenRails
-- names merchants. Existing tenants get a placeholder derived from their UUID;
-- an operator renames them with RenameTenant.
SET LOCAL lock_timeout = '10s';

-- Capture this schema ahead of temporary tables in the function below.
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

ALTER TABLE tenants ADD COLUMN slug text, ADD COLUMN slug_changed_at timestamptz;
UPDATE tenants SET slug = 'tenant-' || replace(id::text, '-', '');
ALTER TABLE tenants ALTER COLUMN slug SET NOT NULL;
ALTER TABLE tenants ADD CONSTRAINT tenants_slug_format
  CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$');
CREATE UNIQUE INDEX tenants_slug_key ON tenants(slug);
COMMENT ON COLUMN tenants.slug IS 'The tenant''s public name: unique, renamable, and never equal to another tenant''s unexpired former name (tenant_slug_aliases). Never a key, scope, claim or storage path; those use id.';
COMMENT ON COLUMN tenants.slug_changed_at IS 'When the tenant was last renamed; NULL if never.';

CREATE TABLE tenant_slug_aliases (
  slug text NOT NULL,
  tenant_id uuid NOT NULL,
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT tenant_slug_aliases_pkey PRIMARY KEY (slug),
  CONSTRAINT tenant_slug_aliases_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
);
CREATE INDEX tenant_slug_aliases_tenant_id_idx ON tenant_slug_aliases(tenant_id);
COMMENT ON TABLE tenant_slug_aliases IS 'Former tenant names. An unexpired alias forwards to its tenant and blocks every other claim of the name; expires_at NULL keeps it forever. Written by a rename, removed when its tenant takes the name back or when it expires and is claimed.';

-- One name namespace across live names and aliases. Claims serialize per name
-- on a transaction lock, so a rename's alias and a concurrent claim of the same
-- name cannot both win.
CREATE FUNCTION guard_tenant_name() RETURNS trigger
LANGUAGE plpgsql SET search_path FROM CURRENT AS $$
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.slug = NEW.slug THEN
      RETURN NEW;
    END IF;
    PERFORM pg_advisory_xact_lock(471, hashtext(least(OLD.slug, NEW.slug)));
    PERFORM pg_advisory_xact_lock(471, hashtext(greatest(OLD.slug, NEW.slug)));
  ELSE
    PERFORM pg_advisory_xact_lock(471, hashtext(NEW.slug));
  END IF;
  DELETE FROM tenant_slug_aliases
   WHERE slug = NEW.slug AND (tenant_id = NEW.id OR expires_at <= now());
  IF EXISTS (SELECT 1 FROM tenant_slug_aliases WHERE slug = NEW.slug) THEN
    RAISE EXCEPTION 'tenant name % is another tenant''s former name', NEW.slug
      USING ERRCODE = '23505', CONSTRAINT = 'tenant_slug_aliases_pkey';
  END IF;
  RETURN NEW;
END;
$$;
COMMENT ON FUNCTION guard_tenant_name() IS 'A tenant name is never another tenant''s unexpired former name. Raises 23505 on tenant_slug_aliases_pkey.';
REVOKE ALL ON FUNCTION guard_tenant_name() FROM PUBLIC;

CREATE TRIGGER guard_tenant_name BEFORE INSERT OR UPDATE OF slug ON tenants
  FOR EACH ROW EXECUTE FUNCTION guard_tenant_name();
