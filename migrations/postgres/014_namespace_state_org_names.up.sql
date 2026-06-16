-- #83: hard-cut owner namespace metadata values from tenant-era names to org names.
--
-- These values live in metadata JSON, not typed columns. Existing rows can carry
-- the old enum strings from before the AuthKit tenant -> org rename.

UPDATE profiles.orgs
SET metadata = jsonb_set(metadata, '{namespace_state}', to_jsonb('registered_org'::text), true)
WHERE metadata->>'namespace_state' = 'registered_tenant';

UPDATE profiles.orgs
SET metadata = jsonb_set(metadata, '{namespace_state}', to_jsonb('parked_org'::text), true)
WHERE metadata->>'namespace_state' = 'parked_tenant';
