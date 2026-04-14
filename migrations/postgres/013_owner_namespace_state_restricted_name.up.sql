-- Rename legacy owner namespace state label to restricted_name.
-- This is a metadata compatibility migration for any installs that may have
-- persisted namespace_state='reserved_name' in org metadata.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

UPDATE profiles.orgs
SET metadata=jsonb_set(COALESCE(metadata, '{}'::jsonb), '{namespace_state}', to_jsonb('restricted_name'::text), true),
    updated_at=now()
WHERE lower(COALESCE(COALESCE(metadata, '{}'::jsonb)->>'namespace_state', ''))='reserved_name';
