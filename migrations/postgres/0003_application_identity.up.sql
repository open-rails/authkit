-- ak#264: application self-registration + naming doctrine.
--
-- Identity is the uuid (v7, both tables already key on it); slugs are meaningful
-- unique HANDLES (GitHub model). Applications earn slug = domain by domain proof,
-- so slugs (and permission-group instance slugs, where each application's
-- service-owned org mirrors its domain) must admit dotted DNS names.

-- permission_groups: first-class display name (free-form, non-unique, renameable
-- at will — vanity naming lives here, never on the slug) + domain-shaped slugs.
ALTER TABLE profiles.permission_groups
  ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '';

ALTER TABLE profiles.permission_groups
  DROP CONSTRAINT pg_instance_slug_format_chk;
ALTER TABLE profiles.permission_groups
  ADD CONSTRAINT pg_instance_slug_format_chk CHECK (
    instance_slug IS NULL OR (
      char_length(instance_slug) BETWEEN 1 AND 253
      AND instance_slug ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'
      AND instance_slug NOT LIKE '%..%'
    )
  );

-- Slug rename tombstones: a renamed-away instance slug is PERMANENTLY reserved
-- to the same group and forwards to it at resolution time. Never reclaimable by
-- another group (repojacking prevention); the owning group may reclaim its own
-- tombstone by renaming back, which deletes the row.
--
-- DELIBERATELY NO FK: tombstones must survive their group's deletion (the
-- default delete path tombstones the live slug too) — the reservation
-- outlives the group; a dangling tombstone resolves to nothing but still
-- blocks every claim. Releasing a name on delete is an explicit host opt-in,
-- safe only for names nothing ever referenced.
CREATE TABLE IF NOT EXISTS profiles.permission_group_slug_tombstones (
  persona text NOT NULL,
  slug text NOT NULL,
  permission_group_id uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (persona, slug),
  CONSTRAINT pgst_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 253
    AND slug ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'
    AND slug NOT LIKE '%..%'
  )
);
CREATE INDEX IF NOT EXISTS pgst_group_idx
  ON profiles.permission_group_slug_tombstones (permission_group_id);
COMMENT ON TABLE profiles.permission_group_slug_tombstones IS
  'Renamed-away instance slugs, permanently reserved to their group; slug->id resolution forwards through them.';

-- remote_applications: self-registration identity/trust metadata.
--   tier        registered (self-registered: exists, authenticates, serves/fetches
--               documents — zero default capability) | approved (admin act).
--   trust_root  what can rotate the keys: manual (admin/bootstrap-managed),
--               domain (re-fetching https://<slug>/.well-known/authkit/application.json
--               re-proves control and adopts current keys), user (the owning
--               user's authenticated session). NEVER the keypair alone.
ALTER TABLE profiles.remote_applications
  ADD COLUMN IF NOT EXISTS display_name text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS tier text NOT NULL DEFAULT 'approved',
  ADD COLUMN IF NOT EXISTS trust_root text NOT NULL DEFAULT 'manual',
  ADD COLUMN IF NOT EXISTS document_endpoint text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS root_verified_at timestamptz;

ALTER TABLE profiles.remote_applications
  ADD CONSTRAINT remote_applications_tier_chk CHECK (tier IN ('registered', 'approved')),
  ADD CONSTRAINT remote_applications_trust_root_chk CHECK (trust_root IN ('manual', 'domain', 'user'));

ALTER TABLE profiles.remote_applications
  DROP CONSTRAINT remote_applications_slug_format_chk;
ALTER TABLE profiles.remote_applications
  ADD CONSTRAINT remote_applications_slug_format_chk CHECK (
    char_length(slug) BETWEEN 1 AND 253
    AND slug ~ '^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$'
    AND slug NOT LIKE '%..%'
  );

COMMENT ON COLUMN profiles.remote_applications.tier IS
  'registered (self-registered; zero default capability) | approved (admin act on the host).';
COMMENT ON COLUMN profiles.remote_applications.trust_root IS
  'What rotates the keys: manual | domain | user. Never the keypair alone.';
COMMENT ON COLUMN profiles.remote_applications.root_verified_at IS
  'Last successful trust-root proof (domain fetch). Re-verification cadence is host policy (host sweepers disable stale registered-tier apps; re-registration re-proves and re-enables).';
