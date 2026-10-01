-- parent: 5 sha256:b20e92c2a20fe237edbd2aba02c31f1e8653ae2f1b342266e51b97dd37d0c2f0
-- The one application field AuthKit keeps is public metadata: a JSON object
-- the host writes and anyone may read. A host keeps every other per-account
-- datum in its own tables, keyed by users(id). The old metadata and
-- avatar_url go with their contents.
SET LOCAL lock_timeout = '10s';

ALTER TABLE users
  DROP COLUMN metadata,
  DROP COLUMN avatar_url,
  ADD COLUMN public_metadata jsonb NOT NULL DEFAULT '{}'::jsonb
    CONSTRAINT users_public_metadata_object CHECK (jsonb_typeof(public_metadata) = 'object');
COMMENT ON COLUMN users.public_metadata IS 'Host-written application data anyone may read';
