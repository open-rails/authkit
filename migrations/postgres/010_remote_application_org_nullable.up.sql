-- #80: remote_applications.org_id -> NULLABLE. Reverses #77's NOT NULL ("exactly
-- one org"). An issuer is a standalone JWKS-signing principal that need NOT belong
-- to an org (standalone OpenRails: doujins/hentai0 have issuers but no orgs). The
-- FK stays, so a SET value still validates against profiles.orgs(id).
--
-- NEW numbered migration (migratekit is name-tracked). Idempotent: DROP NOT NULL
-- is a no-op once the column is already nullable.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

ALTER TABLE IF EXISTS profiles.remote_applications ALTER COLUMN org_id DROP NOT NULL;

COMMENT ON COLUMN profiles.remote_applications.org_id IS
  'Owning org, OPTIONAL (#80). NULL = org-less issuer (standalone shape, each token subject is its own payer); SET = org-bound issuer (the org is the single payer). FK validates a SET value.';
