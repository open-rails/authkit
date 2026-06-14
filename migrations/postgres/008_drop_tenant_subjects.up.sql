-- #78: Drop tenant_subjects. The delegated-user registry was write-mostly and
-- never read for an auth decision (auth rides entirely on the token). The one
-- side-effect it provided — the fail-closed issuer gate — moved to a read-only
-- remote_application(issuer) enabled-check on the verify path. The (issuer,
-- subject) pair that matters is tracked on the BILLING side (openrails#491).
--
-- NEW numbered migration (migratekit is name-tracked). Idempotent: a no-op on a
-- fresh DB whose 001 baseline no longer creates the table.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

DROP TABLE IF EXISTS profiles.tenant_subjects;
