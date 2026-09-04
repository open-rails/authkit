-- #259: a database that acquired its authority graph before StartupOnly
-- claims existed has no row in bootstrap_applies and would be refused at every
-- boot. Record the bootstrap that demonstrably already ran.
INSERT INTO profiles.bootstrap_applies (name)
SELECT 'authkit.backfill'
WHERE NOT EXISTS (SELECT 1 FROM profiles.bootstrap_applies)
  AND (
    EXISTS (SELECT 1 FROM profiles.users WHERE deleted_at IS NULL)
    OR EXISTS (SELECT 1 FROM profiles.remote_applications)
  );
