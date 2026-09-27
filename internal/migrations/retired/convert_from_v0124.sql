-- Converts a schema built by AuthKit v0.124.0 (retired 0001 plus
-- 0002_recoverable_account_deletion) to the current 0001, which dropped the
-- jobs_enqueued adoption flag. A deletion v0.124.0 never adopted has no River
-- job, so it refuses rather than strand it.
DO $$
DECLARE unscheduled bigint;
BEGIN
  SELECT count(*) INTO unscheduled FROM account_deletions
   WHERE NOT jobs_enqueued AND state IN ('deleted','finalizing');
  IF unscheduled > 0 THEN
    RAISE EXCEPTION 'authkit: % account deletion(s) were never scheduled by AuthKit v0.124.0 and have no River finalization job', unscheduled;
  END IF;
END $$;

ALTER TABLE account_deletions DROP COLUMN jobs_enqueued;
