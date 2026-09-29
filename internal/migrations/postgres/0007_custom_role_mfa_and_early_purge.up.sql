-- parent: 6 sha256:06240f8684a9b78945c8f99c89cc60c46f3b355709f31f75b201c84acf1e5585
-- A custom role needs MFA when its permissions do; the stored flag was never read.
ALTER TABLE group_custom_roles DROP COLUMN requires_mfa;

-- An operator purge ends the recovery window early: purge_at moves forward and
-- deleted_at keeps the real deletion time.
ALTER TABLE account_deletions
  DROP CONSTRAINT account_deletions_check,
  ADD CONSTRAINT account_deletions_purge_window_chk
    CHECK (purge_at >= deleted_at AND purge_at <= deleted_at + interval '720 hours');
