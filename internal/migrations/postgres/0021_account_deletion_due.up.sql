-- One daily sweep reads due lifecycle state. Keep the rows and per-issuer
-- cleanup receipts authoritative; River no longer stores account deadlines.
CREATE INDEX account_deletions_due_idx ON account_deletions (purge_at, id)
  WHERE state IN ('deleted', 'finalizing');
CREATE INDEX account_deletion_deliveries_pending_deletion_idx ON account_deletion_deliveries (deletion_id)
  WHERE stage = 'hard' AND completed_at IS NULL;
