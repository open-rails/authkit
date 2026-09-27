-- Converts a schema built by AuthKit v0.106.2–v0.124.0's baseline (without
-- v0.124.0's 0002_recoverable_account_deletion) to the current 0001.
-- The only difference is account deletion: the retired erasure obligations
-- become recoverable deletions scheduled through River. Accounts still inside
-- the retired lifecycle need River jobs this SQL cannot create, so it refuses.
DO $$
DECLARE deleted bigint; obligations bigint;
BEGIN
  SELECT count(*) INTO deleted FROM users WHERE deleted_at IS NOT NULL;
  SELECT count(*) INTO obligations FROM account_erasure_obligations;
  IF deleted > 0 OR obligations > 0 THEN
    RAISE EXCEPTION 'authkit: % soft-deleted account(s) and % erasure obligation(s) are inside the retired deletion lifecycle, which needs River finalization jobs this conversion cannot create', deleted, obligations;
  END IF;
END $$;

DROP TABLE account_erasure_acknowledgements;
DROP TABLE account_erasure_obligations;

-- Account deletion is recoverable for thirty days. Delivery receipts are
-- private lifecycle state; River owns scheduling and execution.
-- Applications may share identities while running separate River schemas.
CREATE TABLE account_delivery_fleets (
    issuer text PRIMARY KEY,
    river_schema text NOT NULL
);

CREATE TABLE account_deletions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL,
    deleted_at timestamptz NOT NULL,
    purge_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'deleted' CHECK (state IN ('deleted','restored','finalizing','purged')),
    recipients text[] NOT NULL DEFAULT '{}',
    restored_at timestamptz,
    purged_at timestamptz,
    CHECK (purge_at = deleted_at + interval '720 hours')
);
CREATE UNIQUE INDEX account_deletions_active_user_idx ON account_deletions(user_id)
    WHERE state IN ('deleted','finalizing');
CREATE INDEX account_deletions_user_idx ON account_deletions(user_id,deleted_at,id);
CREATE INDEX account_deletions_terminal_idx ON account_deletions((COALESCE(restored_at,purged_at)),id)
    WHERE state IN ('restored','purged');

CREATE TABLE account_deletion_deliveries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    deletion_id uuid NOT NULL REFERENCES account_deletions(id) ON DELETE CASCADE,
    user_id uuid NOT NULL,
    issuer text NOT NULL,
    stage text NOT NULL CHECK (stage IN ('soft','restore','hard')),
    completed_at timestamptz,
    UNIQUE (deletion_id,issuer,stage)
);
CREATE INDEX account_deletion_deliveries_pending_idx
    ON account_deletion_deliveries(user_id,issuer,id) WHERE completed_at IS NULL;
