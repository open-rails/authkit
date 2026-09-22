-- parent: 1 sha256:1478859af0e6f0aa719845106b03f98cf74e7e9555e8c4647ed07d063c56157f
-- Account deletion is recoverable for thirty days. Delivery receipts are
-- private lifecycle state; River owns scheduling and execution.
CREATE TABLE account_deletions (
    id uuid PRIMARY KEY DEFAULT uuidv7(),
    user_id uuid NOT NULL,
    deleted_at timestamptz NOT NULL,
    purge_at timestamptz NOT NULL,
    state text NOT NULL DEFAULT 'deleted' CHECK (state IN ('deleted','restored','finalizing','purged')),
    recipients text[] NOT NULL DEFAULT '{}',
    jobs_enqueued boolean NOT NULL DEFAULT false,
    restored_at timestamptz,
    purged_at timestamptz,
    CHECK (purge_at = deleted_at + interval '720 hours')
);
CREATE UNIQUE INDEX account_deletions_active_user_idx ON account_deletions(user_id)
    WHERE state IN ('deleted','finalizing');
CREATE INDEX account_deletions_user_idx ON account_deletions(user_id,deleted_at,id);

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

-- Preserve the original timestamp of already-soft-deleted accounts. Runtime
-- River binding adopts these rows once; normal writes enqueue transactionally.
INSERT INTO account_deletions(user_id,deleted_at,purge_at)
SELECT id,deleted_at,deleted_at + interval '720 hours' FROM users WHERE deleted_at IS NOT NULL;
