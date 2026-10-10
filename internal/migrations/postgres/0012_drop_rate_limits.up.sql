-- parent: 11 sha256:c89a3016d794cddd6a1cba94ae37b28ba3938f69cb02f97ee5178871aef12de5
-- Rate-limit budgets live in Redis, or without it in each process's memory,
-- never in PostgreSQL (#446): v1.16.0's rate_limits table is dropped.
SET LOCAL lock_timeout = '10s';

DROP TABLE rate_limits;
