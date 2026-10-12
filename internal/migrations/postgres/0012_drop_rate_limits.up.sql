-- Rate-limit budgets live in Redis, or without it in each process's memory,
-- never in PostgreSQL (#446): v1.16.0's rate_limits table is dropped.
SET LOCAL lock_timeout = '10s';

DROP TABLE rate_limits;
