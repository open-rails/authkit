-- Migration: Drop signin_history (replaced by external auth session event logging)
DROP TABLE IF EXISTS profiles.signin_history;

