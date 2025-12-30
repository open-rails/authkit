-- Migration: Add signin_history table for tracking logins
CREATE TABLE IF NOT EXISTS profiles.signin_history (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
    date TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip TEXT,
    site TEXT,
    success BOOLEAN NOT NULL,
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES profiles.users(id)
);

CREATE INDEX IF NOT EXISTS idx_signin_history_user_id_date ON profiles.signin_history(user_id, date DESC);
