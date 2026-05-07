ALTER TABLE profiles.refresh_sessions
  ADD COLUMN IF NOT EXISTS last_authenticated_at timestamptz;

