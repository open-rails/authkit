ALTER TABLE profiles.refresh_sessions
  ADD COLUMN IF NOT EXISTS auth_methods text[] NOT NULL DEFAULT ARRAY['pwd']::text[];
