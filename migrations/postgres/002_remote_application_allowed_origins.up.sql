ALTER TABLE profiles.remote_applications
  ADD COLUMN IF NOT EXISTS allowed_origins text[] NOT NULL DEFAULT '{}';
