-- Add ban metadata to profiles.users
ALTER TABLE profiles.users
  ADD COLUMN IF NOT EXISTS banned_at timestamptz,
  ADD COLUMN IF NOT EXISTS banned_until timestamptz,
  ADD COLUMN IF NOT EXISTS ban_reason text,
  ADD COLUMN IF NOT EXISTS banned_by uuid REFERENCES profiles.users(id) ON DELETE SET NULL;

COMMENT ON COLUMN profiles.users.banned_at IS 'When the user was banned';
COMMENT ON COLUMN profiles.users.banned_until IS 'When a temporary ban expires (NULL for permanent)';
COMMENT ON COLUMN profiles.users.ban_reason IS 'Reason for ban';
COMMENT ON COLUMN profiles.users.banned_by IS 'User ID of admin who imposed ban';
