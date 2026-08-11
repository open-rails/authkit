-- #262: first-class avatar URL field on the user record. Blob storage stays
-- host-supplied — authkit stores only the URL/key string.
ALTER TABLE profiles.users ADD COLUMN IF NOT EXISTS avatar_url text;
COMMENT ON COLUMN profiles.users.avatar_url IS 'Host-supplied avatar URL/key string; blob storage is host-owned';
