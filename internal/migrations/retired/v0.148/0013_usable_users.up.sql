-- The one definition of a usable account: not deleted, not reserved, and no
-- ban in force (an expired temporary ban is no ban). Credential issuers,
-- registrars and group owners count only while usable. Queries use it as
-- EXISTS(SELECT 1 FROM usable_users WHERE id = ...) or JOIN usable_users.
CREATE VIEW usable_users AS
SELECT id FROM users
WHERE deleted_at IS NULL
  AND COALESCE(metadata->'reserved', 'false'::jsonb) <> 'true'::jsonb
  AND ((banned_at IS NULL AND banned_until IS NULL AND ban_reason IS NULL AND banned_by IS NULL)
       OR banned_until <= statement_timestamp());
