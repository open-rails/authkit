-- parent: 13 sha256:d807ac93bb7aeaa26f08d86c1a6788d2db6d5bf18ec7ddd7321b52775858ad2a
-- A role has one text form everywhere, `<persona>:<name>` (`channel:moderator`):
-- in rows as on the wire and in Go. Remote applications are addressed by id,
-- so their slug goes.
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

ALTER TABLE remote_applications DROP COLUMN slug;

ALTER TABLE group_user_roles DROP CONSTRAINT gur_role_format_chk;
UPDATE group_user_roles r SET role = g.persona || ':' || r.role
FROM permission_groups g WHERE g.id = r.permission_group_id;
ALTER TABLE group_user_roles
  ADD CONSTRAINT gur_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$');

ALTER TABLE group_remote_application_roles DROP CONSTRAINT grar_role_format_chk;
UPDATE group_remote_application_roles r SET role = g.persona || ':' || r.role
FROM permission_groups g WHERE g.id = r.permission_group_id;
ALTER TABLE group_remote_application_roles
  ADD CONSTRAINT grar_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$');

ALTER TABLE group_invite_links DROP CONSTRAINT gil_role_format_chk;
UPDATE group_invite_links l SET role = g.persona || ':' || l.role
FROM permission_groups g WHERE g.id = l.permission_group_id;
ALTER TABLE group_invite_links
  ADD CONSTRAINT gil_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$');

ALTER TABLE account_registration_invites DROP CONSTRAINT ari_role_format_chk;
UPDATE account_registration_invites i SET role = g.persona || ':' || i.role
FROM permission_groups g WHERE g.id = i.permission_group_id AND i.role IS NOT NULL;
ALTER TABLE account_registration_invites
  ADD CONSTRAINT ari_role_format_chk CHECK (role IS NULL OR role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$');

ALTER TABLE api_keys DROP CONSTRAINT api_keys_role_format_chk;
UPDATE api_keys k SET role = g.persona || ':' || k.role
FROM permission_groups g WHERE g.id = k.permission_group_id;
ALTER TABLE api_keys
  ADD CONSTRAINT api_keys_role_format_chk CHECK (role ~ '^[a-z][a-z0-9-]*:[a-z][a-z0-9-]*$');
COMMENT ON COLUMN api_keys.role IS 'The one catalog role this API key holds in its permission group.';

-- Undelivered role events carry the role in the same form.
UPDATE account_events SET
  previous_value = CASE WHEN previous_value = '' THEN '' ELSE persona || ':' || previous_value END,
  current_value = CASE WHEN current_value = '' THEN '' ELSE persona || ':' || current_value END
WHERE kind LIKE 'role.%';
