-- parent: 4 sha256:555ccaad5d712be979db5102a5ce2cc679a4e7efbd1365c283711a894bc47298
-- Permission groups are flat: root plus one level of persona groups. A role
-- held on root applies in every group, so no parent link is stored.
DROP TRIGGER permission_group_containment ON permission_groups;
DROP FUNCTION trg_permission_group_containment();
ALTER TABLE permission_groups DROP CONSTRAINT pg_root_parentless_chk;
ALTER TABLE permission_groups DROP COLUMN parent_id;
ALTER TABLE permission_groups ADD CONSTRAINT pg_root_singleton_shape_chk CHECK ((persona = 'root') = (instance_slug IS NULL));
DROP TABLE group_persona_parents;
COMMENT ON COLUMN remote_applications.permission_group_id IS
  'Required controlling permission-group. Authority comes from group_remote_application_roles on it and on root.';
COMMENT ON COLUMN permission_groups.deleted_at IS 'Retained inactive group state; the trusted host owns retention and purge.';
