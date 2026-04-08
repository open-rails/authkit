-- Seed reserved owner slugs as reserved placeholder user + personal-org records.
--
-- Canonical list (hard-cut): this SQL migration is the source of truth.
-- No legacy-data compatibility path is provided; conflicting pre-existing rows fail migration.

SET lock_timeout = '10s';
SET statement_timeout = '300s';

DO $$
DECLARE
  reserved_slug text;
  uid uuid;
  oid uuid;
BEGIN
  FOREACH reserved_slug IN ARRAY ARRAY['admin', 'superuser', 'root', 'sudo'] LOOP
    INSERT INTO profiles.users (email, username, email_verified, phone_number, phone_verified, metadata)
    VALUES (NULL, reserved_slug, false, NULL, false, jsonb_build_object('reserved', to_jsonb(true)))
    RETURNING id INTO uid;

    -- Placeholders must remain non-loginable.
    DELETE FROM profiles.user_passwords WHERE user_id = uid;
    DELETE FROM profiles.user_providers WHERE user_id = uid;
    UPDATE profiles.users
       SET email = NULL,
           email_verified = false,
           phone_number = NULL,
           phone_verified = false,
           metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{reserved}', to_jsonb(true), true),
           updated_at = now()
     WHERE id = uid;

    INSERT INTO profiles.orgs (slug, is_personal, owner_user_id, metadata)
    VALUES (reserved_slug, true, uid, jsonb_build_object('reserved', to_jsonb(true)))
    RETURNING id INTO oid;

    INSERT INTO profiles.org_roles (org_id, role)
    VALUES (oid, 'owner'), (oid, 'member')
    ON CONFLICT (org_id, role) DO NOTHING;

    INSERT INTO profiles.org_members (org_id, user_id)
    VALUES (oid, uid)
    ON CONFLICT (org_id, user_id)
    DO UPDATE SET deleted_at = NULL, updated_at = now();

    INSERT INTO profiles.org_member_roles (org_id, user_id, role)
    VALUES (oid, uid, 'owner')
    ON CONFLICT (org_id, user_id, role) DO NOTHING;
  END LOOP;
END $$;
