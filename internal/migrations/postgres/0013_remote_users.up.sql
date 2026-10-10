-- parent: 12 sha256:fbb0d9e9dd05d03f7b2d57eff79a49776ba3c2e3ba4b5b7d8c8656258c1134e4
-- A group's directory of its remote applications' users (SCIM 2.0, RFC 7643
-- and RFC 7644): each known by its issuer and subject, which only together
-- identify a user (OpenID Connect Core §2, §5.7). A SCIM client provisions
-- them (provisioned_at), or a token's contact claims record them. A SCIM
-- DELETE deletes the row.
SET LOCAL lock_timeout = '10s';
SELECT set_config('search_path', format('%I, public, pg_temp', current_schema()), true);

CREATE TABLE remote_users (
  id uuid PRIMARY KEY DEFAULT uuidv7(),
  permission_group_id uuid NOT NULL REFERENCES permission_groups(id) ON DELETE CASCADE,
  issuer text NOT NULL CHECK (issuer <> ''),
  subject text NOT NULL CHECK (subject <> '' AND char_length(subject) <= 255),
  user_name public.citext CHECK (user_name <> '' AND char_length(user_name) <= 256),
  display_name text CHECK (display_name <> '' AND char_length(display_name) <= 256),
  name_formatted text CHECK (name_formatted <> '' AND char_length(name_formatted) <= 256),
  given_name text CHECK (given_name <> '' AND char_length(given_name) <= 256),
  family_name text CHECK (family_name <> '' AND char_length(family_name) <= 256),
  email public.citext CHECK (email <> '' AND char_length(email) <= 320),
  email_type text CHECK (email_type <> '' AND char_length(email_type) <= 256),
  active boolean NOT NULL DEFAULT true,
  provisioned_at timestamptz,
  source_updated_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT remote_users_subject_key UNIQUE (permission_group_id, issuer, subject)
);
CREATE UNIQUE INDEX remote_users_user_name_key
  ON remote_users (permission_group_id, issuer, user_name)
  WHERE provisioned_at IS NOT NULL;
CREATE INDEX remote_users_provisioned_idx
  ON remote_users (permission_group_id, issuer, id)
  WHERE provisioned_at IS NOT NULL;
COMMENT ON TABLE remote_users IS
  'The users of the issuers a group trusts, by issuer and subject: SCIM-provisioned or recorded from token claims; a SCIM DELETE deletes the row.';
COMMENT ON COLUMN remote_users.subject IS 'The issuer''s sub for the user: the SCIM externalId';
COMMENT ON COLUMN remote_users.email IS 'An address the issuer asserts: pushed over SCIM, or an email claim with email_verified';
COMMENT ON COLUMN remote_users.provisioned_at IS 'When a SCIM client created the User (meta.created); NULL when only token claims recorded it';
COMMENT ON COLUMN remote_users.source_updated_at IS 'When the values were last reported: a SCIM write''s arrival, or a token''s updated_at claim. An older claim is ignored';

ALTER TABLE api_keys ADD COLUMN provisions_for uuid REFERENCES remote_applications(id) ON DELETE CASCADE;
CREATE INDEX api_keys_provisions_for_idx ON api_keys (provisions_for) WHERE provisions_for IS NOT NULL;
COMMENT ON COLUMN api_keys.provisions_for IS 'The remote application of the key''s group whose users the key provisions over SCIM; NULL for none.';
