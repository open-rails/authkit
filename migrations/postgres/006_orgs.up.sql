-- Organizations (multi-tenant) schema

SET lock_timeout = '10s';
SET statement_timeout = '300s';

CREATE TABLE IF NOT EXISTS profiles.orgs (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug         text NOT NULL UNIQUE,
  created_at   timestamptz NOT NULL DEFAULT now(),
  updated_at   timestamptz NOT NULL DEFAULT now(),
  deleted_at   timestamptz
);

-- Slug guardrail: 1..63 chars, lower-case letters/digits, hyphen allowed (not leading/trailing).
ALTER TABLE profiles.orgs
  ADD CONSTRAINT orgs_slug_format_chk
  CHECK (
    char_length(slug) BETWEEN 1 AND 63
    AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  );

CREATE TABLE IF NOT EXISTS profiles.org_slug_aliases (
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  slug       text NOT NULL UNIQUE,
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  PRIMARY KEY (org_id, slug)
);

ALTER TABLE profiles.org_slug_aliases
  ADD CONSTRAINT org_slug_aliases_slug_format_chk
  CHECK (
    char_length(slug) BETWEEN 1 AND 63
    AND slug ~ '^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$'
  );

CREATE INDEX IF NOT EXISTS org_slug_aliases_org_id_idx ON profiles.org_slug_aliases (org_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.org_members (
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  user_id    uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz,
  UNIQUE (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS org_members_user_id_idx ON profiles.org_members (user_id) WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS profiles.org_roles (
  org_id     uuid NOT NULL REFERENCES profiles.orgs(id) ON DELETE CASCADE,
  role       text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, role)
);

-- Role guardrail: short, safe charset.
ALTER TABLE profiles.org_roles
  ADD CONSTRAINT org_roles_role_format_chk
  CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  );

CREATE TABLE IF NOT EXISTS profiles.org_member_roles (
  org_id  uuid NOT NULL,
  user_id uuid NOT NULL,
  role    text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (org_id, user_id, role),
  FOREIGN KEY (org_id, user_id) REFERENCES profiles.org_members(org_id, user_id) ON DELETE CASCADE,
  FOREIGN KEY (org_id, role) REFERENCES profiles.org_roles(org_id, role) ON DELETE CASCADE
);

ALTER TABLE profiles.org_member_roles
  ADD CONSTRAINT org_member_roles_role_format_chk
  CHECK (
    char_length(role) BETWEEN 1 AND 64
    AND role ~ '^[a-zA-Z0-9:_-]+$'
  );

CREATE INDEX IF NOT EXISTS org_member_roles_member_idx ON profiles.org_member_roles (org_id, user_id);
CREATE INDEX IF NOT EXISTS org_member_roles_org_idx ON profiles.org_member_roles (org_id);
