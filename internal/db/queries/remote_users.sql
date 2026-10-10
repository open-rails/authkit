-- A group's directory of its remote applications' users (SCIM 2.0), by
-- issuer and subject. A SCIM client's tenant is (group, issuer) and it sees
-- the provisioned rows; claims-only rows serve UserInfo too.

-- name: SCIMTenantByAPIKey :one
-- The tenant an API key provisions: its live group and the remote
-- application it is bound to.
SELECT k.permission_group_id AS group_id, g.persona, a.issuer, a.enabled,
  (a.permission_group_id = k.permission_group_id)::boolean AS same_group
FROM api_keys k
JOIN permission_groups g ON g.id = k.permission_group_id
JOIN remote_applications a ON a.id = k.provisions_for
WHERE k.id = sqlc.arg(api_key_id) AND g.deleted_at IS NULL;

-- name: SCIMTenantByIssuer :one
-- The tenant a remote application's own token provisions.
SELECT a.permission_group_id AS group_id, g.persona, a.issuer, a.enabled
FROM remote_applications a JOIN permission_groups g ON g.id = a.permission_group_id
WHERE a.issuer = sqlc.arg(issuer) AND g.deleted_at IS NULL;

-- name: RemoteUserCreate :one
-- A SCIM create: a new row, or the claims-only row of the same subject
-- adopted. A subject already provisioned returns no row.
INSERT INTO remote_users AS r (permission_group_id, issuer, subject, user_name, display_name, name_formatted, given_name, family_name, email, email_type, active, provisioned_at, source_updated_at)
VALUES (sqlc.arg(group_id), sqlc.arg(issuer), sqlc.arg(subject), sqlc.arg(user_name)::text::public.citext, sqlc.narg(display_name)::text,
  sqlc.narg(name_formatted)::text, sqlc.narg(given_name)::text, sqlc.narg(family_name)::text, sqlc.narg(email)::text::public.citext,
  sqlc.narg(email_type)::text, sqlc.arg(active), now(), now())
ON CONFLICT (permission_group_id, issuer, subject) DO UPDATE SET
  user_name = EXCLUDED.user_name, display_name = EXCLUDED.display_name, name_formatted = EXCLUDED.name_formatted,
  given_name = EXCLUDED.given_name, family_name = EXCLUDED.family_name, email = EXCLUDED.email, email_type = EXCLUDED.email_type, active = EXCLUDED.active,
  provisioned_at = now(), source_updated_at = now(), updated_at = now()
WHERE r.provisioned_at IS NULL
RETURNING *;

-- name: RemoteUserProvisioned :one
SELECT * FROM remote_users
WHERE id = sqlc.arg(id) AND permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL;

-- name: RemoteUserProvisionedForUpdate :one
SELECT * FROM remote_users
WHERE id = sqlc.arg(id) AND permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL
FOR UPDATE;

-- name: RemoteUserReplace :one
UPDATE remote_users SET
  subject = sqlc.arg(subject), user_name = sqlc.arg(user_name)::text::public.citext, display_name = sqlc.narg(display_name)::text,
  name_formatted = sqlc.narg(name_formatted)::text, given_name = sqlc.narg(given_name)::text, family_name = sqlc.narg(family_name)::text,
  email = sqlc.narg(email)::text::public.citext, email_type = sqlc.narg(email_type)::text, active = sqlc.arg(active),
  source_updated_at = now(), updated_at = now()
WHERE id = sqlc.arg(id) AND permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL
RETURNING *;

-- name: RemoteUserDelete :execrows
DELETE FROM remote_users
WHERE id = sqlc.arg(id) AND permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL;

-- name: RemoteUsersCount :one
SELECT count(*)::bigint FROM remote_users
WHERE permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL;

-- name: RemoteUsersPage :many
SELECT * FROM remote_users
WHERE permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL
ORDER BY id LIMIT sqlc.arg(page_size) OFFSET sqlc.arg(skip);

-- name: RemoteUsersMatching :many
-- The provisioned users any equality term matches (RFC 7644 §3.4.2.2 "or").
SELECT * FROM remote_users
WHERE permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND provisioned_at IS NOT NULL
  AND (id = ANY(sqlc.arg(ids)::uuid[])
       OR subject = ANY(sqlc.arg(subjects)::text[])
       OR user_name = ANY(sqlc.arg(user_names)::text[]::public.citext[])
       OR email = ANY(sqlc.arg(emails)::text[]::public.citext[]))
ORDER BY id;

-- name: RemoteUserBySubject :one
SELECT * FROM remote_users
WHERE permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND subject = sqlc.arg(subject);

-- name: RemoteUsersBySubjects :many
-- The active users among subjects, for UserInfo.
SELECT * FROM remote_users
WHERE permission_group_id = sqlc.arg(group_id) AND issuer = sqlc.arg(issuer) AND subject = ANY(sqlc.arg(subjects)::text[]) AND active;

-- name: RemoteUsersSearch :many
-- Active users whose username, email or a name contains the pattern, in any case.
SELECT * FROM remote_users r
WHERE r.permission_group_id = sqlc.arg(group_id) AND r.issuer = sqlc.arg(issuer) AND r.active
  AND (r.user_name::text ILIKE sqlc.arg(pattern)::text OR r.email::text ILIKE sqlc.arg(pattern)::text
       OR r.display_name ILIKE sqlc.arg(pattern)::text OR r.name_formatted ILIKE sqlc.arg(pattern)::text
       OR r.given_name ILIKE sqlc.arg(pattern)::text OR r.family_name ILIKE sqlc.arg(pattern)::text)
ORDER BY r.id
LIMIT sqlc.arg(max_rows);

-- name: RemoteUserRecordClaims :exec
-- A token's contact claims: a new subject's are recorded at once; a held
-- one's only when dated after what it holds and different, so a token that
-- repeats them writes nothing. An absent claim keeps the held value.
WITH held AS (
  UPDATE remote_users r SET
    user_name = COALESCE(sqlc.narg(user_name)::text::public.citext, r.user_name),
    display_name = COALESCE(sqlc.narg(display_name)::text, r.display_name),
    email = COALESCE(sqlc.narg(email)::text::public.citext, r.email),
    source_updated_at = sqlc.narg(claims_updated_at)::timestamptz,
    updated_at = now()
  WHERE r.permission_group_id = sqlc.arg(group_id) AND r.issuer = sqlc.arg(issuer) AND r.subject = sqlc.arg(subject)
    AND (r.source_updated_at IS NULL OR r.source_updated_at < sqlc.narg(claims_updated_at)::timestamptz)
    AND ROW(r.user_name::text, r.display_name, r.email::text) IS DISTINCT FROM ROW(
      COALESCE(sqlc.narg(user_name)::text, r.user_name::text), COALESCE(sqlc.narg(display_name)::text, r.display_name),
      COALESCE(sqlc.narg(email)::text, r.email::text))
  RETURNING r.id
)
INSERT INTO remote_users (permission_group_id, issuer, subject, user_name, display_name, email, source_updated_at)
SELECT sqlc.arg(group_id), sqlc.arg(issuer), sqlc.arg(subject), sqlc.narg(user_name)::text::public.citext,
  sqlc.narg(display_name)::text, sqlc.narg(email)::text::public.citext, sqlc.narg(claims_updated_at)::timestamptz
WHERE NOT EXISTS (SELECT 1 FROM held)
ON CONFLICT (permission_group_id, issuer, subject) DO NOTHING;
