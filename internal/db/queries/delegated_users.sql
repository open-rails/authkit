-- Delegated-user identity anchor (core/delegated_users.go, #81). A federated
-- end-user vouched for by a remote_application (issuer). Cross-domain FK target
-- for app + billing; authkit makes NO auth decision off this table.

-- name: DelegatedUserTouch :one
-- Idempotent upsert on the UNIQUE(remote_application_id, subject) natural key.
-- The uuidv7 id is minted ONCE and RETURNED; callers stamp the returned value.
INSERT INTO profiles.delegated_users (remote_application_id, issuer, subject)
VALUES (sqlc.arg(remote_application_id)::uuid, $2, $3)
ON CONFLICT (remote_application_id, subject) DO UPDATE
  SET last_seen_at = now()
RETURNING id::text, remote_application_id::text AS remote_application_id, issuer, subject, first_seen_at, last_seen_at;

-- name: DelegatedUserByAppSubject :one
SELECT id::text, remote_application_id::text AS remote_application_id, issuer, subject, first_seen_at, last_seen_at
FROM profiles.delegated_users
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid AND subject = $2;

-- name: DelegatedUsersByApp :many
SELECT id::text, remote_application_id::text AS remote_application_id, issuer, subject, first_seen_at, last_seen_at
FROM profiles.delegated_users
WHERE remote_application_id = sqlc.arg(remote_application_id)::uuid
ORDER BY last_seen_at DESC;
