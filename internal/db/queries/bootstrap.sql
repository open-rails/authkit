-- Bootstrap manifests and EnsureUserRole: find and lock the account a
-- manifest user or a UserRef names. verified reports whether the key proves
-- who holds the account (the id itself, or a verified contact).

-- name: BootstrapAccountByIDForUpdate :one
SELECT id::text AS id, true AS verified, (deleted_at IS NOT NULL)::boolean AS deleted
FROM users WHERE id = sqlc.arg(id)::uuid FOR UPDATE;

-- name: BootstrapAccountByEmailForUpdate :one
SELECT id::text AS id, email_verified AS verified, (deleted_at IS NOT NULL)::boolean AS deleted
FROM users WHERE email = sqlc.arg(email)::text::public.citext FOR UPDATE;

-- name: BootstrapAccountByPhoneForUpdate :one
SELECT id::text AS id, phone_verified AS verified, (deleted_at IS NOT NULL)::boolean AS deleted
FROM users WHERE phone_number = sqlc.arg(phone)::text FOR UPDATE;

-- name: BootstrapAccountByCanonicalNameForUpdate :one
-- A canonical username only; an alias is never followed.
SELECT u.id::text AS id, (u.deleted_at IS NOT NULL)::boolean AS deleted
FROM name_claims c JOIN users u ON u.id = c.owner_id
WHERE c.owner_kind = 'user' AND c.persona = '' AND c.name = lower(sqlc.arg(username)::text) AND c.canonical
FOR UPDATE OF u;

-- name: BootstrapApplyState :one
SELECT
  EXISTS (SELECT 1 FROM bootstrap_applies b WHERE b.name = sqlc.arg(name)::text)::boolean AS name_claimed,
  EXISTS (SELECT 1 FROM bootstrap_applies)::boolean AS any_claimed,
  (NOT EXISTS (SELECT 1 FROM users WHERE deleted_at IS NULL)
   AND NOT EXISTS (SELECT 1 FROM remote_applications))::boolean AS graph_empty;

-- name: BootstrapApplyInsert :exec
INSERT INTO bootstrap_applies (name) VALUES (sqlc.arg(name));
