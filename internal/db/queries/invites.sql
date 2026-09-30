-- Group invite links and account registration invites.

-- name: InviteLinksRevokeInvitedBy :exec
UPDATE group_invite_links SET revoked_at = now()
WHERE invited_by = sqlc.arg(user_id)::uuid AND revoked_at IS NULL AND redeemed_at IS NULL;

-- name: AccountInvitesRevokeInvitedBy :exec
UPDATE account_registration_invites SET revoked_at = now()
WHERE invited_by = sqlc.arg(user_id)::uuid AND revoked_at IS NULL AND consumed_at IS NULL;

-- An issuer is the system (NULL) or a usable account: a credential never
-- outlives its issuer's authority.

-- name: InviteLinkInsert :one
INSERT INTO group_invite_links (permission_group_id, role, invited_by, code_hash, expires_at, catalog_issuer)
VALUES (sqlc.arg(group_id), sqlc.arg(role), sqlc.narg(invited_by)::uuid, sqlc.arg(code_hash), sqlc.arg(expires_at)::timestamptz, sqlc.arg(catalog_issuer)::text)
RETURNING id, created_at;

-- InvitationsByGroup lists a group's invite links and email invitations,
-- newest first, never a code hash. In the root group (root) it includes the
-- plain registration invites, which have no group.
-- name: InvitationsByGroup :many
SELECT i.id, i.role, i.email, i.created_by, i.created_at, i.expires_at, i.redeemed_at, i.revoked_at FROM (
  SELECT l.id, l.role, ''::text AS email, COALESCE(l.invited_by::text, '')::text AS created_by,
    l.created_at, l.expires_at, l.redeemed_at, l.revoked_at
  FROM group_invite_links l WHERE l.permission_group_id = sqlc.arg(group_id)::uuid
  UNION ALL
  SELECT a.id, COALESCE(a.role, '')::text, a.email::text, COALESCE(a.invited_by::text, '')::text,
    a.created_at, a.expires_at, a.consumed_at, a.revoked_at
  FROM account_registration_invites a
  WHERE a.permission_group_id = sqlc.arg(group_id)::uuid OR (sqlc.arg(root)::boolean AND a.permission_group_id IS NULL)) i
WHERE sqlc.narg(after)::uuid IS NULL OR i.id < sqlc.narg(after)::uuid
ORDER BY i.id DESC
LIMIT sqlc.arg(page_limit)::bigint;

-- name: InviteLinkForRevoke :one
SELECT role, revoked_at, redeemed_at FROM group_invite_links
WHERE id = sqlc.arg(id) AND permission_group_id = sqlc.arg(group_id) FOR UPDATE;

-- name: AccountInviteForRevoke :one
SELECT COALESCE(role, '')::text AS role, revoked_at, consumed_at FROM account_registration_invites
WHERE id = sqlc.arg(id) AND (permission_group_id = sqlc.arg(group_id)::uuid OR (sqlc.arg(root)::boolean AND permission_group_id IS NULL))
FOR UPDATE;

-- name: InviteLinkGroupByCode :one
SELECT permission_group_id FROM group_invite_links WHERE code_hash = sqlc.arg(code_hash);

-- name: InviteLinkByCodeForUpdate :one
SELECT l.id, g.id AS group_id, g.persona, l.role, l.redeemed_at, l.expires_at, l.revoked_at,
  (l.invited_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = l.invited_by))::boolean AS issuer_live
FROM group_invite_links l JOIN permission_groups g ON g.id = l.permission_group_id
WHERE l.code_hash = sqlc.arg(code_hash) AND l.permission_group_id = sqlc.arg(group_id)
FOR UPDATE OF l;

-- name: InviteLinkRedeem :exec
UPDATE group_invite_links SET redeemed_at = now() WHERE id = sqlc.arg(id);

-- name: AccountInviteInsert :one
INSERT INTO account_registration_invites (email, invited_by, code_hash, expires_at, permission_group_id, role, catalog_issuer)
VALUES (sqlc.arg(email), sqlc.narg(invited_by)::uuid, sqlc.arg(code_hash), sqlc.arg(expires_at), sqlc.narg(group_id)::uuid, sqlc.narg(role)::text, sqlc.arg(catalog_issuer)::text)
RETURNING id, created_at;

-- AccountInviteValid: code_hash names a live registration invite.
-- name: AccountInviteValid :one
SELECT EXISTS(
  SELECT 1 FROM account_registration_invites i
  WHERE i.code_hash = sqlc.arg(code_hash) AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at > now()
    AND (i.invited_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = i.invited_by)))::boolean;

-- name: AccountInviteGroupLive :one
SELECT i.permission_group_id FROM account_registration_invites i
WHERE i.code_hash = sqlc.arg(code_hash) AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at > now()
  AND (i.invited_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = i.invited_by));

-- name: AccountInviteForUpdate :one
SELECT i.id, i.permission_group_id, i.role, g.persona
FROM account_registration_invites i LEFT JOIN permission_groups g ON g.id = i.permission_group_id
WHERE i.code_hash = sqlc.arg(code_hash) AND i.revoked_at IS NULL AND i.consumed_at IS NULL AND i.expires_at > now()
  AND (i.invited_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = i.invited_by))
  AND i.permission_group_id IS NOT DISTINCT FROM sqlc.narg(group_id)::uuid
FOR UPDATE OF i;

-- name: AccountInviteGroupByCode :one
SELECT permission_group_id::uuid AS group_id FROM account_registration_invites
WHERE code_hash = sqlc.arg(code_hash) AND permission_group_id IS NOT NULL;

-- AccountInviteByCodeForUpdate: addressed is whether user_id has verified the
-- invited address.
-- name: AccountInviteByCodeForUpdate :one
SELECT i.id, g.id AS group_id, g.persona, COALESCE(i.role, '')::text AS role, i.consumed_at, i.expires_at, i.revoked_at,
  (i.invited_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = i.invited_by))::boolean AS issuer_live,
  EXISTS(SELECT 1 FROM users u WHERE u.id = sqlc.arg(user_id)::uuid AND lower(u.email::text) = lower(i.email::text) AND u.email_verified)::boolean AS addressed
FROM account_registration_invites i JOIN permission_groups g ON g.id = i.permission_group_id AND g.deleted_at IS NULL
WHERE i.code_hash = sqlc.arg(code_hash) AND i.permission_group_id = sqlc.arg(group_id)::uuid
FOR UPDATE OF i;

-- name: AccountInviteConsume :exec
UPDATE account_registration_invites SET consumed_at = now()
WHERE id = sqlc.arg(id);
