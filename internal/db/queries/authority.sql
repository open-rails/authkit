-- Authority: the lock and transaction settings of authority mutations, group
-- and actor resolution, ownership invariants and the credential sweep. A
-- usable account is a row of usable_users; an application's registrar counts
-- only while usable.

-- name: TransactionSettings :one
SELECT current_setting('transaction_isolation')::text AS isolation, current_setting('search_path')::text AS search_path;

-- name: PermissionGroupEnsureRoot :one
-- DO NOTHING keeps a concurrent singleton insert from aborting the caller's
-- transaction; no row means another transaction created root.
INSERT INTO permission_groups (persona) VALUES ('root') ON CONFLICT DO NOTHING RETURNING id;

-- name: AuthorityGroup :one
SELECT * FROM permission_groups WHERE id = $1 AND deleted_at IS NULL;

-- name: AuthorityGroupState :one
SELECT * FROM permission_groups WHERE id = $1;

-- name: AuthorityUserGroups :many
-- The live groups other than root where the user holds a role.
SELECT g.* FROM group_user_roles r JOIN permission_groups g ON g.id = r.permission_group_id
WHERE r.user_id = sqlc.arg(user_id) AND g.id <> sqlc.arg(root_id) AND g.deleted_at IS NULL
ORDER BY g.id;

-- name: AuthorityApplicationGroup :one
-- The controlling group of an enabled application in a live group whose
-- registrar is usable.
SELECT a.permission_group_id FROM remote_applications a JOIN permission_groups g ON g.id = a.permission_group_id
WHERE a.id = $1 AND a.enabled AND g.deleted_at IS NULL
  AND (a.trust_root <> 'user' OR EXISTS(SELECT 1 FROM usable_users WHERE id = a.registered_by));

-- name: AuthorityAPIKeyRole :one
-- The group and role of a live key in a live group whose creator is the
-- system (NULL) or usable.
SELECT k.permission_group_id, k.role FROM api_keys k JOIN permission_groups g ON g.id = k.permission_group_id
WHERE k.id = $1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now()) AND g.deleted_at IS NULL
  AND (k.created_by IS NULL OR EXISTS(SELECT 1 FROM usable_users WHERE id = k.created_by));

-- name: UserUsable :one
SELECT EXISTS(SELECT 1 FROM usable_users WHERE id = sqlc.arg(id)::uuid)::boolean AS usable;

-- name: RemoteApplicationUsable :one
SELECT EXISTS(
  SELECT 1 FROM remote_applications a JOIN permission_groups g ON g.id = a.permission_group_id
  WHERE a.id = sqlc.arg(id)::uuid AND a.enabled AND g.deleted_at IS NULL
    AND (a.trust_root <> 'user' OR EXISTS(SELECT 1 FROM usable_users WHERE id = a.registered_by))
)::boolean AS usable;

-- name: GroupUserRoleName :one
SELECT role FROM group_user_roles WHERE permission_group_id = sqlc.arg(group_id) AND user_id = sqlc.arg(user_id);

-- name: GroupApplicationRoleName :one
SELECT role FROM group_remote_application_roles WHERE permission_group_id = sqlc.arg(group_id) AND remote_application_id = sqlc.arg(application_id);

-- name: GroupsOwnedByApplication :many
SELECT permission_group_id FROM group_remote_application_roles WHERE remote_application_id = $1 AND role LIKE '%:owner' ORDER BY permission_group_id;

-- name: AuthorityApplicationOwnsGroup :one
-- Whether group_id controls the application, and the group's persona.
SELECT (a.permission_group_id = sqlc.arg(group_id)::uuid)::boolean AS controls, g.persona
FROM remote_applications a JOIN permission_groups g ON g.id = sqlc.arg(group_id)::uuid
WHERE a.id = sqlc.arg(application_id)::uuid;

-- name: GroupHasOtherUsableOwner :one
-- Whether the group has an owner that counts, other than the subject
-- (excluding_kind, excluding_id): a usable user, MFA-enrolled when needs_mfa,
-- or, when owners need no MFA, an enabled application of the group itself
-- whose registrar is usable. An application a departing user registered
-- never stands in for that user: its authority ends with theirs (R1).
SELECT EXISTS(
  SELECT 1 FROM group_user_roles r JOIN usable_users u ON u.id = r.user_id
  WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role LIKE '%:owner'
    AND NOT (sqlc.arg(excluding_kind)::text = 'user' AND u.id = sqlc.narg(excluding_id)::uuid)
    AND (NOT sqlc.arg(needs_mfa)::boolean OR EXISTS(SELECT 1 FROM mfa_settings m WHERE m.user_id = u.id AND m.enabled
      AND EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id)))
  UNION ALL
  SELECT 1 FROM group_remote_application_roles r JOIN remote_applications a ON a.id = r.remote_application_id
  WHERE NOT sqlc.arg(needs_mfa)::boolean AND r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role LIKE '%:owner'
    AND NOT (sqlc.arg(excluding_kind)::text = 'remote_application' AND a.id = sqlc.narg(excluding_id)::uuid)
    AND NOT (sqlc.arg(excluding_kind)::text = 'user' AND a.registered_by IS NOT DISTINCT FROM sqlc.narg(excluding_id)::uuid)
    AND a.enabled AND a.permission_group_id = r.permission_group_id
    AND (a.trust_root <> 'user' OR EXISTS(SELECT 1 FROM usable_users WHERE id = a.registered_by))
    AND EXISTS(SELECT 1 FROM permission_groups control WHERE control.id = a.permission_group_id AND control.deleted_at IS NULL)
)::boolean AS remains;

-- name: AuthorityOutsideApplicationOwnerGroups :many
-- The other groups owned by enabled applications that group_id controls.
SELECT DISTINCT r.permission_group_id FROM group_remote_application_roles r
JOIN remote_applications a ON a.id = r.remote_application_id
WHERE a.permission_group_id = sqlc.arg(group_id)::uuid AND a.enabled AND r.role LIKE '%:owner'
  AND r.permission_group_id <> sqlc.arg(group_id)::uuid;

-- name: AuthorityUncoveredCredentials :many
-- Live credentials in the scope of a grant change to group_id (root: every
-- live group) issued by user_id ('' = anyone): invite links, account
-- invitations (one without a group belongs to root), API keys and the roles
-- of applications (needs_creator: a group registration, which confers nothing
-- without its registrar).
WITH scope AS (
  SELECT g.id, g.persona FROM permission_groups t JOIN permission_groups g
    ON g.id = t.id OR (t.persona = 'root' AND g.deleted_at IS NULL)
  WHERE t.id = sqlc.arg(group_id)::uuid)
SELECT 'group_invite_links'::text AS kind, l.id::text AS id, l.permission_group_id::text AS group_id, t.persona, l.role,
       COALESCE(l.invited_by::text, '')::text AS creator, false AS needs_creator
  FROM group_invite_links l JOIN scope t ON t.id = l.permission_group_id
 WHERE l.revoked_at IS NULL AND l.redeemed_at IS NULL AND (l.expires_at IS NULL OR l.expires_at > now())
   AND l.invited_by IS NOT NULL AND (sqlc.arg(user_id)::text = '' OR l.invited_by = NULLIF(sqlc.arg(user_id)::text, '')::uuid)
UNION ALL
SELECT 'account_registration_invites', a.id::text, a.permission_group_id::text, t.persona, a.role, a.invited_by::text, false
  FROM account_registration_invites a JOIN scope t ON t.id = a.permission_group_id
 WHERE a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at > now()
   AND a.invited_by IS NOT NULL AND (sqlc.arg(user_id)::text = '' OR a.invited_by = NULLIF(sqlc.arg(user_id)::text, '')::uuid)
UNION ALL
SELECT 'account_registration_invites', a.id::text, t.id::text, t.persona, '', a.invited_by::text, false
  FROM account_registration_invites a JOIN scope t ON t.persona = 'root'
 WHERE a.permission_group_id IS NULL AND a.revoked_at IS NULL AND a.consumed_at IS NULL AND a.expires_at > now()
   AND a.invited_by IS NOT NULL AND (sqlc.arg(user_id)::text = '' OR a.invited_by = NULLIF(sqlc.arg(user_id)::text, '')::uuid)
UNION ALL
SELECT 'api_keys', k.id::text, k.permission_group_id::text, t.persona, k.role, COALESCE(k.created_by::text, ''), false
  FROM api_keys k JOIN scope t ON t.id = k.permission_group_id
 WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > now())
   AND (sqlc.arg(user_id)::text = '' OR k.created_by = NULLIF(sqlc.arg(user_id)::text, '')::uuid)
UNION ALL
SELECT 'group_remote_application_roles', a.id::text, r.permission_group_id::text, t.persona, r.role, COALESCE(a.registered_by::text, ''), a.trust_root = 'user'
  FROM group_remote_application_roles r JOIN scope t ON t.id = r.permission_group_id
  JOIN remote_applications a ON a.id = r.remote_application_id
 WHERE (sqlc.arg(user_id)::text = '' OR a.registered_by = NULLIF(sqlc.arg(user_id)::text, '')::uuid);

-- name: APIKeyRetire :exec
UPDATE api_keys SET revoked_at = now() WHERE id = $1;

-- name: InviteLinkRetire :exec
UPDATE group_invite_links SET revoked_at = now(), updated_at = now() WHERE id = $1;

-- name: AccountInviteRetire :exec
UPDATE account_registration_invites SET revoked_at = now(), updated_at = now() WHERE id = $1;
