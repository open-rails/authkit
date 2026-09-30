-- Permission groups and their role assignments. A group read selects the whole
-- row, so every group read returns db.PermissionGroup. Role tables are one per
-- subject kind, so every assignment statement has a user and an application
-- variant.

-- name: PermissionGroupInsert :one
INSERT INTO permission_groups (persona) VALUES (sqlc.arg(persona)) RETURNING id;

-- name: PermissionGroupInsertWithID :exec
INSERT INTO permission_groups (id, persona) VALUES (sqlc.arg(id)::uuid, sqlc.arg(persona));

-- name: PermissionGroupsByIDs :many
SELECT * FROM permission_groups WHERE id = ANY(sqlc.arg(ids)::uuid[]);

-- name: PermissionGroupRootID :one
SELECT id FROM permission_groups WHERE persona = 'root';

-- PermissionGroupLiveForUpdate is the shared lifecycle lock of a live group.
-- name: PermissionGroupLiveForUpdate :one
SELECT * FROM permission_groups WHERE id = sqlc.arg(id) AND deleted_at IS NULL FOR UPDATE;

-- name: PermissionGroupForUpdate :one
SELECT * FROM permission_groups WHERE id = sqlc.arg(id) FOR UPDATE;

-- name: PermissionGroupSoftDelete :exec
UPDATE permission_groups SET deleted_at = sqlc.arg(deleted_at)::timestamptz WHERE id = sqlc.arg(id);

-- name: PermissionGroupDelete :exec
DELETE FROM permission_groups WHERE id = sqlc.arg(id);

-- PermissionGroupsPage lists non-root groups oldest first. ownerless keeps
-- live groups no owner counts for under the last-owner rule: a usable user
-- (MFA-enrolled in an mfa_personas group), or, where owners need no MFA, an
-- enabled application of the group itself whose registrar is usable.
-- name: PermissionGroupsPage :many
SELECT g.* FROM permission_groups g
WHERE g.persona <> 'root' AND (sqlc.arg(persona)::text = '' OR g.persona = sqlc.arg(persona)::text)
  AND ((sqlc.arg(include_deleted)::boolean AND NOT sqlc.arg(ownerless)::boolean) OR g.deleted_at IS NULL)
  AND (sqlc.arg(after)::text = '' OR g.id > sqlc.arg(after)::text::uuid)
  AND (NOT sqlc.arg(ownerless)::boolean OR NOT EXISTS(
    SELECT 1 FROM group_user_roles r JOIN usable_users u ON u.id = r.user_id
     WHERE r.permission_group_id = g.id AND r.role LIKE '%:owner'
       AND (NOT (g.persona = ANY(sqlc.arg(mfa_personas)::text[])) OR EXISTS(SELECT 1 FROM mfa_settings m WHERE m.user_id = u.id AND m.enabled
         AND EXISTS(SELECT 1 FROM mfa_factors f WHERE f.user_id = u.id)))
    UNION ALL
    SELECT 1 FROM group_remote_application_roles r JOIN remote_applications a ON a.id = r.remote_application_id
     WHERE NOT (g.persona = ANY(sqlc.arg(mfa_personas)::text[])) AND r.permission_group_id = g.id AND r.role LIKE '%:owner'
       AND a.enabled AND a.permission_group_id = r.permission_group_id
       AND (a.trust_root <> 'user' OR EXISTS(SELECT 1 FROM usable_users WHERE id = a.registered_by))
       AND EXISTS(SELECT 1 FROM permission_groups control WHERE control.id = a.permission_group_id AND control.deleted_at IS NULL)))
ORDER BY g.id
LIMIT sqlc.arg(page_limit)::bigint;

-- GroupMembersPage lists the subjects holding a role in a group, by kind then
-- id. live: a usable user, or an enabled application with a live control group.
-- name: GroupMembersPage :many
SELECT m.kind, m.id, m.role FROM (
  SELECT 'user'::text AS kind, r.user_id::text AS id, r.role, EXISTS(SELECT 1 FROM usable_users u WHERE u.id = r.user_id) AS live
    FROM group_user_roles r WHERE r.permission_group_id = sqlc.arg(group_id)::uuid
  UNION ALL
  SELECT 'remote_application'::text, r.remote_application_id::text, r.role, (a.enabled AND c.deleted_at IS NULL)
    FROM group_remote_application_roles r JOIN remote_applications a ON a.id = r.remote_application_id
    JOIN permission_groups c ON c.id = a.permission_group_id WHERE r.permission_group_id = sqlc.arg(group_id)::uuid) m
WHERE (cardinality(sqlc.arg(kinds)::text[]) = 0 OR m.kind = ANY(sqlc.arg(kinds)::text[]))
  AND (cardinality(sqlc.arg(roles)::text[]) = 0 OR m.role = ANY(sqlc.arg(roles)::text[]))
  AND (sqlc.arg(after_kind)::text = '' OR (m.kind, m.id) > (sqlc.arg(after_kind)::text, sqlc.arg(after_id)::text))
  AND (NOT sqlc.arg(live_only)::boolean OR m.live)
ORDER BY m.kind, m.id
LIMIT sqlc.arg(page_limit)::bigint;

-- GroupsOfUserPage and GroupsOfApplicationPage list the live groups a subject
-- holds a role in, by persona then id.
-- name: GroupsOfUserPage :many
SELECT sqlc.embed(g), a.role
FROM group_user_roles a JOIN permission_groups g ON g.id = a.permission_group_id
WHERE a.user_id = sqlc.arg(subject_id) AND g.deleted_at IS NULL
  AND (sqlc.arg(after_persona)::text = '' OR (g.persona, g.id) > (sqlc.arg(after_persona)::text, NULLIF(sqlc.arg(after_id)::text, '')::uuid))
ORDER BY g.persona, g.id
LIMIT sqlc.arg(page_limit)::bigint;

-- name: GroupsOfApplicationPage :many
SELECT sqlc.embed(g), a.role
FROM group_remote_application_roles a JOIN permission_groups g ON g.id = a.permission_group_id
WHERE a.remote_application_id = sqlc.arg(subject_id) AND g.deleted_at IS NULL
  AND (sqlc.arg(after_persona)::text = '' OR (g.persona, g.id) > (sqlc.arg(after_persona)::text, NULLIF(sqlc.arg(after_id)::text, '')::uuid))
ORDER BY g.persona, g.id
LIMIT sqlc.arg(page_limit)::bigint;

-- GroupUserAssignmentsForGroups and GroupApplicationAssignmentsForGroups read,
-- for every live target group, the subject's assignments on it and on root.
-- An application's assignments count only while it is enabled and its control
-- group is live.
-- name: GroupUserAssignmentsForGroups :many
WITH targets AS (
  SELECT id, persona FROM permission_groups WHERE id = ANY(sqlc.arg(group_ids)::uuid[]) AND deleted_at IS NULL),
chain AS (
  SELECT id AS target, id, persona FROM targets
  UNION SELECT t.id, rg.id, rg.persona FROM targets t JOIN permission_groups rg ON rg.persona = 'root')
SELECT c.target::text AS target, c.id::text AS group_id, c.persona::text AS persona, a.role
FROM chain c JOIN group_user_roles a ON a.permission_group_id = c.id AND a.user_id = sqlc.arg(subject_id)::uuid
ORDER BY c.target, c.id;

-- name: GroupApplicationAssignmentsForGroups :many
WITH targets AS (
  SELECT id, persona FROM permission_groups WHERE id = ANY(sqlc.arg(group_ids)::uuid[]) AND deleted_at IS NULL),
chain AS (
  SELECT id AS target, id, persona FROM targets
  UNION SELECT t.id, rg.id, rg.persona FROM targets t JOIN permission_groups rg ON rg.persona = 'root')
SELECT c.target::text AS target, c.id::text AS group_id, c.persona::text AS persona, a.role
FROM chain c JOIN group_remote_application_roles a ON a.permission_group_id = c.id AND a.remote_application_id = sqlc.arg(subject_id)::uuid
WHERE EXISTS(SELECT 1 FROM remote_applications actor JOIN permission_groups control ON control.id = actor.permission_group_id
  WHERE actor.id = sqlc.arg(subject_id)::uuid AND actor.enabled AND control.deleted_at IS NULL)
ORDER BY c.target, c.id;

-- name: GroupRolesForSubjects :many
SELECT 'user'::text AS kind, user_id::text AS subject_id, role FROM group_user_roles
WHERE permission_group_id = sqlc.arg(group_id)::uuid AND user_id = ANY(sqlc.arg(user_ids)::uuid[])
UNION ALL
SELECT 'remote_application'::text, remote_application_id::text, role FROM group_remote_application_roles
WHERE permission_group_id = sqlc.arg(group_id)::uuid AND remote_application_id = ANY(sqlc.arg(application_ids)::uuid[]);

-- name: GroupUserRolesForUsers :many
SELECT user_id, role FROM group_user_roles
WHERE permission_group_id = sqlc.arg(group_id) AND user_id = ANY(sqlc.arg(user_ids)::uuid[]);

-- name: GroupUserHasRole :one
SELECT EXISTS(SELECT 1 FROM group_user_roles
  WHERE permission_group_id = sqlc.arg(group_id)::uuid AND user_id = sqlc.arg(user_id)::uuid AND role = sqlc.arg(role)::text)::boolean;

-- name: GroupUserRoleUpsert :exec
INSERT INTO group_user_roles (permission_group_id, user_id, role) VALUES (sqlc.arg(group_id), sqlc.arg(user_id), sqlc.arg(role))
ON CONFLICT (permission_group_id, user_id) DO UPDATE SET role = EXCLUDED.role;

-- name: GroupApplicationRoleUpsert :exec
INSERT INTO group_remote_application_roles (permission_group_id, remote_application_id, role) VALUES (sqlc.arg(group_id), sqlc.arg(application_id), sqlc.arg(role))
ON CONFLICT (permission_group_id, remote_application_id) DO UPDATE SET role = EXCLUDED.role;

-- GroupUserRoleDelete and GroupApplicationRoleDelete delete the subject's
-- assignment in a group; role, when set, must match.
-- name: GroupUserRoleDelete :one
DELETE FROM group_user_roles r USING permission_groups g
WHERE g.id = r.permission_group_id AND r.permission_group_id = sqlc.arg(group_id)::uuid AND r.user_id = sqlc.arg(user_id)::uuid
  AND (sqlc.narg(role)::text IS NULL OR r.role = sqlc.narg(role)::text)
RETURNING g.persona, r.role;

-- name: GroupApplicationRoleDelete :one
DELETE FROM group_remote_application_roles r USING permission_groups g
WHERE g.id = r.permission_group_id AND r.permission_group_id = sqlc.arg(group_id)::uuid AND r.remote_application_id = sqlc.arg(application_id)::uuid
  AND (sqlc.narg(role)::text IS NULL OR r.role = sqlc.narg(role)::text)
RETURNING g.persona, r.role;

-- PermissionGroupOwnerCount counts usable user owners and enabled application
-- owners of the group itself.
-- name: PermissionGroupOwnerCount :one
SELECT ((SELECT count(*) FROM group_user_roles r JOIN usable_users u ON u.id = r.user_id
          WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role LIKE '%:owner')
      + (SELECT count(*) FROM group_remote_application_roles r JOIN remote_applications a ON a.id = r.remote_application_id
          WHERE r.permission_group_id = sqlc.arg(group_id)::uuid AND r.role LIKE '%:owner' AND a.enabled AND a.permission_group_id = r.permission_group_id))::bigint;

-- name: GroupUserRoleCounts :many
SELECT pg.persona, r.role, count(*)::bigint AS n
FROM group_user_roles r JOIN permission_groups pg ON pg.id = r.permission_group_id
GROUP BY pg.persona, r.role;

-- name: UserExists :one
SELECT EXISTS(SELECT 1 FROM users WHERE id = sqlc.arg(id)::uuid)::boolean;

-- name: RemoteApplicationEnabledInGroup :one
SELECT EXISTS(SELECT 1 FROM remote_applications WHERE id = sqlc.arg(id)::uuid AND enabled AND permission_group_id = sqlc.arg(group_id)::uuid)::boolean;
