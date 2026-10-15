-- A non-secret, repeatable-read snapshot for explicit host maintenance.
-- No credential material or contact data belongs in the operator report.
-- name: GroupPersonaMigrationSnapshot :one
SELECT jsonb_build_object(
  'group', to_jsonb(g),
  'bindings', COALESCE((SELECT jsonb_agg(to_jsonb(b) ORDER BY b.kind,b.id) FROM (
    SELECT 'group_user_roles'::text AS kind, r.user_id::text AS id, r.role, ''::text AS creator, false AS needs_creator, true AS active, ''::text AS issuer, jsonb_build_object('tenant_id',u.tenant_id) AS meta
      FROM group_user_roles r JOIN users u ON u.id=r.user_id WHERE r.permission_group_id=g.id
    UNION ALL SELECT 'group_remote_user_roles', remote_user_id::text, role, '', false, true, '', jsonb_build_object('invitation_id',invitation_id,'created_at',created_at)
      FROM group_remote_user_roles WHERE permission_group_id=g.id
    UNION ALL SELECT 'group_remote_application_roles', r.remote_application_id::text, r.role, COALESCE(a.registered_by::text,''), a.trust_root='user', a.enabled, COALESCE(a.catalog_issuer,''), jsonb_build_object('updated_at',a.updated_at)
      FROM group_remote_application_roles r JOIN remote_applications a ON a.id=r.remote_application_id WHERE r.permission_group_id=g.id
    UNION ALL SELECT 'api_keys', id::text, role, COALESCE(created_by::text,''), false, revoked_at IS NULL AND (expires_at IS NULL OR expires_at>now()), COALESCE(catalog_issuer,''), jsonb_build_object('expires_at',expires_at,'revoked_at',revoked_at,'provisions_for',provisions_for)
      FROM api_keys WHERE permission_group_id=g.id
    UNION ALL SELECT 'group_invite_links', id::text, role, COALESCE(invited_by::text,''), false, revoked_at IS NULL AND redeemed_at IS NULL AND (expires_at IS NULL OR expires_at>now()), COALESCE(catalog_issuer,''), jsonb_build_object('tenant_id',tenant_id,'expires_at',expires_at,'revoked_at',revoked_at,'redeemed_at',redeemed_at)
      FROM group_invite_links WHERE permission_group_id=g.id
    UNION ALL SELECT 'account_registration_invites', id::text, role, COALESCE(invited_by::text,''), false, revoked_at IS NULL AND consumed_at IS NULL AND expires_at>now(), COALESCE(catalog_issuer,''), jsonb_build_object('tenant_id',tenant_id,'expires_at',expires_at,'revoked_at',revoked_at,'consumed_at',consumed_at)
      FROM account_registration_invites WHERE permission_group_id=g.id
  ) b),'[]'::jsonb),
  'custom_roles', COALESCE((SELECT jsonb_agg(to_jsonb(c) ORDER BY c.role) FROM group_custom_roles c WHERE c.permission_group_id=g.id),'[]'::jsonb),
  'remote_applications', COALESCE((SELECT jsonb_agg(jsonb_build_object('id',a.id,'role_map',a.role_map,'enabled',a.enabled,'issuer',COALESCE(a.catalog_issuer,'')) ORDER BY a.id)
    FROM remote_applications a WHERE a.permission_group_id=g.id),'[]'::jsonb),
  'oauth_clients', COALESCE((SELECT jsonb_agg(jsonb_build_object('id',c.client_id,'scopes',c.scopes,'disabled_at',c.disabled_at) ORDER BY c.client_id)
    FROM group_oauth_clients c WHERE c.permission_group_id=g.id),'[]'::jsonb),
  'oauth_consents', COALESCE((SELECT jsonb_agg(jsonb_build_object('client_id',c.client_id,'user_id',c.user_id,'scopes',c.scopes) ORDER BY c.client_id,c.user_id)
    FROM oauth_consents c JOIN group_oauth_clients o ON o.client_id=c.client_id WHERE o.permission_group_id=g.id),'[]'::jsonb)
)::jsonb AS snapshot
FROM permission_groups g WHERE g.id=sqlc.arg(group_id)::uuid;

-- name: GroupPersonaMigrationUsers :exec
UPDATE group_user_roles r SET role=m.value
FROM jsonb_each_text(sqlc.arg(roles)::jsonb) m
WHERE r.permission_group_id=sqlc.arg(group_id)::uuid AND r.role=m.key;

-- name: GroupPersonaMigrationRemoteUsers :exec
UPDATE group_remote_user_roles r SET role=m.value
FROM jsonb_each_text(sqlc.arg(roles)::jsonb) m
WHERE r.permission_group_id=sqlc.arg(group_id)::uuid AND r.role=m.key;

-- name: GroupPersonaMigrationApplications :exec
UPDATE group_remote_application_roles r SET role=m.value
FROM jsonb_each_text(sqlc.arg(roles)::jsonb) m
WHERE r.permission_group_id=sqlc.arg(group_id)::uuid AND r.role=m.key;

-- name: GroupPersonaMigrationKeys :exec
UPDATE api_keys r SET role=m.value
FROM jsonb_each_text(sqlc.arg(roles)::jsonb) m
WHERE r.permission_group_id=sqlc.arg(group_id)::uuid AND r.role=m.key;

-- name: GroupPersonaMigrationLinks :exec
UPDATE group_invite_links r SET role=m.value
FROM jsonb_each_text(sqlc.arg(roles)::jsonb) m
WHERE r.permission_group_id=sqlc.arg(group_id)::uuid AND r.role=m.key;

-- name: GroupPersonaMigrationInvites :exec
UPDATE account_registration_invites r SET role=m.value
FROM jsonb_each_text(sqlc.arg(roles)::jsonb) m
WHERE r.permission_group_id=sqlc.arg(group_id)::uuid AND r.role=m.key;

-- name: GroupPersonaMigrationRoleMaps :exec
UPDATE remote_applications a SET role_map=(
  SELECT COALESCE(jsonb_object_agg(r.key, COALESCE(sqlc.arg(roles)::jsonb->>r.value,r.value)),'{}'::jsonb)
  FROM jsonb_each_text(a.role_map) r), updated_at=now()
WHERE a.permission_group_id=sqlc.arg(group_id)::uuid AND a.role_map IS NOT NULL;

-- name: GroupPersonaMigrationCustomRole :exec
UPDATE group_custom_roles SET role=sqlc.arg(new_role), permissions=sqlc.arg(permissions)::text[], updated_at=now()
WHERE permission_group_id=sqlc.arg(group_id)::uuid AND role=sqlc.arg(old_role);

-- name: GroupPersonaMigrationInsertCustomRole :exec
INSERT INTO group_custom_roles(permission_group_id,role,permissions)
VALUES(sqlc.arg(group_id)::uuid,sqlc.arg(role),sqlc.arg(permissions)::text[]);

-- The caller holds the authority/table locks and has temporarily disabled only
-- permission_group_identity_immutable. All other identity guards stay active.
-- name: GroupPersonaMigrationSetPersona :execrows
UPDATE permission_groups SET persona=sqlc.arg(to_persona)
WHERE id=sqlc.arg(group_id)::uuid AND persona=sqlc.arg(from_persona) AND deleted_at IS NULL;
