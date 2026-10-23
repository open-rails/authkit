-- Current creator and role of a presented delegated credential. The issuer
-- owns its role catalog: another application's catalog cannot judge it.
-- name: CredentialAuthority :one
WITH credential AS (
 SELECT l.permission_group_id AS group_id, l.role, coalesce(l.invited_by::text,'')::text AS creator,
        false AS needs_creator, l.catalog_issuer
 FROM group_invite_links l WHERE sqlc.arg(kind)::text='group_invite_links' AND l.id=sqlc.arg(id)::uuid
 UNION ALL
 SELECT coalesce(i.permission_group_id, (SELECT id FROM permission_groups WHERE persona='root')), coalesce(i.role,''),
        coalesce(i.invited_by::text,''), false, i.catalog_issuer
 FROM account_registration_invites i WHERE sqlc.arg(kind)::text='account_registration_invites' AND i.id=sqlc.arg(id)::uuid
 UNION ALL
 SELECT r.permission_group_id, r.role, coalesce(a.registered_by::text,''), a.trust_root='user', a.catalog_issuer
 FROM group_remote_application_roles r JOIN remote_applications a ON a.id=r.remote_application_id
 WHERE sqlc.arg(kind)::text='group_remote_application_roles' AND a.id=sqlc.arg(id)::uuid AND a.enabled
)
SELECT c.group_id::text AS group_id, g.persona, g.tenant_id, c.role, c.creator, c.needs_creator
FROM credential c JOIN permission_groups g ON g.id=c.group_id AND g.deleted_at IS NULL
WHERE (c.catalog_issuer IS NULL OR c.catalog_issuer=sqlc.arg(issuer)::text)
 AND (sqlc.arg(group_id)::text='' OR c.group_id=nullif(sqlc.arg(group_id)::text,'')::uuid);

-- name: AccountInviteLiveID :one
SELECT id FROM account_registration_invites
WHERE tenant_id=nullif(sqlc.arg(tenant_id)::text,'')::uuid AND code_hash=sqlc.arg(code_hash)
 AND revoked_at IS NULL AND consumed_at IS NULL AND expires_at>now();
