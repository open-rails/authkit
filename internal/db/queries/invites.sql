-- Group invite links and account registration invites.

-- name: InviteLinksRevokeInvitedBy :exec
UPDATE group_invite_links SET revoked_at = now(), updated_at = now()
WHERE invited_by = sqlc.arg(user_id)::uuid AND revoked_at IS NULL AND redeemed_at IS NULL;

-- name: AccountInvitesRevokeInvitedBy :exec
UPDATE account_registration_invites SET revoked_at = now(), updated_at = now()
WHERE invited_by = sqlc.arg(user_id)::uuid AND revoked_at IS NULL AND consumed_at IS NULL;
