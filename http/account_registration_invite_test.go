package authhttp

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func createAccountInvite(t *testing.T, srv *Service, pool *pgxpool.Pool, email string) (string, authkit.AccountRegistrationInviteCreated) {
	t.Helper()
	ctx := context.Background()
	_, err := srv.svc.EnsureRootGroup(ctx)
	require.NoError(t, err)
	inviter, err := srv.svc.CreateUser(ctx, uniqueEmail("account-inviter"), "accountinviter"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, srv.svc.AssignGroupRole(ctx, embedded.RootPersona, "", inviter.ID, embedded.SubjectKindUser, embedded.OwnerRoleName))
	invite, err := srv.svc.CreateAccountRegistrationInvite(ctx, authkit.CreateAccountRegistrationInviteRequest{
		Email:     email,
		InvitedBy: inviter.ID,
	})
	require.NoError(t, err)
	return inviter.ID, invite
}

func requireAccountInviteConsumed(t *testing.T, pool *pgxpool.Pool, inviteID, userID string) {
	t.Helper()
	var consumed bool
	require.NoError(t, pool.QueryRow(context.Background(),
		`SELECT consumed_at IS NOT NULL AND consumed_by = $2::uuid
		   FROM profiles.account_registration_invites WHERE id = $1::uuid`,
		inviteID, userID).Scan(&consumed))
	require.True(t, consumed)
}
