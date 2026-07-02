package authcore

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

type recoverEmailSender struct {
	email string
	token string
}

func (s *recoverEmailSender) SendVerification(context.Context, string, string, VerificationMessage) error {
	return nil
}

func (s *recoverEmailSender) SendPasswordResetLink(_ context.Context, email, _ string, token string) error {
	s.email = email
	s.token = token
	return nil
}

func (s *recoverEmailSender) SendAccountRegistrationInvite(context.Context, string, string) error {
	return nil
}

func (s *recoverEmailSender) SendLoginCode(context.Context, string, string, string) error { return nil }
func (s *recoverEmailSender) SendWelcome(context.Context, string, string) error           { return nil }

func TestAdminRecoverUserEmailReplacesLoginFactors(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	sender := &recoverEmailSender{}
	svc := NewService(Options{Issuer: "https://test", RefreshTokenDuration: time.Hour}, Keyset{}, WithPostgres(pool), WithEmailSender(sender), WithEphemeralStore(memorystore.NewKV(), EphemeralMemory))

	suffix := strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	username := "recover" + suffix
	oldEmail := username + "@old.example"
	newEmail := username + "@new.example"
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username) })

	user, err := svc.ImportUser(ctx, ImportUserInput{Email: oldEmail, Username: username, EmailVerified: true})
	require.NoError(t, err)
	require.NoError(t, svc.AdminSetPassword(ctx, user.ID, "correct horse battery staple"))
	require.NoError(t, svc.LinkProvider(ctx, user.ID, "google", "google-subject-"+suffix, nil))
	_, err = svc.Enable2FA(ctx, user.ID, "email", nil)
	require.NoError(t, err)
	_, _, _, err = svc.IssueRefreshSessionWithAuthMethods(ctx, user.ID, "test", net.ParseIP("127.0.0.1"), []string{"pwd", "otp", "mfa"})
	require.NoError(t, err)

	require.NoError(t, svc.AdminRecoverUser(ctx, user.ID, AdminRecoverUserInput{Email: newEmail}))

	recovered, err := svc.getUserByID(ctx, user.ID)
	require.NoError(t, err)
	require.NotNil(t, recovered.Email)
	require.Equal(t, newEmail, *recovered.Email)
	require.True(t, recovered.EmailVerified)
	require.Nil(t, recovered.PhoneNumber)
	require.False(t, recovered.PhoneVerified)
	require.False(t, svc.hasPassword(ctx, user.ID))
	require.Zero(t, svc.countProviderLinks(ctx, user.ID))
	_, err = svc.Get2FASettings(ctx, user.ID)
	require.ErrorIs(t, err, pgx.ErrNoRows)
	sessions, err := svc.ListUserSessions(ctx, user.ID)
	require.NoError(t, err)
	require.Empty(t, sessions)
	require.Equal(t, newEmail, sender.email)
	require.NotEmpty(t, sender.token)
}
