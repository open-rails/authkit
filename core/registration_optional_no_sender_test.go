package core

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestOptionalVerificationNoSender_CreatesVerifiedUser locks in the graceful
// no-sender degradation under RegistrationVerificationOptional that the
// first-party embedder convention relies on (issue #67): with no email sender
// configured, registration creates the user immediately as VERIFIED, returns
// no pending-verification code, and sends nothing.
func TestOptionalVerificationNoSender_CreatesVerifiedUser(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Options{
		Issuer:                   "https://test",
		RegistrationVerification: RegistrationVerificationOptional,
		// No email/SMS sender configured on purpose.
	}, Keyset{}).WithPostgres(pool)
	ctx := context.Background()

	email := "optional-no-sender@example.com"
	username := "optional_no_sender"
	_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE email=$1 OR username=$2`, email, username)

	code, err := svc.CreatePendingRegistration(ctx, email, username, "x-password-hash", 0)
	require.NoError(t, err)
	require.Empty(t, code, "no verification code should be issued when no sender is configured")

	u, err := svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.NotNil(t, u)
	require.True(t, u.EmailVerified, "user must be created verified under Optional with no sender")
}
