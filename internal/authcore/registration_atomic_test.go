package authcore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestCreateEmailRegistrationUserAtomic verifies that createEmailRegistrationUser
// writes the user row, password row, and email-verified flag as a single atomic
// operation. Happy-path only — mid-tx injection is not possible with the existing
// harness, so rollback atomicity is reasoned from the code: all three writes run on
// one pgx.Tx; any write error returns before Commit and the deferred Rollback fires.
func TestCreateEmailRegistrationUserAtomic(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	username := "regemail" + suffix
	email := username + "@example.com"
	passwordHash := "testhash-" + suffix

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	userID, err := svc.createEmailRegistrationUser(ctx, email, username, passwordHash, true)
	require.NoError(t, err)
	require.NotEmpty(t, userID)

	user, err := svc.getUserByID(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, userID, user.ID)
	require.True(t, user.EmailVerified, "email_verified must be set inside the transaction")
	require.True(t, svc.hasPassword(ctx, userID), "password row must be committed inside the transaction")
}

// TestCreatePhoneRegistrationUserAtomic verifies createPhoneRegistrationUser writes
// the user row, password row, and phone-verified flag as a single atomic operation.
// Same happy-path scope and rollback reasoning as the email case.
func TestCreatePhoneRegistrationUserAtomic(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	username := "regphone" + suffix
	phone := "+15550001" + suffix[len(suffix)-4:]
	passwordHash := "testhash-phone-" + suffix

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username=$1`, username)
	})

	userID, err := svc.createPhoneRegistrationUser(ctx, phone, username, passwordHash, true)
	require.NoError(t, err)
	require.NotEmpty(t, userID)

	user, err := svc.getUserByID(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.Equal(t, userID, user.ID)
	require.True(t, user.PhoneVerified, "phone_verified must be set inside the transaction")
	require.True(t, svc.hasPassword(ctx, userID), "password row must be committed inside the transaction")
}
