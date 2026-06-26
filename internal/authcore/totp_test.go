package authcore

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestTOTPCodeMatching(t *testing.T) {
	secret, err := generateTOTPSecret()
	require.NoError(t, err)

	now := time.Unix(1234567890, 0)
	step := now.Unix() / totpPeriod
	code, err := totpCode(secret, step)
	require.NoError(t, err)

	gotStep, ok, err := matchingTOTPStep(secret, code, now)
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, step, gotStep)

	_, ok, err = matchingTOTPStep(secret, "00000x", now)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestTOTPEnrollmentVerifyAndReplay(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(
		Options{
			Issuer:        "https://test",
			TOTPSecretKey: []byte("0123456789abcdef"),
		},
		Keyset{},
		WithPostgres(pool),
		WithEphemeralStore(memorystore.NewKV(), EphemeralMemory),
	)

	username := fmt.Sprintf("totp%d", time.Now().UnixNano())
	email := username + "@test.example"
	user, err := svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, user.ID) })

	secret, uri, err := svc.StartTOTPEnrollment(ctx, user.ID)
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	require.Contains(t, uri, "otpauth://totp/")

	code, err := totpCode(secret, time.Now().Unix()/totpPeriod)
	require.NoError(t, err)
	backupCodes, err := svc.EnableTOTP2FA(ctx, user.ID, code, false)
	require.NoError(t, err)
	require.Len(t, backupCodes, 10)

	settings, err := svc.Get2FASettings(ctx, user.ID)
	require.NoError(t, err)
	require.True(t, settings.Enabled)
	require.Equal(t, "totp", settings.Method)
	require.NotEmpty(t, settings.TOTPSecret)
	require.NotContains(t, string(settings.TOTPSecret), secret)

	destination, err := svc.Require2FAForLogin(ctx, user.ID)
	require.NoError(t, err)
	require.Equal(t, "authenticator app", destination)

	ok, err := svc.Verify2FACode(ctx, user.ID, code)
	require.NoError(t, err)
	require.False(t, ok)

	loginCode, err := totpCode(secret, time.Now().Unix()/totpPeriod+1)
	require.NoError(t, err)
	ok, err = svc.Verify2FACode(ctx, user.ID, loginCode)
	require.NoError(t, err)
	require.True(t, ok)

	ok, err = svc.Verify2FACode(ctx, user.ID, loginCode)
	require.NoError(t, err)
	require.False(t, ok)

	stored := fmt.Sprintf("%x", settings.TOTPSecret)
	require.False(t, strings.Contains(stored, strings.ToLower(secret)))
}
