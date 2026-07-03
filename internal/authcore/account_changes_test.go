package authcore

import (
	"context"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

// TestConfirmContactChange_RequiresEphemeralStore locks the email and phone
// confirm paths together: pending contact changes live only in the ephemeral
// store, so with Postgres configured but NO ephemeral store both confirms must
// fail closed with ErrTokenUnverifiable rather than fall through to the loader.
// Regression for ConfirmEmailChange previously missing the useEphemeralStore
// guard that ConfirmPhoneChange already had. Skips without a test database.
func TestConfirmContactChange_RequiresEphemeralStore(t *testing.T) {
	pool := testPG(t)
	svc := NewService(Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	require.False(t, svc.useEphemeralStore())

	ctx := context.Background()
	require.ErrorIs(t, svc.ConfirmEmailChange(ctx, "some-user", "new@example.com", "123456"), jwt.ErrTokenUnverifiable)
	require.ErrorIs(t, svc.ConfirmPhoneChange(ctx, "some-user", "+14155550123", "123456"), jwt.ErrTokenUnverifiable)
}
