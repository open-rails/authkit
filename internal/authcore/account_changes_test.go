package authcore

import (
	"context"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// TestConfirmContactChange_RequiresEphemeralStore locks the email and phone
// confirm paths together: pending contact changes live only in the ephemeral
// store, so with Postgres configured but NO ephemeral store both confirms must
// fail closed rather than fall through to the loader. Since ak#324 a missing
// store is a BACKEND failure (the HTTP layer answers 500 and counts no guess),
// not a wrong code, so the error is deliberately not ErrTokenUnverifiable.
// Skips without a test database.
func TestConfirmContactChange_RequiresEphemeralStore(t *testing.T) {
	pool := testdb.Pool(t)
	svc := mustNewService(t, Config{Token: TokenConfig{Issuer: "https://test"}}, Keyset{}, WithPostgres(pool))
	require.False(t, svc.useEphemeralStore())

	ctx := context.Background()
	for _, err := range []error{
		svc.ConfirmEmailChange(ctx, "some-user", "new@example.com", "123456", nil),
		svc.ConfirmPhoneChange(ctx, "some-user", "+14155550123", "123456", nil),
	} {
		require.Error(t, err)
		require.NotErrorIs(t, err, jwt.ErrTokenUnverifiable, "a missing store is a backend failure, not a bad guess")
	}
}
