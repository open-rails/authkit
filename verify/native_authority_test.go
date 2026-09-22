package verify

import (
	"context"
	"crypto"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestNativeUserTokenCannotSupplyRoleOrPermissionAuthority(t *testing.T) {
	v, signer := confirmationVerifier(t)
	require.NoError(t, v.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	raw := jwt.MapClaims{"iss": confirmationIssuer, "sub": "native-user", "aud": []string{"resource"}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "roles": []string{"owner"}, "permissions": []string{"root:*"}, "groups": []string{"root"}, "root_permissions": map[string]any{"v": 1, "grants": []string{"root:*"}}}
	claims, err := v.Verify(context.Background(), signTyped(t, signer, AccessTokenType, raw))
	require.NoError(t, err)
	require.Equal(t, "native-user", claims.UserID)
	require.Empty(t, claims.Roles)
	require.Empty(t, claims.Permissions)
	require.False(t, claims.HasPermission("root:users:ban"))
}
