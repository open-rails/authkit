package verify

import (
	"context"
	"crypto"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/rootsnapshot"
	"github.com/stretchr/testify/require"
)

func TestVerifiedRootPermissionSnapshot(t *testing.T) {
	v, signer := confirmationVerifier(t)
	require.NoError(t, v.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{IsLocal: true, RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	snapshot, err := rootsnapshot.New(confirmationIssuer, uuid.NewString(), []string{"root:posts:*"})
	require.NoError(t, err)
	claims := jwt.MapClaims{"iss": confirmationIssuer, "sub": uuid.NewString(), "aud": []string{"resource"}, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), rootsnapshot.Claim: snapshot}
	verifyToken := func() (Claims, error) {
		return v.Verify(context.Background(), signTyped(t, signer, AccessTokenType, claims))
	}
	verified, err := verifyToken()
	require.NoError(t, err)
	check := func(cl Claims, perm authkit.Perm, wantAllowed, wantComplete bool) {
		t.Helper()
		allowed, complete := cl.RootPermissionSnapshot(perm)
		require.Equal(t, wantAllowed, allowed)
		require.Equal(t, wantComplete, complete)
	}
	check(verified, "root:posts:delete", true, true)
	check(verified, "root:users:delete", false, true)
	check(verified, "project:posts:delete", false, false)
	check(verified, "root:*", false, false)
	check(Claims{UserID: verified.UserID, Issuer: confirmationIssuer, TokenTyp: AccessTokenType, Permissions: []string{"root:*"}}, "root:posts:delete", false, false)
	changed := verified
	changed.UserID = uuid.NewString()
	check(changed, "root:posts:delete", false, false)
	changed = verified
	changed.Issuer = "https://foreign.test"
	check(changed, "root:posts:delete", false, false)
	changed = verified
	changed.TokenType = APIKeyPrincipalType
	check(changed, "root:posts:delete", false, false)
	claims[rootsnapshot.Claim] = map[string]any{"v": 2}
	unknown, err := verifyToken()
	require.NoError(t, err)
	check(unknown, "root:posts:delete", false, false)
	delete(claims, rootsnapshot.Claim)
	absent, err := verifyToken()
	require.NoError(t, err)
	check(absent, "root:posts:delete", false, false)
	claims[rootsnapshot.Claim] = snapshot
	claims["2fa_enrollment"] = true
	enrollment, err := verifyToken()
	require.NoError(t, err)
	check(enrollment, "root:posts:delete", false, false)
	delete(claims, "2fa_enrollment")
	foreign := NewVerifier()
	require.NoError(t, foreign.AddIssuer(confirmationIssuer, []string{"resource"}, IssuerOptions{RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}))
	external, err := foreign.Verify(context.Background(), signTyped(t, signer, AccessTokenType, claims))
	require.NoError(t, err)
	check(external, "root:posts:delete", false, false)
	delete(claims, "sub")
	claims["delegated_sub"] = uuid.NewString()
	delegated, err := v.Verify(context.Background(), signTyped(t, signer, DelegatedAccessTokenType, claims))
	require.NoError(t, err)
	check(delegated, "root:posts:delete", false, false)
	delete(claims, "delegated_sub")
	claims["sub"] = uuid.NewString()
	bad := *snapshot
	bad.Issuer = "https://foreign.test"
	claims[rootsnapshot.Claim] = &bad
	_, err = verifyToken()
	require.ErrorIs(t, err, rootsnapshot.ErrInvalid)
}
