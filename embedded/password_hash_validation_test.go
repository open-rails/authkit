package embedded

import (
	"testing"

	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

func TestImportedPasswordHashValidation(t *testing.T) {
	svc, ctx := importTestService(t)
	username, email := uniq()
	unsafe := "$argon2id$v=19$m=4294967295,t=1,p=1$c2FsdA$aGFzaA"
	res, err := svc.ImportUsers(ctx, []ImportUserInput{
		{Username: username("invalid"), Email: email("invalid"), PasswordHash: unsafe, HashAlgo: "argon2id"},
		{Username: username("reset"), Email: email("reset"), PasswordHash: unsafe, HashAlgo: HashAlgoLegacyResetRequired},
	})
	require.NoError(t, err)
	require.Equal(t, 1, res.Rejected)
	require.Equal(t, 1, res.Inserted)
	require.Equal(t, password.ErrInvalidHash.Error(), res.Results[0].Reason)
	_, err = svc.GetUserByEmail(ctx, email("invalid"))
	require.Error(t, err, "unsafe input must not leave a passwordless account")
	uid := res.Results[1].UserID
	require.ErrorIs(t, svc.CheckUserPassword(ctx, uid, "any"), ErrPasswordResetRequired)
	good, err := password.HashArgon2id("Known-password-123")
	require.NoError(t, err)
	require.NoError(t, svc.UpsertPasswordHash(ctx, uid, good, "argon2id", nil))
	require.ErrorIs(t, svc.UpsertPasswordHash(ctx, uid, unsafe, "argon2id", nil), password.ErrInvalidHash)
	require.NoError(t, svc.CheckUserPassword(ctx, uid, "Known-password-123"))
	t.Cleanup(func() { _, _ = svc.pg.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1`, uid) })
}
