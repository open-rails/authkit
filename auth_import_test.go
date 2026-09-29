package authkit_test

import (
	"testing"
	"time"

	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestImportUserProfileFields: imported rows carry their last sign-in,
// language and avatar; a merge fills what the account lacks and keeps the
// later last sign-in.
func TestImportUserProfileFields(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	op := iam.OperatorActor()
	lastLogin := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	res, err := auth.ImportUsers(ctx, op, []iam.ImportUser{
		{Email: "profile@example.test", Username: "profile", LastLogin: &lastLogin, PreferredLanguage: " FR ", AvatarURL: "https://cdn.example.test/p.png"},
		{Email: "badlang@example.test", Username: "badlang", PreferredLanguage: "not a language"},
		{Email: "badavatar@example.test", Username: "badavatar", AvatarURL: "https://cdn.example.test/\n.png"},
	}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.ImportInserted, res.Rows[0].Status)
	require.Equal(t, iam.ImportRow{Index: 1, Status: iam.ImportRejected, Reason: "invalid_preferred_language"}, res.Rows[1])
	require.Equal(t, iam.ImportRow{Index: 2, Status: iam.ImportRejected, Reason: "avatar_url_invalid"}, res.Rows[2])
	u, err := auth.User(ctx, iam.UserByID(res.Rows[0].UserID))
	require.NoError(t, err)
	require.Equal(t, "fr", u.PreferredLanguage)
	require.Equal(t, "https://cdn.example.test/p.png", u.AvatarURL)
	require.True(t, lastLogin.Equal(*u.LastLogin))

	bare, err := auth.CreateUser(ctx, op, iam.NewUser{Email: "bare@example.test", Username: "bare"})
	require.NoError(t, err)
	earlier, later := lastLogin.Add(-time.Hour), lastLogin.Add(time.Hour)
	merged, err := auth.ImportUsers(ctx, op, []iam.ImportUser{
		{ID: u.ID, Username: "profile", LastLogin: &earlier, PreferredLanguage: "de", AvatarURL: "https://cdn.example.test/other.png"},
		{ID: bare.ID, Username: "bare", LastLogin: &later, PreferredLanguage: "de", AvatarURL: "https://cdn.example.test/bare.png"},
	}, iam.ImportOptions{OnConflict: iam.ImportMerge})
	require.NoError(t, err)
	require.Equal(t, 2, merged.Merged)
	kept, err := auth.User(ctx, iam.UserByID(u.ID))
	require.NoError(t, err)
	require.Equal(t, "fr", kept.PreferredLanguage)
	require.Equal(t, "https://cdn.example.test/p.png", kept.AvatarURL)
	require.True(t, lastLogin.Equal(*kept.LastLogin), "a merge moved the last sign-in back")
	filled, err := auth.User(ctx, iam.UserByID(bare.ID))
	require.NoError(t, err)
	require.Equal(t, "de", filled.PreferredLanguage)
	require.Equal(t, "https://cdn.example.test/bare.png", filled.AvatarURL)
	require.True(t, later.Equal(*filled.LastLogin))
}
