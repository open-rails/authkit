package authkit_test

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// TestImportUserProfileFields: imported rows carry their last sign-in,
// language and avatar; a merge fills what the account lacks and keeps the
// later last sign-in.
func TestImportUserProfileFields(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	lastLogin := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	res, err := auth.ImportUsers(ctx, []iam.ImportUser{
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
	require.Equal(t, "fr", *u.PreferredLanguage)
	require.Equal(t, "https://cdn.example.test/p.png", *u.AvatarURL)
	require.True(t, lastLogin.Equal(*u.LastLogin))

	bare, err := auth.CreateUser(ctx, iam.NewUser{Email: "bare@example.test", Username: "bare"})
	require.NoError(t, err)
	earlier, later := lastLogin.Add(-time.Hour), lastLogin.Add(time.Hour)
	merged, err := auth.ImportUsers(ctx, []iam.ImportUser{
		{ID: u.ID, Username: "profile", LastLogin: &earlier, PreferredLanguage: "de", AvatarURL: "https://cdn.example.test/other.png"},
		{ID: bare.ID, Username: "bare", LastLogin: &later, PreferredLanguage: "de", AvatarURL: "https://cdn.example.test/bare.png"},
	}, iam.ImportOptions{OnConflict: iam.ImportMerge})
	require.NoError(t, err)
	require.Equal(t, 2, merged.Merged)
	kept, err := auth.User(ctx, iam.UserByID(u.ID))
	require.NoError(t, err)
	require.Equal(t, "fr", *kept.PreferredLanguage)
	require.Equal(t, "https://cdn.example.test/p.png", *kept.AvatarURL)
	require.True(t, lastLogin.Equal(*kept.LastLogin), "a merge moved the last sign-in back")
	filled, err := auth.User(ctx, iam.UserByID(bare.ID))
	require.NoError(t, err)
	require.Equal(t, "de", *filled.PreferredLanguage)
	require.Equal(t, "https://cdn.example.test/bare.png", *filled.AvatarURL)
	require.True(t, later.Equal(*filled.LastLogin))
}

// Every text field must be valid UTF-8, metadata included: the bulk insert
// would otherwise store U+FFFD. An imported ban keeps who banned, even an
// account the same batch imports later; a banner that is no account leaves
// the ban without one.
func TestImportTextAndBans(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	at := time.Date(2023, 3, 4, 5, 6, 7, 0, time.UTC)
	banner := uuid.NewString()
	res, err := auth.ImportUsers(ctx, []iam.ImportUser{
		{Email: "banned@example.test", Username: "banned", Ban: &iam.BanState{At: at, Reason: new("spam"), By: &banner}},
		{ID: banner, Email: "moderator@example.test", Username: "moderator"},
		{Email: "bad\xfftext@example.test", Username: "badtext"},
		{Email: "badmeta@example.test", Username: "badmeta", Metadata: map[string]any{"bio": map[string]any{"quote": "\xff"}}},
		{Email: "badkey@example.test", Username: "badkey", Metadata: map[string]any{"\xff": true}},
		{Email: "noat@example.test", Username: "noat", Ban: &iam.BanState{Reason: new("no time")}},
		{Email: "badby@example.test", Username: "badby", Ban: &iam.BanState{At: at, By: new("not-a-uuid")}},
		{Email: "ghostby@example.test", Username: "ghostby", Ban: &iam.BanState{At: at, By: new(uuid.NewString())}},
		{Email: "unicode@example.test", Username: "unicode", Metadata: map[string]any{"bio": "café ☕"}},
	}, iam.ImportOptions{})
	require.NoError(t, err)
	for i, reason := range map[int]iam.ImportReason{2: iam.ImportInvalidText, 3: iam.ImportInvalidText, 4: iam.ImportInvalidText, 5: iam.ImportInvalidBan, 6: iam.ImportInvalidBan} {
		require.Equal(t, iam.ImportRow{Index: i, Status: iam.ImportRejected, Reason: reason}, res.Rows[i])
	}
	require.Equal(t, 4, res.Inserted)
	banned, err := auth.User(ctx, iam.UserByID(res.Rows[0].UserID))
	require.NoError(t, err)
	require.NotNil(t, banned.Ban)
	require.True(t, at.Equal(banned.Ban.At))
	require.Equal(t, iam.BanState{At: banned.Ban.At, Reason: new("spam"), By: &banner}, *banned.Ban)
	ghost, err := auth.User(ctx, iam.UserByID(res.Rows[7].UserID))
	require.NoError(t, err)
	require.NotNil(t, ghost.Ban)
	require.Empty(t, ghost.Ban.By, "a banner that is no account")
	meta, err := auth.UserMetadata(ctx, res.Rows[8].UserID)
	require.NoError(t, err)
	require.Equal(t, "café ☕", meta["bio"])
}
