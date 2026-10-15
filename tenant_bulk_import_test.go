package authkit_test

import (
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func TestTenantBulkImportsKeepMatchesAliasesAndProvidersSeparate(t *testing.T) {
	shared, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DefaultTenantID = iam.TenantID{}; c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	views := make([]*authkit.Client, 2)
	for i := range views {
		id := iam.NewTenantID()
		require.NoError(t, shared.CreateTenant(t.Context(), iam.Tenant{ID: id}))
		var err error
		views[i], err = shared.ForTenant(t.Context(), id)
		require.NoError(t, err)
	}
	input := iam.ImportUser{Email: "same@example.test", Phone: "+12025550123", Username: "sharedimport", Providers: []iam.ProviderLink{{Provider: "oidc", Issuer: "https://idp.example.test", Subject: "shared-subject"}}, PublicMetadata: map[string]any{"owner": "A"}}
	_, err := shared.ImportUsers(t.Context(), []iam.ImportUser{input}, iam.ImportOptions{})
	require.ErrorIs(t, err, iam.ErrTenantRequired)
	first, err := views[0].ImportUsers(t.Context(), []iam.ImportUser{input}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 1, first.Inserted)
	idA := first.Rows[0].UserID
	renamed := "renamedimport"
	_, err = views[0].UpdateUser(t.Context(), iam.SystemIdentity(), idA, iam.UserUpdate{Username: &renamed})
	require.NoError(t, err)
	input.PublicMetadata = map[string]any{"owner": "B"}
	now := time.Now().Add(-time.Hour)
	second, err := views[1].ImportUsers(t.Context(), []iam.ImportUser{input, {Email: "bannedb@example.test", Username: "bannedimport", Ban: &iam.BanState{At: now, By: &idA}}}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, second.Inserted)
	idB := second.Rows[0].UserID
	require.NotEqual(t, idA, idB)
	for i, expected := range []string{idA, idB} {
		currentName := input.Username
		if i == 0 {
			currentName = renamed
		}
		for _, ref := range []iam.UserRef{iam.UserByEmail(input.Email), iam.UserByPhone(input.Phone), iam.UserByUsername(currentName)} {
			user, err := views[i].User(t.Context(), ref)
			require.NoError(t, err)
			require.Equal(t, expected, user.ID)
		}
		alias, err := views[i].ResolveUsername(t.Context(), input.Username)
		require.NoError(t, err)
		require.Equal(t, expected, alias.ID, "each tenant resolves its own canonical name or retained alias")
	}
	foreign, err := views[1].ImportUsers(t.Context(), []iam.ImportUser{{ID: idA, Email: "foreign@example.test", Username: "foreigntarget", PublicMetadata: map[string]any{"owner": "hijacked"}}}, iam.ImportOptions{OnConflict: iam.ImportMerge})
	require.NoError(t, err)
	require.Equal(t, 1, foreign.Rejected)
	require.Empty(t, foreign.Rows[0].UserID)
	own, err := views[1].ImportUsers(t.Context(), []iam.ImportUser{{ID: idB, Username: input.Username, PublicMetadata: map[string]any{"updated": "B"}}}, iam.ImportOptions{OnConflict: iam.ImportMerge})
	require.NoError(t, err)
	require.Equal(t, 1, own.Merged)
	userA, err := views[0].User(t.Context(), iam.UserByID(idA))
	require.NoError(t, err)
	require.Equal(t, map[string]any{"owner": "A"}, userA.PublicMetadata)
	userB, err := views[1].User(t.Context(), iam.UserByID(idB))
	require.NoError(t, err)
	require.Equal(t, map[string]any{"owner": "B", "updated": "B"}, userB.PublicMetadata)
	banned, err := views[1].User(t.Context(), iam.UserByID(second.Rows[1].UserID))
	require.NoError(t, err)
	require.NotNil(t, banned.Ban)
	require.Equal(t, &idA, banned.Ban.By, "a genuine global source actor remains audit provenance, not membership")
}
