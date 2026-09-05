package authhttp

// #262 e2e (real Postgres, mounted handlers): the user profile surface — the
// first-class avatar URL on GET /me and cooldown availability
// (update_username) on GET /me.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type meAvailabilityShape struct {
	Action            string `json:"action"`
	Allowed           bool   `json:"allowed"`
	RetryAfterSeconds int64  `json:"retry_after_seconds"`
}

type meProfileShape struct {
	ID           string                `json:"id"`
	AvatarURL    *string               `json:"avatar_url"`
	Availability []meAvailabilityShape `json:"availability"`
	UserAliases  []string              `json:"user_aliases"`
}

func meAvailabilityFor(t *testing.T, shape meProfileShape, action string) meAvailabilityShape {
	t.Helper()
	for _, a := range shape.Availability {
		if a.Action == action {
			return a
		}
	}
	t.Fatalf("GET /me availability is missing action %q: %+v", action, shape.Availability)
	return meAvailabilityShape{}
}

func TestUserProfileSurface_MetadataAvatarAndAvailability(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	client := newServerClient(t, newServerTestConfig(), pool)
	srv, err := newServer(client, WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("profile-surface")
	// ak#273: the CURRENT username deliberately carries an underscore and
	// uppercase — both admitted by authcore.ValidateUsername — because the rename
	// below records lower(current username) as user_renames.from_slug. Under the
	// 0001 predicate that INSERT violated user_renames_from_slug_format_chk and
	// took the whole rename transaction with it, so this account could never be
	// renamed. Keep the shape: it is the regression pin.
	require.NoError(t, authcore.ValidateUsername("Profile_Surface"),
		"ak#273: this pin only means something while ValidateUsername still admits '_' and uppercase")
	username := "Profile_Surface" + uniqueSuffix()
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	// --- baseline /me: no avatar, update_username currently available -------
	w := serveAuthJSON(srv, http.MethodGet, "/me", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var me meProfileShape
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.Nil(t, me.AvatarURL)
	avail := meAvailabilityFor(t, me, ActionUpdateUsername)
	require.True(t, avail.Allowed)
	require.Zero(t, avail.RetryAfterSeconds)

	// --- avatar: host sets the URL via the Go API; /me serves it -------------
	avatarURL := "https://cdn.example.com/avatars/u.webp"
	require.NoError(t, client.UpdateAvatarURL(ctx, user.ID, &avatarURL))
	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	me = meProfileShape{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.NotNil(t, me.AvatarURL)
	require.Equal(t, avatarURL, *me.AvatarURL)

	// Clearing removes it from /me.
	require.NoError(t, client.UpdateAvatarURL(ctx, user.ID, nil))
	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	me = meProfileShape{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.Nil(t, me.AvatarURL)

	// --- cooldown: after a rename, /me reports the wait BEFORE a client tries -
	// ak#273: the account being renamed here holds an underscore + uppercase
	// username, so this PATCH is also the regression pin for the rename-history
	// CHECK. Before migration 0006 it answered 400 failed_to_update_username.
	w = serveAuthJSON(srv, http.MethodPatch, "/user/username", `{"username":"px`+uniqueSuffix()+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	me = meProfileShape{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	avail = meAvailabilityFor(t, me, ActionUpdateUsername)
	require.False(t, avail.Allowed)
	require.Positive(t, avail.RetryAfterSeconds)
	// The alias is the old username LOWERCASED, not slugified: ak#273 chose
	// "constraint follows validator", so '_' survives into the published alias.
	require.Contains(t, me.UserAliases, strings.ToLower(username))
}
