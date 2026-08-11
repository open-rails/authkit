package authhttp

// #262 e2e (real Postgres, mounted handlers): the user profile surface —
// GET|PATCH /user/metadata (host-namespaced keys, authkit-internal flags
// invisible), the first-class avatar URL on GET /me, and cooldown availability
// (update_username) on GET /me.

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

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
	pool := newServerTestPool(t)
	ctx := context.Background()
	client := newServerClient(t, newServerTestConfig(), pool)
	srv, err := NewServer(client, WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("profile-surface")
	username := "profilesurface" + uniqueSuffix()
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

	// --- metadata: PATCH a host-namespaced key, read it back -----------------
	w = serveAuthJSON(srv, http.MethodPatch, "/user/metadata", `{"cozy_avatar":{"object_key":"avatars/u/x.webp"}}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var patched struct {
		OK       bool           `json:"ok"`
		Metadata map[string]any `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &patched))
	require.True(t, patched.OK)
	require.Contains(t, patched.Metadata, "cozy_avatar")

	w = serveAuthJSON(srv, http.MethodGet, "/user/metadata", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var got struct {
		Metadata map[string]any `json:"metadata"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.Contains(t, got.Metadata, "cozy_avatar")

	// --- metadata: authkit-internal keys are write-rejected and read-hidden --
	w = serveAuthJSON(srv, http.MethodPatch, "/user/metadata", `{"reserved":true}`, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrMetadataKeyReserved))

	// The host-trusted Go API can still set it — the HTTP read must hide it.
	require.NoError(t, client.PatchUserMetadata(ctx, user.ID, map[string]any{"reserved": true}))
	w = serveAuthJSON(srv, http.MethodGet, "/user/metadata", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	got.Metadata = nil
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
	require.NotContains(t, got.Metadata, "reserved")
	require.Contains(t, got.Metadata, "cozy_avatar")

	// Malformed keys are rejected outright.
	w = serveAuthJSON(srv, http.MethodPatch, "/user/metadata", `{"bad key":1}`, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodPatch, "/user/metadata", `{}`, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

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
	w = serveAuthJSON(srv, http.MethodPatch, "/user/username", `{"username":"px`+uniqueSuffix()+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	me = meProfileShape{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	avail = meAvailabilityFor(t, me, ActionUpdateUsername)
	require.False(t, avail.Allowed)
	require.Positive(t, avail.RetryAfterSeconds)
}
