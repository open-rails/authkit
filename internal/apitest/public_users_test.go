package apitest_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// GET /users shows signed-in callers other people as anyone may see them: by
// ids in request order (unknown ids absent, deleted accounts tombstones), or
// by username (a former name resolves), with only the public metadata keys
// and never a contact, ban or sign-in data.
func TestPublicUsersRoute(t *testing.T) {
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.PublicUserMetadata = []string{"bio"} }))
	ctx, op := t.Context(), iam.SystemActor()
	a := newAPI(t, auth)
	caller, alice, bob, gone := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, caller).AccessToken
	require.NoError(t, auth.PatchUserMetadata(ctx, op, alice.ID, map[string]any{"bio": "hello", "plan": "gold"}))
	avatar := "https://img.example/alice.png"
	_, err := auth.UpdateUser(ctx, op, alice.ID, iam.UserUpdate{AvatarURL: &avatar})
	require.NoError(t, err)
	require.NoError(t, auth.Ban(ctx, op, bob.ID, iam.Ban{Reason: "spam"}))
	require.NoError(t, opErr(auth.DeleteUsers(ctx, op, []string{gone.ID})))

	users := func(query string) (response, []iam.PublicUser) {
		t.Helper()
		res := expect(t, http.StatusOK, a.get("/users?"+query, token))
		var page iam.ListPage[iam.PublicUser]
		res.decode(t, &page)
		require.Empty(t, page.Next)
		return res, page.Items
	}
	ids := url.QueryEscape(strings.Join([]string{bob.ID, uuid.NewString(), " " + strings.ToUpper(alice.ID), gone.ID, bob.ID, "not-a-uuid"}, ","))
	res, got := users("ids=" + ids)
	require.Equal(t, []iam.PublicUser{
		{ID: bob.ID, Username: bob.Username, Metadata: map[string]any{}},
		{ID: alice.ID, Username: alice.Username, AvatarURL: &avatar, Metadata: map[string]any{"bio": "hello"}},
		{ID: gone.ID, Deleted: true, Metadata: map[string]any{}},
	}, got, "request order, each once; unknown ids absent; a ban is not visible")
	var raw struct {
		Data []json.RawMessage `json:"data"`
	}
	res.decode(t, &raw)
	require.JSONEq(t, `{"id":"`+gone.ID+`","username":"","avatar_url":null,"deleted":true,"metadata":{}}`, string(raw.Data[2]))
	for _, leak := range []string{alice.Email, bob.Email, gone.Email, "gold", "spam", "email", "phone", "ban", "last_login", "created_at"} {
		require.NotContains(t, res.String(), leak)
	}

	// By username: a former name resolves to its owner; a name nobody holds,
	// or a deleted account's, is an empty page.
	former, renamed := alice.Username, "renamed"+alice.Username
	_, err = auth.UpdateUser(ctx, op, alice.ID, iam.UserUpdate{Username: &renamed})
	require.NoError(t, err)
	for _, name := range []string{renamed, former, strings.ToUpper(renamed)} {
		_, got = users("username=" + name)
		require.Len(t, got, 1, name)
		require.Equal(t, alice.ID, got[0].ID)
		require.Equal(t, renamed, got[0].Username)
	}
	for _, name := range []string{"nobody_here", gone.Username} {
		_, got = users("username=" + name)
		require.Empty(t, got, name)
	}

	// Exactly one of ids and username; at most 100 ids.
	many := make([]string, 101)
	for i := range many {
		many[i] = uuid.NewString()
	}
	for _, query := range []string{"", "ids=", "ids=" + alice.ID + ",," + bob.ID, "ids=" + alice.ID + "&username=" + renamed, "ids=" + strings.Join(many, ",")} {
		res := a.get("/users?"+query, token)
		require.Equal(t, http.StatusBadRequest, res.status, "%s: %s", query, res)
		require.Equal(t, "invalid_request", res.code())
	}
	_, got = users("ids=" + strings.Join(many[:100], ","))
	require.Empty(t, got)

	expect(t, http.StatusUnauthorized, a.get("/users?ids="+alice.ID, ""))
}
