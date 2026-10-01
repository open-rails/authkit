package apitest_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// GET /users shows anyone, signed in or not, other people as anyone may see
// them: by ids in request order (unknown ids absent, deleted accounts
// tombstones), or by username (a former name resolves), with the join date and
// public metadata, never a contact, ban or sign-in data.
func TestPublicUsersRoute(t *testing.T) {
	auth, _ := authtest.New(t)
	ctx, op := t.Context(), iam.SystemActor()
	a := newAPI(t, auth)
	caller, alice, bob, gone := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, caller).AccessToken
	profile := map[string]any{"bio": "hello", "avatar": "https://img.example/alice.png"}
	require.NoError(t, auth.PatchPublicMetadata(ctx, op, alice.ID, profile))
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
	joined := func(id string) *time.Time {
		t.Helper()
		u, err := auth.User(ctx, iam.UserByID(id))
		require.NoError(t, err)
		return &u.CreatedAt
	}
	ids := url.QueryEscape(strings.Join([]string{bob.ID, uuid.NewString(), " " + strings.ToUpper(alice.ID), gone.ID, bob.ID, "not-a-uuid"}, ","))
	res, got := users("ids=" + ids)
	require.Len(t, got, 3)
	for i, id := range []string{bob.ID, alice.ID} {
		require.True(t, got[i].CreatedAt != nil && got[i].CreatedAt.Equal(*joined(id)), "member since")
		got[i].CreatedAt = nil
	}
	require.Equal(t, []iam.PublicUser{
		{ID: bob.ID, Username: bob.Username, PublicMetadata: map[string]any{}},
		{ID: alice.ID, Username: alice.Username, PublicMetadata: profile},
		{ID: gone.ID, Deleted: true, PublicMetadata: map[string]any{}},
	}, got, "request order, each once; unknown ids absent; a ban is not visible")
	var raw struct {
		Data []json.RawMessage `json:"data"`
	}
	res.decode(t, &raw)
	require.JSONEq(t, `{"id":"`+gone.ID+`","username":"","created_at":null,"deleted":true,"public_metadata":{}}`, string(raw.Data[2]))
	for _, leak := range []string{alice.Email, bob.Email, gone.Email, "spam", "email", "phone", "ban", "last_login", "updated_at"} {
		require.NotContains(t, res.String(), leak)
	}

	// By username: a former name resolves to its owner; a name nobody holds,
	// or a deleted account's, is an empty page.
	former, renamed := alice.Username, "renamed"+alice.Username
	_, err := auth.UpdateUser(ctx, op, alice.ID, iam.UserUpdate{Username: &renamed})
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

	// Public profile pages need no sign-in, and a stale bearer changes nothing.
	for _, bearer := range []string{"", "not-a-token"} {
		res := expect(t, http.StatusOK, a.get("/users?username="+renamed, bearer))
		var page iam.ListPage[iam.PublicUser]
		res.decode(t, &page)
		require.Len(t, page.Items, 1)
		require.Equal(t, alice.ID, page.Items[0].ID)
	}
}
