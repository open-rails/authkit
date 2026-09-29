package authkit_test

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func newUsersRuntime(t *testing.T) *authkit.Auth {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	auth := newPublicRuntime(t, testConfig(t), pg.Pool)
	t.Cleanup(auth.Close)
	return auth
}

func itemErr(res []iam.OpResult, err error) error {
	if err != nil {
		return err
	}
	return res[0].Err
}

func TestUserLookups(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	op := iam.SystemActor()
	alice, err := auth.CreateUser(ctx, op, iam.NewUser{Email: "Alice@Example.test", Phone: "+15555550100", Username: "alice", EmailVerified: true})
	require.NoError(t, err)
	require.Equal(t, "alice@example.test", alice.Email)
	require.True(t, alice.EmailVerified)
	require.False(t, alice.PhoneVerified)
	require.True(t, alice.Live)

	for _, ref := range []iam.UserRef{iam.UserByID(alice.ID), iam.UserByEmail("ALICE@example.test"), iam.UserByPhone("+15555550100"), iam.UserByUsername("Alice")} {
		u, err := auth.User(ctx, ref)
		require.NoError(t, err, ref.String())
		require.Equal(t, alice.ID, u.ID, ref.String())
	}
	for _, ref := range []iam.UserRef{{}, iam.UserByID("not-a-uuid"), iam.UserByID("0190a0a0-0000-7000-8000-000000000000"), iam.UserByEmail("nobody@example.test"), iam.UserByPhone("+15555550199"), iam.UserByUsername("nobody")} {
		_, err := auth.User(ctx, ref)
		require.ErrorIs(t, err, iam.ErrUserNotFound, ref.String())
	}

	t.Run("deleted accounts need IncludeDeleted and publish a tombstone", func(t *testing.T) {
		bob, err := auth.CreateUser(ctx, op, iam.NewUser{Email: "bobby@example.test", Username: "bobby"})
		require.NoError(t, err)
		require.NoError(t, itemErr(auth.DeleteUsers(ctx, op, []string{bob.ID})))
		_, err = auth.User(ctx, iam.UserByUsername("bobby"))
		require.ErrorIs(t, err, iam.ErrUserNotFound)
		deleted, err := auth.User(ctx, iam.UserByID(bob.ID), iam.IncludeDeleted())
		require.NoError(t, err)
		require.NotNil(t, deleted.DeletedAt)
		require.False(t, deleted.Live)
		users, err := auth.Users(ctx, []string{alice.ID, bob.ID, "0190a0a0-0000-7000-8000-000000000000", "junk"})
		require.NoError(t, err)
		require.Len(t, users, 2)
		require.True(t, users[alice.ID].Live)
		require.False(t, users[bob.ID].Live)
		public, err := auth.PublicUsers(ctx, []string{alice.ID, bob.ID})
		require.NoError(t, err)
		require.Equal(t, iam.PublicUser{ID: bob.ID, Deleted: true}, public[bob.ID])
		require.Equal(t, "alice", public[alice.ID].DisplayName())
		require.Equal(t, "user-"+bob.ID[:8], iam.PublicDisplayName(public, bob.ID))
		require.NoError(t, itemErr(auth.RestoreUsers(ctx, op, []string{bob.ID})))
		restored, err := auth.User(ctx, iam.UserByID(bob.ID))
		require.NoError(t, err)
		require.True(t, restored.Live)
	})
}

func TestUserBanState(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	op := iam.SystemActor()
	carol, err := auth.CreateUser(ctx, op, iam.NewUser{Email: "carol@example.test", Username: "carol"})
	require.NoError(t, err)
	ban := func() *iam.BanState {
		t.Helper()
		users, err := auth.Users(ctx, []string{carol.ID})
		require.NoError(t, err)
		require.Equal(t, users[carol.ID].Ban == nil, users[carol.ID].Live)
		return users[carol.ID].Ban
	}
	past := time.Now().Add(-time.Minute)
	require.ErrorIs(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Until: &past}), iam.ErrInvalidUntil)
	require.NoError(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Reason: "spam"}))
	require.Equal(t, "spam", ban().Reason)
	require.Empty(t, ban().By, "the system ban has no banning account")
	require.NoError(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Reason: "again", KeepExisting: true}))
	require.Equal(t, "spam", ban().Reason, "KeepExisting leaves a ban in force unchanged")
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Reason: "extended", Until: &until}))
	require.Equal(t, "extended", ban().Reason)
	require.True(t, until.Equal(*ban().Until))
	require.NoError(t, auth.Unban(ctx, op, carol.ID))
	require.Nil(t, ban())
	_, err = auth.User(ctx, iam.UserByID(carol.ID))
	require.NoError(t, err)
}

func TestUserUpdateAndMetadata(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	op := iam.SystemActor()
	dave, err := auth.CreateUser(ctx, op, iam.NewUser{Email: "dave@example.test", Username: "dave", EmailVerified: true})
	require.NoError(t, err)
	self := iam.UserActor(dave.ID)
	lang, avatar := "fr", "https://cdn.example.test/dave.png"
	u, err := auth.UpdateUser(ctx, self, dave.ID, iam.UserUpdate{PreferredLanguage: &lang, AvatarURL: &avatar})
	require.NoError(t, err)
	require.Equal(t, "fr", u.PreferredLanguage)
	require.Equal(t, avatar, u.AvatarURL)
	email := "dave2@example.test"
	_, err = auth.UpdateUser(ctx, self, dave.ID, iam.UserUpdate{Email: &email})
	require.ErrorIs(t, err, iam.ErrCannotTargetSelf, "contact changes go through the verified flow")
	u, err = auth.UpdateUser(ctx, op, dave.ID, iam.UserUpdate{Email: &email})
	require.NoError(t, err)
	require.Equal(t, email, u.Email)
	require.False(t, u.EmailVerified, "a new address starts unverified")
	clear := ""
	u, err = auth.UpdateUser(ctx, op, dave.ID, iam.UserUpdate{AvatarURL: &clear})
	require.NoError(t, err)
	require.Empty(t, u.AvatarURL)
	_, err = auth.UpdateUser(ctx, op, dave.ID, iam.UserUpdate{PasswordHash: &iam.PasswordHash{Hash: "not-a-hash", Algo: "argon2id"}})
	require.Error(t, err)

	require.NoError(t, auth.PatchUserMetadata(ctx, op, dave.ID, map[string]any{"bio": "hi", "tier": "gold"}))
	require.NoError(t, auth.PatchUserMetadata(ctx, op, dave.ID, map[string]any{"tier": nil}))
	meta, err := auth.UserMetadata(ctx, dave.ID)
	require.NoError(t, err)
	require.Equal(t, map[string]any{"bio": "hi"}, meta, "a nil value deletes its key")
	require.ErrorIs(t, auth.PatchUserMetadata(ctx, op, dave.ID, map[string]any{"reserved": true}), errmodel.E(errmodel.CodeInvalidRequest))
	_, err = auth.UserMetadata(ctx, "0190a0a0-0000-7000-8000-000000000000")
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	sessions, err := auth.Sessions(ctx, dave.ID)
	require.NoError(t, err)
	require.Empty(t, sessions)
}

func TestOperatorOnlyAccountOperations(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	erin, err := auth.CreateUser(ctx, iam.SystemActor(), iam.NewUser{Email: "erin@example.test", Username: "erin"})
	require.NoError(t, err)
	for _, actor := range []iam.Actor{{}, iam.UserActor(erin.ID)} {
		_, err := auth.CreateUser(ctx, actor, iam.NewUser{Email: "frank@example.test", Username: "frank"})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
		_, err = auth.PurgeUsers(ctx, actor, []string{erin.ID})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
		_, err = auth.MintAccessToken(ctx, actor, erin.ID, iam.AccessTokenOptions{})
		require.ErrorIs(t, err, iam.ErrInsufficientAuthority)
	}
	require.ErrorIs(t, auth.Ban(ctx, iam.Actor{}, erin.ID, iam.Ban{}), iam.ErrInsufficientAuthority, "the zero actor is refused")
	token, err := auth.MintAccessToken(ctx, iam.SystemActor(), erin.ID, iam.AccessTokenOptions{TTL: time.Minute})
	require.NoError(t, err)
	require.NotEmpty(t, token.Value)
	require.WithinDuration(t, time.Now().Add(time.Minute), token.ExpiresAt, 5*time.Second)
	_, err = auth.MintAccessToken(ctx, iam.SystemActor(), "0190a0a0-0000-7000-8000-000000000000", iam.AccessTokenOptions{})
	require.ErrorIs(t, err, iam.ErrUserNotFound)
}

func TestListUsersKeysetPaging(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	var want []string
	for _, name := range []string{"pgcharlie", "pgalpha", "pgecho", "pgbravo", "pgdelta"} {
		_, err := auth.CreateUser(ctx, iam.SystemActor(), iam.NewUser{Email: name + "@example.test", Username: name})
		require.NoError(t, err)
		want = append(want, name)
	}
	sort.Strings(want)
	walk := func(q iam.UserQuery) []string {
		t.Helper()
		var got []string
		for range 10 {
			page, err := auth.ListUsers(ctx, q)
			require.NoError(t, err)
			require.LessOrEqual(t, len(page.Items), 2)
			for _, u := range page.Items {
				got = append(got, u.Username)
			}
			if page.Next == "" {
				return got
			}
			q.Page.Cursor = page.Next
		}
		t.Fatal("paging never ended")
		return nil
	}
	query := iam.UserQuery{Search: "pg", Page: iam.PageRequest{Limit: 2}}
	for _, sortBy := range []iam.UserSort{iam.UserSortUsername, iam.UserSortEmail} {
		query.Sort, query.Desc = sortBy, false
		require.Equal(t, want, walk(query), sortBy)
		query.Desc = true
		desc := append([]string(nil), want...)
		sort.Sort(sort.Reverse(sort.StringSlice(desc)))
		require.Equal(t, desc, walk(query), sortBy)
	}
	query.Sort, query.Desc = iam.UserSortLastLogin, false
	got := walk(query)
	sort.Strings(got)
	require.Equal(t, want, got, "NULL sort values page by id")

	page, err := auth.ListUsers(ctx, iam.UserQuery{Search: "pg", Sort: iam.UserSortUsername, Page: iam.PageRequest{Limit: 2}})
	require.NoError(t, err)
	require.NotEmpty(t, page.Next)
	_, err = auth.ListUsers(ctx, iam.UserQuery{Search: "pg", Sort: iam.UserSortEmail, Page: iam.PageRequest{Cursor: page.Next}})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeInvalidRequest), "a cursor is bound to its sort")
	_, err = auth.ListUsers(ctx, iam.UserQuery{Page: iam.PageRequest{Cursor: "garbage"}})
	require.ErrorIs(t, err, errmodel.E(errmodel.CodeInvalidRequest))
	banned, err := auth.ListUsers(ctx, iam.UserQuery{Search: "pgalpha", Status: iam.UserStatusBanned})
	require.NoError(t, err)
	require.Empty(t, banned.Items)
	all, err := auth.ListUsers(ctx, iam.UserQuery{Search: "PGALPHA"})
	require.NoError(t, err)
	require.Len(t, all.Items, 1)
	require.True(t, strings.HasPrefix(all.Items[0].Email, "pgalpha"))
}

func TestListGroupMembersLiveOnlyWithUsers(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	cfg.Roles = authkit.RoleConfig{
		Personas: map[string]authkit.Persona{"team": {Permissions: []string{"team:docs:read"}}},
		Roles:    []authkit.Role{{Persona: "team", Name: "member", Permissions: []string{"team:docs:read"}}},
	}
	auth := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(auth.Close)
	ctx := t.Context()
	op := iam.SystemActor()
	_, _, err := auth.CreateGroup(ctx, op, iam.NewGroup{Persona: "team", Slug: "alpha"})
	require.NoError(t, err)
	ref := iam.GroupBySlug("team", "alpha")
	ids := map[string]string{}
	var subjects []iam.Subject
	for _, name := range []string{"liveone", "banned", "deleted"} {
		u, err := auth.CreateUser(ctx, op, iam.NewUser{Email: name + "@example.test", Username: name})
		require.NoError(t, err)
		ids[name] = u.ID
		subjects = append(subjects, iam.UserSubject(u.ID))
	}
	res, err := auth.AssignGroupRoles(ctx, op, ref, subjects, "member")
	require.NoError(t, err)
	for _, r := range res {
		require.NoError(t, r.Err)
	}
	require.NoError(t, auth.Ban(ctx, op, ids["banned"], iam.Ban{}))
	require.NoError(t, itemErr(auth.DeleteUsers(ctx, op, []string{ids["deleted"]})))

	all, err := auth.ListGroupMembers(ctx, ref, iam.MemberQuery{})
	require.NoError(t, err)
	require.Len(t, all.Items, 3)
	require.Nil(t, all.Items[0].User)
	live, err := auth.ListGroupMembers(ctx, ref, iam.MemberQuery{LiveOnly: true, WithUsers: true})
	require.NoError(t, err)
	require.Len(t, live.Items, 1)
	require.Equal(t, ids["liveone"], live.Items[0].Subject.ID)
	require.NotNil(t, live.Items[0].User)
	require.Equal(t, "liveone@example.test", live.Items[0].User.Email)
	withUsers, err := auth.ListGroupMembers(ctx, ref, iam.MemberQuery{WithUsers: true})
	require.NoError(t, err)
	for _, m := range withUsers.Items {
		require.NotNil(t, m.User)
		require.Equal(t, m.Subject.ID == ids["liveone"], m.User.Live)
	}
}
