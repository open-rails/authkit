package authkit_test

import (
	"context"
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

func newUsersRuntime(t *testing.T) *authkit.Client {
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
	alice, err := auth.CreateUser(ctx, iam.NewUser{Email: "Alice@Example.test", Phone: "+15555550100", Username: "alice", EmailVerified: true})
	require.NoError(t, err)
	require.Equal(t, "alice@example.test", *alice.Email)
	require.True(t, alice.EmailVerified)
	require.False(t, alice.PhoneVerified)
	require.Nil(t, alice.DeletedAt)
	require.Nil(t, alice.Ban)

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
		bob, err := auth.CreateUser(ctx, iam.NewUser{Email: "bobby@example.test", Username: "bobby"})
		require.NoError(t, err)
		require.NoError(t, itemErr(auth.DeleteUsers(ctx, op, []string{bob.ID})))
		_, err = auth.User(ctx, iam.UserByUsername("bobby"))
		require.ErrorIs(t, err, iam.ErrUserNotFound)
		deleted, err := auth.User(ctx, iam.UserByID(bob.ID), authkit.IncludeDeleted())
		require.NoError(t, err)
		require.NotNil(t, deleted.DeletedAt)
		users, err := auth.Users(ctx, []string{alice.ID, bob.ID, "0190a0a0-0000-7000-8000-000000000000", "junk"})
		require.NoError(t, err)
		require.Len(t, users, 2)
		require.Nil(t, users[alice.ID].DeletedAt)
		require.NotNil(t, users[bob.ID].DeletedAt)
		public, err := auth.PublicUsers(ctx, []string{alice.ID, bob.ID})
		require.NoError(t, err)
		require.Equal(t, iam.PublicUser{ID: bob.ID, Deleted: true, PublicMetadata: map[string]any{}}, public[bob.ID])
		require.Equal(t, "alice", public[alice.ID].DisplayName())
		require.Equal(t, "user-"+bob.ID[:8], iam.PublicDisplayName(public, bob.ID))
		require.NoError(t, itemErr(auth.RestoreUsers(ctx, op, []string{bob.ID})))
		restored, err := auth.User(ctx, iam.UserByID(bob.ID))
		require.NoError(t, err)
		require.Nil(t, restored.DeletedAt)
	})
}

// Public metadata is the host's: PublicUsers and User return it whole, and
// a deleted account's tombstone carries none.
func TestPublicMetadata(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	op := iam.SystemActor()
	alice, err := auth.CreateUser(ctx, iam.NewUser{Email: "meta-alice@example.test", Username: "metaalice"})
	require.NoError(t, err)
	bob, err := auth.CreateUser(ctx, iam.NewUser{Email: "meta-bob@example.test", Username: "metabob"})
	require.NoError(t, err)
	carol, err := auth.CreateUser(ctx, iam.NewUser{Email: "meta-carol@example.test", Username: "metacarol"})
	require.NoError(t, err)
	profile := map[string]any{"avatar": "https://cdn.example.test/a.png", "biography": "hi", "links": []any{"https://alice.example"}}
	require.NoError(t, auth.PatchPublicMetadata(ctx, op, alice.ID, profile))
	require.NoError(t, auth.PatchPublicMetadata(ctx, op, bob.ID, map[string]any{"biography": "gone"}))
	require.NoError(t, itemErr(auth.DeleteUsers(ctx, op, []string{bob.ID})))

	public, err := auth.PublicUsers(ctx, []string{alice.ID, bob.ID, carol.ID})
	require.NoError(t, err)
	require.Equal(t, profile, public[alice.ID].PublicMetadata)
	require.Equal(t, iam.PublicUser{ID: bob.ID, Deleted: true, PublicMetadata: map[string]any{}}, public[bob.ID], "a tombstone carries no metadata")
	require.Equal(t, map[string]any{}, public[carol.ID].PublicMetadata)
	u, err := auth.User(ctx, iam.UserByID(alice.ID))
	require.NoError(t, err)
	require.Equal(t, profile, u.PublicMetadata)
}

func TestUserBanState(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	op := iam.SystemActor()
	carol, err := auth.CreateUser(ctx, iam.NewUser{Email: "carol@example.test", Username: "carol"})
	require.NoError(t, err)
	ban := func() *iam.BanState {
		t.Helper()
		users, err := auth.Users(ctx, []string{carol.ID})
		require.NoError(t, err)
		return users[carol.ID].Ban
	}
	past := time.Now().Add(-time.Minute)
	require.ErrorIs(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Until: &past}), iam.ErrInvalidUntil)
	require.NoError(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Reason: "spam"}))
	require.Equal(t, "spam", *ban().Reason)
	require.Empty(t, ban().By, "the system ban has no banning account")
	require.NoError(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Reason: "again", KeepExisting: true}))
	require.Equal(t, "spam", *ban().Reason, "KeepExisting leaves a ban in force unchanged")
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	require.NoError(t, auth.Ban(ctx, op, carol.ID, iam.Ban{Reason: "extended", Until: &until}))
	require.Equal(t, "extended", *ban().Reason)
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
	dave, err := auth.CreateUser(ctx, iam.NewUser{Email: "dave@example.test", Username: "dave", EmailVerified: true})
	require.NoError(t, err)
	self := iam.UserActor(dave.ID)
	lang := "fr"
	u, err := auth.UpdateUser(ctx, self, dave.ID, iam.UserUpdate{PreferredLanguage: &lang})
	require.NoError(t, err)
	require.Equal(t, "fr", *u.PreferredLanguage)
	email := "dave2@example.test"
	_, err = auth.UpdateUser(ctx, self, dave.ID, iam.UserUpdate{Email: &email})
	require.ErrorIs(t, err, iam.ErrCannotTargetSelf, "contact changes go through the verified flow")
	u, err = auth.UpdateUser(ctx, op, dave.ID, iam.UserUpdate{Email: &email})
	require.NoError(t, err)
	require.Equal(t, email, *u.Email)
	require.False(t, u.EmailVerified, "a new address starts unverified")
	clear := ""
	u, err = auth.UpdateUser(ctx, op, dave.ID, iam.UserUpdate{PreferredLanguage: &clear})
	require.NoError(t, err)
	require.Nil(t, u.PreferredLanguage)
	_, err = auth.UpdateUser(ctx, op, dave.ID, iam.UserUpdate{PasswordHash: &iam.PasswordHash{Hash: "not-a-hash", Algo: "argon2id"}})
	require.Error(t, err)

	require.NoError(t, auth.PatchPublicMetadata(ctx, op, dave.ID, map[string]any{"bio": "hi", "badge": "gold"}))
	require.NoError(t, auth.PatchPublicMetadata(ctx, op, dave.ID, map[string]any{"badge": nil}))
	u, err = auth.User(ctx, iam.UserByID(dave.ID))
	require.NoError(t, err)
	require.Equal(t, map[string]any{"bio": "hi"}, u.PublicMetadata, "a nil value deletes its key")
	require.ErrorIs(t, auth.PatchPublicMetadata(ctx, op, "0190a0a0-0000-7000-8000-000000000000", map[string]any{"bio": "x"}), iam.ErrUserNotFound)
	sessions, err := auth.Sessions(ctx, dave.ID)
	require.NoError(t, err)
	require.Empty(t, sessions)
}

func TestAccountHostOperations(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	erin, err := auth.CreateUser(ctx, iam.NewUser{Email: "erin@example.test", Username: "erin"})
	require.NoError(t, err)
	require.ErrorIs(t, auth.Ban(ctx, iam.Actor{}, erin.ID, iam.Ban{}), iam.ErrInsufficientAuthority, "the zero actor is refused")
	token, err := auth.MintAccessToken(ctx, erin.ID, iam.AccessTokenOptions{TTL: time.Minute})
	require.NoError(t, err)
	require.NotEmpty(t, token.Value)
	require.WithinDuration(t, time.Now().Add(time.Minute), token.ExpiresAt, 5*time.Second)
	_, err = auth.MintAccessToken(ctx, "0190a0a0-0000-7000-8000-000000000000", iam.AccessTokenOptions{})
	require.ErrorIs(t, err, iam.ErrUserNotFound)
}

func TestListUsersKeysetPaging(t *testing.T) {
	auth := newUsersRuntime(t)
	ctx := t.Context()
	var want []string
	for _, name := range []string{"pgcharlie", "pgalpha", "pgecho", "pgbravo", "pgdelta"} {
		_, err := auth.CreateUser(ctx, iam.NewUser{Email: name + "@example.test", Username: name})
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
	require.True(t, strings.HasPrefix(*all.Items[0].Email, "pgalpha"))
}

func TestListGroupMembersLiveOnlyWithUsers(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig(t)
	roles := authkit.NewRoles()
	team := roles.Persona("team")
	member := team.Role("member", team.Permission("docs", "read"))
	cfg.Roles = roles
	auth := newPublicRuntime(t, cfg, pg.Pool)
	t.Cleanup(auth.Close)
	ctx := t.Context()
	op := iam.SystemActor()
	g, err := auth.CreateGroup(ctx, iam.NewGroup{Persona: team.Persona})
	require.NoError(t, err)
	ref := iam.GroupByID(g.ID)
	ids := map[string]string{}
	var subjects []iam.Subject
	for _, name := range []string{"liveone", "banned", "deleted"} {
		u, err := auth.CreateUser(ctx, iam.NewUser{Email: name + "@example.test", Username: name})
		require.NoError(t, err)
		ids[name] = u.ID
		subjects = append(subjects, iam.UserSubject(u.ID))
	}
	for _, s := range subjects {
		_, err := auth.SetGroupRole(ctx, op, ref, s, member)
		require.NoError(t, err)
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
	require.Equal(t, "liveone", live.Items[0].User.Username)
	// Members expand to what others may see: a deleted member is a
	// tombstone, and a ban is not visible.
	withUsers, err := auth.ListGroupMembers(ctx, ref, iam.MemberQuery{WithUsers: true})
	require.NoError(t, err)
	for _, m := range withUsers.Items {
		require.NotNil(t, m.User)
		require.Equal(t, m.Subject.ID == ids["deleted"], m.User.Deleted)
	}
}

// entitlements is the host's billing view of accounts.
type entitlements map[string][]string

func (e entitlements) of(_ context.Context, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, id := range ids {
		if ents, ok := e[id]; ok {
			out[id] = ents
		}
	}
	return out, nil
}

// The user directory pages by number when asked for a total, and each entry
// carries its root role and, when asked, its entitlements.
func TestUserDirectoryEntries(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	rbac := authkit.NewRoles()
	staff := rbac.Root.Role("staff", rbac.Root.Users.Read)
	cfg := testConfig(t)
	cfg.Roles = rbac
	billing := entitlements{}
	deps := testDeps(pg.Pool)
	deps.Entitlements = billing.of
	auth, err := authkit.New(t.Context(), cfg, deps)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	ctx := t.Context()
	var ids []string
	for _, name := range []string{"dira", "dirb", "dirc"} {
		u, err := auth.CreateUser(ctx, iam.NewUser{Email: name + "@example.test", Username: name})
		require.NoError(t, err)
		ids = append(ids, u.ID)
	}
	_, err = auth.SetGroupRole(ctx, iam.SystemActor(), iam.RootGroup(), iam.UserSubject(ids[1]), staff)
	require.NoError(t, err)
	billing[ids[1]] = []string{"premium"}

	page, err := auth.ListUsers(ctx, iam.UserQuery{Total: true, Sort: iam.UserSortUsername, Page: iam.PageRequest{Limit: 2}})
	require.NoError(t, err)
	require.NotNil(t, page.Total)
	require.Equal(t, 3, *page.Total, "the total counts every match, not the page")
	require.Len(t, page.Items, 2)
	require.Equal(t, iam.UserEntry{User: page.Items[1].User, RootRole: &staff}, page.Items[1], "dirb holds staff; no entitlements unless asked")
	require.Nil(t, page.Items[0].RootRole)
	rest, err := auth.ListUsers(ctx, iam.UserQuery{Total: true, Sort: iam.UserSortUsername, WithEntitlements: true, Page: iam.PageRequest{Limit: 2, Cursor: page.Next}})
	require.NoError(t, err)
	require.Equal(t, 3, *rest.Total, "the total ignores the cursor")
	require.Len(t, rest.Items, 1)
	require.Equal(t, []string{}, rest.Items[0].Entitlements)
	staffOnly, err := auth.ListUsers(ctx, iam.UserQuery{Total: true, RootRole: staff, WithEntitlements: true})
	require.NoError(t, err)
	require.Equal(t, 1, *staffOnly.Total)
	require.Equal(t, ids[1], staffOnly.Items[0].ID)
	require.Equal(t, []string{"premium"}, staffOnly.Items[0].Entitlements)
	plain, err := auth.ListUsers(ctx, iam.UserQuery{})
	require.NoError(t, err)
	require.Nil(t, plain.Total, "no count unless asked")
}

// <schema>.users(id) is the one AuthKit column a host table may reference:
// the row stays through the recovery window and is deleted at purge, once the
// deletion callbacks succeed, taking the host's cascading rows with it.
func TestUsersIDIsAHostForeignKeyTarget(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	ctx := t.Context()
	purged := make(chan string, 1)
	deps := testDeps(pg.Pool)
	deps.OnPurge = func(_ context.Context, d iam.UserDeletion) error {
		select {
		case purged <- d.UserID:
		default:
		}
		return nil
	}
	auth, err := authkit.New(ctx, testConfig(t), deps)
	require.NoError(t, err)
	t.Cleanup(auth.Close)
	_, err = pg.Pool.Exec(ctx, `CREATE TABLE public.host_notes (
		id serial PRIMARY KEY,
		user_id uuid NOT NULL REFERENCES profiles.users(id) ON DELETE CASCADE,
		body text NOT NULL)`)
	require.NoError(t, err)
	u, err := auth.CreateUser(ctx, iam.NewUser{Email: "fk@example.test", Username: "fkuser"})
	require.NoError(t, err)
	_, err = pg.Pool.Exec(ctx, `INSERT INTO public.host_notes (user_id, body) VALUES ($1, 'hello')`, u.ID)
	require.NoError(t, err)
	notes := func() int {
		var n int
		require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM public.host_notes WHERE user_id = $1`, u.ID).Scan(&n))
		return n
	}

	require.NoError(t, itemErr(auth.DeleteUsers(ctx, iam.SystemActor(), []string{u.ID})))
	require.Equal(t, 1, notes(), "a soft-deleted account keeps its row")
	require.NoError(t, itemErr(auth.PurgeUsers(ctx, []string{u.ID})))
	require.NoError(t, auth.Start(ctx))
	select {
	case id := <-purged:
		require.Equal(t, u.ID, id)
	case <-time.After(15 * time.Second):
		t.Fatal("the purge never ran")
	}
	require.Eventually(t, func() bool { return notes() == 0 }, 15*time.Second, 25*time.Millisecond, "the purge deletes users(id) and cascades")
	_, err = auth.User(ctx, iam.UserByID(u.ID), authkit.IncludeDeleted())
	require.ErrorIs(t, err, iam.ErrUserNotFound)
}
