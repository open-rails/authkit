package remote_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/remote"
	"github.com/open-rails/authkit/server"
	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"
)

// newParityPair builds the real embedded engine on a real Postgres plus a
// remote.Client driving that same engine over the generated management-API wire,
// so every assertion below runs twice: once in process, once across the
// transport a remote host would actually use.
func newParityPair(t *testing.T, issuer string) (*embedded.Client, *remote.Client, *pgxpool.Pool) {
	t.Helper()
	dsn := os.Getenv("AUTHKIT_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("AUTHKIT_TEST_DATABASE_URL not set; skipping DB-backed test")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	client, err := embedded.New(embedded.Config{
		Environment: "development",
		Token: embedded.TokenConfig{
			Issuer:            issuer,
			IssuedAudiences:   []string{"authkit"},
			ExpectedAudiences: []string{"authkit"},
		},
		Keys: embedded.KeysConfig{Path: t.TempDir(), AllowEphemeralDevKeys: true},
	}, pool)
	require.NoError(t, err)

	ts := httptest.NewServer(server.NewHandler(client, "tok"))
	t.Cleanup(ts.Close)
	return client, remote.New(ts.URL, "tok"), pool
}

// TestPublicUserRef_CarriesNoEmailField is the type-level half of #268: the
// reason hosts can nest a resolved author straight into a response body is that
// there is no email on the type to forget an `omitempty` on. Asserted by
// reflection so a future widening of the projection trips this test rather than
// a production response.
func TestPublicUserRef_CarriesNoEmailField(t *testing.T) {
	rt := reflect.TypeOf(authkit.PublicUserRef{})
	for i := 0; i < rt.NumField(); i++ {
		name := strings.ToLower(rt.Field(i).Name)
		require.NotContains(t, name, "email",
			"PublicUserRef must never carry an email-shaped field; found %q", rt.Field(i).Name)
	}
	// The privileged twin still does — that difference IS the feature.
	priv := reflect.TypeOf(authkit.UserRef{})
	_, hasEmail := priv.FieldByName("Email")
	require.True(t, hasEmail, "UserRef is the privileged projection and keeps Email")
}

func TestPublicDisplayName_FallsBackForAbsentAndTombstonedIDs(t *testing.T) {
	const id = "0198c0de-0000-4000-8000-00000000abcd"
	refs := map[string]authkit.PublicUserRef{
		"live": {ID: "live", Username: "someone"},
		id:     {ID: id, Deleted: true},
	}
	require.Equal(t, "someone", authkit.PublicDisplayName(refs, "live"))
	require.Equal(t, "user-0198c0de", authkit.PublicDisplayName(refs, id),
		"a tombstone renders the stable placeholder, never the deleted account's old name")
	require.Equal(t, "user-nobody-a", authkit.PublicDisplayName(refs, "nobody-at-all"),
		"an id the batch never resolved still renders, with no branch at the call site")
}

// TestPublicUsersByIDs_DB is #268 end to end on a real database and across both
// transports: one batch call resolves live authors, tombstones deleted ones,
// keeps banned ones visible, and omits ids that were never users.
func TestPublicUsersByIDs_DB(t *testing.T) {
	client, rc, _ := newParityPair(t, "https://public-proj.example.com")
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	mk := func(tag string) string {
		u, err := client.CreateUser(ctx, "pub"+tag+suffix+"@example.com", "pub"+tag+suffix)
		require.NoError(t, err)
		return u.ID
	}
	live, banned, deleted := mk("live"), mk("banned"), mk("gone")

	avatar := "avatars/" + live + ".webp"
	require.NoError(t, client.UpdateAvatarURL(ctx, live, &avatar))
	reason := "spam"
	require.NoError(t, client.BanUser(ctx, banned, &reason, nil, live))
	res, err := client.SoftDeleteUsers(ctx, []string{deleted})
	require.NoError(t, err)
	require.Len(t, res, 1)

	const neverExisted = "0198c0de-dead-4000-8000-000000000001"
	ids := []string{live, banned, deleted, neverExisted}

	for name, c := range map[string]authkit.Client{"embedded": client, "remote": rc} {
		t.Run(name, func(t *testing.T) {
			refs, err := c.PublicUsersByIDs(ctx, ids)
			require.NoError(t, err)

			l := refs[live]
			require.Equal(t, "publive"+suffix, l.Username)
			require.Equal(t, avatar, l.AvatarURL)
			require.False(t, l.Deleted)
			require.False(t, l.CreatedAt.IsZero(), "join date is part of the public profile shape")
			require.Equal(t, "publive"+suffix, l.DisplayName())

			b, ok := refs[banned]
			require.True(t, ok, "a ban is an access decision, not a visibility one: banned authors still render")
			require.Equal(t, "pubbanned"+suffix, b.Username)
			require.False(t, b.Deleted)

			d, ok := refs[deleted]
			require.True(t, ok, "a soft-deleted author resolves to a tombstone, not a hole")
			require.True(t, d.Deleted)
			require.Empty(t, d.Username, "a tombstone must not publish the deleted account's name")
			require.Empty(t, d.AvatarURL)
			require.True(t, d.CreatedAt.IsZero(), "a tombstone publishes no attribute of the deleted account, not even its join date")
			require.Equal(t, "user-"+deleted[:8], d.DisplayName())

			_, ok = refs[neverExisted]
			require.False(t, ok, "an id that matches no row stays absent from the map")
			require.Equal(t, "user-0198c0de", authkit.PublicDisplayName(refs, neverExisted))

			// The privileged twin is what still carries the address, and the two
			// must be reading the same people.
			priv, err := c.UsersByIDs(ctx, []string{live})
			require.NoError(t, err)
			require.Equal(t, "publive"+suffix+"@example.com", priv[live].Email)
			require.Equal(t, priv[live].Username, l.Username)
		})
	}
}

// TestUserLivenessByIDs_DB is #267's read half: one batch call returns the same
// ban/delete/reserve verdict the login gate applies, plus identity fresh as of
// that lookup — the two things a host was calling IsUserAllowed + AdminGetUser
// to get.
func TestUserLivenessByIDs_DB(t *testing.T) {
	client, rc, pool := newParityPair(t, "https://liveness.example.com")
	ctx := context.Background()
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	mk := func(tag string) string {
		u, err := client.CreateUser(ctx, "live"+tag+suffix+"@example.com", "live"+tag+suffix)
		require.NoError(t, err)
		return u.ID
	}
	ok, banned, deleted, expired, reserved := mk("ok"), mk("ban"), mk("del"), mk("exp"), mk("res")

	reason := "spam"
	require.NoError(t, client.BanUser(ctx, banned, &reason, nil, ok))
	_, err := client.SoftDeleteUsers(ctx, []string{deleted})
	require.NoError(t, err)

	// A temporary ban that has already run out must read as LIVE — the same lazy
	// unban the single-user login gate performs. BanUser refuses a past `until`,
	// so the elapsed state is written directly: this is the row a live database
	// holds the moment a timed ban expires and nobody has logged in since.
	until := time.Now().UTC().Add(time.Hour)
	require.NoError(t, client.BanUser(ctx, expired, &reason, &until, ok))
	_, err = pool.Exec(ctx,
		`UPDATE profiles.users SET banned_until = now() - interval '1 hour' WHERE id = $1::uuid`, expired)
	require.NoError(t, err)

	require.NoError(t, client.PatchUserMetadata(ctx, reserved, map[string]any{"reserved": true}))

	const neverExisted = "0198c0de-dead-4000-8000-000000000002"
	ids := []string{ok, banned, deleted, expired, reserved, neverExisted}

	for name, c := range map[string]authkit.Client{"embedded": client, "remote": rc} {
		t.Run(name, func(t *testing.T) {
			live, err := c.UserLivenessByIDs(ctx, ids)
			require.NoError(t, err)

			require.True(t, live[ok].Allowed)
			require.False(t, live[banned].Allowed, "a banned account is not live")
			require.False(t, live[deleted].Allowed, "a soft-deleted account is not live")
			require.False(t, live[reserved].Allowed, "a reserved account is not live")
			require.True(t, live[expired].Allowed, "an expired temporary ban must not keep denying")

			_, present := live[neverExisted]
			require.False(t, present, "an unknown id is absent — a gate must read that as a denial")

			// The verdict agrees with the single-user gate it shares its policy with.
			for _, id := range []string{ok, banned, deleted, expired, reserved} {
				single, err := c.IsUserAllowed(ctx, id)
				require.NoError(t, err)
				require.Equal(t, single, live[id].Allowed,
					"batch liveness and IsUserAllowed must never disagree (id %s)", id)
			}

			// Identity rides along, so nothing needs the admin directory for it.
			require.Equal(t, "liveok"+suffix, live[ok].Username)
			require.Equal(t, "liveok"+suffix+"@example.com", live[ok].Email)
		})
	}

	// Freshness: rename, then the very next liveness read reports the new name.
	renamed := "renamed" + suffix
	require.NoError(t, client.UpdateUsername(ctx, ok, renamed))
	after, err := rc.UserLivenessByIDs(ctx, []string{ok})
	require.NoError(t, err)
	require.Equal(t, renamed, after[ok].Username,
		"liveness returns identity fresh as of the lookup — that is what replaces the per-request AdminGetUser")
}
