package engine

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func usernameEngine(t *testing.T, names []string) *Engine {
	t.Helper()
	cfg := testConfig()
	cfg.Username.RandomNames = names
	return newTestEngine(t, cfg, config.Deps{Postgres: testdb.ScratchPostgres(t).Pool})
}

func TestGeneratedUsernameDoesNotExposeContact(t *testing.T) {
	e := usernameEngine(t, nil)
	name, err := e.GenerateUsername(t.Context())
	require.NoError(t, err)
	require.Regexp(t, `^user[0-9]{3}$`, name)
}

func TestGeneratedUsernameConfiguredPoolAndCollision(t *testing.T) {
	e := usernameEngine(t, []string{"Naruto", "Sakura"})
	for range 20 {
		name, err := e.GenerateUsername(t.Context())
		require.NoError(t, err)
		require.Regexp(t, `^(naruto|sakura)[0-9]{3}$`, name)
	}
	// The initial candidate was free when offered, then another signup claimed it.
	_, err := e.createUser(t.Context(), "existing@example.test", "Naruto000")
	require.NoError(t, err)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			out, err := e.registerAccount(t.Context(), accountRegistration{
				GeneratedUsername: true,
				User:              newAccount{Username: "Naruto000", Email: uniqueEmail("race")},
			})
			if err != nil {
				t.Errorf("generated registration: %v", err)
				return
			}
			u, err := e.getUserByID(t.Context(), out.ID)
			if err != nil {
				t.Error(err)
				return
			}
			if !regexp.MustCompile(`^(naruto|sakura)[0-9]{3}$`).MatchString(deref(u.Username)) {
				t.Errorf("unexpected generated name %q", deref(u.Username))
			}
		}(i)
	}
	wg.Wait()
	_, err = e.registerAccount(t.Context(), accountRegistration{User: newAccount{Username: "Naruto000", Email: uniqueEmail("manual")}})
	require.ErrorIs(t, err, iam.ErrUsernameInUse, "a chosen name must never be silently replaced")
}

func TestGeneratedUsernameExhaustionAndStoreFailure(t *testing.T) {
	e := usernameEngine(t, []string{"Naruto"})
	// Occupy the entire configured pool in this disposable database.
	_, err := e.pg.Exec(t.Context(), `INSERT INTO users (id, username) SELECT gen_random_uuid(), 'Naruto' || lpad(n::text,3,'0') FROM generate_series(0,999) n`)
	require.NoError(t, err)
	_, err = e.GenerateUsername(t.Context())
	require.ErrorIs(t, err, iam.ErrUsernameInUse)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = e.GenerateUsername(ctx)
	require.ErrorIs(t, err, context.Canceled)
}

func TestGeneratedUsernameConfigValidation(t *testing.T) {
	for _, names := range [][]string{{}, {"Paul Fidika"}, {""}, {"Naruto", "naruto"}, {"1Naruto"}, {strings.Repeat("x", 30)}} {
		_, err := config.NormalizeUsername(config.UsernameConfig{RandomNames: names})
		require.Error(t, err, "pool=%v", names)
	}
	input := []string{"Naruto"}
	c, err := config.NormalizeUsername(config.UsernameConfig{RandomNames: input})
	require.NoError(t, err)
	input[0] = "changed"
	require.Equal(t, "Naruto", c.RandomNames[0])
	e := &Engine{cfg: config.Config{Username: c}}
	// Invalid syntax must be refused before attempting any database lookup.
	err = e.CheckUsername(t.Context(), "Paul Fidika")
	require.Error(t, err)
	detail, ok := iam.AsError(err)
	require.True(t, ok)
	require.Equal(t, "username_invalid_characters", detail.Code())
	require.False(t, errors.Is(err, iam.ErrUsernameInUse))
}

func TestUsernameCaseCanonicalization(t *testing.T) {
	e := usernameEngine(t, nil)
	u, err := e.CreateUser(t.Context(), iam.NewUser{Username: "Paul"})
	require.NoError(t, err)
	require.Equal(t, "paul", u.Username)
	row, err := e.getUserByID(t.Context(), u.ID)
	require.NoError(t, err)
	require.Equal(t, "paul", deref(row.Username))
	_, err = e.CreateUser(t.Context(), iam.NewUser{Username: "pAuL"})
	require.ErrorIs(t, err, iam.ErrUsernameInUse)
	for _, name := range []string{"Paul", "PAUL", "paul"} {
		require.ErrorIs(t, e.CheckUsername(t.Context(), name), iam.ErrUsernameInUse)
		resolved, err := e.ResolveUsername(t.Context(), name)
		require.NoError(t, err)
		require.Equal(t, u.ID, resolved.ID)
		require.Equal(t, "paul", resolved.CanonicalName)
	}
	// A historical spelling is normalized only in projections, not by reading it.
	_, err = e.pg.Exec(t.Context(), `UPDATE users SET username='PaUl' WHERE id=$1`, u.ID)
	require.NoError(t, err)
	row, err = e.getUserByID(t.Context(), u.ID)
	require.NoError(t, err)
	require.Equal(t, "PaUl", deref(row.Username))
	require.Equal(t, "paul", publicUser(row, e.namingNow()).Username)
	require.Equal(t, "paul", accountUserInfo(*row).Username)
	next := "KaKaShI"
	changed, err := e.UpdateUser(t.Context(), iam.SystemIdentity(), u.ID, iam.UserUpdate{Username: &next})
	require.NoError(t, err)
	require.Equal(t, "kakashi", changed.Username)
	alias, err := e.ResolveUsername(t.Context(), "PAUL")
	require.NoError(t, err)
	require.True(t, alias.IsAlias)
	require.Equal(t, "kakashi", alias.CanonicalName)
	state, err := e.UserNamingState(t.Context(), u.ID)
	require.NoError(t, err)
	require.Equal(t, "paul", state.Aliases[0].Name)
}
