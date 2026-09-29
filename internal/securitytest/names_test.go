package securitytest

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/stretchr/testify/require"
)

func withDeps(fn func(*authkit.Deps)) hostOption {
	return func(c *hostConfig) { fn(&c.deps) }
}

// TestSecurityUsernameChecks: CheckUsername answers every name an account
// holds (current or live alias, any case; deleted, banned or purged owner)
// with one identical username_in_use that carries nothing about the owner.
// ResolveUsername forwards only live aliases of live accounts.
func TestSecurityUsernameChecks(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withDeps(func(d *authkit.Deps) {
		d.NameAdmission = func(_ context.Context, r iam.NameAdmissionRequest) error {
			if strings.Contains(strings.ToLower(r.RequestedName), "forbidden") {
				return errors.New("a brand name")
			}
			return nil
		}
	}))
	ctx := context.Background()
	op := iam.SystemActor()
	owner := h.newAccount("chkowner")
	renamed := unique("chkrenamed")
	_, err := h.auth.UpdateUser(ctx, op, owner.id, iam.UserUpdate{Username: &renamed})
	require.NoError(t, err)
	deleted, banned, purged := h.newAccount("chkdeleted"), h.newAccount("chkbanned"), h.newAccount("chkpurged")
	require.NoError(t, opErr(h.auth.DeleteUsers(ctx, op, []string{deleted.id})))
	require.NoError(t, h.auth.Ban(ctx, op, banned.id, iam.Ban{Reason: "spam"}))
	_, err = h.pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, purged.id)
	require.NoError(t, err)

	var first string
	for _, name := range []string{renamed, strings.ToUpper(renamed), owner.username, strings.ToUpper(owner.username), " " + deleted.username + " ", banned.username, purged.username} {
		err := h.auth.CheckUsername(ctx, name)
		require.ErrorIs(t, err, iam.ErrUsernameInUse, name)
		rec := httptest.NewRecorder()
		iam.WriteError(rec, err)
		body := rec.Body.String()
		for _, a := range []account{owner, deleted, banned, purged} {
			require.NotContains(t, body, a.id)
			require.NotContains(t, body, a.email)
		}
		if first == "" {
			first = body
		}
		require.Equal(t, first, body, "%s: the answer differs by owner", name)
	}

	for name, code := range map[string]errmodel.Code{
		"ab": errmodel.CodeUsernameTooShort, "1abcd": errmodel.CodeUsernameMustStartWithLetter,
		"has space": errmodel.CodeUsernameInvalidCharacters, "a@bcd": errmodel.CodeUsernameCannotContainAt,
	} {
		e, ok := iam.AsError(h.auth.CheckUsername(ctx, name))
		require.True(t, ok, name)
		require.Equal(t, code.String(), e.Code(), name)
	}
	require.ErrorIs(t, h.auth.CheckUsername(ctx, unique("forbidden")), errmodel.ErrNameAdmissionRefused)
	require.NoError(t, h.auth.CheckUsername(ctx, unique("chkfree")))

	t.Run("resolve", func(t *testing.T) {
		r, err := h.auth.ResolveUsername(ctx, strings.ToUpper(owner.username))
		require.NoError(t, err)
		require.Equal(t, owner.id, r.ID)
		require.Equal(t, renamed, r.CanonicalName)
		require.True(t, r.IsAlias)
		require.NotNil(t, r.AliasExpiresAt)
		require.WithinDuration(t, time.Now().Add(iam.DefaultFormerNameRetention), *r.AliasExpiresAt, time.Hour)
		r, err = h.auth.ResolveUsername(ctx, renamed)
		require.NoError(t, err)
		require.Equal(t, iam.NameResolution{ID: owner.id, CanonicalName: renamed}, r)
		r, err = h.auth.ResolveUsername(ctx, banned.username)
		require.NoError(t, err)
		require.Equal(t, banned.id, r.ID)
		for _, name := range []string{deleted.username, purged.username, unique("nobody")} {
			_, err := h.auth.ResolveUsername(ctx, name)
			require.ErrorIs(t, err, iam.ErrUserNotFound, name)
		}
	})

	t.Run("an expired alias is free and resolves nobody", func(t *testing.T) {
		_, err := h.pool.Exec(ctx, `UPDATE name_claims SET expires_at=now()-interval '1 minute' WHERE owner_kind='user' AND name=lower($1) AND NOT canonical`, owner.username)
		require.NoError(t, err)
		require.NoError(t, h.auth.CheckUsername(ctx, owner.username))
		_, err = h.auth.ResolveUsername(ctx, owner.username)
		require.ErrorIs(t, err, iam.ErrUserNotFound)
	})
}
