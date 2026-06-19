package core

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// fakeDirectoryProvider implements BOTH EntitlementsProvider (enrich) and
// EntitlementFilterProvider (reverse filter) so the directory can enrich rows and
// filter by entitlement without a real billing backend.
type fakeDirectoryProvider struct {
	byUser    map[string][]string // user id -> entitlement names (enrich)
	bySubject map[string][]string // entitlement -> subject ids (reverse filter)
	filterErr error
}

func (p *fakeDirectoryProvider) ListEntitlements(_ context.Context, userID string) ([]string, error) {
	return p.byUser[userID], nil
}

func (p *fakeDirectoryProvider) ListSubjectsWithEntitlement(_ context.Context, entitlement string) ([]string, error) {
	if p.filterErr != nil {
		return nil, p.filterErr
	}
	return p.bySubject[entitlement], nil
}

// TestAdminListUsers_GenericDirectory exercises issue #91 phase-1+2 against a real
// Postgres: generic search/role/status/sort + provider-backed entitlement filter,
// with NO hardcoded host role slugs. Skips without AUTHKIT_TEST_DATABASE_URL.
func TestAdminListUsers_GenericDirectory(t *testing.T) {
	pool := testPG(t)
	ctx := context.Background()
	svc := NewService(Options{Issuer: "https://test"}, Keyset{}).WithPostgres(pool)

	suffix := time.Now().UnixNano()
	prefix := fmt.Sprintf("dir%d", suffix)
	roleSlug := fmt.Sprintf("dir-role-%d", suffix)

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.global_roles WHERE slug = $1`, roleSlug)
	})

	// Four users: aaa, bbb, ccc, ddd (usernames sort deterministically).
	mk := func(name string) string {
		u, err := svc.CreateUser(ctx, fmt.Sprintf("%s-%s@test.example", prefix, name), prefix+name)
		require.NoError(t, err, "create user %s", name)
		return u.ID
	}
	idA := mk("aaa")
	idB := mk("bbb")
	idC := mk("ccc")
	idD := mk("ddd")

	// A generic global role on A + B (replaces the old hardcoded "taggers" etc.).
	require.NoError(t, svc.UpsertRoleBySlug(ctx, "Dir Role", roleSlug, nil))
	require.NoError(t, svc.AssignRoleBySlug(ctx, idA, roleSlug))
	require.NoError(t, svc.AssignRoleBySlug(ctx, idB, roleSlug))

	// Ban D.
	require.NoError(t, svc.BanUser(ctx, idD, nil, nil, idA))

	// all four, isolated to this run via search=prefix.
	base := AdminUserListOptions{Search: prefix, PageSize: 100}

	t.Run("search isolates this run; count matches", func(t *testing.T) {
		res, err := svc.AdminListUsers(ctx, base)
		require.NoError(t, err)
		require.EqualValues(t, 4, res.Total)
		require.Len(t, res.Users, 4)
		cnt, err := svc.AdminCountUsers(ctx, base)
		require.NoError(t, err)
		require.EqualValues(t, 4, cnt)
	})

	t.Run("generic role filter (no hardcoded slugs)", func(t *testing.T) {
		o := base
		o.Role = roleSlug
		res, err := svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.EqualValues(t, 2, res.Total)
		got := map[string]bool{}
		for _, u := range res.Users {
			got[u.ID] = true
		}
		require.True(t, got[idA] && got[idB])
	})

	t.Run("status filter: banned vs active", func(t *testing.T) {
		o := base
		o.Status = AdminUserStatusBanned
		res, err := svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.EqualValues(t, 1, res.Total)
		require.Equal(t, idD, res.Users[0].ID)

		o.Status = AdminUserStatusActive
		res, err = svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.EqualValues(t, 3, res.Total) // A, B, C (D is banned)
	})

	t.Run("sort by username asc/desc", func(t *testing.T) {
		o := base
		o.Sort = AdminUserSortUsername
		o.Desc = false
		res, err := svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.Equal(t, []string{idA, idB, idC, idD}, idsOf(res.Users))

		o.Desc = true
		res, err = svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.Equal(t, []string{idD, idC, idB, idA}, idsOf(res.Users))
	})

	t.Run("pagination", func(t *testing.T) {
		o := base
		o.Sort = AdminUserSortUsername
		o.Desc = false
		o.PageSize = 2
		o.Page = 2
		res, err := svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.EqualValues(t, 4, res.Total)
		require.Equal(t, []string{idC, idD}, idsOf(res.Users))
	})

	t.Run("entitlement filter delegates to provider", func(t *testing.T) {
		// No provider -> loud failure, not "everyone".
		o := base
		o.Entitlement = "premium"
		_, err := svc.AdminListUsers(ctx, o)
		require.ErrorIs(t, err, ErrEntitlementFilterUnavailable)

		// With a provider that says only A and C are premium.
		svc.WithEntitlements(&fakeDirectoryProvider{
			byUser:    map[string][]string{idA: {"premium"}, idC: {"premium"}},
			bySubject: map[string][]string{"premium": {idA, idC}},
		})
		o.Sort = AdminUserSortUsername
		o.Desc = false
		res, err := svc.AdminListUsers(ctx, o)
		require.NoError(t, err)
		require.EqualValues(t, 2, res.Total)
		require.Equal(t, []string{idA, idC}, idsOf(res.Users))
		// And the enrich path filled entitlements for the returned rows.
		require.Equal(t, []string{"premium"}, res.Users[0].Entitlements)

		// Count agrees with the filtered list.
		cnt, err := svc.AdminCountUsers(ctx, o)
		require.NoError(t, err)
		require.EqualValues(t, 2, cnt)
	})
}

func idsOf(users []AdminUser) []string {
	out := make([]string, len(users))
	for i := range users {
		out[i] = users[i].ID
	}
	return out
}
