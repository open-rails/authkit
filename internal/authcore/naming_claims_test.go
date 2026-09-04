package authcore

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func namingTestService(t *testing.T, config authkit.NamingConfig) (*Service, func(time.Time)) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	var clock atomic.Int64
	clock.Store(time.Now().UTC().Truncate(time.Microsecond).UnixMicro())
	svc := NewService(Config{Naming: config, RBAC: []PersonaDef{{Name: "merchant", Parent: RootPersona}}}, Keyset{}, WithPostgres(pg.Pool), WithNamingClock(func() time.Time { return time.UnixMicro(clock.Load()).UTC() }))
	require.NoError(t, svc.SeedPermissionGroupContainment(context.Background()))
	_, err := svc.EnsureRootGroup(context.Background())
	require.NoError(t, err)
	return svc, func(now time.Time) { clock.Store(now.UnixMicro()) }
}

func TestNamingUserAndGroupBoundaries(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"user", "group"} {
		t.Run(kind, func(t *testing.T) {
			svc, setTime := namingTestService(t, authkit.NamingConfig{})
			owner, err := svc.CreateUser(ctx, "owner@example.test", "owner-account")
			require.NoError(t, err)
			var id string
			if kind == "user" {
				u, err := svc.CreateUser(ctx, "identity@example.test", "original")
				require.NoError(t, err)
				id = u.ID
			} else {
				id, err = svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "original", OwnerSubjectID: owner.ID})
				require.NoError(t, err)
			}
			rename := func(from, to string) error {
				if kind == "user" {
					return svc.UpdateUsername(ctx, id, to)
				}
				resolved, err := svc.ResolveGroupSlug(ctx, "merchant", from)
				if err != nil {
					return err
				}
				_, err = svc.UpdateGroupInstanceAs(ctx, owner.ID, resolved.ID, authkit.GroupInstanceUpdate{Slug: &to})
				return err
			}
			resolve := func(name string) (authkit.NameResolution, error) {
				if kind == "user" {
					return svc.ResolveUsername(ctx, name)
				}
				return svc.ResolveGroupSlug(ctx, "merchant", name)
			}
			start := svc.namingNow()
			require.NoError(t, rename("original", "second"))
			alias, err := resolve("original")
			require.NoError(t, err)
			require.Equal(t, id, alias.ID)
			require.Equal(t, "second", alias.CanonicalName)
			require.True(t, alias.IsAlias)
			require.True(t, start.Add(90*24*time.Hour).Equal(*alias.AliasExpiresAt))
			require.NoError(t, rename("original", "second")) // alias-addressed authorized no-op
			require.ErrorIs(t, rename("second", "third"), authkit.ErrRenameRateLimited)
			setTime(start.Add(72*time.Hour - time.Microsecond))
			require.ErrorIs(t, rename("second", "third"), authkit.ErrRenameRateLimited)
			setTime(start.Add(72 * time.Hour))
			require.NoError(t, rename("original", "third"))
			alias, err = resolve("original")
			require.NoError(t, err)
			require.Equal(t, "third", alias.CanonicalName)
			require.True(t, start.Add(90*24*time.Hour).Equal(*alias.AliasExpiresAt))
			setTime(start.Add(90*24*time.Hour - time.Microsecond))
			_, err = resolve("original")
			require.NoError(t, err)
			setTime(start.Add(90 * 24 * time.Hour))
			_, err = resolve("original")
			require.Error(t, err)
			// Reclaim through actual creation at the same injected expiry boundary.
			var replacement string
			if kind == "user" {
				u, err := svc.CreateUser(ctx, "replacement@example.test", "original")
				require.NoError(t, err)
				replacement = u.ID
			} else {
				replacement, err = svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "original"})
				require.NoError(t, err)
			}
			claimed, err := resolve("original")
			require.NoError(t, err)
			require.Equal(t, replacement, claimed.ID)
			require.NotEqual(t, id, replacement)
			require.False(t, claimed.IsAlias)
		})
	}
}

func TestNamingConcurrentOwnerRenamesPreserveAliases(t *testing.T) {
	zero := time.Duration(0)
	svc, _ := namingTestService(t, authkit.NamingConfig{RenameInterval: &zero})
	ctx := context.Background()
	u, err := svc.CreateUser(ctx, "race@example.test", "start")
	require.NoError(t, err)
	begin := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"first", "second"} {
		go func() { <-begin; results <- svc.UpdateUsername(ctx, u.ID, name) }()
	}
	close(begin)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	for _, name := range []string{"start", "first", "second"} {
		resolved, err := svc.ResolveUsername(ctx, name)
		require.NoError(t, err)
		require.Equal(t, u.ID, resolved.ID)
	}
}

func TestNamingCreateVersusRenameHasOneOwner(t *testing.T) {
	for i := 0; i < 8; i++ {
		svc, _ := namingTestService(t, authkit.NamingConfig{})
		ctx := context.Background()
		u, err := svc.CreateUser(ctx, "a@example.test", "outgoing")
		require.NoError(t, err)
		begin := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var renameErr, createErr error
		go func() { defer wg.Done(); <-begin; renameErr = svc.UpdateUsername(ctx, u.ID, "contested") }()
		go func() { defer wg.Done(); <-begin; _, createErr = svc.CreateUser(ctx, "b@example.test", "contested") }()
		close(begin)
		wg.Wait()
		require.NotEqual(t, renameErr == nil, createErr == nil)
		var count int
		require.NoError(t, svc.pg.QueryRow(ctx, `SELECT count(*) FROM profiles.name_claims WHERE owner_kind='user' AND name='contested'`).Scan(&count))
		require.Equal(t, 1, count)
	}
}

func TestNamingReservationsProtectTrustedWriters(t *testing.T) {
	svc, _ := namingTestService(t, authkit.NamingConfig{})
	ctx := context.Background()
	u, err := svc.CreateUser(ctx, "a@example.test", "reserved_name")
	require.NoError(t, err)
	require.NoError(t, svc.UpdateUsername(ctx, u.ID, "current_name"))
	_, err = svc.pg.Exec(ctx, `INSERT INTO profiles.users(username) VALUES ('reserved_name')`)
	require.Error(t, err)
	_, err = svc.ImportUser(ctx, ImportUserInput{Email: "b@example.test", Username: "reserved_name"})
	require.Error(t, err)
	bulk, err := svc.ImportUsers(ctx, []ImportUserInput{{Email: "b@example.test", Username: "reserved_name"}, {Email: "c@example.test", Username: "available_name"}})
	require.NoError(t, err)
	require.Equal(t, ImportStatusSkipped, bulk.Results[0].Status)
	require.Equal(t, ImportStatusInserted, bulk.Results[1].Status)
	_, err = svc.pg.Exec(ctx, `UPDATE profiles.users SET username='untracked' WHERE id=$1::uuid`, u.ID)
	require.Error(t, err)
	retained, err := svc.ResolveUsername(ctx, "reserved_name")
	require.NoError(t, err)
	require.Equal(t, u.ID, retained.ID)
}

func TestNamingRetentionModesAndRenameBack(t *testing.T) {
	ctx := context.Background()
	zero := time.Duration(0)
	for _, mode := range []authkit.FormerNameRetentionMode{authkit.FormerNamesFinite, authkit.FormerNamesForever, authkit.FormerNamesImmediate} {
		t.Run(string(mode), func(t *testing.T) {
			svc, setTime := namingTestService(t, authkit.NamingConfig{RenameInterval: &zero, FormerNames: authkit.FormerNameRetentionConfig{Mode: mode}})
			u, err := svc.CreateUser(ctx, "mode@example.test", "old_name")
			require.NoError(t, err)
			require.NoError(t, svc.UpdateUsername(ctx, u.ID, "new_name"))
			old, err := svc.ResolveUsername(ctx, "old_name")
			if mode == authkit.FormerNamesImmediate {
				require.True(t, errors.Is(err, pgx.ErrNoRows))
			} else {
				require.NoError(t, err)
				require.Equal(t, u.ID, old.ID)
			}
			require.NoError(t, svc.UpdateUsername(ctx, u.ID, "old_name"))
			setTime(svc.namingNow().Add(100 * 24 * time.Hour))
			_, err = svc.ResolveUsername(ctx, "new_name")
			if mode == authkit.FormerNamesForever {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestNamingGroupConcurrentRenamesAndRelease(t *testing.T) {
	zero := time.Duration(0)
	svc, setTime := namingTestService(t, authkit.NamingConfig{RenameInterval: &zero})
	ctx := context.Background()
	owner, err := svc.CreateUser(ctx, "groupowner@example.test", "groupowner")
	require.NoError(t, err)
	gid, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "original", OwnerSubjectID: owner.ID})
	require.NoError(t, err)
	originalTime := svc.namingNow()
	begin := make(chan struct{})
	results := make(chan error, 2)
	for _, name := range []string{"first", "second"} {
		go func() {
			<-begin
			_, err := svc.UpdateGroupInstanceAs(ctx, owner.ID, gid, authkit.GroupInstanceUpdate{Slug: &name})
			results <- err
		}()
	}
	close(begin)
	require.NoError(t, <-results)
	require.NoError(t, <-results)
	current, err := svc.groupStore().GroupInstanceByID(ctx, gid)
	require.NoError(t, err)
	for _, name := range []string{"original", "first", "second"} {
		resolution, err := svc.ResolveGroupSlug(ctx, "merchant", name)
		require.NoError(t, err)
		require.Equal(t, gid, resolution.ID)
	}
	require.NoError(t, svc.DeletePermissionGroup(ctx, "merchant", current.InstanceSlug, authkit.DeletePermissionGroupOptions{ReleaseSlug: true}))
	replacement, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: current.InstanceSlug})
	require.NoError(t, err)
	require.NotEqual(t, gid, replacement)
	_, err = svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "original"})
	require.ErrorIs(t, err, authkit.ErrGroupSlugTaken)
	// Dead identities do not forward, but earlier reservations are still honored.
	_, err = svc.ResolveGroupSlug(ctx, "merchant", "original")
	require.ErrorIs(t, err, authkit.ErrGroupNotFound)
	setTime(originalTime.Add(90 * 24 * time.Hour))
	_, err = svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "original"})
	require.NoError(t, err)
}

func TestNamingDisabledNoOpAndSupportOverride(t *testing.T) {
	disabled := false
	svc, _ := namingTestService(t, authkit.NamingConfig{Enabled: &disabled})
	ctx := context.Background()
	user, err := svc.CreateUser(ctx, "disabled@example.test", "disabled_user")
	require.NoError(t, err)
	require.NoError(t, svc.UpdateUsername(ctx, user.ID, "disabled_user"))
	require.ErrorIs(t, svc.UpdateUsername(ctx, user.ID, "new_user"), authkit.ErrRenamesDisabled)
	require.NoError(t, svc.UpdateUsernameForce(ctx, user.ID, "new_user"))
	owner, err := svc.CreateUser(ctx, "other@example.test", "other_user")
	require.NoError(t, err)
	require.ErrorIs(t, svc.UpdateUsernameForce(ctx, owner.ID, "disabled_user"), authkit.ErrOwnerSlugTaken)
	gid, err := svc.CreatePermissionGroup(ctx, CreatePermissionGroupRequest{Persona: "merchant", InstanceSlug: "disabled", OwnerSubjectID: user.ID})
	require.NoError(t, err)
	same, next := "disabled", "changed"
	_, err = svc.UpdateGroupInstanceAs(ctx, owner.ID, gid, authkit.GroupInstanceUpdate{Slug: &same})
	require.ErrorIs(t, err, authkit.ErrInsufficientRoleAuthority)
	_, err = svc.UpdateGroupInstanceAs(ctx, user.ID, gid, authkit.GroupInstanceUpdate{Slug: &same})
	require.NoError(t, err)
	_, err = svc.UpdateGroupInstanceAs(ctx, user.ID, gid, authkit.GroupInstanceUpdate{Slug: &next})
	require.ErrorIs(t, err, authkit.ErrRenamesDisabled)
}

func TestNamingPolicyChangeDoesNotRewriteReservations(t *testing.T) {
	zero := time.Duration(0)
	svc, setTime := namingTestService(t, authkit.NamingConfig{RenameInterval: &zero})
	ctx := context.Background()
	user, err := svc.CreateUser(ctx, "promise@example.test", "promised")
	require.NoError(t, err)
	start := svc.namingNow()
	require.NoError(t, svc.UpdateUsername(ctx, user.ID, "middle"))
	// Simulate a service restart with a different deployment policy and the same DB.
	next := NewService(Config{Naming: authkit.NamingConfig{RenameInterval: &zero, FormerNames: authkit.FormerNameRetentionConfig{Mode: authkit.FormerNamesImmediate}}}, Keyset{}, WithPostgres(svc.pg), WithNamingClock(svc.namingNow))
	require.NoError(t, next.UpdateUsername(ctx, user.ID, "current"))
	_, err = next.ResolveUsername(ctx, "middle")
	require.ErrorIs(t, err, pgx.ErrNoRows)
	resolution, err := next.ResolveUsername(ctx, "promised")
	require.NoError(t, err)
	require.Equal(t, user.ID, resolution.ID)
	setTime(start.Add(90 * 24 * time.Hour))
	_, err = next.ResolveUsername(ctx, "promised")
	require.ErrorIs(t, err, pgx.ErrNoRows)
}
