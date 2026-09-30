package apitest_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// A purge ends the recovery window by moving it to now, never by backdating
// the deletion, whether the account was live or deleted earlier.
func TestAccountPurgeKeepsTheRealDeletionTime(t *testing.T) {
	var mu sync.Mutex
	purged := map[string]iam.UserDeletion{}
	auth, _ := authtest.New(t, authtest.WithDeps(func(d *authkit.Deps) {
		d.OnPurge = func(_ context.Context, deletion iam.UserDeletion) error {
			mu.Lock()
			defer mu.Unlock()
			purged[deletion.UserID] = deletion
			return nil
		}
	}))
	ctx := t.Context()
	deletedAt := func(id string) time.Time {
		t.Helper()
		u, err := auth.User(ctx, iam.UserByID(id), authkit.IncludeDeleted())
		require.NoError(t, err)
		require.NotNil(t, u.DeletedAt)
		return *u.DeletedAt
	}

	earlier := authtest.NewUser(t, auth)
	require.NoError(t, opErr(auth.DeleteUsers(ctx, iam.SystemActor(), []string{earlier.ID})))
	softDeleted := deletedAt(earlier.ID)
	require.NoError(t, opErr(auth.PurgeUsers(ctx, []string{earlier.ID})))
	require.True(t, deletedAt(earlier.ID).Equal(softDeleted), "deleted_at keeps the soft-delete time")

	live := authtest.NewUser(t, auth)
	before := time.Now()
	require.NoError(t, opErr(auth.PurgeUsers(ctx, []string{live.ID})))
	liveDeleted := deletedAt(live.ID)
	require.WithinDuration(t, before, liveDeleted, time.Minute, "a purged live account is deleted now")
	for _, id := range []string{earlier.ID, live.ID} {
		res, err := auth.RestoreUsers(ctx, iam.SystemActor(), []string{id})
		require.NoError(t, err)
		require.ErrorIs(t, res[0].Err, iam.ErrAccountRecoveryExpired, "a purge closes the recovery window")
	}

	// The host's purge callback sees the deletion as stored: the real deletion
	// time, and the window's end moved to the purge.
	require.NoError(t, auth.Start(ctx))
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(purged) == 2
	}, 15*time.Second, 25*time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	deletion := purged[earlier.ID]
	require.True(t, deletion.DeletedAt.Equal(softDeleted))
	windowEnd := softDeleted.Add(iam.UserRecoveryPeriod)
	require.True(t, deletion.PurgeAt.Before(windowEnd) && !deletion.PurgeAt.Before(softDeleted), "purge_at moves to the purge")
	deletion = purged[live.ID]
	require.True(t, deletion.DeletedAt.Equal(liveDeleted))
	require.False(t, deletion.PurgeAt.Before(deletion.DeletedAt))
}

// A self-deleted account comes back only through a recovery proof its
// password earns: one confirmation wins, a ban, a later deletion cycle, a
// credential change and the end of the window each void the proof, and
// restoring never lifts a ban.
func TestAccountRecoveryPasswordConfirmationBoundary(t *testing.T) {
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.TwoFactor.Mode = iam.TwoFactorDisabled }))
	a := newAPI(t, auth)
	ctx := t.Context()
	user := authtest.NewUser(t, auth)
	password := user.Password
	login := func() response {
		return a.post("/password/login", "", map[string]string{"identifier": user.Email, "password": password})
	}
	old := expect(t, http.StatusOK, login()).answer(t).TokenSet
	remove := func() {
		t.Helper()
		require.NoError(t, opErr(auth.DeleteUsers(ctx, iam.UserActor(user.ID), []string{user.ID})))
	}
	proof := func() string {
		t.Helper()
		res := expect(t, http.StatusConflict, login())
		require.NotContains(t, res.String(), "access_token")
		require.NotContains(t, res.String(), "refresh_token")
		var body struct {
			Error struct {
				Code     string `json:"code"`
				Metadata struct {
					Recovery struct {
						Token string `json:"token"`
					} `json:"recovery"`
				} `json:"metadata"`
			} `json:"error"`
		}
		res.decode(t, &body)
		require.Equal(t, "account_recovery_required", body.Error.Code)
		require.NotEmpty(t, body.Error.Metadata.Recovery.Token)
		return body.Error.Metadata.Recovery.Token
	}
	confirm := func(token string) response {
		return a.post("/account/recovery/confirm", "", map[string]string{"token": token})
	}
	remove()
	expect(t, http.StatusUnauthorized, a.post("/password/login", "", map[string]string{"identifier": user.Email, "password": "wrong"}))
	token := proof()
	_, err := auth.Verify(ctx, token)
	require.Error(t, err, "recovery proof cannot authenticate as a normal access token")
	deleted, err := auth.User(ctx, iam.UserByID(user.ID), authkit.IncludeDeleted())
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt, "ordinary login never restores an account")
	// Concurrent confirmations have one winner, even with the same valid proof.
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Go(func() {
			res, err := a.send(request{method: http.MethodPost, path: "/account/recovery/confirm", body: map[string]string{"token": token}})
			if err != nil {
				res.status = 0
			}
			statuses <- res.status
		})
	}
	wg.Wait()
	close(statuses)
	winners := 0
	for status := range statuses {
		if status == http.StatusNoContent {
			winners++
		} else {
			require.Equal(t, http.StatusUnauthorized, status)
		}
	}
	require.Equal(t, 1, winners)
	expect(t, http.StatusUnauthorized, confirm(token))
	expect(t, http.StatusUnauthorized, a.post("/token", "", map[string]string{"grant_type": "refresh_token", "refresh_token": *old.RefreshToken}))
	expect(t, http.StatusOK, login())

	remove()
	bannedProof := proof()
	require.NoError(t, auth.Ban(ctx, iam.SystemActor(), user.ID, iam.Ban{}))
	expect(t, http.StatusUnauthorized, confirm(bannedProof))
	expect(t, http.StatusUnauthorized, login())
	require.NoError(t, opErr(auth.RestoreUsers(ctx, iam.SystemActor(), []string{user.ID})))
	require.Equal(t, http.StatusUnauthorized, login().status, "restoring an account never removes a ban")
	require.NoError(t, auth.Unban(ctx, iam.SystemActor(), user.ID))

	// A system restore and a later deletion cannot reuse an earlier proof.
	remove()
	stale := proof()
	require.NoError(t, opErr(auth.RestoreUsers(ctx, iam.SystemActor(), []string{user.ID})))
	remove()
	require.NotEqual(t, http.StatusNoContent, confirm(stale).status)
	// A credential change voids the proof.
	current := proof()
	password = "Rotated-recovery-password-2"
	_, err = auth.UpdateUser(ctx, iam.SystemActor(), user.ID, iam.UserUpdate{Password: &password})
	require.NoError(t, err)
	expect(t, http.StatusUnauthorized, confirm(current))
	// So does the end of the recovery window.
	current = proof()
	require.NoError(t, opErr(auth.PurgeUsers(ctx, []string{user.ID})))
	require.Equal(t, "account_recovery_expired", expect(t, http.StatusConflict, confirm(current)).code())
	require.Equal(t, "account_recovery_expired", expect(t, http.StatusConflict, login()).code())
}

// Staff restore a deleted account over HTTP only while they hold the
// authority: revoking the role refuses a token issued before.
func TestStaffAccountRestoreHTTPRequiresCurrentAuthority(t *testing.T) {
	rbac := authkit.NewRoles()
	staffRole := rbac.Root.Role("staff", rbac.Root.Users.Delete)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Roles = rbac
	}))
	a := newAPI(t, auth)
	ctx := t.Context()
	register := func(name string) (iam.TokenSet, string) {
		t.Helper()
		res := expect(t, http.StatusAccepted, a.post("/register", "", map[string]any{"identifier": name + "@example.test", "username": name, "password": "Correct-horse-account-recovery-1"}))
		tokens := res.answer(t).Nested
		claims, err := auth.Verify(ctx, tokens.AccessToken)
		require.NoError(t, err)
		return tokens, claims.UserID
	}
	deletedAt := func(id string) *time.Time {
		t.Helper()
		u, err := auth.User(ctx, iam.UserByID(id), authkit.IncludeDeleted())
		require.NoError(t, err)
		return u.DeletedAt
	}
	staff, staffID := register("restorestaff")
	target, targetID := register("restoretarget")
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staffID), staffRole)
	path := "/admin/users/" + targetID
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: path, token: staff.AccessToken}))
	expect(t, http.StatusUnauthorized, a.post(path+"/restore", "", nil))
	refused := expect(t, http.StatusUnauthorized, a.post(path+"/restore", target.AccessToken, nil))
	require.Equal(t, "session_revoked", refused.code(), "the deletion ended the target's own session")
	expect(t, http.StatusNoContent, a.post(path+"/restore", staff.AccessToken, nil))
	require.Nil(t, deletedAt(targetID))
	expect(t, http.StatusUnauthorized, a.post("/token", "", map[string]any{"grant_type": "refresh_token", "refresh_token": target.RefreshToken}))
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: path, token: staff.AccessToken}))
	authtest.RevokeRole(t, auth, iam.RootGroup(), iam.UserSubject(staffID), staffRole)
	expect(t, http.StatusForbidden, a.post(path+"/restore", staff.AccessToken, nil))
	require.NotNil(t, deletedAt(targetID), "revocation is immediate even for a previously accepted staff token")
	expect(t, http.StatusNotFound, a.get("/admin/erasure/backlog", staff.AccessToken))
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An account issuer that never started against the shared database blocks
// deletion. The wire stays internal_error; startup and the 500 log name why.
// It replaces the process logger, so it never runs in parallel.
func TestUserDeleteWithUnboundAccountIssuerLogsCause(t *testing.T) {
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const peer = "https://peer.example"
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Token.AccountIssuers = []string{authtest.Issuer, peer}
	}))
	require.Contains(t, logs.String(), "account deletion fails until these account issuers start")
	require.Contains(t, logs.String(), peer)

	token := authtest.SignIn(t, auth, authtest.NewUser(t, auth)).AccessToken
	res := expect(t, http.StatusInternalServerError, newAPI(t, auth).do(request{method: http.MethodDelete, path: "/user", token: token}))
	require.Equal(t, "internal_error", res.code())
	require.NotContains(t, res.String(), peer, "deployment topology stays off the wire")
	require.Contains(t, logs.String(), `failed_to_delete: authkit: account issuer \"`+peer+`\" must compose its River fleet before account deletion`)
}

// A Client from authtest.New soft-deletes and restores with nothing but its
// defaults: its managed River carries the account lifecycle.
func TestDeleteUsersOnAPlainTestClient(t *testing.T) {
	auth, _ := authtest.New(t)
	ctx := t.Context()
	u := authtest.NewUser(t, auth)
	require.NoError(t, opErr(auth.DeleteUsers(ctx, iam.SystemActor(), []string{u.ID})))
	deleted, err := auth.User(ctx, iam.UserByID(u.ID), authkit.IncludeDeleted())
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt)
	_, err = auth.User(ctx, iam.UserByID(u.ID))
	require.ErrorIs(t, err, iam.ErrUserNotFound)
	require.NoError(t, opErr(auth.RestoreUsers(ctx, iam.SystemActor(), []string{u.ID})))
	restored, err := auth.User(ctx, iam.UserByID(u.ID))
	require.NoError(t, err)
	require.Nil(t, restored.DeletedAt)
}
