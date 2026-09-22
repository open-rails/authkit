package authhttp

import (
	"context"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/verify"
	"github.com/stretchr/testify/require"
)

func TestRootPermissionSnapshotLoginRefreshWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Token.RootPermissionSnapshot = true
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.RBAC = []embedded.PersonaDef{embedded.IntrinsicRootPersona(embedded.RoleDef{Name: "moderator", Permissions: []string{"root:posts:*"}})}
	f := newAccountFlow(t, pg.Pool, ephemeralStore{name: "memory"}, cfg)
	ctx := context.Background()
	const email, password = "snapshot@example.test", "Correct-horse-snapshot-password-1"
	registered := f.expect(http.StatusAccepted, f.post("/register", map[string]any{"identifier": email, "username": "snapshot", "password": password}))
	verified := func(token string) verify.Claims {
		t.Helper()
		claims, err := f.service.Verifier().Verify(ctx, token)
		require.NoError(t, err)
		return claims
	}
	assertDecision := func(claims verify.Claims, want bool) {
		t.Helper()
		allowed, complete := claims.RootPermissionSnapshot("root:posts:delete")
		require.True(t, complete)
		require.Equal(t, want, allowed)
	}
	ordinary := verified(registered.Tokens.AccessToken)
	assertDecision(ordinary, false)
	login := func() flowResponse {
		return f.expect(200, f.post("/password/login", map[string]any{"identifier": email, "password": password}))
	}
	initial := login()
	assertDecision(verified(initial.AccessToken), false)
	client := f.service.svc
	require.NoError(t, client.OperatorAssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(ordinary.UserID), "moderator"))
	// Granting a role does not rewrite an already issued complete negative.
	assertDecision(ordinary, false)
	refreshed := f.expect(200, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": initial.RefreshToken}))
	positive := verified(refreshed.AccessToken)
	assertDecision(positive, true)
	allowed, err := client.Can(ctx, authkit.UserSubject(ordinary.UserID), authkit.RootGroup(), "root:posts:delete")
	require.NoError(t, err)
	require.True(t, allowed)
	require.NoError(t, client.OperatorUnassignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(ordinary.UserID), "moderator"))
	assertDecision(positive, true) // token-time snapshot; the live gate catches revocation.
	allowed, err = client.Can(ctx, authkit.UserSubject(ordinary.UserID), authkit.RootGroup(), "root:posts:delete")
	require.NoError(t, err)
	require.False(t, allowed)
	assertDecision(verified(login().AccessToken), false)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(ordinary.UserID), authkit.OwnerRole))
	owner := verified(login().AccessToken)
	assertDecision(owner, true)
	allowed, complete := owner.RootPermissionSnapshot("root:users:ban")
	require.True(t, allowed && complete)
	allowed, complete = owner.RootPermissionSnapshot("project:posts:delete")
	require.False(t, allowed || complete)
	backup, err := client.CreateUser(ctx, "snapshot-backup@example.test", "snapshot-backup")
	require.NoError(t, err)
	require.NoError(t, client.OperatorAssignGroupRole(ctx, authkit.RootGroup(), authkit.UserSubject(backup.ID), authkit.OwnerRole))
	require.NoError(t, client.BanUser(ctx, ordinary.UserID, nil, nil, ordinary.UserID))
	live, _, err := f.service.Verifier().IsLive(ctx, owner)
	require.NoError(t, err)
	require.False(t, live)
	f.expect(http.StatusUnauthorized, f.post("/token", map[string]any{"grant_type": "refresh_token", "refresh_token": refreshed.RefreshToken}))
}
