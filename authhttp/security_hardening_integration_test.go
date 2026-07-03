package authhttp

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

func TestDestructiveUserRoutesRequireFreshAuthOrPassword(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	const pass = "Correct-password-12345"
	userID, token := stalePasswordUserToken(t, srv, pool, "destructive", pass)

	w := serveAuthJSON(srv, http.MethodDelete, "/user", `{}`, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "step_up_required")

	w = serveAuthJSON(srv, http.MethodDelete, "/user", `{"password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	u, err := srv.svc.AdminGetUser(ctx, userID)
	require.NoError(t, err)
	require.NotNil(t, u.DeletedAt)
}

func TestProviderUnlinkRequiresFreshAuthOrPassword(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	const pass = "Correct-password-12345"
	userID, token := stalePasswordUserToken(t, srv, pool, "unlink-provider", pass)
	require.NoError(t, srv.svc.LinkProviderByIssuer(ctx, userID, "https://accounts.example", "google", "subject-1", nil))

	w := serveAuthJSON(srv, http.MethodDelete, "/user/providers/google", `{}`, token)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "step_up_required")

	w = serveAuthJSON(srv, http.MethodDelete, "/user/providers/google", `{"password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Equal(t, 0, srv.svc.CountProviderLinks(ctx, userID))
}

func stalePasswordUserToken(t *testing.T, srv *Service, pool *pgxpool.Pool, prefix, pass string) (string, string) {
	t.Helper()
	ctx := context.Background()
	email := uniqueEmail(prefix)
	username := strings.ReplaceAll(prefix, "-", "") + uniqueSuffix()
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = srv.svc.Postgres().Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID)
	})
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at=$1 WHERE id=$2::uuid`, time.Now().Add(-time.Hour), sid)
	require.NoError(t, err)
	token, _, err := srv.svc.IssueAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, token
}
