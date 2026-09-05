package authhttp

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// #288/6: the authenticated email-change flow end to end — request with the
// password, confirm with the code sent to the NEW address, the row changes, and
// the code is single-use.
func TestEmailChangeRequestConfirmReplay(t *testing.T) {
	forEachStore(t, testEmailChangeRequestConfirmReplay)
}

func testEmailChangeRequestConfirmReplay(t *testing.T, store ephemeralStore) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	sender := &captureEmailSender{}
	opts := append(store.engineOpts(), embedded.WithEmailSender(sender))
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, opts...), WithoutRateLimiter())
	require.NoError(t, err)

	email, pass := newCookieTestUser(t, pool, srv, "email-change")
	user, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	access, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)
	newEmail := uniqueEmail("email-change-new")

	w := serveAuthJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+newEmail+`","password":"`+pass+`"}`, access)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	code := sender.verificationCode(t)

	var current string
	require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM profiles.users WHERE id=$1::uuid`, user.ID).Scan(&current))
	require.Equal(t, email, current, "the address must not change before confirmation")

	w = serveAuthJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`","email":"`+newEmail+`"}`, access)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM profiles.users WHERE id=$1::uuid`, user.ID).Scan(&current))
	require.Equal(t, newEmail, current)

	replay := serveAuthJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`","email":"`+newEmail+`"}`, access)
	require.Equal(t, http.StatusBadRequest, replay.Code, replay.Body.String())
	require.Contains(t, replay.Body.String(), string(ErrInvalidOrExpiredCode))
	require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM profiles.users WHERE id=$1::uuid`, user.ID).Scan(&current))
	require.Equal(t, newEmail, current)
}
