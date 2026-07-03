package authhttp

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

func TestRegisterInviteOnlyRequiresAndConsumesAccountInvite(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	cfg := newServerTestConfig()
	cfg.Registration.NativeUserMode = embedded.RegistrationModeInviteOnly
	srv, err := NewServer(newServerClient(t, cfg, pool), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("register-invite")
	suffix := uniqueSuffix()
	username := "ri" + suffix[len(suffix)-10:]
	body := `{"identifier":"` + email + `","username":"` + username + `","password":"Correct-password-12345"}`
	w := serveJSON(srv, http.MethodPost, "/register", body)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"registration_disabled"`)

	inviter, invite := createAccountInvite(t, srv, pool, email)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, inviter)
	})

	w = serveJSON(srv, http.MethodPost, "/register", `{"identifier":"`+email+`","username":"`+username+`","password":"Correct-password-12345","account_invite_token":"`+invite.Code+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	u, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	require.True(t, u.EmailVerified)
	requireAccountInviteConsumed(t, pool, invite.ID, u.ID)
}
