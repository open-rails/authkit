package authhttp

// #312: every contact flow has ONE route and the channel comes from the
// identifier. Both channels run through the merged routes against real
// Postgres with capturing senders.

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type captureSender interface {
	verificationCode(*testing.T) string
	verificationToken(*testing.T) string
	passwordResetToken(*testing.T) string
}

func TestContactChannelRoutes_BothChannels(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := newServer(newServerClient(t, newServerTestConfig(), pool, withEmailSender(emailSender), withSMSSender(smsSender)), WithoutRateLimiter())
	require.NoError(t, err)

	// seed creates an unverified account for the identifier so the verify and
	// reset flows have something to act on (an unknown identifier is a 404).
	seedEmail := func(t *testing.T) string {
		email := uniqueEmail("chan")
		u, err := srv.svc.CreateUser(ctx, email, "ch"+uniqueSuffix()[8:])
		require.NoError(t, err)
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
		return email
	}
	seedPhone := func(t *testing.T) string {
		phone := uniquePhone()
		createPhoneUser(t, pool, srv, phone, "ch"+uniqueSuffix()[8:])
		return phone
	}

	cases := []struct {
		channel string
		seed    func(*testing.T) string
		sender  captureSender
	}{
		{"email", seedEmail, emailSender},
		{"phone", seedPhone, smsSender},
	}
	for _, tc := range cases {
		t.Run(tc.channel, func(t *testing.T) {
			// Verify by typed code.
			byCode := tc.seed(t)
			w := serveJSON(srv, http.MethodPost, "/verify/request", `{"identifier":"`+byCode+`"}`)
			require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
			w = serveJSON(srv, http.MethodPost, "/verify/confirm", `{"identifier":"`+byCode+`","code":"`+tc.sender.verificationCode(t)+`"}`)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			requireTokenResponse(t, w)

			// Verify by link token with NO identifier: the server finds the
			// channel by trying both.
			byToken := tc.seed(t)
			w = serveJSON(srv, http.MethodPost, "/verify/request", `{"identifier":"`+byToken+`"}`)
			require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
			w = serveJSON(srv, http.MethodPost, "/verify/confirm", `{"token":"`+tc.sender.verificationToken(t)+`"}`)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			requireTokenResponse(t, w)

			// Password reset for the account verified above.
			w = serveJSON(srv, http.MethodPost, "/password/reset/request", `{"identifier":"`+byCode+`"}`)
			require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
			w = serveJSON(srv, http.MethodPost, "/password/reset/confirm", `{"token":"`+tc.sender.passwordResetToken(t)+`","new_password":"Reset-password-12345"}`)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		})
	}

	// An identifier that is neither is rejected with the phone validation
	// code (no "@" means phone), never silently accepted.
	w := serveJSON(srv, http.MethodPost, "/verify/request", `{"identifier":"not-an-identifier"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrInvalidPhoneNumber))
	w = serveJSON(srv, http.MethodPost, "/verify/request", `{}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), string(ErrInvalidRequest))
}
