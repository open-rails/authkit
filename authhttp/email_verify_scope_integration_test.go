package authhttp

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// AK security audit F1: the typed email-verification code must be email-scoped at
// the HTTP layer — a correct code presented with the wrong (or missing) email must
// be rejected, so a guessed code can't confirm whichever account happens to hold
// it. The correct (email, code) pair still succeeds.
func TestEmailVerifyConfirm_CodeIsEmailScoped(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithEmailSender(emailSender)), WithoutRateLimiter())
	require.NoError(t, err)

	victim := uniqueEmail("f1-victim")
	victimUser, err := srv.svc.CreateUser(ctx, victim, "f1victim")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, victimUser.ID) })

	w := serveJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+victim+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	code := emailSender.verificationCode(t)

	// The victim's code presented with an attacker-controlled email is rejected.
	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`","email":"f1-attacker@example.com"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// A missing email is rejected too.
	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	// The correct (email, code) pair still succeeds.
	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+code+`","email":"`+victim+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)
}
