package authhttp

import (
	"context"
	"net/http"
	"testing"

	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// #179: a banned user confirming a PHONE verification link must get 401 — the same
// as the email channel. Before the verify-confirm-twin unification the phone path
// lacked the ErrUserBanned→401 mapping the email path had, so a banned user hit a
// generic 500. This pins the unified behaviour.
func TestPhoneVerifyConfirm_BannedUserGets401(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	smsSender := &captureSMSSender{}
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithSMSSender(smsSender)), WithoutRateLimiter())
	require.NoError(t, err)

	phone := uniquePhone()
	userID := createPhoneUser(t, pool, srv, phone, "bannedphoneverify")

	w := serveJSON(srv, http.MethodPost, "/phone/verify/request", `{"phone_number":"`+phone+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	token := smsSender.verificationToken(t)

	// Ban the user after the verification link is issued but before they confirm.
	require.NoError(t, srv.svc.BanUser(ctx, userID, nil, nil, userID))

	w = serveJSON(srv, http.MethodPost, "/phone/verify/confirm", `{"token":"`+token+`","phone_number":"`+phone+`"}`)
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
}
