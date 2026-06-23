package authhttp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	core "github.com/open-rails/authkit/core"
	"github.com/stretchr/testify/require"
)

var resetVerifySeq atomic.Int64

type captureEmailSender struct {
	mu          sync.Mutex
	resetToken  string
	verifyCode  string
	verifyToken string
}

func (s *captureEmailSender) SendVerification(_ context.Context, _, _ string, msg core.VerificationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCode = msg.Code
	s.verifyToken = tokenFromURL(msg.LinkURL)
	return nil
}

func (s *captureEmailSender) SendPasswordResetLink(_ context.Context, _, _, resetURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetToken = tokenFromURL(resetURL)
	return nil
}

func (s *captureEmailSender) SendLoginCode(context.Context, string, string, string) error { return nil }
func (s *captureEmailSender) SendWelcome(context.Context, string, string) error           { return nil }

func (s *captureEmailSender) passwordResetToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.resetToken)
	return s.resetToken
}

func (s *captureEmailSender) verificationCode(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyCode)
	return s.verifyCode
}

func (s *captureEmailSender) verificationToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyToken)
	return s.verifyToken
}

type captureSMSSender struct {
	mu          sync.Mutex
	resetToken  string
	verifyCode  string
	verifyToken string
}

func (s *captureSMSSender) SendVerification(_ context.Context, _ string, msg core.VerificationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCode = msg.Code
	s.verifyToken = tokenFromURL(msg.LinkURL)
	return nil
}

func (s *captureSMSSender) SendPasswordResetLink(_ context.Context, _ string, resetURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetToken = tokenFromURL(resetURL)
	return nil
}

func (s *captureSMSSender) SendLoginCode(context.Context, string, string) error { return nil }

func (s *captureSMSSender) passwordResetToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.resetToken)
	return s.resetToken
}

func (s *captureSMSSender) verificationCode(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyCode)
	return s.verifyCode
}

func (s *captureSMSSender) verificationToken(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyToken)
	return s.verifyToken
}

func tokenFromURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Query().Get("token"))
}

func TestPasswordResetConfirmConsumesTokenDirectly(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := NewServer(newServerTestConfig(), pool, WithEmailSender(emailSender), WithSMSSender(smsSender), WithoutRateLimiter())
	require.NoError(t, err)

	suffix := uniqueSuffix()
	email := "reset-email-" + suffix + "@example.com"
	username := "resetemail" + suffix
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	w := serveJSON(srv, http.MethodPost, "/email/password/reset/request", `{"email":"`+email+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	token := emailSender.passwordResetToken(t)

	w = serveJSON(srv, http.MethodPost, "/email/password/reset/confirm", `{"token":"`+token+`","new_password":"New-password-12345"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"ok":true`)

	_, _, err = srv.svc.PasswordLogin(ctx, email, "New-password-12345", nil)
	require.NoError(t, err)

	w = serveJSON(srv, http.MethodPost, "/email/password/reset/confirm", `{"token":"`+token+`","new_password":"Another-password-12345"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"invalid_or_expired_token"`)

	w = serveJSON(srv, http.MethodPost, "/email/password/reset/confirm", `{"reset_session":"legacy","new_password":"Another-password-12345"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"invalid_request"`)

	phone := uniquePhone()
	phoneUser, err := srv.svc.CreateUser(ctx, "reset-phone-"+suffix+"@example.com", "resetphone"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, phoneUser.ID) })
	_, err = pool.Exec(ctx, `UPDATE profiles.users SET phone_number=$1, phone_verified=false WHERE id=$2::uuid`, phone, phoneUser.ID)
	require.NoError(t, err)

	w = serveJSON(srv, http.MethodPost, "/phone/password/reset/request", `{"phone_number":"`+phone+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	phoneToken := smsSender.passwordResetToken(t)

	w = serveJSON(srv, http.MethodPost, "/phone/password/reset/confirm", `{"token":"`+phoneToken+`","new_password":"Phone-password-12345"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"user_id":"`+phoneUser.ID+`"`)

	for _, path := range []string{
		"/email/password/reset/confirm-link",
		"/phone/password/reset/confirm-link",
	} {
		w = serveJSON(srv, http.MethodPost, path, `{"token":"unused"}`)
		require.Equal(t, http.StatusNotFound, w.Code, path)
	}
}

func TestVerificationConfirmAcceptsCodeOrToken(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := NewServer(newServerTestConfig(), pool, WithEmailSender(emailSender), WithSMSSender(smsSender), WithoutRateLimiter())
	require.NoError(t, err)

	emailCode := uniqueEmail("verify-code")
	emailCodeUser, err := srv.svc.CreateUser(ctx, emailCode, "verifycodeuser")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, emailCodeUser.ID) })
	w := serveJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+emailCode+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"code":"`+emailSender.verificationCode(t)+`","email":"`+emailCode+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)

	emailToken := uniqueEmail("verify-token")
	emailTokenUser, err := srv.svc.CreateUser(ctx, emailToken, "verifytokenuser")
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, emailTokenUser.ID) })
	w = serveJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+emailToken+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"token":"`+emailSender.verificationToken(t)+`","email":"`+emailToken+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)

	phoneCode := uniquePhone()
	phoneCodeUser := createPhoneUser(t, pool, srv, phoneCode, "verifyphonecode")
	w = serveJSON(srv, http.MethodPost, "/phone/verify/request", `{"phone_number":"`+phoneCode+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	w = serveJSON(srv, http.MethodPost, "/phone/verify/confirm", `{"phone_number":"`+phoneCode+`","code":"`+smsSender.verificationCode(t)+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)
	_ = phoneCodeUser

	phoneToken := uniquePhone()
	createPhoneUser(t, pool, srv, phoneToken, "verifyphonetoken")
	w = serveJSON(srv, http.MethodPost, "/phone/verify/request", `{"phone_number":"`+phoneToken+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	w = serveJSON(srv, http.MethodPost, "/phone/verify/confirm", `{"token":"`+smsSender.verificationToken(t)+`","phone_number":"`+phoneToken+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)

	for _, path := range []string{"/email/verify/confirm-link", "/phone/verify/confirm-link"} {
		w = serveJSON(srv, http.MethodPost, path, `{"token":"unused"}`)
		require.Equal(t, http.StatusNotFound, w.Code, path)
	}
}

func serveJSON(srv *Service, method, path, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	srv.APIHandler().ServeHTTP(w, r)
	return w
}

func requireTokenResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body["access_token"])
	require.NotEmpty(t, body["refresh_token"])
}

func uniqueEmail(prefix string) string {
	return prefix + "-" + uniqueSuffix() + "@example.com"
}

func uniquePhone() string {
	suffix := uniqueSuffix()
	if len(suffix) > 10 {
		suffix = suffix[len(suffix)-10:]
	}
	return "+1555" + suffix
}

func uniqueSuffix() string {
	n := resetVerifySeq.Add(1)
	return fmt.Sprintf("%d%03d", time.Now().UnixNano(), n)
}

func createPhoneUser(t *testing.T, pool *pgxpool.Pool, srv *Service, phone, username string) string {
	t.Helper()
	ctx := context.Background()
	user, err := srv.svc.CreateUser(ctx, uniqueEmail(username), username+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	_, err = pool.Exec(ctx, `UPDATE profiles.users SET phone_number=$1, phone_verified=false WHERE id=$2::uuid`, phone, user.ID)
	require.NoError(t, err)
	return user.ID
}
