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
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

var resetVerifySeq atomic.Int64

type captureEmailSender struct {
	mu          sync.Mutex
	resetToken  string
	resetURL    string
	verifyCode  string
	verifyToken string
	verifyURL   string
}

func (s *captureEmailSender) SendVerification(_ context.Context, _, _ string, msg embedded.VerificationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCode = msg.Code
	s.verifyURL = msg.LinkURL
	s.verifyToken = tokenFromURL(msg.LinkURL)
	return nil
}

func (s *captureEmailSender) SendPasswordResetLink(_ context.Context, _, _, resetURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetURL = resetURL
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

func (s *captureEmailSender) passwordResetURL(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.resetURL)
	return s.resetURL
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

func (s *captureEmailSender) verificationURL(t *testing.T) string {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	require.NotEmpty(t, s.verifyURL)
	return s.verifyURL
}

type captureSMSSender struct {
	mu          sync.Mutex
	resetToken  string
	resetURL    string
	verifyCode  string
	verifyToken string
	verifyURL   string
}

func (s *captureSMSSender) SendVerification(_ context.Context, _ string, msg embedded.VerificationMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.verifyCode = msg.Code
	s.verifyURL = msg.LinkURL
	s.verifyToken = tokenFromURL(msg.LinkURL)
	return nil
}

func (s *captureSMSSender) SendPasswordResetLink(_ context.Context, _ string, resetURL string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resetURL = resetURL
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
	require.Contains(t, emailSender.passwordResetURL(t), "https://example.com/reset?channel=email&token=")

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

func TestAuthKitBuiltLinksRedirectWithoutConsumingToken(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	srv, err := NewServer(newServerTestConfig(), pool, WithEmailSender(emailSender), WithoutRateLimiter())
	require.NoError(t, err)

	suffix := uniqueSuffix()
	email := "link-reset-" + suffix + "@example.com"
	user, err := srv.svc.CreateUser(ctx, email, "linkreset"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	w := serveJSON(srv, http.MethodPost, "/email/password/reset/request", `{"email":"`+email+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	resetToken := emailSender.passwordResetToken(t)
	w = serveRequest(srv, http.MethodGet, "/email/password/reset/confirm?token="+url.QueryEscape(resetToken)+"&return_to=%2Fsubscribe%3Fplan%3Dpro", "")
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "https", loc.Scheme)
	require.Equal(t, "example.com", loc.Host)
	require.Equal(t, "/reset", loc.Path)
	require.Equal(t, "ready", loc.Query().Get("status"))
	require.Equal(t, "email", loc.Query().Get("channel"))
	require.Equal(t, resetToken, loc.Query().Get("token"))
	require.Equal(t, "/subscribe?plan=pro", loc.Query().Get("return_to"))

	w = serveJSON(srv, http.MethodPost, "/email/password/reset/confirm", `{"token":"`+resetToken+`","new_password":"New-password-12345"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	verifyEmail := "link-verify-" + suffix + "@example.com"
	verifyUser, err := srv.svc.CreateUser(ctx, verifyEmail, "linkverify"+suffix)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, verifyUser.ID) })
	w = serveJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+verifyEmail+`"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Contains(t, emailSender.verificationURL(t), "https://example.com/verify?channel=email&token=")
	verifyToken := emailSender.verificationToken(t)
	w = serveRequest(srv, http.MethodGet, "/email/verify/confirm?token="+url.QueryEscape(verifyToken)+"&return_to=https%3A%2F%2Fevil.example", "")
	require.Equal(t, http.StatusFound, w.Code, w.Body.String())
	loc, err = url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "/verify", loc.Path)
	require.Empty(t, loc.Query().Get("return_to"))
	require.Equal(t, verifyToken, loc.Query().Get("token"))

	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"token":"`+verifyToken+`","email":"`+verifyEmail+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	requireTokenResponse(t, w)
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

func TestUnifiedVerificationRoutesHandleContactChanges(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := NewServer(newServerTestConfig(), pool, WithEmailSender(emailSender), WithSMSSender(smsSender), WithoutRateLimiter())
	require.NoError(t, err)

	const pass = "Correct-password-12345"
	userID, token, _ := createPasswordUserAccessToken(t, pool, srv, "contact-change", pass)

	for _, path := range []string{"/user/email", "/user/phone"} {
		w := serveAuthJSON(srv, http.MethodPost, path, `{}`, token)
		require.Equal(t, http.StatusNotFound, w.Code, path)
	}

	newEmail := uniqueEmail("change-email")
	w := serveAuthJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+newEmail+`","password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	emailCode := emailSender.verificationCode(t)
	require.NotEmpty(t, emailSender.verificationToken(t))

	w = serveAuthJSON(srv, http.MethodPost, "/email/verify/confirm", `{"email":"`+uniqueEmail("wrong-email")+`","code":"`+emailCode+`"}`, token)
	require.NotEqual(t, http.StatusOK, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodPost, "/email/verify/confirm", `{"email":"`+newEmail+`","code":"`+emailCode+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var gotEmail string
	var emailVerified bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT email, email_verified FROM profiles.users WHERE id=$1::uuid`, userID).Scan(&gotEmail, &emailVerified))
	require.Equal(t, newEmail, gotEmail)
	require.True(t, emailVerified)

	newPhone := uniquePhone()
	w = serveAuthJSON(srv, http.MethodPost, "/phone/verify/request", `{"phone_number":"`+newPhone+`","password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	phoneCode := smsSender.verificationCode(t)
	require.NotEmpty(t, smsSender.verificationToken(t))

	w = serveAuthJSON(srv, http.MethodPost, "/phone/verify/confirm", `{"phone_number":"`+uniquePhone()+`","code":"`+phoneCode+`"}`, token)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodPost, "/phone/verify/confirm", `{"phone_number":"`+newPhone+`","code":"`+phoneCode+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var gotPhone string
	var phoneVerified bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT phone_number, phone_verified FROM profiles.users WHERE id=$1::uuid`, userID).Scan(&gotPhone, &phoneVerified))
	require.Equal(t, newPhone, gotPhone)
	require.True(t, phoneVerified)
}

func TestUnifiedVerificationContactChangeTokenAndFreshAuth(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := NewServer(newServerTestConfig(), pool, WithEmailSender(emailSender), WithSMSSender(smsSender), WithoutRateLimiter())
	require.NoError(t, err)

	const pass = "Correct-password-12345"
	userID, token, _ := createPasswordUserAccessToken(t, pool, srv, "contact-token", pass)
	newEmail := uniqueEmail("change-token")

	w := serveAuthJSON(srv, http.MethodPost, "/email/verify/request", `{"email":"`+newEmail+`"}`, token)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	emailToken := emailSender.verificationToken(t)

	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"email":"`+newEmail+`","token":"`+emailToken+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var gotEmail string
	require.NoError(t, pool.QueryRow(ctx, `SELECT email FROM profiles.users WHERE id=$1::uuid`, userID).Scan(&gotEmail))
	require.Equal(t, newEmail, gotEmail)

	w = serveJSON(srv, http.MethodPost, "/email/verify/confirm", `{"email":"`+newEmail+`","token":"`+emailToken+`"}`)
	require.NotEqual(t, http.StatusOK, w.Code, w.Body.String())

	staleUserID, _, sid := createPasswordUserAccessToken(t, pool, srv, "contact-stale", pass)
	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at = now() - interval '1 hour', auth_methods = ARRAY['pwd']::text[] WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	staleToken, _, err := srv.svc.IssueAccessToken(ctx, staleUserID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w = serveAuthJSON(srv, http.MethodPost, "/phone/verify/request", `{"phone_number":"`+uniquePhone()+`"}`, staleToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"step_up_required"`)

	w = serveAuthJSON(srv, http.MethodPost, "/phone/verify/request", `{"phone_number":"`+uniquePhone()+`","password":"`+pass+`"}`, staleToken)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.NotEmpty(t, smsSender.verificationToken(t))
}

func serveJSON(srv *Service, method, path, body string) *httptest.ResponseRecorder {
	return serveRequest(srv, method, path, body)
}

func serveRequest(srv *Service, method, path, body string) *httptest.ResponseRecorder {
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

func createPasswordUserAccessToken(t *testing.T, pool *pgxpool.Pool, srv *Service, prefix, pass string) (string, string, string) {
	t.Helper()
	ctx := context.Background()
	user, err := srv.svc.CreateUser(ctx, uniqueEmail(prefix), prefix+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)
	return user.ID, token, sid
}
