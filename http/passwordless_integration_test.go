package authhttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type passwordlessTokenBody struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	ReturnTo     string `json:"return_to"`
}

func passwordlessTestServer(t *testing.T, autoRegister bool) (*Service, *captureEmailSender, *captureSMSSender) {
	t.Helper()
	pool := newServerTestPool(t)
	cfg := newServerTestConfig()
	cfg.Frontend.PasswordlessPath = "/wallet/login"
	cfg.Registration.PasswordlessLogin = true
	cfg.Registration.PasswordlessAutoRegistration = autoRegister
	emailSender := &captureEmailSender{}
	smsSender := &captureSMSSender{}
	srv, err := NewServer(cfg, pool, WithEmailSender(emailSender), WithSMSSender(smsSender), WithoutRateLimiter())
	require.NoError(t, err)
	return srv, emailSender, smsSender
}

func TestPasswordlessEmailOTPCreateIfMissingNoPasswordRow(t *testing.T) {
	ctx := context.Background()
	srv, emailSender, _ := passwordlessTestServer(t, true)
	pool := srv.svc.Postgres()
	email := uniqueEmail("pwless-create")

	w := serveJSON(srv, http.MethodPost, "/passwordless/start", `{"identifier":"`+email+`","mode":"code","return_to":"/checkout?plan=pro"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	code := emailSender.verificationCode(t)

	w = serveJSON(srv, http.MethodPost, "/passwordless/confirm", `{"identifier":"`+email+`","code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body passwordlessTokenBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)
	require.Equal(t, "/checkout?plan=pro", body.ReturnTo)
	require.ElementsMatch(t, []any{"email"}, unverifiedAccessClaims(t, body.AccessToken)["amr"])

	u, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.True(t, u.EmailVerified)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })

	var passwordRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.user_passwords WHERE user_id=$1::uuid`, u.ID).Scan(&passwordRows))
	require.Zero(t, passwordRows)
}

func TestPasswordlessRealHTTPServerEmailOTP(t *testing.T) {
	ctx := context.Background()
	srv, emailSender, _ := passwordlessTestServer(t, true)
	pool := srv.svc.Postgres()
	ts := httptest.NewServer(srv.APIHandler())
	t.Cleanup(ts.Close)

	post := func(path, body string) (int, []byte) {
		t.Helper()
		resp, err := http.Post(ts.URL+path, "application/json", strings.NewReader(body))
		require.NoError(t, err)
		defer resp.Body.Close()
		b, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		return resp.StatusCode, b
	}

	email := uniqueEmail("pwless-http")
	status, body := post("/passwordless/start", `{"identifier":"`+email+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, status, string(body))

	status, body = post("/passwordless/confirm", `{"identifier":"`+email+`","code":"`+emailSender.verificationCode(t)+`"}`)
	require.Equal(t, http.StatusOK, status, string(body))
	var tokens passwordlessTokenBody
	require.NoError(t, json.Unmarshal(body, &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.ElementsMatch(t, []any{"email"}, unverifiedAccessClaims(t, tokens.AccessToken)["amr"])

	u, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	require.True(t, u.EmailVerified)
}

func TestPasswordlessEmailMagicLinkExistingUserAndTokenReuse(t *testing.T) {
	ctx := context.Background()
	srv, emailSender, _ := passwordlessTestServer(t, true)
	pool := srv.svc.Postgres()
	email := uniqueEmail("pwless-link")
	user, err := srv.svc.CreateUser(ctx, email, "pwlesslink"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	w := serveJSON(srv, http.MethodPost, "/passwordless/start", `{"email":"`+email+`","mode":"link","return_to":"https://evil.example/steal"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	token := emailSender.verificationToken(t)
	require.Contains(t, emailSender.verificationURL(t), "https://example.com/wallet/login?channel=email&token=")

	w = serveJSON(srv, http.MethodPost, "/passwordless/confirm", `{"token":"`+token+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body passwordlessTokenBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Empty(t, body.ReturnTo, "absolute external return_to must be dropped")
	require.ElementsMatch(t, []any{"email"}, unverifiedAccessClaims(t, body.AccessToken)["amr"])

	u, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	require.Equal(t, user.ID, u.ID)
	require.True(t, u.EmailVerified)

	w = serveJSON(srv, http.MethodPost, "/passwordless/confirm", `{"token":"`+token+`"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"invalid_or_expired_code"`)
}

func TestPasswordlessSMSOTPAndMagicLink(t *testing.T) {
	ctx := context.Background()
	srv, _, smsSender := passwordlessTestServer(t, true)
	pool := srv.svc.Postgres()

	phone := uniquePhone()
	w := serveJSON(srv, http.MethodPost, "/passwordless/start", `{"phone_number":"`+phone+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	code := smsSender.verificationCode(t)
	w = serveJSON(srv, http.MethodPost, "/passwordless/confirm", `{"phone_number":"`+phone+`","code":"`+code+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var otpBody passwordlessTokenBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &otpBody))
	require.ElementsMatch(t, []any{"sms"}, unverifiedAccessClaims(t, otpBody.AccessToken)["amr"])

	autoUser, err := srv.svc.GetUserByPhone(ctx, phone)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, autoUser.ID) })
	var passwordRows int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.user_passwords WHERE user_id=$1::uuid`, autoUser.ID).Scan(&passwordRows))
	require.Zero(t, passwordRows)

	existingPhone := uniquePhone()
	existing, err := srv.svc.CreateUser(ctx, uniqueEmail("pwless-sms-existing"), "pwlesssms"+uniqueSuffix())
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE profiles.users SET phone_number=$1, phone_verified=false WHERE id=$2::uuid`, existingPhone, existing.ID)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, existing.ID) })

	w = serveJSON(srv, http.MethodPost, "/passwordless/start", `{"identifier":"`+existingPhone+`","mode":"link"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	token := smsSender.verificationToken(t)
	w = serveJSON(srv, http.MethodPost, "/passwordless/confirm", `{"token":"`+token+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var linkBody passwordlessTokenBody
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &linkBody))
	require.ElementsMatch(t, []any{"sms"}, unverifiedAccessClaims(t, linkBody.AccessToken)["amr"])

	u, err := srv.svc.GetUserByPhone(ctx, existingPhone)
	require.NoError(t, err)
	require.Equal(t, existing.ID, u.ID)
	require.True(t, u.PhoneVerified)
}

func TestPasswordlessDisabledAntiEnumerationAndCodeAttemptCap(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	disabledSrv, err := NewServer(newServerTestConfig(), pool, WithEmailSender(&captureEmailSender{}), WithoutRateLimiter())
	require.NoError(t, err)
	w := serveJSON(disabledSrv, http.MethodPost, "/passwordless/start", `{"identifier":"`+uniqueEmail("pwless-disabled")+`"}`)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())

	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin = true
	unknownSender := &captureEmailSender{}
	noAutoSrv, err := NewServer(cfg, pool, WithEmailSender(unknownSender), WithoutRateLimiter())
	require.NoError(t, err)
	w = serveJSON(noAutoSrv, http.MethodPost, "/passwordless/start", `{"identifier":"`+uniqueEmail("pwless-unknown")+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	require.Empty(t, unknownSender.verifyCode, "unknown contact should not receive a challenge when auto-registration is off")

	cfg.Registration.PasswordlessAutoRegistration = true
	attemptSender := &captureEmailSender{}
	attemptSrv, err := NewServer(cfg, pool, WithEmailSender(attemptSender), WithoutRateLimiter())
	require.NoError(t, err)
	email := uniqueEmail("pwless-attempt")
	w = serveJSON(attemptSrv, http.MethodPost, "/passwordless/start", `{"identifier":"`+email+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	code := attemptSender.verificationCode(t)
	for i := 0; i < 5; i++ {
		w = serveJSON(attemptSrv, http.MethodPost, "/passwordless/confirm", `{"identifier":"`+email+`","code":"WRONG`+uniqueSuffix()+`"}`)
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	}
	w = serveJSON(attemptSrv, http.MethodPost, "/passwordless/confirm", `{"identifier":"`+email+`","code":"`+code+`"}`)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"invalid_or_expired_code"`)

	_, err = attemptSrv.svc.GetUserByEmail(ctx, email)
	require.Error(t, err)
}

func TestPasswordlessGeneratedUsernameCollision(t *testing.T) {
	ctx := context.Background()
	srv, emailSender, _ := passwordlessTestServer(t, true)
	pool := srv.svc.Postgres()
	collidingUsername := "walletcollision" + uniqueSuffix()
	existing, err := srv.svc.CreateUser(ctx, uniqueEmail("pwless-collision-existing"), collidingUsername)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, existing.ID) })

	email := collidingUsername + "@example.com"
	w := serveJSON(srv, http.MethodPost, "/passwordless/start", `{"identifier":"`+email+`","mode":"code"}`)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	w = serveJSON(srv, http.MethodPost, "/passwordless/confirm", `{"identifier":"`+email+`","code":"`+emailSender.verificationCode(t)+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	u, err := srv.svc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, u.ID) })
	require.NotNil(t, u.Username)
	require.NotEqual(t, collidingUsername, *u.Username)
}
