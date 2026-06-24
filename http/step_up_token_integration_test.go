package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/password"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestPasswordStepUpReturnsFreshAccessToken(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerTestConfig(), pool, WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("stepup-password")
	username := "stepuppwd" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/step-up/password", `{"password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)
	require.Equal(t, "Bearer", body.TokenType)
	require.Positive(t, body.ExpiresIn)

	claims := unverifiedAccessClaims(t, body.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd"}, claims["amr"])
	require.Equal(t, core.AssuranceLevelPassword, claims["acr"])
}

// A password-only re-auth on a session that was established with MFA must NOT
// strip its otp/mfa AMR: re-proving identity unions methods, it never downgrades
// assurance, so a later MFA-required step-up gate still passes.
func TestPasswordStepUpDoesNotDowngradeMFASession(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerTestConfig(), pool, WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("stepup-nodowngrade")
	username := "stepupnodg" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	// Simulate a session that proved a second factor at login.
	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET auth_methods = ARRAY['pwd','otp','mfa']::text[] WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	token, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/step-up/password", `{"password":"`+pass+`"}`, token)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))

	claims := unverifiedAccessClaims(t, body.AccessToken)
	require.ElementsMatch(t, []any{"pwd", "otp", "mfa"}, claims["amr"], "password re-auth must preserve MFA methods")
	require.Equal(t, core.AssuranceLevelMFA, claims["acr"], "password re-auth must not downgrade MFA assurance")
}

func TestTOTPStepUpReturnsFreshMFAAccessToken(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("stepup-totp")
	username := "stepupotp" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	require.NotEmpty(t, enrollment.Secret)

	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	stepUpCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", `{"code":"`+stepUpCode+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body.AccessToken)

	claims := unverifiedAccessClaims(t, body.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd", "otp", "mfa"}, claims["amr"])
	require.Equal(t, core.AssuranceLevelMFA, claims["acr"])
}

func TestTwoFactorStepUpMethodOptionsAndStaleMFARetry(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("stepup-options")
	username := "stepupopts" + uniqueSuffix()
	const pass = "Correct-password-12345"
	user, err := srv.svc.CreateUser(ctx, email, username)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	hash, err := password.HashArgon2id(pass)
	require.NoError(t, err)
	require.NoError(t, srv.svc.UpsertPasswordHash(ctx, user.ID, hash, "argon2id", nil))

	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	setupToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w := serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"email"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	phone := "+15555550123"
	_, err = srv.svc.Enable2FA(ctx, user.ID, "sms", &phone)
	require.NoError(t, err)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	w = serveAuthJSON(srv, http.MethodGet, "/me", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var me struct {
		StepUpMethods []string               `json:"step_up_methods"`
		StepUp2FA     stepUpOptionsTestShape `json:"step_up_2fa"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &me))
	require.Contains(t, me.StepUpMethods, "2fa")
	requireStepUp2FAOptions(t, me.StepUp2FA, []string{"email", "sms", "totp"}, "email")

	_, err = pool.Exec(ctx, `UPDATE profiles.refresh_sessions SET last_authenticated_at = now() - interval '1 hour', auth_methods = ARRAY['pwd','otp','mfa']::text[] WHERE id=$1::uuid`, sid)
	require.NoError(t, err)
	staleToken, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", map[string]any{"sid": sid})
	require.NoError(t, err)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, staleToken)
	require.Equal(t, http.StatusForbidden, w.Code, w.Body.String())
	var stepUpRequired struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				StepUpMethods []string               `json:"step_up_methods"`
				StepUp2FA     stepUpOptionsTestShape `json:"step_up_2fa"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stepUpRequired))
	require.Equal(t, "step_up_required", stepUpRequired.Error.Code)
	require.Contains(t, stepUpRequired.Error.Metadata.StepUpMethods, "2fa")
	requireStepUp2FAOptions(t, stepUpRequired.Error.Metadata.StepUp2FA, []string{"email", "sms", "totp"}, "email")

	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", `{"method":"totp"}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"method":"totp"`)
	require.NotContains(t, w.Body.String(), "factor")
	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", `{"method":"bad"}`, staleToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", `{"factor_id":"anything"}`, staleToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())

	stepUpCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveAuthJSON(srv, http.MethodPost, "/step-up/2fa", `{"method":"totp","code":"`+stepUpCode+`"}`, staleToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var stepUpBody struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &stepUpBody))
	require.NotEmpty(t, stepUpBody.AccessToken)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa/backup-codes", `{}`, stepUpBody.AccessToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "backup_codes")
}

type stepUpOptionsTestShape struct {
	Methods       []string `json:"methods"`
	DefaultMethod string   `json:"default_method"`
	Options       []struct {
		ID             string `json:"id"`
		Method         string `json:"method"`
		IsDefault      bool   `json:"is_default"`
		VerificationID string `json:"verification_id"`
	} `json:"options"`
}

func requireStepUp2FAOptions(t *testing.T, got stepUpOptionsTestShape, methods []string, defaultMethod string) {
	t.Helper()
	require.ElementsMatch(t, methods, got.Methods)
	require.Equal(t, defaultMethod, got.DefaultMethod)
	seen := map[string]bool{}
	for _, option := range got.Options {
		require.Empty(t, option.ID)
		require.NotEmpty(t, option.Method)
		seen[option.Method] = true
		if option.Method == defaultMethod {
			require.True(t, option.IsDefault)
		}
		if option.Method == "email" || option.Method == "sms" {
			require.NotEmpty(t, option.VerificationID)
		}
	}
	for _, method := range methods {
		require.True(t, seen[method], "missing 2FA option %q", method)
	}
}

// The access token carries mfa_enrolled once the user has a usable second factor,
// so the stateless Sensitive() gate can require 2FA from enrolled users without a DB call.
func TestAccessTokenCarriesMFAEnrolledClaim(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerTestConfig(), pool, WithoutRateLimiter())
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("mfa-enrolled"), "mfaenrolled"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })

	// No 2FA yet → claim absent.
	tok, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", nil)
	require.NoError(t, err)
	_, present := unverifiedAccessClaims(t, tok)["mfa_enrolled"]
	require.False(t, present, "mfa_enrolled must be absent before enrollment")

	// Enroll a usable second factor → claim true on the next token.
	phone := "+15555550177"
	_, err = srv.svc.Enable2FA(ctx, user.ID, "sms", &phone)
	require.NoError(t, err)
	tok2, _, err := srv.svc.IssueAccessToken(ctx, user.ID, "", nil)
	require.NoError(t, err)
	require.Equal(t, true, unverifiedAccessClaims(t, tok2)["mfa_enrolled"], "mfa_enrolled must be true after enrollment")
}
