package authhttp

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	core "github.com/open-rails/authkit/core"
	"github.com/open-rails/authkit/password"
	memorystore "github.com/open-rails/authkit/storage/memory"
	"github.com/stretchr/testify/require"
)

func TestTOTPEnrollmentAndLoginHTTPIntegration(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("totp-http")
	username := "totphttp" + uniqueSuffix()
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
		Secret     string `json:"secret"`
		OtpauthURI string `json:"otpauth_uri"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	require.NotEmpty(t, enrollment.Secret)
	require.Contains(t, enrollment.OtpauthURI, "otpauth://totp/")

	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"backup_codes"`)

	w = serveJSON(srv, http.MethodPost, "/password/login", `{"login":"`+email+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var challenge struct {
		Requires2FA bool   `json:"requires_2fa"`
		UserID      string `json:"user_id"`
		Method      string `json:"method"`
		Challenge   string `json:"challenge"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.True(t, challenge.Requires2FA)
	require.Equal(t, user.ID, challenge.UserID)
	require.Equal(t, "totp", challenge.Method)
	require.NotEmpty(t, challenge.Challenge)

	loginCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveJSON(srv, http.MethodPost, "/2fa/verify", `{"user_id":"`+user.ID+`","challenge":"`+challenge.Challenge+`","code":"`+loginCode+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken)

	claims := unverifiedAccessClaims(t, tokens.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd", "otp", "mfa"}, claims["amr"])
}

func TestMultiple2FAFactorsDefaultAndSelectedLoginHTTPIntegration(t *testing.T) {
	pool := newServerTestPool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, err := NewServer(cfg, pool, WithEphemeralStore(memorystore.NewKV(), core.EphemeralMemory), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("multi-2fa")
	username := "multi2fa" + uniqueSuffix()
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
	require.Contains(t, w.Body.String(), `"backup_codes"`)
	var emailEnable struct {
		BackupCodes []string `json:"backup_codes"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &emailEnable))
	require.NotEmpty(t, emailEnable.BackupCodes)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var enrollment struct {
		Secret string `json:"secret"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &enrollment))
	require.NotEmpty(t, enrollment.Secret)
	code := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30)
	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"method":"totp","code":"`+code+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotContains(t, w.Body.String(), "backup_codes")

	w = serveAuthJSON(srv, http.MethodGet, "/user/2fa", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var status struct {
		Method               string `json:"method"`
		BackupCodesRemaining int    `json:"backup_codes_remaining"`
		AvailableFactors     []struct {
			ID        string `json:"id"`
			Method    string `json:"method"`
			IsDefault bool   `json:"is_default"`
		} `json:"available_factors"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	require.Equal(t, "email", status.Method)
	require.Equal(t, 10, status.BackupCodesRemaining)
	require.Len(t, status.AvailableFactors, 2)
	totpFactorID := ""
	for _, factor := range status.AvailableFactors {
		require.NotEqual(t, "backup_code", factor.Method)
		if factor.Method == "email" {
			require.True(t, factor.IsDefault)
		}
		if factor.Method == "totp" {
			totpFactorID = factor.ID
			require.False(t, factor.IsDefault)
		}
	}
	require.NotEmpty(t, totpFactorID)

	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"method":"totp"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"method":"totp"`)
	require.NotContains(t, w.Body.String(), "factor")
	reauthCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"method":"totp","code":"`+reauthCode+`"}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "access_token")

	w = serveAuthJSON(srv, http.MethodPost, "/reauth/2fa", `{"factor_id":"`+totpFactorID+`"}`, setupToken)
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	// Keep the selected-login assertion below independent from the selected
	// reauth assertion above; core replay tests cover reuse rejection.
	_, err = pool.Exec(ctx, `UPDATE profiles.mfa_factors SET last_totp_step=NULL WHERE id=$1::uuid`, totpFactorID)
	require.NoError(t, err)

	w = serveJSON(srv, http.MethodPost, "/password/login", `{"login":"`+email+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var challenge struct {
		Requires2FA bool   `json:"requires_2fa"`
		UserID      string `json:"user_id"`
		Method      string `json:"method"`
		Challenge   string `json:"challenge"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.True(t, challenge.Requires2FA)
	require.Equal(t, "email", challenge.Method)

	w = serveJSON(srv, http.MethodPost, "/2fa/verify", `{"user_id":"`+user.ID+`","challenge":"`+challenge.Challenge+`","code":"`+emailEnable.BackupCodes[0]+`","backup_code":true}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), "access_token")

	w = serveJSON(srv, http.MethodPost, "/password/login", `{"login":"`+email+`","password":"`+pass+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.True(t, challenge.Requires2FA)
	require.Equal(t, "email", challenge.Method)

	w = serveJSON(srv, http.MethodPost, "/2fa/challenge", `{"user_id":"`+user.ID+`","challenge":"`+challenge.Challenge+`","factor_id":"`+totpFactorID+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"method":"totp"`)

	loginCode := testTOTPCode(t, enrollment.Secret, time.Now().Unix()/30+1)
	w = serveJSON(srv, http.MethodPost, "/2fa/verify", `{"user_id":"`+user.ID+`","challenge":"`+challenge.Challenge+`","factor_id":"`+totpFactorID+`","code":"`+loginCode+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens struct {
		AccessToken string `json:"access_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))
	require.NotEmpty(t, tokens.AccessToken)

	w = serveAuthJSON(srv, http.MethodPost, "/user/2fa", `{"factor_id":"`+totpFactorID+`","default":true}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	w = serveAuthJSON(srv, http.MethodGet, "/user/2fa", `{}`, setupToken)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	require.Equal(t, "totp", status.Method)
}

func serveAuthJSON(srv *Service, method, path, body, token string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	srv.APIHandler().ServeHTTP(w, r)
	return w
}

func testTOTPCode(t *testing.T, secret string, step int64) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	require.NoError(t, err)
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	return fmt.Sprintf("%06d", bin%1000000)
}
