package authhttp

import (
	"encoding/json"

	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func TestFactorManagementWorkflow(t *testing.T) {
	ctx := t.Context()
	pool := testdb.Pool(t)
	f := newAccountFlow(t, pool, newServerTestConfig())
	const pass = "Correct-password-12345"
	userID, stale := stalePasswordUserToken(t, f.service, pool, "factor-management", pass)
	require.NotContains(t, unverifiedAccessClaims(t, stale), "mfa_enrolled")
	for _, body := range []any{
		map[string]any{"method": "totp"}, map[string]any{"method": "totp", "code": "123456"},
		map[string]any{"method": "email"}, map[string]any{"method": "sms", "phone": "+15551234567"},
		map[string]any{"default": true, "factor_id": "anything"},
	} {
		denied := f.expect(403, f.request("POST", "/user/2fa", stale, body))
		require.Equal(t, "step_up_required", denied.Error.Code)
	}
	stepped := f.expect(200, f.request("POST", "/step-up/password", stale, map[string]any{"password": pass})).Tokens
	require.NotEmpty(t, stepped.AccessToken)
	require.Equal(t, "Bearer", stepped.TokenType)
	require.Positive(t, stepped.ExpiresIn)
	claims := unverifiedAccessClaims(t, stepped.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd"}, claims["amr"])
	require.Equal(t, embedded.AssuranceLevelPassword, claims["acr"])
	sid := claims["sid"]
	var beforeTime, afterTime time.Time
	var beforeAMR, afterAMR []string
	require.NoError(t, pool.QueryRow(ctx, `SELECT last_authenticated_at, auth_methods FROM refresh_sessions WHERE id=$1`, sid).Scan(&beforeTime, &beforeAMR))
	pending := f.expect(200, f.request("POST", "/user/2fa", stepped.AccessToken, map[string]any{"method": "totp"}))
	require.NotEmpty(t, pending.Secret)
	require.Contains(t, pending.raw, "otpauth://totp/")
	// Start with the previous accepted counter so the real step-up and login
	// can follow without resetting replay state. Only an actually expired
	// counter may retry with a fresh code if this request crosses the window.
	enrolledStep := time.Now().Unix()/30 - 1
	enroll := func(counter int64) flowResponse {
		return f.request("POST", "/user/2fa", stepped.AccessToken, map[string]any{"method": "totp", "code": testTOTPCode(t, pending.Secret, counter), "default": true})
	}
	enabled := enroll(enrolledStep)
	if enabled.status == 400 && enabled.Error.Code == "invalid_code" && time.Now().Unix()/30 > enrolledStep+1 {
		enrolledStep = time.Now().Unix() / 30
		enabled = enroll(enrolledStep)
	}
	f.expect(200, enabled)
	nextCode := func(after int64) (int64, string) {
		t.Helper()
		counter := max(time.Now().Unix()/30, after+1)
		// The server accepts the next counter, but never a later one. This
		// wait is needed only after the expiry retry consumed a newer counter.
		if delay := time.Until(time.Unix((counter-1)*30, 0)); delay > 0 {
			require.LessOrEqual(t, delay, 35*time.Second)
			t.Logf("waiting %s for an unused TOTP counter", delay)
			timer := time.NewTimer(delay)
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		return counter, testTOTPCode(t, pending.Secret, counter)
	}
	require.Len(t, enabled.BackupCodes, 10)
	original, err := f.service.svc.Get2FASettings(ctx, userID)
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `SELECT last_authenticated_at, auth_methods FROM refresh_sessions WHERE id=$1`, sid).Scan(&afterTime, &afterAMR))
	require.True(t, afterTime.After(beforeTime), "the enrollment code is a fresh second-factor proof (#389)")
	require.ElementsMatch(t, append(beforeAMR, "totp", "otp", "mfa"), afterAMR)
	require.ElementsMatch(t, []any{"pwd", "totp", "otp", "mfa"}, unverifiedAccessClaims(t, enabled.Tokens.AccessToken)["amr"])
	// Age the enrolling session so the step-up gates below apply again.
	_, err = pool.Exec(ctx, `UPDATE refresh_sessions SET last_authenticated_at=now()-interval '1 hour' WHERE id=$1`, sid)
	require.NoError(t, err)
	current, _, err := f.service.svc.MintAccessToken(ctx, userID, map[string]any{"sid": sid})
	require.NoError(t, err)
	require.Equal(t, true, unverifiedAccessClaims(t, current)["mfa_enrolled"])
	denied := f.expect(403, f.request("POST", "/user/2fa/backup-codes", current, map[string]any{}))
	require.Equal(t, "step_up_required", denied.Error.Code)
	f.expect(403, f.request("POST", "/user/2fa", stepped.AccessToken, map[string]any{"method": "totp"}))

	var status struct {
		Method               string `json:"method"`
		BackupCodesRemaining int    `json:"backup_codes_remaining"`
		AvailableFactors     []struct {
			ID        string `json:"id"`
			Method    string `json:"method"`
			IsDefault bool   `json:"is_default"`
		} `json:"available_factors"`
	}
	listed := f.expect(200, f.request("GET", "/user/2fa", current, nil))
	require.NoError(t, json.Unmarshal([]byte(listed.raw), &status))
	require.Equal(t, "totp", status.Method)
	require.Equal(t, 10, status.BackupCodesRemaining)
	require.Len(t, status.AvailableFactors, 1)
	factor := status.AvailableFactors[0]
	require.NotEmpty(t, factor.ID)
	require.Equal(t, "totp", factor.Method)
	require.True(t, factor.IsDefault)
	var me struct {
		Security struct {
			StepUpMethods []string               `json:"step_up_methods"`
			StepUp2FA     stepUpOptionsTestShape `json:"step_up_2fa"`
		} `json:"security"`
	}
	profile := f.expect(200, f.request("GET", "/me", current, nil))
	require.NoError(t, json.Unmarshal([]byte(profile.raw), &me))
	require.Contains(t, me.Security.StepUpMethods, "2fa")
	requireStepUp2FAOptions(t, me.Security.StepUp2FA, []string{"totp"}, "totp")
	for _, body := range []any{map[string]any{}, map[string]any{"method": "totp"}} {
		challenge := f.expect(403, f.request("POST", "/step-up/2fa", current, body))
		require.Equal(t, "totp", challenge.Error.Metadata.Method)
		require.NotContains(t, challenge.raw, `"factor"`)
	}
	for _, body := range []any{map[string]any{"method": "bad"}, map[string]any{"factor_id": factor.ID}} {
		f.expect(400, f.request("POST", "/step-up/2fa", current, body))
	}
	stepUpCounter, stepUpCode := nextCode(enrolledStep)
	mfa := f.expect(200, f.request("POST", "/step-up/2fa", current, map[string]any{"code": stepUpCode})).Tokens
	claims = unverifiedAccessClaims(t, mfa.AccessToken)
	require.NotEmpty(t, claims["auth_time"])
	require.ElementsMatch(t, []any{"pwd", "totp", "otp", "mfa"}, claims["amr"])
	require.Equal(t, embedded.AssuranceLevelMFA, claims["acr"])
	passwordAgain := f.expect(200, f.request("POST", "/step-up/password", mfa.AccessToken, map[string]any{"password": pass})).Tokens
	require.ElementsMatch(t, claims["amr"], unverifiedAccessClaims(t, passwordAgain.AccessToken)["amr"], "password re-auth preserves actual MFA proof")
	require.Equal(t, embedded.AssuranceLevelMFA, unverifiedAccessClaims(t, passwordAgain.AccessToken)["acr"])

	// A fresh factor proof permits management but cannot replace the factor.
	replacement := f.expect(200, f.request("POST", "/user/2fa", mfa.AccessToken, map[string]any{"method": "totp"}))
	conflict := f.expect(409, f.request("POST", "/user/2fa", mfa.AccessToken, map[string]any{"method": "totp", "code": testTOTPCode(t, replacement.Secret, time.Now().Unix()/30)}))
	require.Equal(t, "2fa_factor_exists", conflict.Error.Code)
	preserved, err := f.service.svc.Get2FASettings(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, original.Factors[0].ID, preserved.Factors[0].ID)
	require.Equal(t, original.TOTPSecret, preserved.TOTPSecret)
	require.Equal(t, original.BackupCodes, preserved.BackupCodes)
	f.expect(204, f.request("POST", "/user/2fa", mfa.AccessToken, map[string]any{"factor_id": factor.ID, "default": true}))
	listed = f.expect(200, f.request("GET", "/user/2fa", current, nil))
	require.NoError(t, json.Unmarshal([]byte(listed.raw), &status))
	require.Equal(t, "totp", status.Method)

	user, err := f.service.svc.AdminGetUser(ctx, userID)
	require.NoError(t, err)
	challenge := f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": pass}))
	require.Equal(t, userID, challenge.Error.Metadata.UserID)
	require.Equal(t, "totp", challenge.Error.Metadata.Method)
	require.NotEmpty(t, challenge.Error.Metadata.Challenge)
	proof := map[string]any{"user_id": userID, "challenge": challenge.Error.Metadata.Challenge, "factor_id": factor.ID}
	selected := f.expect(403, f.post("/2fa/challenge", proof))
	require.Equal(t, "totp", selected.Error.Metadata.Method)
	_, proof["code"] = nextCode(stepUpCounter)
	tokens := f.expect(200, f.post("/2fa/verify", proof)).TokenSet
	f.session(tokens, "pwd", "totp", "otp", "mfa")
	loginSID := unverifiedAccessClaims(t, tokens.AccessToken)["sid"]
	var loginIP string
	require.NoError(t, pool.QueryRow(ctx, `SELECT host(ip_addr) FROM refresh_sessions WHERE id=$1`, loginSID).Scan(&loginIP))
	require.Equal(t, "127.0.0.1", loginIP, "MFA completion records the actual HTTP client IP")
	f.expect(401, f.post("/2fa/verify", proof))
	challenge = f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": pass}))
	backup := f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": userID, "challenge": challenge.Error.Metadata.Challenge, "code": enabled.BackupCodes[0], "backup_code": true}))
	f.session(backup.TokenSet, "pwd", "backup_code", "otp", "mfa")

	// Only age the real MFA session; never inject proof or reset TOTP replay state.
	_, err = pool.Exec(ctx, `UPDATE refresh_sessions SET last_authenticated_at=now()-interval '1 hour' WHERE id=$1`, loginSID)
	require.NoError(t, err)
	staleMFA, _, err := f.service.svc.MintAccessToken(ctx, userID, map[string]any{"sid": loginSID})
	require.NoError(t, err)
	denied = f.expect(403, f.request("POST", "/user/2fa/backup-codes", staleMFA, map[string]any{}))
	var staleResponse struct {
		Error struct {
			Metadata struct {
				StepUpMethods []string               `json:"step_up_methods"`
				StepUp2FA     stepUpOptionsTestShape `json:"step_up_2fa"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(denied.raw), &staleResponse))
	require.Equal(t, "step_up_required", denied.Error.Code)
	require.Contains(t, staleResponse.Error.Metadata.StepUpMethods, "2fa")
	requireStepUp2FAOptions(t, staleResponse.Error.Metadata.StepUp2FA, []string{"totp"}, "totp")
	freshMFA := f.expect(200, f.request("POST", "/step-up/2fa", staleMFA, map[string]any{"code": enabled.BackupCodes[1], "backup_code": true})).Tokens
	regenerated := f.expect(200, f.request("POST", "/user/2fa/backup-codes", freshMFA.AccessToken, map[string]any{}))
	require.Len(t, regenerated.BackupCodes, 10)
}
