package authhttp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/stretchr/testify/require"
)

// #293: an account with a usable second factor must present it before a device
// key — a standing credential — is enrolled on it. The email code alone yields
// step_up_required, leaves the ceremony live, and the retry with a TOTP code
// enrolls the key and mints an MFA-marked token.
func TestDeviceKeyEnrollmentRequiresSecondFactorForMFAUser(t *testing.T) {
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	srv, sender := deviceKeyTestServerWithConfig(t, cfg)
	pool := srv.svc.Postgres()

	email := uniqueEmail("device-key-mfa")
	user, err := srv.svc.CreateUser(ctx, email, "dkmfa"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	secret, _, err := srv.svc.StartTOTPEnrollment(ctx, user.ID)
	require.NoError(t, err)
	step := time.Now().Unix() / 30
	_, err = srv.svc.EnableTOTP2FA(ctx, embedded.TOTPEnrollment{UserID: user.ID, Code: testTOTPCode(t, secret, step), MakeDefault: true, Mode: embedded.FirstFactorOnly})
	require.NoError(t, err)

	publicKey, privateKey := newDeviceKey(t)
	enrollment := beginDeviceEnrollment(t, srv, email, publicKey)
	finish := func(secondFactor string) (int, []byte) {
		body := map[string]any{
			"enrollment_id": enrollment.EnrollmentID,
			"code":          sender.verificationCode(t),
			"signature":     signDeviceChallenge(t, privateKey, testDeviceEnrollmentDomain, enrollment.Challenge),
		}
		if secondFactor != "" {
			body["code_2fa"] = secondFactor
		}
		return postDeviceJSON(t, srv, "/device-keys/enroll/finish", body)
	}

	// Email code + key proof alone: refused, ceremony intact, method named.
	status, raw := finish("")
	require.Equal(t, http.StatusForbidden, status, string(raw))
	var refused struct {
		Error struct {
			Code     string         `json:"code"`
			Metadata map[string]any `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(raw, &refused))
	require.Equal(t, string(ErrStepUpRequired), refused.Error.Code)
	require.Equal(t, "totp", refused.Error.Metadata["method"])
	require.Equal(t, "code_2fa", refused.Error.Metadata["param"])

	// A wrong second factor is a failed attempt, not a consumed ceremony.
	status, raw = finish("000000")
	require.Equal(t, http.StatusBadRequest, status, string(raw))

	status, raw = finish(testTOTPCode(t, secret, step+1))
	require.Equal(t, http.StatusOK, status, string(raw))
	requireDeviceKeyTokenShape(t, raw)
	var enrolled deviceKeyTokenBody
	require.NoError(t, json.Unmarshal(raw, &enrolled))
	claims := unverifiedAccessClaims(t, enrolled.AccessToken)
	require.ElementsMatch(t, []any{"device_key", "email", "otp", "mfa"}, claims["amr"])
	require.Equal(t, embedded.AssuranceLevelMFA, claims["acr"])
	require.Equal(t, user.ID, claims["sub"])

	var keys int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1::uuid AND revoked_at IS NULL`, user.ID).Scan(&keys))
	require.Equal(t, 1, keys)
	require.Equal(t, []string{email}, sender.deviceKeyNotices())
}

// #293: enrolling a key on an EXISTING account notifies its address; a brand-new
// registration has no owner to warn.
func TestDeviceKeyEnrollmentNotifiesExistingAccountOnly(t *testing.T) {
	ctx := context.Background()
	srv, sender := deviceKeyTestServer(t)
	pool := srv.svc.Postgres()

	existing := uniqueEmail("device-key-notice")
	user, err := srv.svc.CreateUser(ctx, existing, "dknotice"+uniqueSuffix())
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	publicKey, privateKey := newDeviceKey(t)
	finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, existing, publicKey), privateKey)
	require.Equal(t, []string{existing}, sender.deviceKeyNotices())

	fresh := uniqueEmail("device-key-fresh")
	publicKey, privateKey = newDeviceKey(t)
	finishDeviceEnrollment(t, srv, sender, beginDeviceEnrollment(t, srv, fresh, publicKey), privateKey)
	created, err := srv.svc.GetUserByEmail(ctx, fresh)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, created.ID) })
	require.Equal(t, []string{existing}, sender.deviceKeyNotices(), "a new registration is not a notice-worthy addition")
}

// #293: the device-key surface is an email-code login, so hosts opt in through
// DeviceKeys.Enabled — off, the routes are not mounted and the engine refuses.
func TestDeviceKeyRoutesRequireConfigOptIn(t *testing.T) {
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.DeviceKeys.Enabled = false
	srv, _ := deviceKeyTestServerWithConfig(t, cfg)

	require.Empty(t, srv.APIRoutes(RouteDeviceKeys))
	publicKey, _ := newDeviceKey(t)
	status, _ := postDeviceJSON(t, srv, "/device-keys/enroll/begin", map[string]any{"email": uniqueEmail("device-key-off"), "public_key": publicKey})
	require.Equal(t, http.StatusNotFound, status)

	_, err := srv.svc.BeginDeviceKeyEnrollment(ctx, uniqueEmail("device-key-off"), publicKey, "")
	require.True(t, errors.Is(err, authkit.ErrDeviceKeysDisabled), "engine must refuse without the opt-in: %v", err)
	_, err = srv.svc.BeginDeviceKeyLogin(ctx, "00000000-0000-0000-0000-000000000000")
	require.True(t, errors.Is(err, authkit.ErrDeviceKeysDisabled), "engine must refuse without the opt-in: %v", err)
}
