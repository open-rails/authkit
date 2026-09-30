package securitytest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func withDeviceKeys(c *authkit.Config) { c.DeviceKeys = authkit.DeviceKeysConfig{Enabled: true} }

type deviceKey struct {
	public  string
	private ed25519.PrivateKey
	id      string
}

func newDeviceKey(t *testing.T) *deviceKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return &deviceKey{public: base64.RawURLEncoding.EncodeToString(pub), private: priv}
}

func (k *deviceKey) sign(t *testing.T, domain, challenge string) string {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, devicekey.Message(domain, raw)))
}

// deviceEnroll runs the enrollment ceremony for email; secondFactor, when
// set, answers the second-factor demand of an account that has one.
func (h *host) deviceEnroll(k *deviceKey, email string, secondFactor func() string) response {
	h.t.Helper()
	resp := h.post("/device-keys/enroll/begin", map[string]string{"email": email, "public_key": k.public, "label": "laptop"}, "")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var begin struct {
		EnrollmentID string `json:"enrollment_id"`
		Challenge    string `json:"challenge"`
	}
	resp.json(h.t, &begin)
	finish := map[string]string{
		"enrollment_id": begin.EnrollmentID,
		"code":          h.verificationCode(email),
		"signature":     k.sign(h.t, devicekey.EnrollmentDomain, begin.Challenge),
	}
	resp = h.post("/device-keys/enroll/finish", finish, "")
	if secondFactor == nil || resp.status != http.StatusForbidden || resp.errorCode() != "2fa_required" {
		return h.keepDeviceKey(k, resp)
	}
	finish["code_2fa"] = secondFactor()
	return h.keepDeviceKey(k, h.post("/device-keys/enroll/finish", finish, ""))
}

func (h *host) keepDeviceKey(k *deviceKey, resp response) response {
	if resp.status == http.StatusOK {
		var out struct {
			DeviceKey struct {
				ID string `json:"id"`
			} `json:"device_key"`
		}
		resp.json(h.t, &out)
		k.id = out.DeviceKey.ID
	}
	return resp
}

func (h *host) deviceLogin(k *deviceKey) response {
	h.t.Helper()
	resp := h.post("/device-keys/login/begin", map[string]string{"device_key_id": k.id}, "")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var begin struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	resp.json(h.t, &begin)
	return h.post("/device-keys/login/finish", map[string]string{"challenge_id": begin.ChallengeID, "signature": k.sign(h.t, devicekey.LoginDomain, begin.Challenge)}, "")
}

// TestSecurityDeviceKeyMFAGate (N2): a device key is a login and passes the
// session MFA gate like every other. A key enrolled with only an emailed code
// stops signing in once the account has a second factor, until re-enrolled
// with a factor independent of that mailbox; a holder of an MFA-required role
// without one cannot enroll a key; and a password change ends every device key.
func TestSecurityDeviceKeyMFAGate(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withAccountRoles), authtest.WithConfig(withDeviceKeys))
	ctx := context.Background()
	victim := h.newAccount("devkey")
	// The attacker reads the victim's mailbox for a while and enrolls a key;
	// the victim enrolls their own laptop.
	stolen, laptop := newDeviceKey(t), newDeviceKey(t)
	for _, k := range []*deviceKey{stolen, laptop} {
		resp := h.deviceEnroll(k, victim.email, nil)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		require.Equal(t, http.StatusOK, h.deviceLogin(k).status, "control: a key signs in while the account has no second factor")
	}

	// The victim enables 2FA and is made an MFA-required root role holder.
	backup := h.enrollEmail2FA(victim)
	h.grant(iam.RootGroup(), victim, "security")
	for _, k := range []*deviceKey{stolen, laptop} {
		resp := h.deviceLogin(k)
		require.Equal(t, http.StatusForbidden, resp.status, "a key enrolled before MFA signed in without it: %s", resp)
		require.Equal(t, "2fa_required", resp.errorCode())
	}

	t.Run("re-enrolling with an independent factor re-proves a key", func(t *testing.T) {
		resp := h.deviceEnroll(laptop, victim.email, nil)
		require.Equal(t, http.StatusForbidden, resp.status, "the emailed code alone re-proved the key: %s", resp)
		require.Equal(t, "2fa_required", resp.errorCode())
		// The email factor reads the enrollment mailbox (P1); a backup code does not.
		resp = h.deviceEnroll(laptop, victim.email, func() string { return backup[0] })
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp = h.deviceLogin(laptop)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		_, claims := splitToken(t, session(t, resp).AccessToken)
		require.ElementsMatch(t, []any{"device_key", "mfa"}, claims["amr"])
		require.Equal(t, http.StatusForbidden, h.deviceLogin(stolen).status, "re-proving one key re-proved another")
	})

	t.Run("a password change ends every device key", func(t *testing.T) {
		resp := h.post("/user/password", map[string]string{"current_password": password, "new_password": password + "x"}, h.mfaSession(victim))
		require.Less(t, resp.status, 300, resp.String())
		var live int
		require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1::uuid AND revoked_at IS NULL`, victim.id).Scan(&live))
		require.Zero(t, live)
		for _, k := range []*deviceKey{stolen, laptop} {
			require.Equal(t, http.StatusUnauthorized, h.deviceLogin(k).status)
		}
	})

	t.Run("an MFA-required role holder without a factor enrolls no key", func(t *testing.T) {
		holder := h.newAccount("devkeyrole")
		early := newDeviceKey(t)
		require.Equal(t, http.StatusOK, h.deviceEnroll(early, holder.email, nil).status)
		// The role is granted while 2FA was off (the gate never ran).
		_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'root:security')`, h.rootGroupID(), holder.id)
		require.NoError(t, err)
		resp := h.deviceEnroll(newDeviceKey(t), holder.email, nil)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		require.Equal(t, "2fa_enrollment_required", resp.errorCode())
		resp = h.deviceLogin(early)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		require.Equal(t, "2fa_enrollment_required", resp.errorCode())
	})
}

// TestSecurityDeviceKeyNeedsIndependentFactor (P1): the enrollment code is
// emailed, so the email factor, read from the same mailbox, never makes a
// device key MFA-grade. A mailbox reader gets no second-factor code and cannot
// bind a key; a TOTP or SMS code or a backup code can.
func TestSecurityDeviceKeyNeedsIndependentFactor(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withDeviceKeys))
	ctx := context.Background()
	victim := h.newAccount("p1victim")
	backup := h.enrollEmail2FA(victim)
	// The attacker reads the victim's mailbox, including the victim's own
	// sign-in codes.
	h.passwordStep(victim, "198.51.100.41")
	mailbox := func() string { return h.mail.Last(t, iam.MessageLoginCode, victim.email).Code }
	sent := len(h.mail.Messages(iam.MessageLoginCode, victim.email))

	stolen := newDeviceKey(t)
	resp := h.deviceEnroll(stolen, victim.email, nil)
	require.Equal(t, "backup_code", secondFactorMethod(t, resp), "the enrollment mailbox was offered as the second factor")
	require.Equal(t, sent, len(h.mail.Messages(iam.MessageLoginCode, victim.email)), "enrollment mailed a second-factor code to the enrollment mailbox")

	resp = h.deviceEnroll(stolen, victim.email, mailbox)
	require.Equal(t, http.StatusUnauthorized, resp.status, "a mailbox code bound a device key: %s", resp)
	require.Equal(t, "invalid_code", resp.errorCode())
	var keys int
	require.NoError(t, h.pool.QueryRow(ctx, `SELECT count(*) FROM profiles.user_device_keys WHERE user_id=$1::uuid`, victim.id).Scan(&keys))
	require.Zero(t, keys)

	t.Run("control: a backup code binds the key", func(t *testing.T) {
		laptop := newDeviceKey(t)
		resp := h.deviceEnroll(laptop, victim.email, func() string { return backup[0] })
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp = h.deviceLogin(laptop)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		_, claims := splitToken(t, session(t, resp).AccessToken)
		require.ElementsMatch(t, []any{"device_key", "mfa"}, claims["amr"])
	})
}

// secondFactorMethod is the second factor a device-key enrollment's
// 2fa_required refusal asks for in code_2fa.
func secondFactorMethod(t *testing.T, resp response) string {
	t.Helper()
	require.Equal(t, http.StatusForbidden, resp.status, resp.String())
	var env struct {
		Error struct {
			Code     string `json:"code"`
			Param    string `json:"param"`
			Metadata struct {
				Method string `json:"method"`
			} `json:"metadata"`
		} `json:"error"`
	}
	resp.json(t, &env)
	require.Equal(t, "2fa_required", env.Error.Code)
	require.Equal(t, "code_2fa", env.Error.Param)
	return env.Error.Metadata.Method
}

// TestSecurityDeviceKeyIndependentFactors (P1, I8): an authenticator-app code,
// or the SMS code sent for the ceremony, makes a device key MFA-grade.
func TestSecurityDeviceKeyIndependentFactors(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withDeviceKeys), withSMS)
	for _, tc := range []struct {
		method string
		enroll func(a account) (next func() string)
	}{
		{"totp", func(a account) func() string {
			secret, _ := h.enrollTOTP(h.login(a).AccessToken)
			return func() string { return authtest.TOTPCode(t, secret, time.Now().Add(30*time.Second)) }
		}},
		{"sms", func(a account) func() string {
			phone := "+1555" + uniqueDigits(7)
			h.enrollSMS(h.login(a).AccessToken, phone)
			return func() string { return h.mail.Last(t, iam.MessageLoginCode, phone).Code }
		}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			a := h.newAccount("p1" + tc.method)
			next := tc.enroll(a)
			key := newDeviceKey(t)
			require.Equal(t, tc.method, secondFactorMethod(t, h.deviceEnroll(key, a.email, nil)))
			resp := h.deviceEnroll(key, a.email, next)
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			resp = h.deviceLogin(key)
			require.Equal(t, http.StatusOK, resp.status, resp.String())
			_, claims := splitToken(t, session(t, resp).AccessToken)
			require.ElementsMatch(t, []any{"device_key", "mfa"}, claims["amr"])
		})
	}
}

// TestSecurityDeviceKeyRefusedBeforeBackupCode (R4): a key that can no longer
// enroll (revoked, or bound to another account) is refused before any second
// factor is asked for, and a backup code is spent only by an enrollment that
// commits, so retrying a stale key burns none.
func TestSecurityDeviceKeyRefusedBeforeBackupCode(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withDeviceKeys))
	ctx := context.Background()
	owner := h.newAccount("r4owner")
	backup := h.enrollEmail2FA(owner)
	key := newDeviceKey(t)
	require.Equal(t, http.StatusOK, h.deviceEnroll(key, owner.email, func() string { return backup[0] }).status)
	_, err := h.auth.RevokeAccountSessions(ctx, iam.SystemActor(), owner.id)
	require.NoError(t, err)

	signInWithBackup := func(a account, code string) response {
		ch := h.passwordStep(a, "198.51.100.44")
		return h.post("/2fa/verify", map[string]any{"user_id": a.id, "challenge": ch.Challenge, "code": code, "backup_code": true}, "")
	}
	t.Run("revoked", func(t *testing.T) {
		for range 2 {
			resp := h.deviceEnroll(key, owner.email, func() string { return backup[1] })
			require.Equal(t, http.StatusUnauthorized, resp.status, "a revoked key re-enrolled: %s", resp)
			require.Equal(t, "invalid_code", resp.errorCode())
		}
		resp := signInWithBackup(owner, backup[1])
		require.Equal(t, http.StatusOK, resp.status, "a refused enrollment spent the backup code: %s", resp)
	})
	live := newDeviceKey(t)
	t.Run("control: an enrollment that commits spends the backup code", func(t *testing.T) {
		resp := h.deviceEnroll(live, owner.email, func() string { return backup[2] })
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp = signInWithBackup(owner, backup[2])
		require.Equal(t, http.StatusUnauthorized, resp.status, "the enrollment left its backup code usable: %s", resp)
	})
	t.Run("bound to another account", func(t *testing.T) {
		other := h.newAccount("r4other")
		otherBackup := h.enrollEmail2FA(other)
		resp := h.deviceEnroll(live, other.email, func() string { return otherBackup[0] })
		require.Equal(t, http.StatusUnauthorized, resp.status, "another account's key enrolled: %s", resp)
		require.Equal(t, "invalid_code", resp.errorCode())
		resp = signInWithBackup(other, otherBackup[0])
		require.Equal(t, http.StatusOK, resp.status, "a refused enrollment spent the backup code: %s", resp)
	})
}
