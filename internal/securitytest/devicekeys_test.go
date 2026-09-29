package securitytest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"testing"

	"github.com/open-rails/authkit"
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
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(k.private, append(append([]byte(domain), 0), raw...)))
}

// deviceEnroll runs the enrollment ceremony for email; secondFactor, when
// set, answers the second-factor demand of an account that has one.
func (h *host) deviceEnroll(k *deviceKey, email string, secondFactor func() string) response {
	h.t.Helper()
	resp := h.post("/device-keys/enroll/begin", map[string]string{"email": email, "public_key": k.public, "label": "laptop"}, "")
	require.Equal(h.t, http.StatusAccepted, resp.status, resp.String())
	var begin struct {
		EnrollmentID string `json:"enrollment_id"`
		Challenge    string `json:"challenge"`
	}
	resp.json(h.t, &begin)
	finish := map[string]string{
		"enrollment_id": begin.EnrollmentID,
		"code":          h.verificationCode(email),
		"signature":     k.sign(h.t, "authkit.device-key-enrollment/1", begin.Challenge),
	}
	resp = h.post("/device-keys/enroll/finish", finish, "")
	if secondFactor == nil || resp.status != http.StatusForbidden || resp.errorCode() != "step_up_required" {
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
	require.Equal(h.t, http.StatusAccepted, resp.status, resp.String())
	var begin struct {
		ChallengeID string `json:"challenge_id"`
		Challenge   string `json:"challenge"`
	}
	resp.json(h.t, &begin)
	return h.post("/device-keys/login/finish", map[string]string{"challenge_id": begin.ChallengeID, "signature": k.sign(h.t, "authkit.device-key-login/1", begin.Challenge)}, "")
}

// TestSecurityDeviceKeyMFAGate (N2): a device key is a login and passes the
// session MFA gate like every other. A key enrolled with only an emailed code
// stops signing in once the account has a second factor, until re-enrolled
// with it; a holder of an MFA-required role without one cannot enroll a key;
// and a password change ends every device key.
func TestSecurityDeviceKeyMFAGate(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), withEngine(withAccountRoles), withEngine(withDeviceKeys))
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
	h.enrollEmail2FA(victim)
	h.grant(iam.RootGroup(), victim, "security")
	for _, k := range []*deviceKey{stolen, laptop} {
		resp := h.deviceLogin(k)
		require.Equal(t, http.StatusForbidden, resp.status, "a key enrolled before MFA signed in without it: %s", resp)
		require.Equal(t, "2fa_required", resp.errorCode())
	}

	t.Run("re-enrolling with the second factor re-proves a key", func(t *testing.T) {
		resp := h.deviceEnroll(laptop, victim.email, nil)
		require.Equal(t, http.StatusForbidden, resp.status, "the emailed code alone re-proved the key: %s", resp)
		require.Equal(t, "step_up_required", resp.errorCode())
		resp = h.deviceEnroll(laptop, victim.email, func() string { return h.mail.last(t, `^login to=`+victim.email+` code=(\S+)`) })
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		resp = h.deviceLogin(laptop)
		require.Equal(t, http.StatusOK, resp.status, resp.String())
		_, claims := splitToken(t, session(t, resp).AccessToken)
		require.ElementsMatch(t, []any{"device_key", "mfa"}, claims["amr"])
		require.Equal(t, http.StatusForbidden, h.deviceLogin(stolen).status, "re-proving one key re-proved another")
	})

	t.Run("a password change ends every device key", func(t *testing.T) {
		sid := h.mfaSession(victim)
		resp := h.post("/user/password", map[string]string{"current_password": password, "new_password": password + "x"}, h.sessionToken(victim.id, sid))
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
		_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'security')`, h.rootGroupID(), holder.id)
		require.NoError(t, err)
		resp := h.deviceEnroll(newDeviceKey(t), holder.email, nil)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		require.Equal(t, "2fa_enrollment_required", resp.errorCode())
		resp = h.deviceLogin(early)
		require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		require.Equal(t, "2fa_enrollment_required", resp.errorCode())
	})
}
