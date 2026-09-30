package securitytest

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

func (h *host) deviceKeyClient() *devicekey.Client {
	h.t.Helper()
	c, err := devicekey.NewClient(h.server.URL+apiPrefix, h.server.Client())
	require.NoError(h.t, err)
	return c
}

func ed25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return pub, priv
}

// requireRefusal asserts err is the AuthKit refusal code with status.
func requireRefusal(t *testing.T, err error, status int, code string) {
	t.Helper()
	e, ok := iam.AsError(err)
	require.True(t, ok, "not an AuthKit refusal: %v", err)
	require.Equal(t, status, e.Status(), err.Error())
	require.Equal(t, code, e.Code(), err.Error())
}

// TestSecurityDeviceKeyClient drives the public devicekey client, as a CLI
// would, against a mounted AuthKit: an account with a second factor enrolls a
// key only with a factor independent of the emailed code, signatures are
// bound to their domain, revoked and foreign keys are refused, and only an
// email-proven token revokes the other machines.
func TestSecurityDeviceKeyClient(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withAccountRoles), authtest.WithConfig(withDeviceKeys))
	ctx := context.Background()
	c := h.deviceKeyClient()

	enroll := func(t *testing.T, email string, pub ed25519.PublicKey, priv ed25519.PrivateKey) devicekey.Session {
		t.Helper()
		e, err := c.BeginEnrollment(ctx, email, pub, "laptop")
		require.NoError(t, err)
		s, err := c.FinishEnrollment(ctx, e, priv, h.verificationCode(email), "")
		require.NoError(t, err)
		return s
	}

	t.Run("enroll, sign in, list and sign out", func(t *testing.T) {
		email := unique("dkclient") + "@security.test"
		pub, priv := ed25519Key(t)
		e, err := c.BeginEnrollment(ctx, email, pub, "laptop")
		require.NoError(t, err)
		require.WithinDuration(t, time.Now().Add(10*time.Minute), e.ExpiresAt, time.Minute)
		_, other := ed25519Key(t)
		_, err = c.FinishEnrollment(ctx, e, other, h.verificationCode(email), "")
		require.Error(t, err, "a key other than the enrollment's was sent")
		_, isRefusal := iam.AsError(err)
		require.False(t, isRefusal, "the client sent a foreign key's signature: %v", err)

		enrolled, err := c.FinishEnrollment(ctx, e, priv, h.verificationCode(email), "")
		require.NoError(t, err)
		require.Equal(t, "laptop", enrolled.DeviceKey.Label)
		require.True(t, enrolled.DeviceKey.Current)
		require.True(t, enrolled.ExpiresAt.After(time.Now()))
		_, claims := splitToken(t, enrolled.AccessToken)
		require.ElementsMatch(t, []any{"device_key", "email"}, claims["amr"])
		require.Equal(t, enrolled.DeviceKey.ID, claims["device_key_id"])
		_, err = c.FinishEnrollment(ctx, e, priv, h.verificationCode(email), "")
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_code")

		s, err := c.Login(ctx, enrolled.DeviceKey.ID, priv)
		require.NoError(t, err)
		require.Equal(t, enrolled.DeviceKey.ID, s.DeviceKey.ID)
		_, claims = splitToken(t, s.AccessToken)
		require.ElementsMatch(t, []any{"device_key"}, claims["amr"])
		keys, err := c.List(ctx, s.AccessToken)
		require.NoError(t, err)
		require.Len(t, keys, 1)
		require.True(t, keys[0].Current)
		require.NotNil(t, keys[0].LastUsedAt)

		_, err = c.Login(ctx, enrolled.DeviceKey.ID, other)
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_credentials")

		require.NoError(t, c.Revoke(ctx, s.AccessToken, s.DeviceKey.ID))
		require.NoError(t, c.Revoke(ctx, s.AccessToken, s.DeviceKey.ID), "signing out is retry-safe")
		_, err = c.Login(ctx, enrolled.DeviceKey.ID, priv)
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_credentials")
		e, err = c.BeginEnrollment(ctx, email, pub, "")
		require.NoError(t, err)
		_, err = c.FinishEnrollment(ctx, e, priv, h.verificationCode(email), "")
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_code")
	})

	t.Run("signatures are bound to their domain", func(t *testing.T) {
		email := unique("dkdomain") + "@security.test"
		pub, priv := ed25519Key(t)
		e, err := c.BeginEnrollment(ctx, email, pub, "")
		require.NoError(t, err)
		code := h.verificationCode(email)
		wrong, err := devicekey.SignLogin(priv, e.Challenge)
		require.NoError(t, err)
		resp := h.post("/device-keys/enroll/finish", map[string]string{"enrollment_id": e.ID, "code": code, "signature": wrong}, "")
		require.Equal(t, http.StatusUnauthorized, resp.status, "a login signature enrolled a key: %s", resp)
		s, err := c.FinishEnrollment(ctx, e, priv, code, "")
		require.NoError(t, err, "a refused signature burned the ceremony")

		resp = h.post("/device-keys/login/begin", map[string]string{"device_key_id": s.DeviceKey.ID}, "")
		require.Equal(t, http.StatusAccepted, resp.status, resp.String())
		var begun struct {
			ID        string `json:"challenge_id"`
			Challenge string `json:"challenge"`
		}
		resp.json(t, &begun)
		wrong, err = devicekey.SignEnrollment(priv, begun.Challenge)
		require.NoError(t, err)
		resp = h.post("/device-keys/login/finish", map[string]string{"challenge_id": begun.ID, "signature": wrong}, "")
		require.Equal(t, http.StatusUnauthorized, resp.status, "an enrollment signature signed in: %s", resp)
		right, err := devicekey.SignLogin(priv, begun.Challenge)
		require.NoError(t, err)
		resp = h.post("/device-keys/login/finish", map[string]string{"challenge_id": begun.ID, "signature": right}, "")
		require.Equal(t, http.StatusOK, resp.status, resp.String())
	})

	t.Run("an account's second factor gates enrollment", func(t *testing.T) {
		a := h.newAccount("dkmfa")
		backup := h.enrollEmail2FA(a)
		pub, priv := ed25519Key(t)
		e, err := c.BeginEnrollment(ctx, a.email, pub, "")
		require.NoError(t, err)
		code := h.verificationCode(a.email)
		_, err = c.FinishEnrollment(ctx, e, priv, code, "")
		var sf *devicekey.SecondFactorRequired
		require.ErrorAs(t, err, &sf)
		require.Equal(t, "backup_code", sf.Method, "the enrollment mailbox was offered as the second factor")
		requireRefusal(t, err, http.StatusForbidden, "step_up_required")

		h.passwordStep(a, "198.51.100.61")
		_, err = c.FinishEnrollment(ctx, e, priv, code, h.mail.Last(t, authtest.LoginCode, a.email).Code)
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_code")
		s, err := c.FinishEnrollment(ctx, e, priv, code, backup[0])
		require.NoError(t, err)
		s, err = c.Login(ctx, s.DeviceKey.ID, priv)
		require.NoError(t, err)
		_, claims := splitToken(t, s.AccessToken)
		require.ElementsMatch(t, []any{"device_key", "mfa"}, claims["amr"])
	})

	t.Run("an authenticator app is a second factor", func(t *testing.T) {
		a := h.newAccount("dktotp")
		secret, _ := h.enrollTOTP(h.login(a).AccessToken)
		pub, priv := ed25519Key(t)
		e, err := c.BeginEnrollment(ctx, a.email, pub, "")
		require.NoError(t, err)
		code := h.verificationCode(a.email)
		_, err = c.FinishEnrollment(ctx, e, priv, code, "")
		var sf *devicekey.SecondFactorRequired
		require.ErrorAs(t, err, &sf)
		require.Equal(t, "totp", sf.Method)
		_, err = c.FinishEnrollment(ctx, e, priv, code, authtest.TOTPCode(t, secret, time.Now().Add(30*time.Second)))
		require.NoError(t, err)
	})

	t.Run("a key enrolled before MFA signs in only once re-proven", func(t *testing.T) {
		a := h.newAccount("dkbefore")
		pub, priv := ed25519Key(t)
		s := enroll(t, a.email, pub, priv)
		backup := h.enrollEmail2FA(a)
		h.grant(iam.RootGroup(), a, "security")
		_, err := c.Login(ctx, s.DeviceKey.ID, priv)
		requireRefusal(t, err, http.StatusForbidden, "2fa_required")
		e, err := c.BeginEnrollment(ctx, a.email, pub, "")
		require.NoError(t, err)
		proof, err := c.FinishEnrollment(ctx, e, priv, h.verificationCode(a.email), backup[0])
		require.NoError(t, err)
		require.Equal(t, s.DeviceKey.ID, proof.DeviceKey.ID)
		_, err = c.Login(ctx, s.DeviceKey.ID, priv)
		require.NoError(t, err)
	})

	t.Run("an MFA-required role holder without a factor enrolls no key", func(t *testing.T) {
		holder := h.newAccount("dkrole")
		_, err := h.pool.Exec(ctx, `INSERT INTO profiles.group_user_roles(permission_group_id,user_id,role) VALUES($1::uuid,$2::uuid,'root:security')`, h.rootGroupID(), holder.id)
		require.NoError(t, err)
		pub, priv := ed25519Key(t)
		e, err := c.BeginEnrollment(ctx, holder.email, pub, "")
		require.NoError(t, err)
		_, err = c.FinishEnrollment(ctx, e, priv, h.verificationCode(holder.email), "")
		require.True(t, errors.Is(err, iam.ErrTwoFAEnrollmentRequired), "%v", err)
	})

	t.Run("only an email-proven token revokes the other machines", func(t *testing.T) {
		a := h.newAccount("dkothers")
		pub, priv := ed25519Key(t)
		otherPub, otherPriv := ed25519Key(t)
		kept, other := enroll(t, a.email, pub, priv), enroll(t, a.email, otherPub, otherPriv)
		s, err := c.Login(ctx, kept.DeviceKey.ID, priv)
		require.NoError(t, err)
		requireRefusal(t, c.RevokeOthers(ctx, s.AccessToken), http.StatusForbidden, "forbidden")
		_, err = c.Login(ctx, other.DeviceKey.ID, otherPriv)
		require.NoError(t, err)

		proof := enroll(t, a.email, pub, priv)
		require.Equal(t, kept.DeviceKey.ID, proof.DeviceKey.ID, "re-enrolling a live key made a new one")
		require.NoError(t, c.RevokeOthers(ctx, proof.AccessToken))
		_, err = c.Login(ctx, other.DeviceKey.ID, otherPriv)
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_credentials")
		keys, err := c.List(ctx, proof.AccessToken)
		require.NoError(t, err)
		require.Len(t, keys, 2)
		for _, k := range keys {
			require.Equal(t, k.ID == kept.DeviceKey.ID, k.RevokedAt == nil, "%+v", k)
		}

		// A key bound to one account never enrolls on another.
		stranger := h.newAccount("dkstranger")
		e, err := c.BeginEnrollment(ctx, stranger.email, pub, "")
		require.NoError(t, err)
		_, err = c.FinishEnrollment(ctx, e, priv, h.verificationCode(stranger.email), "")
		requireRefusal(t, err, http.StatusUnauthorized, "invalid_code")
	})

	t.Run("rate limits decode with their retry delay", func(t *testing.T) {
		limited := newHost(t, authtest.WithConfig(withDeviceKeys)).deviceKeyClient()
		email := unique("dkrate") + "@security.test"
		pub, _ := ed25519Key(t)
		var err error
		for range 10 {
			if _, err = limited.BeginEnrollment(ctx, email, pub, ""); err != nil {
				break
			}
		}
		requireRefusal(t, err, http.StatusTooManyRequests, "rate_limited")
		e, _ := iam.AsError(err)
		require.Positive(t, e.Metadata()["retry_after_seconds"], "%v", e.Metadata())
	})

	t.Run("a host without device keys mounts none and answers 404 with no code", func(t *testing.T) {
		offHost := newHost(t)
		off := offHost.deviceKeyClient()
		pub, _ := ed25519Key(t)
		_, err := off.BeginEnrollment(ctx, unique("dkoff")+"@security.test", pub, "")
		requireRefusal(t, err, http.StatusNotFound, "")
		require.False(t, errors.Is(err, iam.ErrDeviceKeysDisabled))
		for _, route := range offHost.auth.Routes() {
			require.NotEqual(t, iam.RouteDeviceKeys, route.Group, "%s %s", route.Method, route.Path)
		}
		_, err = offHost.auth.DeviceKeys(ctx, "00000000-0000-0000-0000-000000000000")
		require.ErrorIs(t, err, iam.ErrDeviceKeysDisabled, "the Client refuses device keys without the opt-in")
	})
}
