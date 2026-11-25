package critical_test

import (
	"crypto/ed25519"
	"net/http"
	"testing"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
)

// TestCriticalDeviceKeys drives a machine's Ed25519 sign-in key over HTTP:
// enrolled by the emailed code and its own signature, then signing in by
// signing a fresh challenge.
func TestCriticalDeviceKeys(t *testing.T) {
	t.Parallel()
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { mountGroups(c, iam.RouteDeviceKeys) }))
	u := f.user(t)
	machine, err := devicekey.NewClient(f.server.URL+f.auth.APIBase(), f.server.Client())
	noError(t, err)
	pub, key, err := ed25519.GenerateKey(nil)
	noError(t, err)
	_, stranger, err := ed25519.GenerateKey(nil)
	noError(t, err)
	var enrolled devicekey.Session

	t.Run("AK-J10-C01_a_device_key_enrolls_only_with_the_emailed_code_and_its_own_signature", func(t *testing.T) {
		begin := func() (devicekey.Enrollment, string) {
			e, err := machine.BeginEnrollment(t.Context(), u.Email, pub, "build agent")
			noError(t, err)
			return e, f.out.Last(t, iam.MessageVerification, u.Email).Code
		}
		e, code := begin()
		wrong := "000000"
		if code == wrong {
			wrong = "111111"
		}
		_, err := machine.FinishEnrollment(t.Context(), e, key, wrong, "")
		if ae, ok := iam.AsError(err); !ok || ae.Code() != "invalid_code" {
			t.Errorf("a wrong code = %v, want invalid_code", err)
		}
		// Another key's signature over the enrollment's challenge.
		forged, err := devicekey.SignEnrollment(stranger, e.Challenge)
		noError(t, err)
		f.call(t, "POST", "/device-keys/enroll/finish", "", map[string]string{"enrollment_id": e.ID, "code": code, "signature": forged}).expect(t, http.StatusUnauthorized, "invalid_code")
		e, code = begin()
		enrolled, err = machine.FinishEnrollment(t.Context(), e, key, code, "")
		noError(t, err)
		me := f.call(t, "GET", "/me", enrolled.AccessToken, nil)
		me.want(t, http.StatusOK, "")
		var who struct {
			ID string `json:"id"`
		}
		decode(t, me.body, &who)
		if who.ID != u.ID || enrolled.DeviceKey.ID == "" {
			t.Fatalf("the enrolled key signed in %s with key %q", who.ID, enrolled.DeviceKey.ID)
		}
		// The enrollment is spent.
		if _, err := machine.FinishEnrollment(t.Context(), e, key, code, ""); err == nil {
			t.Error("an enrollment finished twice")
		}
	})

	t.Run("AK-J10-C02_a_device_key_signs_in_by_its_own_signature_over_one_fresh_challenge", func(t *testing.T) {
		if enrolled.DeviceKey.ID == "" {
			t.Fatal("AK-J10-C01 enrolled no key")
		}
		begin := func() (id, challenge string) {
			r := f.call(t, "POST", "/device-keys/login/begin", "", map[string]string{"device_key_id": enrolled.DeviceKey.ID})
			r.want(t, http.StatusOK, "")
			var begun struct {
				ID        string `json:"challenge_id"`
				Challenge string `json:"challenge"`
			}
			decode(t, r.body, &begun)
			return begun.ID, begun.Challenge
		}
		finish := func(id, signature string) response {
			return f.call(t, "POST", "/device-keys/login/finish", "", map[string]string{"challenge_id": id, "signature": signature})
		}
		id, challenge := begin()
		forged, err := devicekey.SignLogin(stranger, challenge)
		noError(t, err)
		finish(id, forged).expect(t, http.StatusUnauthorized, "authentication_failed")
		// An enrollment signature over a login challenge is another domain's.
		id, challenge = begin()
		crossed, err := devicekey.SignEnrollment(key, challenge)
		noError(t, err)
		finish(id, crossed).expect(t, http.StatusUnauthorized, "authentication_failed")
		id, challenge = begin()
		signed, err := devicekey.SignLogin(key, challenge)
		noError(t, err)
		r := finish(id, signed)
		r.want(t, http.StatusOK, "")
		var result signInResult
		decode(t, r.body, &result)
		if result.Status != "complete" || result.Tokens == nil || result.User == nil || result.User.ID != u.ID {
			t.Fatalf("device-key sign-in answered %s", r.body)
		}
		f.call(t, "GET", "/me", result.Tokens.AccessToken, nil).want(t, http.StatusOK, "")
		// The challenge answers once.
		finish(id, signed).expect(t, http.StatusUnauthorized, "authentication_failed")
		session, err := machine.Login(t.Context(), enrolled.DeviceKey.ID, key)
		noError(t, err)
		if session.DeviceKey.ID != enrolled.DeviceKey.ID {
			t.Fatalf("signed in with key %s, want %s", session.DeviceKey.ID, enrolled.DeviceKey.ID)
		}
		if _, err := machine.Login(t.Context(), enrolled.DeviceKey.ID, stranger); err == nil {
			t.Error("another key signed in as the enrolled one")
		}
	})
}
