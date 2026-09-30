package authkit_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/adapters/twilio"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/stretchr/testify/require"
)

// A Twilio outage or misconfiguration disables only phone flows (503), and the
// next passing probe, scheduled by Start, re-arms them without a restart.
func TestSMSHealthProbeRearmsPhoneFlows(t *testing.T) {
	var mode atomic.Value // "", "reset", "nosender"
	twilioAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch mode.Load() {
		case "reset":
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		switch r.URL.Path {
		case "/2010-04-01/Accounts/AC123.json":
			_, _ = w.Write([]byte(`{"status":"active"}`))
		case "/v1/Services/MG123":
			_, _ = w.Write([]byte(`{}`))
		case "/v1/Services/MG123/PhoneNumbers":
			if mode.Load() == "nosender" {
				_, _ = w.Write([]byte(`{"phone_numbers":[]}`))
				return
			}
			_, _ = w.Write([]byte(`{"phone_numbers":[{"sid":"PN1","phone_number":"+15017122661"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(twilioAPI.Close)
	// Route Twilio's fixed API hosts to the stand-in.
	toStandIn := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = "http", twilioAPI.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(r)
	})
	sms, err := twilio.NewSMS(twilio.SMSConfig{AccountSID: "AC123", AuthToken: "token", MessagingServiceSID: "MG123", Client: &http.Client{Transport: toStandIn}})
	require.NoError(t, err)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.SMSHealthInterval = 50 * time.Millisecond
	}), authtest.WithDeps(func(d *authkit.Deps) { d.SMS, d.SMSHealth = sms.Send, sms.CheckHealth }))

	serve := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		auth.Handler().ServeHTTP(w, r)
		return w
	}
	phoneFlows := func() (bool, int, string) {
		var caps struct {
			Channels struct {
				SMS bool `json:"sms"`
			} `json:"channels"`
		}
		require.NoError(t, json.Unmarshal(serve(http.MethodGet, "/api/v1/capabilities", "").Body.Bytes(), &caps))
		w := serve(http.MethodPost, "/api/v1/verify/request", `{"identifier":"+15551230000"}`)
		var env iam.ErrorEnvelope
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return caps.Channels.SMS, w.Code, env.Error.Code
	}
	probed := func(since time.Time) error {
		var err error
		require.Eventually(t, func() bool {
			var at time.Time
			at, err = auth.SMSHealth()
			return at.After(since)
		}, 5*time.Second, 10*time.Millisecond)
		return err
	}

	at, _ := auth.SMSHealth()
	require.True(t, at.IsZero(), "no probe before Start")
	offered, _, _ := phoneFlows()
	require.True(t, offered, "optimistic before the first probe")
	require.True(t, auth.SMSAvailable())
	require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorSMS, iam.TwoFactorTOTP}, auth.TwoFactorMethods())
	require.NoError(t, auth.Start(t.Context()))
	require.NoError(t, probed(time.Time{}), "Start probes at once")
	for _, failure := range []string{"reset", "nosender"} {
		mode.Store(failure)
		require.Error(t, probed(time.Now()), failure)
		offered, status, code := phoneFlows()
		require.False(t, offered, failure)
		require.False(t, auth.SMSAvailable(), failure)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorTOTP}, auth.TwoFactorMethods(), "an unhealthy sender enrolls no SMS factor")
		require.Equal(t, http.StatusServiceUnavailable, status, failure)
		require.Equal(t, string(errmodel.CodeSMSUnavailable), code, failure)

		mode.Store("")
		require.NoError(t, probed(time.Now()), failure)
		offered, _, _ = phoneFlows()
		require.True(t, offered, failure)
		require.Contains(t, auth.TwoFactorMethods(), iam.TwoFactorSMS, failure)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
