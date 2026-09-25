package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	authkit "github.com/open-rails/authkit"
	twilio "github.com/open-rails/authkit/adapters/twilio/sms"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// A Twilio outage or misconfiguration disables only phone flows (503), and the
// next passing probe re-arms them without a restart.
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
	sender, err := twilio.New(twilio.Config{AccountSID: "AC123", AuthToken: "token", MessagingServiceSID: "MG123", Client: &http.Client{Transport: toStandIn}})
	require.NoError(t, err)
	srv, err := newServer(newServerClient(t, newServerTestConfig(), testdb.Pool(t), withSMSSender(sender)), WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	phoneFlows := func() (bool, int, string) {
		w := serveJSON(srv, http.MethodPost, "/verify/request", `{"identifier":"+15551230000"}`)
		var env authkit.ErrorEnvelope
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return slices.Contains(srv.capabilities().Passwordless.Channels, "sms"), w.Code, env.Error.Code
	}

	require.True(t, srv.SMSAvailable(), "optimistic before the first probe")
	for _, failure := range []string{"reset", "nosender"} {
		mode.Store(failure)
		require.Error(t, srv.CheckSMSHealth(t.Context()))
		offered, status, code := phoneFlows()
		require.False(t, offered, failure)
		require.Equal(t, http.StatusServiceUnavailable, status, failure)
		require.Equal(t, string(authkit.CodePhoneVerificationUnavailable), code, failure)

		mode.Store("")
		require.NoError(t, srv.CheckSMSHealth(t.Context()))
		offered, _, _ = phoneFlows()
		require.True(t, offered, failure)
		require.True(t, srv.SMSAvailable(), failure)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
