package authkit_test

import (
	"context"
	"crypto"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-rails/authkit"
	twilio "github.com/open-rails/authkit/adapters/twilio/sms"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
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
	signer, err := jwtkit.NewRSASigner(2048, "sms-health")
	require.NoError(t, err)
	auth, err := authkit.New(context.Background(), authkit.Config{
		Keys:  authkit.KeysConfig{Source: jwtkit.StaticKeySource{Active: signer, Pubs: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()}}},
		Token: authkit.TokenConfig{Issuer: "https://example.com", IssuedAudiences: []string{"test-app"}},
		HTTP:  authkit.HTTPConfig{DirectPeerIP: true, DisableRateLimiting: true},
	}, authkit.Deps{Postgres: testdb.Pool(t), SMS: sender})
	require.NoError(t, err)
	t.Cleanup(auth.Close)

	serve := func(method, path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		auth.Handler().ServeHTTP(w, r)
		return w
	}
	phoneFlows := func() (bool, int, string) {
		var caps struct {
			Passwordless struct {
				Channels []string `json:"channels"`
			} `json:"passwordless"`
		}
		require.NoError(t, json.Unmarshal(serve(http.MethodGet, "/api/v1/capabilities", "").Body.Bytes(), &caps))
		w := serve(http.MethodPost, "/api/v1/verify/request", `{"identifier":"+15551230000"}`)
		var env iam.ErrorEnvelope
		_ = json.Unmarshal(w.Body.Bytes(), &env)
		return slices.Contains(caps.Passwordless.Channels, "sms"), w.Code, env.Error.Code
	}

	offered, _, _ := phoneFlows()
	require.True(t, offered, "optimistic before the first probe")
	for _, failure := range []string{"reset", "nosender"} {
		mode.Store(failure)
		require.Error(t, auth.CheckSMSHealth(t.Context()))
		offered, status, code := phoneFlows()
		require.False(t, offered, failure)
		require.Equal(t, http.StatusServiceUnavailable, status, failure)
		require.Equal(t, string(errmodel.CodePhoneVerificationUnavailable), code, failure)

		mode.Store("")
		require.NoError(t, auth.CheckSMSHealth(t.Context()))
		offered, _, _ = phoneFlows()
		require.True(t, offered, failure)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
