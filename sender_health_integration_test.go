package authkit_test

import (
	"encoding/json"
	"errors"
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
	sms, err := twilio.NewSMS(twilio.SMSConfig{AccountSID: "AC123", AuthToken: "token", MessagingServiceSID: "MG123",
		Client: standIn(t, func(w http.ResponseWriter, r *http.Request) {
			if mode.Load() == "reset" {
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
		})})
	require.NoError(t, err)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.SenderHealthInterval = 50 * time.Millisecond
	}), authtest.WithDeps(func(d *authkit.Deps) { d.SMS = sms }))

	at, _ := auth.SMSHealth()
	require.True(t, at.IsZero(), "no probe before Start")
	require.True(t, capabilitiesOf(t, auth).Channels.SMS, "optimistic before the first probe")
	require.True(t, auth.SMSAvailable())
	require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorSMS, iam.TwoFactorTOTP}, auth.TwoFactorMethods())
	require.NoError(t, auth.Start(t.Context()))
	require.NoError(t, probed(t, auth.SMSHealth, time.Time{}), "Start probes at once")
	for _, failure := range []string{"reset", "nosender"} {
		mode.Store(failure)
		require.Error(t, probed(t, auth.SMSHealth, time.Now()), failure)
		require.False(t, capabilitiesOf(t, auth).Channels.SMS, failure)
		require.False(t, auth.SMSAvailable(), failure)
		require.True(t, auth.EmailAvailable(), "%s: email is unaffected", failure)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorTOTP}, auth.TwoFactorMethods(), "an unhealthy sender enrolls no SMS factor")
		expectUnavailable(t, serve(auth, http.MethodPost, "/api/v1/verify/request", `{"identifier":"+15551230000"}`), errmodel.CodeSMSUnavailable)

		mode.Store("")
		require.NoError(t, probed(t, auth.SMSHealth, time.Now()), failure)
		require.True(t, capabilitiesOf(t, auth).Channels.SMS, failure)
		require.Contains(t, auth.TwoFactorMethods(), iam.TwoFactorSMS, failure)
	}
}

// A SendGrid key that is invalid, can't send mail, or sends from an unproven
// address disables only email flows (503); a key that can't read its senders
// can't tell, which stays healthy. The next passing probe re-arms them.
func TestEmailHealthProbeRearmsEmailFlows(t *testing.T) {
	var mode atomic.Value // "", "badkey", "noscope", "unverified", "cant_tell"
	mode.Store("")
	email, err := twilio.NewEmail(twilio.EmailConfig{APIKey: "SG.key", FromEmail: "hello@acme.test",
		Client: standIn(t, func(w http.ResponseWriter, r *http.Request) {
			m := mode.Load().(string)
			if r.Header.Get("Authorization") != "Bearer SG.key" {
				http.Error(w, `{"errors":[{"message":"bad auth"}]}`, http.StatusUnauthorized)
				return
			}
			switch r.URL.Path {
			case "/v3/scopes":
				switch m {
				case "badkey":
					http.Error(w, `{"errors":[{"message":"authorization required"}]}`, http.StatusUnauthorized)
				case "noscope":
					_, _ = w.Write([]byte(`{"scopes":["alerts.read"]}`))
				default:
					_, _ = w.Write([]byte(`{"scopes":["alerts.read","mail.send"]}`))
				}
			case "/v3/whitelabel/domains":
				switch m {
				case "cant_tell":
					http.Error(w, `{"errors":[{"message":"access forbidden"}]}`, http.StatusForbidden)
				case "unverified":
					_, _ = w.Write([]byte(`[{"domain":"acme.test","valid":false}]`))
				default:
					if r.URL.Query().Get("domain") != "acme.test" {
						_, _ = w.Write([]byte(`[]`))
						return
					}
					_, _ = w.Write([]byte(`[{"domain":"mail.acme.test","valid":true},{"domain":"acme.test","valid":true}]`))
				}
			case "/v3/verified_senders":
				switch m {
				case "cant_tell":
					http.Error(w, `{"errors":[{"message":"access forbidden"}]}`, http.StatusForbidden)
				case "unverified":
					if r.URL.Query().Get("lastSeenID") != "" {
						_, _ = w.Write([]byte(`{"results":[]}`))
						return
					}
					_, _ = w.Write([]byte(`{"results":[{"id":1,"from_email":"other@acme.test","verified":true},{"id":2,"from_email":"hello@acme.test","verified":false}]}`))
				default:
					_, _ = w.Write([]byte(`{"results":[]}`))
				}
			default:
				http.NotFound(w, r)
			}
		})})
	require.NoError(t, err)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.SenderHealthInterval = 50 * time.Millisecond
	}), authtest.WithDeps(func(d *authkit.Deps) { d.Email = email }))

	require.True(t, auth.EmailAvailable(), "optimistic before the first probe")
	require.NoError(t, auth.Start(t.Context()))
	require.NoError(t, probed(t, auth.EmailHealth, time.Time{}), "Start probes at once")
	for _, failure := range []string{"badkey", "noscope", "unverified"} {
		mode.Store(failure)
		require.Error(t, probed(t, auth.EmailHealth, time.Now()), failure)
		require.False(t, capabilitiesOf(t, auth).Channels.Email, failure)
		require.False(t, auth.EmailAvailable(), failure)
		require.True(t, auth.SMSAvailable(), "%s: SMS is unaffected", failure)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorSMS, iam.TwoFactorTOTP}, auth.TwoFactorMethods(), "an unhealthy sender enrolls no email factor")
		expectUnavailable(t, serve(auth, http.MethodPost, "/api/v1/verify/request", `{"identifier":"ana@acme.test"}`), errmodel.CodeEmailUnavailable)

		mode.Store("")
		require.NoError(t, probed(t, auth.EmailHealth, time.Now()), failure)
		require.True(t, capabilitiesOf(t, auth).Channels.Email, failure)
		require.Contains(t, auth.TwoFactorMethods(), iam.TwoFactorEmail, failure)
	}
	mode.Store("cant_tell")
	require.NoError(t, probed(t, auth.EmailHealth, time.Now()), "a key without read access can't tell")
	require.True(t, auth.EmailAvailable())
}

// A host's own sender reports its health the same way: while its
// CheckHealth fails, flows over its channel answer the channel's unavailable
// error at once, before any send or account lookup, and the other channel
// keeps working; the next passing check re-arms it.
func TestHostSenderHealthGatesItsChannel(t *testing.T) {
	auth, out := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.SenderHealthInterval = 50 * time.Millisecond
		c.Registration.PasswordlessLogin = true
	}))
	mail, phone := "ana@example.test", "+15551234567"
	_, err := auth.CreateUser(t.Context(), iam.NewUser{Email: mail, Phone: phone, Username: "anaberry", EmailVerified: true, PhoneVerified: true})
	require.NoError(t, err)
	require.NoError(t, auth.Start(t.Context()))
	require.NoError(t, probed(t, auth.EmailHealth, time.Time{}))
	require.NoError(t, probed(t, auth.SMSHealth, time.Time{}))

	start := func(identifier string) *httptest.ResponseRecorder {
		return serve(auth, http.MethodPost, "/api/v1/passwordless/start", `{"identifier":"`+identifier+`","mode":"code"}`)
	}
	for _, ch := range []struct {
		name        string
		setHealth   func(error)
		health      func() (time.Time, error)
		available   func() bool
		offered     func(capabilities) bool
		to, unknown string
		code        errmodel.Code
		other       string
	}{
		{"email", out.SetEmailHealth, auth.EmailHealth, auth.EmailAvailable, func(c capabilities) bool { return c.Channels.Email },
			mail, "nobody@example.test", errmodel.CodeEmailUnavailable, phone},
		{"sms", out.SetSMSHealth, auth.SMSHealth, auth.SMSAvailable, func(c capabilities) bool { return c.Channels.SMS },
			phone, "+15550000000", errmodel.CodeSMSUnavailable, mail},
	} {
		ch.setHealth(errors.New(ch.name + " provider down"))
		require.Error(t, probed(t, ch.health, time.Now()), ch.name)
		require.False(t, ch.available(), ch.name)
		caps := capabilitiesOf(t, auth)
		require.False(t, ch.offered(caps), ch.name)
		require.NotContains(t, caps.Passwordless.Channels, ch.name, ch.name)
		sent := len(out.Messages("", ch.to))
		expectUnavailable(t, start(ch.to), ch.code)
		expectUnavailable(t, start(ch.unknown), ch.code)
		require.Len(t, out.Messages("", ch.to), sent, "%s: nothing is sent while the channel is down", ch.name)
		require.Equal(t, http.StatusAccepted, start(ch.other).Code, "%s: the other channel keeps working", ch.name)

		ch.setHealth(nil)
		require.NoError(t, probed(t, ch.health, time.Now()), ch.name)
		require.True(t, ch.available(), ch.name)
		require.Contains(t, capabilitiesOf(t, auth).Passwordless.Channels, ch.name, ch.name)
		require.Equal(t, http.StatusAccepted, start(ch.to).Code, ch.name)
		require.NotEmpty(t, out.Last(t, iam.MessageVerification, ch.to).Code, ch.name)
	}
}

type capabilities struct {
	Channels struct {
		Email bool `json:"email"`
		SMS   bool `json:"sms"`
	} `json:"channels"`
	Passwordless struct {
		Channels []string `json:"channels"`
	} `json:"passwordless"`
}

func capabilitiesOf(t *testing.T, auth *authkit.Client) capabilities {
	t.Helper()
	var caps capabilities
	require.NoError(t, json.Unmarshal(serve(auth, http.MethodGet, "/api/v1/capabilities", "").Body.Bytes(), &caps))
	return caps
}

func serve(auth *authkit.Client, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	auth.Handler().ServeHTTP(w, r)
	return w
}

func expectUnavailable(t *testing.T, w *httptest.ResponseRecorder, code errmodel.Code) {
	t.Helper()
	var env iam.ErrorEnvelope
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &env), w.Body.String())
	require.Equal(t, http.StatusServiceUnavailable, w.Code, w.Body.String())
	require.Equal(t, string(code), env.Error.Code)
}

// probed waits for a health check that started after since and returns its
// verdict.
func probed(t *testing.T, health func() (time.Time, error), since time.Time) error {
	t.Helper()
	var err error
	require.Eventually(t, func() bool {
		var at time.Time
		at, err = health()
		return at.After(since)
	}, 5*time.Second, 10*time.Millisecond)
	return err
}

// standIn serves a provider's fixed API hosts from handler.
func standIn(t *testing.T, handler http.HandlerFunc) *http.Client {
	api := httptest.NewServer(handler)
	t.Cleanup(api.Close)
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host = "http", api.Listener.Addr().String()
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
