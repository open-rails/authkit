package authkit_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
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
	healthy := &twilioPool{numbers: []string{"+15017122661"}}
	var pool atomic.Pointer[twilioPool]
	pool.Store(healthy)
	sms, err := twilio.NewSMS(twilio.SMSConfig{AccountSID: "AC123", AuthToken: "token", MessagingServiceSID: "MG123",
		Client: twilioStandIn(t, &pool)})
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
	for failure, p := range map[string]*twilioPool{"reset": {reset: true}, "nosender": {}} {
		pool.Store(p)
		require.Error(t, probed(t, auth.SMSHealth, time.Now()), failure)
		require.False(t, capabilitiesOf(t, auth).Channels.SMS, failure)
		require.False(t, auth.SMSAvailable(), failure)
		require.True(t, auth.EmailAvailable(), "%s: email is unaffected", failure)
		require.Equal(t, []iam.TwoFactorMethod{iam.TwoFactorEmail, iam.TwoFactorTOTP}, auth.TwoFactorMethods(), "an unhealthy sender enrolls no SMS factor")
		expectUnavailable(t, serve(auth, http.MethodPost, "/api/v1/verify/request", `{"identifier":"+15551230000"}`), errmodel.CodeSMSUnavailable)

		pool.Store(healthy)
		require.NoError(t, probed(t, auth.SMSHealth, time.Now()), failure)
		require.True(t, capabilitiesOf(t, auth).Channels.SMS, failure)
		require.Contains(t, auth.TwoFactorMethods(), iam.TwoFactorSMS, failure)
	}
}

// SMS health fails only when Twilio surely refuses: the account or service
// lookup fails or is refused, the service has no sender, or every sender is a
// toll-free number whose verification is missing, pending or rejected (error
// 30032). Every kind of sender counts. A refused toll-free sender beside a
// working one, or a sender it can't tell about, stays healthy and warns once
// per change.
func TestSMSHealthFailsOnlyWhenTwilioRefuses(t *testing.T) {
	logs := captureLogs(t)
	var pool atomic.Pointer[twilioPool]
	sms, err := twilio.NewSMS(twilio.SMSConfig{AccountSID: "AC123", AuthToken: "token", MessagingServiceSID: "MG123",
		Client: twilioStandIn(t, &pool)})
	require.NoError(t, err)

	const longCode, tollFree, tollFree2, elsewhere = "+15017122661", "+18005550100", "+18445550101", "+18885550199"
	type verifications = [][2]string // {number, status}, in list order
	for i, step := range []struct {
		name             string
		pool             twilioPool
		fails            string // in the error; "" when healthy
		refused, unknown int    // warnings so far
	}{
		{"a long code", twilioPool{numbers: []string{longCode}}, "", 0, 0},
		{"a short code", twilioPool{senders: map[string]int{"ShortCodes": 1}}, "", 0, 0},
		{"an alphanumeric sender", twilioPool{senders: map[string]int{"AlphaSenders": 1}}, "", 0, 0},
		{"a destination alphanumeric sender", twilioPool{senders: map[string]int{"DestinationAlphaSenders": 1}}, "", 0, 0},
		{"a channel sender", twilioPool{senders: map[string]int{"ChannelSenders": 1}}, "", 0, 0},
		{"a toll-free number approved on a later page", twilioPool{numbers: []string{tollFree},
			verifications: verifications{{tollFree2, "TWILIO_APPROVED"}, {tollFree, "TWILIO_REJECTED"}, {tollFree, "TWILIO_APPROVED"}}}, "", 0, 0},
		{"no sender", twilioPool{}, "has no sender", 0, 0},
		{"only pending and unverified toll-free numbers", twilioPool{numbers: []string{tollFree, tollFree2},
			verifications: verifications{{elsewhere, "TWILIO_APPROVED"}, {tollFree, "PENDING_REVIEW"}}},
			"(" + tollFree + ", " + tollFree2 + "); Twilio refuses them with error 30032", 0, 0},
		{"an unverified toll-free number beside a short code", twilioPool{numbers: []string{tollFree2}, senders: map[string]int{"ShortCodes": 1}}, "", 1, 0},
		{"a pending toll-free number beside a long code on a later page", twilioPool{numbers: []string{tollFree, longCode},
			verifications: verifications{{tollFree, "IN_REVIEW"}}}, "", 2, 0},
		{"the same pool again", twilioPool{numbers: []string{tollFree, longCode},
			verifications: verifications{{tollFree, "IN_REVIEW"}}}, "", 2, 0},
		{"verifications the credentials can't read", twilioPool{numbers: []string{tollFree},
			failing: map[string]int{"/v1/Tollfree/Verifications": http.StatusForbidden}}, "", 2, 1},
		{"a failing verification lookup", twilioPool{numbers: []string{tollFree},
			failing: map[string]int{"/v1/Tollfree/Verifications": http.StatusInternalServerError}}, "", 2, 1},
		{"a verification status Twilio may add", twilioPool{numbers: []string{tollFree},
			verifications: verifications{{tollFree, "SOMETHING_NEW"}}}, "", 2, 1},
		{"a sender list it can't read", twilioPool{numbers: []string{tollFree}, verifications: verifications{{tollFree, "TWILIO_REJECTED"}},
			failing: map[string]int{"/v1/Services/MG123/ShortCodes": http.StatusForbidden}}, "", 3, 2},
		{"a sender list outage", twilioPool{numbers: []string{tollFree}, verifications: verifications{{tollFree, "PENDING_REVIEW"}},
			failing: map[string]int{"/v1/Services/MG123/ShortCodes": http.StatusBadGateway}}, "sender check failed", 3, 2},
		{"a service outage", twilioPool{failing: map[string]int{"/v1/Services/MG123": http.StatusServiceUnavailable}}, "messaging service check failed", 3, 2},
		{"a missing service", twilioPool{failing: map[string]int{"/v1/Services/MG123": http.StatusNotFound}}, "messaging service check failed", 3, 2},
		{"an account outage", twilioPool{failing: map[string]int{"/2010-04-01/Accounts/AC123.json": http.StatusInternalServerError}}, "credential check failed", 3, 2},
		{"rejected credentials", twilioPool{failing: map[string]int{"/2010-04-01/Accounts/AC123.json": http.StatusUnauthorized}}, "credential check failed", 3, 2},
	} {
		pool.Store(&step.pool)
		err := sms.CheckHealth(t.Context())
		if step.fails == "" {
			require.NoError(t, err, "step %d: %s", i, step.name)
		} else {
			require.ErrorContains(t, err, step.fails, "step %d: %s", i, step.name)
		}
		require.Equal(t, step.refused, strings.Count(logs.String(), "Twilio refuses these toll-free SMS senders"), "step %d: %s", i, step.name)
		require.Equal(t, step.unknown, strings.Count(logs.String(), "can't tell whether Twilio accepts these SMS senders"), "step %d: %s", i, step.name)
	}
	for _, named := range []string{"senders=[" + tollFree2 + "]", "senders=[" + tollFree + "]", "senders=[ShortCodes]"} {
		require.Contains(t, logs.String(), named)
	}
}

// A SendGrid key that is rejected or can't send mail disables only email flows
// (503), and the next passing probe re-arms them. Anything else stays healthy:
// an unauthenticated sender, since not every SendGrid account enforces sender
// identity, only warns once per change; a key that can't read its senders, or
// an outage, can't tell.
func TestEmailHealthProbeRearmsEmailFlows(t *testing.T) {
	logs := captureLogs(t)
	warnings := func() int { return strings.Count(logs.String(), "SendGrid sender is unauthenticated") }

	var mode atomic.Value // "", "badkey", "noscope", "unauthenticated", "unverified", "cant_tell", "outage"
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
				case "outage":
					http.Error(w, `{"errors":[{"message":"internal error"}]}`, http.StatusServiceUnavailable)
				default:
					_, _ = w.Write([]byte(`{"scopes":["alerts.read","mail.send"]}`))
				}
			case "/v3/whitelabel/domains":
				switch m {
				case "cant_tell":
					http.Error(w, `{"errors":[{"message":"access forbidden"}]}`, http.StatusForbidden)
				case "unauthenticated", "unverified":
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
	for _, failure := range []string{"badkey", "noscope"} {
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
	require.Zero(t, warnings(), "a valid authenticated domain warns nothing")

	// Each step's warning count is cumulative. The order keeps a probe that
	// straddles a mode change from reaching a third state.
	for i, step := range []struct {
		mode     string
		warnings int
	}{{"unverified", 1}, {"unverified", 1}, {"unauthenticated", 2}, {"", 2}, {"unauthenticated", 3}} {
		mode.Store(step.mode)
		require.NoError(t, probed(t, auth.EmailHealth, time.Now()), "step %d", i)
		require.True(t, capabilitiesOf(t, auth).Channels.Email, "step %d", i)
		require.Equal(t, step.warnings, warnings(), "step %d", i)
	}
	require.Contains(t, logs.String(), `from=hello@acme.test reason="single sender not verified yet"`)
	require.Contains(t, logs.String(), `from=hello@acme.test reason="no valid authenticated domain and no verified single sender"`)

	for _, m := range []string{"cant_tell", "outage"} {
		mode.Store(m)
		require.NoError(t, probed(t, auth.EmailHealth, time.Now()), m)
		require.True(t, auth.EmailAvailable(), m)
	}
	require.Equal(t, 3, warnings(), "can't tell warns nothing")
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

// twilioPool is what twilioStandIn serves. Its lists answer one item per page,
// so every read pages.
type twilioPool struct {
	reset         bool           // close every connection
	numbers       []string       // the service's phone numbers
	verifications [][2]string    // the account's toll-free verifications: {number, status}
	senders       map[string]int // entries of the service's other sender lists, by path
	failing       map[string]int // status to answer, by path
}

// twilioStandIn serves the Twilio API that SMS health reads from pool.
func twilioStandIn(t *testing.T, pool *atomic.Pointer[twilioPool]) *http.Client {
	sid := func(number string) string { return "PN" + strings.TrimPrefix(number, "+") }
	return standIn(t, func(w http.ResponseWriter, r *http.Request) {
		p := pool.Load()
		if p.reset {
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
			return
		}
		if status := p.failing[r.URL.Path]; status != 0 {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"code":20001,"message":"stand-in failure"}`))
			return
		}
		var items []map[string]string
		switch r.URL.Path {
		case "/2010-04-01/Accounts/AC123.json":
			_, _ = w.Write([]byte(`{"status":"active"}`))
			return
		case "/v1/Services/MG123":
			_, _ = w.Write([]byte(`{}`))
			return
		case "/v1/Services/MG123/PhoneNumbers":
			for _, n := range p.numbers {
				items = append(items, map[string]string{"sid": sid(n), "phone_number": n})
			}
			twilioPage(w, r, "phone_numbers", items)
			return
		case "/v1/Tollfree/Verifications":
			for _, v := range p.verifications {
				items = append(items, map[string]string{"tollfree_phone_number_sid": sid(v[0]), "tollfree_phone_number": v[0], "status": v[1]})
			}
			twilioPage(w, r, "verifications", items)
			return
		}
		kind := strings.TrimPrefix(r.URL.Path, "/v1/Services/MG123/")
		key, ok := map[string]string{"ShortCodes": "short_codes", "AlphaSenders": "alpha_senders",
			"DestinationAlphaSenders": "alpha_senders", "ChannelSenders": "senders"}[kind]
		if !ok {
			http.NotFound(w, r)
			return
		}
		for range p.senders[kind] {
			items = append(items, map[string]string{"sid": "XX1"})
		}
		twilioPage(w, r, key, items)
	})
}

// twilioPage answers item ?Page= of items under key, with Twilio's meta.
func twilioPage(w http.ResponseWriter, r *http.Request, key string, items []map[string]string) {
	page, _ := strconv.Atoi(r.URL.Query().Get("Page"))
	body := map[string]any{key: []map[string]string{}, "meta": map[string]any{"key": key, "next_page_url": nil}}
	if page < len(items) {
		body[key] = items[page : page+1]
	}
	if page+1 < len(items) {
		body["meta"] = map[string]any{"key": key, "next_page_url": fmt.Sprintf("https://%s%s?Page=%d&PageToken=PT%d", r.Host, r.URL.Path, page+1, page+1)}
	}
	_ = json.NewEncoder(w).Encode(body)
}

// captureLogs sends the process logger to the returned buffer until the test
// ends, so the test never runs in parallel.
func captureLogs(t *testing.T) *lockedBuffer {
	logs := &lockedBuffer{}
	previous, logOut, logFlags := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() {
		slog.SetDefault(previous)
		log.SetOutput(logOut)
		log.SetFlags(logFlags)
	})
	return logs
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
