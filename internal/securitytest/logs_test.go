package securitytest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/stretchr/testify/require"
)

// logBuffer is everything logged while a test runs.
type logBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *logBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *logBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureLogs routes the slog default, which also carries the standard log
// package, into a buffer for the rest of the test. Timestamps are dropped so
// their digits cannot pass for a one-time code.
func captureLogs(t *testing.T) *logBuffer {
	b := &logBuffer{}
	prev, out, flags, prefix := slog.Default(), log.Writer(), log.Flags(), log.Prefix()
	slog.SetDefault(slog.New(slog.NewTextHandler(b, &slog.HandlerOptions{Level: slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		}})))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(out)
		log.SetFlags(flags)
		log.SetPrefix(prefix)
	})
	return b
}

// secretJar collects every secret that crosses AuthKit's HTTP surface or its
// outbox: request credentials, issued tokens, codes and keys.
type secretJar struct {
	mu      sync.Mutex
	secrets map[string]string // secret -> where it was seen
}

var (
	requestSecrets  = map[string]bool{"password": true, "new_password": true, "current_password": true, "code": true, "code_2fa": true, "token": true, "refresh_token": true, "signature": true, "challenge": true, "invite_code": true}
	responseSecrets = map[string]bool{"access_token": true, "refresh_token": true, "secret": true, "otpauth_uri": true, "backup_codes": true, "code": true, "token": true, "challenge": true}
)

func (j *secretJar) add(where string, v any) {
	switch v := v.(type) {
	case string:
		if len(v) < 6 {
			return
		}
		j.mu.Lock()
		defer j.mu.Unlock()
		if j.secrets == nil {
			j.secrets = map[string]string{}
		}
		j.secrets[v] = where
	case []any:
		for _, x := range v {
			j.add(where, x)
		}
	}
}

// harvest adds the values of fields found anywhere in v, except inside an
// error envelope.
func (j *secretJar) harvest(where string, v any, fields map[string]bool) {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if k == "error" {
				continue
			}
			if fields[k] {
				j.add(where+" "+k, x)
			}
			j.harvest(where, x, fields)
		}
	case []any:
		for _, x := range v {
			j.harvest(where, x, fields)
		}
	}
}

func (j *secretJar) harvestJSON(where string, raw []byte, fields map[string]bool) {
	var v any
	if json.Unmarshal(raw, &v) == nil {
		j.harvest(where, v, fields)
	}
}

func (j *secretJar) all() map[string]string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return maps.Clone(j.secrets)
}

func isRefreshCookie(c *http.Cookie) bool { return strings.HasSuffix(c.Name, "authkit_rt") }

// observe serves next and records the secrets of every exchange.
func (j *secretJar) observe(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		where := r.Method + " " + r.URL.Path
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		j.harvestJSON(where+" request", body, requestSecrets)
		if bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok {
			j.add(where+" bearer", bearer)
		}
		for _, c := range r.Cookies() {
			if isRefreshCookie(c) {
				j.add(where+" cookie", c.Value)
			}
		}
		rec := httptest.NewRecorder()
		next.ServeHTTP(rec, r)
		if rec.Code < 300 {
			j.harvestJSON(where+" response", rec.Body.Bytes(), responseSecrets)
		}
		for _, c := range rec.Result().Cookies() {
			if isRefreshCookie(c) {
				j.add(where+" set-cookie", c.Value)
			}
		}
		maps.Copy(w.Header(), rec.Header())
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	})
}

// observed serves h's runtime through j.
func (h *host) observed(j *secretJar) *host {
	h.t.Helper()
	out := *h
	out.server = httptest.NewServer(j.observe(h.auth.Handler()))
	h.t.Cleanup(out.server.Close)
	return &out
}

// addOutbox adds every code, link and link token AuthKit asked the host to
// deliver.
func (j *secretJar) addOutbox(mail *authtest.Outbox) {
	for _, m := range mail.Messages("", "") {
		where := "outbox " + string(m.Kind)
		j.add(where+" code", m.Code)
		j.add(where+" link", m.Link)
		j.add(where+" token", m.Token)
		if u, err := url.Parse(m.Link); err == nil {
			if q, err := url.ParseQuery(u.Fragment); err == nil {
				j.add(where+" invite", q.Get("account_invite_token"))
			}
		}
	}
}

var digits = regexp.MustCompile(`^[0-9]+$`)

// leakedIn returns the log line holding secret. A numeric code counts only as
// a whole word, so it is not found inside a longer number or an identifier.
func leakedIn(logs, secret string) string {
	match := func(line string) bool { return strings.Contains(line, secret) }
	if digits.MatchString(secret) {
		word := regexp.MustCompile(`(^|[^0-9A-Za-z])` + secret + `($|[^0-9A-Za-z])`)
		match = word.MatchString
	}
	for _, line := range strings.Split(logs, "\n") {
		if match(line) {
			return line
		}
	}
	return ""
}

// flakyEmail delivers through send, then fails code and link messages while
// down is set, as a mail provider outage does after AuthKit handed it the
// message.
func flakyEmail(send func(context.Context, iam.EmailMessage) error, down *atomic.Bool) func(context.Context, iam.EmailMessage) error {
	return func(ctx context.Context, m iam.EmailMessage) error {
		err := send(ctx, m)
		switch m.Kind {
		case iam.MessageVerification, iam.MessagePasswordReset, iam.MessageInvite, iam.MessageLoginCode:
			if err == nil && down.Load() {
				return errors.New("smtp: 451 4.3.0 mail server temporarily unavailable")
			}
		}
		return err
	}
}

// TestSecuritySecretsStayOutOfLogs: AuthKit's log output (the slog default,
// which carries the standard log package and AuthKit's River) never holds a
// secret it handled: a password or its hash, an access or refresh token, an
// API-key secret, a one-time or backup code, a TOTP secret, or a reset,
// verification or invite link or its token. The credential flows run on the
// HTTP surface, then again while the mail provider fails, so the error paths
// log too.
func TestSecuritySecretsStayOutOfLogs(t *testing.T) {
	logs := captureLogs(t)
	var mailDown atomic.Bool
	jar := &secretJar{}
	h := newHost(t, withHTTP(generousLimits), authtest.WithConfig(withRBAC), authtest.WithConfig(withDeviceKeys), authtest.WithConfig(strictRotation),
		authtest.WithConfig(func(c *authkit.Config) { c.Registration.PasswordlessLogin = true }),
		authtest.WithDeps(func(d *authkit.Deps) { d.Email = flakyEmail(d.Email, &mailDown) }))
	h = h.observed(jar)
	// AuthKit's River runs through every flow below and logs to the same place.
	require.NoError(t, h.auth.Start(context.Background()))
	require.Eventually(t, func() bool { return strings.Contains(logs.String(), "River client started") }, time.Minute, 50*time.Millisecond,
		"AuthKit's River did not log through the slog default")
	ok := func(r response) response {
		t.Helper()
		require.Less(t, r.status, 300, r.String())
		return r
	}

	// Register, verify with a code and with a link, sign in with a password.
	email := unique("logs") + "@security.test"
	own := h.register(email)
	h.proveOwnEmail(email, own)
	other := unique("logslink") + "@security.test"
	h.register(other)
	ok(h.post("/verify/confirm", map[string]string{"identifier": other, "token": h.mail.Last(t, iam.MessageVerification, other).Token}, ""))
	a := account{id: h.userID(email), email: email}
	h.post("/password/login", map[string]string{"identifier": email, "password": "wrong-" + password}, "")
	signedIn := h.login(a)

	// Refresh, then replay the spent refresh token.
	ok(h.refresh(signedIn.RefreshToken))
	require.Equal(t, http.StatusUnauthorized, h.refresh(signedIn.RefreshToken).status)

	// Reset the password from its emailed link.
	ok(h.post("/password/reset/request", map[string]string{"identifier": email}, ""))
	reset := map[string]string{"token": h.mail.Last(t, iam.MessagePasswordReset, email).Token, "new_password": "Logs-reset-passphrase-5"}
	ok(h.post("/password/reset/confirm", reset, ""))
	h.post("/password/reset/confirm", reset, "")

	// Passwordless sign-in with a code and with a link.
	ok(h.post("/passwordless/start", map[string]string{"identifier": email}, ""))
	h.post("/passwordless/confirm", map[string]string{"identifier": email, "code": wrongCode(h.verificationCode(email))}, "")
	ok(h.post("/passwordless/confirm", map[string]string{"identifier": email, "code": h.verificationCode(email)}, ""))
	ok(h.post("/passwordless/start", map[string]string{"identifier": email}, ""))
	ok(h.post("/passwordless/confirm", map[string]string{"token": h.mail.Last(t, iam.MessageVerification, email).Token}, ""))

	// Second factors: TOTP enrollment; the email factor, its sign-in codes and
	// backup codes.
	totpUser := h.newAccount("logstotp")
	h.enrollTOTP(h.login(totpUser).AccessToken)
	mfa := h.newAccount("logsmfa")
	require.NotEmpty(t, h.enrollEmail2FA(mfa))
	ch := h.passwordStep(mfa, "198.51.100.60")
	code := h.mail.Last(t, iam.MessageLoginCode, mfa.email).Code
	require.Equal(t, http.StatusUnauthorized, h.secondStep(mfa, ch, wrongCode(code), "198.51.100.60").status)
	fresh := session(t, ok(h.secondStep(mfa, ch, code, "198.51.100.60")))
	var regenerated struct {
		BackupCodes []string `json:"backup_codes"`
	}
	ok(h.post("/user/2fa/backup-codes", nil, fresh.AccessToken)).json(t, &regenerated)
	require.NotEmpty(t, regenerated.BackupCodes)
	ch = h.passwordStep(mfa, "198.51.100.60")
	ok(h.post("/2fa/verify", map[string]any{"user_id": mfa.id, "challenge": ch.Challenge, "code": regenerated.BackupCodes[0], "backup_code": true}, ""))

	// Device keys: enroll with an emailed code, sign in with the key.
	device := h.newAccount("logsdevice")
	k := newDeviceKey(t)
	ok(h.deviceEnroll(k, device.email, nil))
	ok(h.deviceLogin(k))

	// API keys and invitations.
	owner := h.newAccount("logsowner")
	ownerToken := h.login(owner).AccessToken
	_, base := h.newOrg(owner)
	key := h.issue(base+"/api-keys", ownerToken, map[string]any{"name": "ci", "role": "org:manager"})
	ok(h.get(base+"/members", key.Secret))
	h.get(base+"/members", key.Secret+"x")
	link := h.issue(base+"/invitations", ownerToken, map[string]any{"role": "org:member"})
	ok(h.post("/invitations/redeem", map[string]string{"code": link.Code}, h.login(h.newAccount("logsmember")).AccessToken))
	invited := unique("logsinvited") + "@security.test"
	ok(h.post(base+"/invitations", map[string]string{"email": invited, "role": "org:member"}, ownerToken))
	ok(h.post("/register", map[string]string{"identifier": invited, "username": unique("logsinv"), "password": password,
		"invite_code": h.inviteCode(invited)}, ""))

	// The mail provider fails after AuthKit hands it each message.
	before := len(logs.String())
	mailDown.Store(true)
	pending := unique("logspending") + "@security.test"
	h.post("/register", map[string]string{"identifier": pending, "username": unique("logspend"), "password": password}, "")
	h.post("/verify/request", map[string]string{"identifier": pending}, "")
	h.post("/password/reset/request", map[string]string{"identifier": email}, "")
	h.post("/passwordless/start", map[string]string{"identifier": email}, "")
	h.post("/password/login", map[string]string{"identifier": mfa.email, "password": password}, "")
	h.post(base+"/invitations", map[string]string{"email": unique("logsinvited") + "@security.test", "role": "org:member"}, ownerToken)
	h.post("/device-keys/enroll/begin", map[string]string{"email": device.email, "public_key": newDeviceKey(t).public, "label": "phone"}, "")
	mailDown.Store(false)
	require.Greater(t, len(logs.String()), before, "the mail failures logged nothing")

	log.Print("securitytest: the standard log is captured")
	jar.addOutbox(h.mail)
	rows, err := h.pool.Query(context.Background(), `SELECT password_hash FROM user_passwords`)
	require.NoError(t, err)
	hashes, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(t, err)
	require.NotEmpty(t, hashes)
	for _, hash := range hashes {
		jar.add("a stored password hash", hash)
	}
	out := logs.String()
	require.Contains(t, out, "securitytest: the standard log is captured")
	secrets := jar.all()
	require.Greater(t, len(secrets), 40, "the flows handled too few secrets")
	for secret, where := range secrets {
		if line := leakedIn(out, secret); line != "" {
			t.Errorf("the secret from %s is logged: %s", where, line)
		}
	}
}
