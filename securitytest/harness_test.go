// Package securitytest attacks AuthKit the way an embedding host exposes it:
// embedded.New with an authhttp surface mounted under /auth/v1, a real
// PostgreSQL database and real ephemeral stores. docs/security-tests.md maps
// each threat to its test.
package securitytest

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

const (
	apiPrefix = "/auth/v1"
	issuer    = "https://auth.security.test"
	audience  = "security-app"
	password  = "Correct-horse-battery-9"
)

var signer = sync.OnceValue(func() *jwtkit.RSASigner {
	s, err := jwtkit.NewRSASigner(2048, "security-kid")
	if err != nil {
		panic(err)
	}
	return s
})

type host struct {
	t       *testing.T
	cfg     hostConfig
	runtime *embedded.Runtime
	client  authkit.Client
	pool    *pgxpool.Pool
	server  *httptest.Server
	mail    *outbox
}

type hostConfig struct {
	engine embedded.Config
	deps   embedded.Deps
	http   authhttp.Config
}

type hostOption func(*hostConfig)

func withRedis(rdb *redis.Client) hostOption {
	return func(c *hostConfig) { c.deps.Redis = rdb; c.engine.Ephemeral.AllowMemory = false }
}

func withEngine(fn func(*embedded.Config)) hostOption {
	return func(c *hostConfig) { fn(&c.engine) }
}

func withHTTP(fn func(*authhttp.Config)) hostOption {
	return func(c *hostConfig) { fn(&c.http) }
}

// generousLimits keeps the ordinary per-IP buckets out of the way of tests
// that exercise something other than rate limiting.
func generousLimits(c *authhttp.Config) {
	limits := authhttp.DefaultRateLimits()
	for bucket, limit := range limits {
		limit.Limit = 10000
		limit.Cooldown = 0
		limits[bucket] = limit
	}
	c.RateLimits = limits
}

func newHost(t *testing.T, opts ...hostOption) *host {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	mail := &outbox{}
	s := signer()
	cfg := hostConfig{
		engine: embedded.Config{
			Keys: embedded.KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}},
			Token: embedded.TokenConfig{
				Issuer:            issuer,
				IssuedAudiences:   []string{audience},
				ExpectedAudiences: []string{audience},
			},
			Registration: embedded.RegistrationConfig{
				NativeUserMode: embedded.RegistrationModeOpen,
				Verification:   embedded.RegistrationVerificationOptional,
			},
			Ephemeral: embedded.EphemeralConfig{AllowMemory: true},
			TwoFactor: embedded.TwoFactorConfig{
				Mode:          embedded.TwoFactorOptional,
				Methods:       []embedded.TwoFactorMethod{embedded.TwoFactorTOTP, embedded.TwoFactorEmail},
				TOTPSecretKey: bytes.Repeat([]byte{7}, 32),
			},
		},
		deps: embedded.Deps{Postgres: pg.Pool, Email: mail},
		http: authhttp.Config{DirectPeerIP: true, Mount: authhttp.MountOptions{APIPrefix: apiPrefix}},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	cfg.engine.HTTP = cfg.http
	runtime, err := embedded.New(cfg.engine, cfg.deps)
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	h := &host{t: t, cfg: cfg, pool: pg.Pool, mail: mail}
	return h.fork(runtime)
}

// fork serves runtime's configured routes; every route shares the one
// canonical AuthKit mount.
func (h *host) fork(runtime *embedded.Runtime) *host {
	h.t.Helper()
	routes, err := runtime.HTTPRoutes()
	require.NoError(h.t, err)
	require.NotEmpty(h.t, routes)
	server := httptest.NewServer(routes[0].Handler)
	h.t.Cleanup(server.Close)
	out := *h
	out.runtime, out.client, out.server = runtime, runtime.Client(), server
	return &out
}

type response struct {
	status  int
	body    []byte
	header  http.Header
	cookies []*http.Cookie
}

func (r response) String() string { return string(r.body) }

func (r response) errorCode() string {
	var env authkit.ErrorEnvelope
	_ = json.Unmarshal(r.body, &env)
	return env.Error.Code
}

func (r response) json(t *testing.T, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(r.body, v), string(r.body))
}

type request struct {
	method  string
	path    string // relative to apiPrefix unless it starts with "//"
	body    any
	token   string
	header  http.Header
	cookies []*http.Cookie
}

func (h *host) do(req request) response {
	h.t.Helper()
	var reader io.Reader
	switch b := req.body.(type) {
	case nil:
	case string:
		reader = strings.NewReader(b)
	case []byte:
		reader = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		require.NoError(h.t, err)
		reader = bytes.NewReader(raw)
	}
	target := h.server.URL + apiPrefix + req.path
	if strings.HasPrefix(req.path, "//") {
		target = h.server.URL + req.path[1:]
	}
	r, err := http.NewRequest(req.method, target, reader)
	require.NoError(h.t, err)
	if reader != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if req.token != "" {
		r.Header.Set("Authorization", "Bearer "+req.token)
	}
	for k, vs := range req.header {
		r.Header.Del(k)
		for _, v := range vs {
			r.Header.Add(k, v)
		}
	}
	for _, c := range req.cookies {
		r.AddCookie(c)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(r)
	require.NoError(h.t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(h.t, err)
	return response{status: resp.StatusCode, body: body, header: resp.Header, cookies: resp.Cookies()}
}

func (h *host) post(path string, body any, token string) response {
	h.t.Helper()
	return h.do(request{method: http.MethodPost, path: path, body: body, token: token})
}

func (h *host) get(path, token string) response {
	h.t.Helper()
	return h.do(request{method: http.MethodGet, path: path, token: token})
}

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type account struct {
	id, email, username string
}

var seq = struct {
	sync.Mutex
	n int
}{}

func unique(prefix string) string {
	seq.Lock()
	defer seq.Unlock()
	seq.n++
	return strings.ToLower(prefix) + strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "") + string(rune('a'+seq.n%26))
}

// newAccount creates a password user with a verified address through the
// trusted host client.
func (h *host) newAccount(prefix string) account {
	h.t.Helper()
	name := unique(prefix)
	email := name + "@security.test"
	u, err := h.client.CreateUser(context.Background(), email, name)
	require.NoError(h.t, err)
	require.NoError(h.t, h.client.MarkEmailVerified(context.Background(), u.ID))
	require.NoError(h.t, h.client.AdminSetPassword(context.Background(), u.ID, password))
	return account{id: u.ID, email: email, username: name}
}

func (h *host) login(a account) tokens {
	h.t.Helper()
	resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var out tokens
	resp.json(h.t, &out)
	require.NotEmpty(h.t, out.AccessToken)
	return out
}

func (h *host) refresh(refreshToken string) response {
	h.t.Helper()
	return h.post("/token", map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken}, "")
}

// outbox captures every message AuthKit asks the host to deliver.
type outbox struct {
	mu   sync.Mutex
	msgs []string
}

func (o *outbox) add(s string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.msgs = append(o.msgs, s)
	return nil
}

func (o *outbox) last(t *testing.T, pattern string) string {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	re := regexp.MustCompile(pattern)
	for i := len(o.msgs) - 1; i >= 0; i-- {
		if m := re.FindStringSubmatch(o.msgs[i]); m != nil {
			return m[1]
		}
	}
	t.Fatalf("no delivered message matches %q", pattern)
	return ""
}

func (o *outbox) SendVerification(_ context.Context, email, _ string, msg embedded.VerificationMessage) error {
	return o.add("verification to=" + email + " code=" + msg.Code + " link=" + msg.LinkURL)
}

func (o *outbox) SendPasswordResetLink(_ context.Context, email, _, resetURL string) error {
	token := ""
	if u, err := url.Parse(resetURL); err == nil {
		token = u.Query().Get("token")
		if token == "" && u.Fragment != "" {
			if q, err := url.ParseQuery(u.Fragment); err == nil {
				token = q.Get("token")
			}
		}
	}
	return o.add("reset to=" + email + " url=" + resetURL + " token=" + token)
}

func (o *outbox) SendAccountRegistrationInvite(_ context.Context, email, link string) error {
	return o.add("invite to=" + email + " link=" + link)
}

func (o *outbox) SendLoginCode(_ context.Context, email, _, code string) error {
	return o.add("login to=" + email + " code=" + code)
}

func (o *outbox) SendWelcome(context.Context, string, string) error { return nil }

func (o *outbox) SendContactChanged(context.Context, string, string, embedded.ContactChange) error {
	return nil
}

func (o *outbox) SendDeviceKeyEnrolled(context.Context, string, string, embedded.DeviceKeyNotice) error {
	return nil
}
