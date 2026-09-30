// Package securitytest attacks AuthKit the way an embedding host exposes it:
// a Client from authtest.New with its HTTP surface mounted under /auth/v1, a
// real PostgreSQL database and real ephemeral stores.
package securitytest

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testkeys"
	"github.com/open-rails/authkit/keys"
	"github.com/stretchr/testify/require"
)

const (
	apiPrefix = "/auth/v1"
	issuer    = "https://auth.security.test"
	audience  = "security-app"
	password  = "Correct-horse-battery-9"
)

// signingKey is the deployment's RSA key; forgery tests sign with it directly.
var signingKey = sync.OnceValue(func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
})

var signer = sync.OnceValue(func() keys.Signer {
	s, err := keys.SignerFromKey("security-kid", signingKey())
	if err != nil {
		panic(err)
	}
	return s
})

type host struct {
	t      *testing.T
	auth   *authkit.Client
	pool   *pgxpool.Pool
	server *httptest.Server
	mail   *authtest.Outbox
}

// withHTTP edits the host's HTTPConfig.
func withHTTP(fn func(*authkit.HTTPConfig)) authtest.Option {
	return authtest.WithConfig(func(c *authkit.Config) { fn(&c.HTTP) })
}

// withSMS offers SMS as a second factor; a host delivers SMS to its outbox
// only then.
var withSMS = authtest.WithConfig(func(c *authkit.Config) {
	c.TwoFactor.Methods = append(slices.Clone(c.TwoFactor.Methods), iam.TwoFactorSMS)
})

// generousLimits keeps the ordinary per-IP buckets out of the way of tests
// that exercise something other than rate limiting.
func generousLimits(c *authkit.HTTPConfig) {
	limits := authkit.DefaultRateLimits()
	for bucket, limit := range limits {
		limit.Limit = 10000
		limit.Cooldown = 0
		limits[bucket] = limit
	}
	c.RateLimits = limits
}

// newHost is authtest.New on a scratch database of the test's own (schema
// profiles, River in public) with the host's issuer, keys, policy and HTTP
// surface, then opts. The HTTPConfig replaces authtest's unlimited one, so
// rate limits are real.
func newHost(t *testing.T, opts ...authtest.Option) *host {
	t.Helper()
	pg := testdb.EmptyScratchPostgres(t)
	s := signer()
	var sms bool
	opts = append([]authtest.Option{
		authtest.WithConfig(func(c *authkit.Config) {
			c.Schema, c.River.Schema = "profiles", "public"
			c.Keys = authkit.KeysConfig{Source: testkeys.Source(s)}
			c.Token = authkit.TokenConfig{Issuer: issuer, IssuedAudiences: []string{audience}, ExpectedAudiences: []string{audience}}
			c.Registration = authkit.RegistrationConfig{NativeUserMode: iam.RegistrationModeOpen, Verification: iam.RegistrationVerificationOptional}
			c.TwoFactor = authkit.TwoFactorConfig{
				Mode:          iam.TwoFactorOptional,
				Methods:       []iam.TwoFactorMethod{iam.TwoFactorTOTP, iam.TwoFactorEmail},
				TOTPSecretKey: bytes.Repeat([]byte{7}, 32),
			}
			c.HTTP = authkit.HTTPConfig{DirectPeerIP: true, APIPath: apiPrefix}
		}),
		authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = pg.Pool }),
	}, opts...)
	opts = append(opts,
		authtest.WithConfig(func(c *authkit.Config) { sms = slices.Contains(c.TwoFactor.Methods, iam.TwoFactorSMS) }),
		authtest.WithDeps(func(d *authkit.Deps) {
			if !sms {
				d.SMS = nil
			}
		}))
	auth, mail := authtest.New(t, opts...)
	return (&host{t: t, pool: pg.Pool, mail: mail}).fork(auth)
}

// replica is another replica of h's deployment (authtest.Replica), opts
// applied to its Config and Deps.
func (h *host) replica(opts ...authtest.Option) *host {
	h.t.Helper()
	return h.fork(authtest.Replica(h.t, h.auth, opts...))
}

// fork serves runtime's configured routes; every route shares the one
// canonical AuthKit mount.
func (h *host) fork(runtime *authkit.Client) *host {
	h.t.Helper()
	require.NotNil(h.t, runtime.Handler())
	server := httptest.NewServer(runtime.Handler())
	h.t.Cleanup(server.Close)
	out := *h
	out.auth, out.server = runtime, server
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
	var env iam.ErrorEnvelope
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

// newAccount creates a password user with a verified address with system
// authority.
func (h *host) newAccount(prefix string) account {
	h.t.Helper()
	name := unique(prefix)
	email := name + "@security.test"
	u, err := h.auth.CreateUser(context.Background(), iam.NewUser{Email: email, Username: name, Password: password, EmailVerified: true})
	require.NoError(h.t, err)
	return account{id: u.ID, email: email, username: name}
}

// setPassword replaces a password with system authority.
func (h *host) setPassword(id, pw string) error {
	_, err := h.auth.UpdateUser(context.Background(), iam.SystemActor(), id, iam.UserUpdate{Password: &pw})
	return err
}

// verifyEmail marks the account's email verified with system authority.
func (h *host) verifyEmail(id string) {
	h.t.Helper()
	verified := true
	_, err := h.auth.UpdateUser(context.Background(), iam.SystemActor(), id, iam.UserUpdate{EmailVerified: &verified})
	require.NoError(h.t, err)
}

// login signs a in with its password and, when the account has one, the
// email second factor.
func (h *host) login(a account) tokens {
	h.t.Helper()
	resp := h.post("/password/login", map[string]string{"identifier": a.email, "password": password}, "")
	if resp.status == http.StatusForbidden && resp.errorCode() == "2fa_required" {
		var ch challenge
		resp.json(h.t, &ch)
		resp = h.post("/2fa/verify", map[string]string{"user_id": a.id, "challenge": ch.Error.Metadata.Challenge,
			"code": h.mail.Last(h.t, authtest.LoginCode, a.email).Code}, "")
	}
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	return session(h.t, resp)
}

func (h *host) refresh(refreshToken string) response {
	h.t.Helper()
	return h.post("/token", map[string]string{"grant_type": "refresh_token", "refresh_token": refreshToken}, "")
}

// roleIn resolves the role name for ref's persona through the schema, as a
// host reading a name at run time does.
func roleIn(t testing.TB, auth *authkit.Client, ref iam.GroupRef, name string) iam.Role {
	t.Helper()
	g, err := auth.Group(t.Context(), ref)
	require.NoError(t, err)
	role, err := auth.Role(g.Persona, name)
	require.NoError(t, err)
	return role
}

// role resolves a role name of persona through the schema.
func (h *host) role(persona iam.Persona, name string) iam.Role {
	h.t.Helper()
	r, err := h.auth.Role(persona, name)
	require.NoError(h.t, err)
	return r
}

// grantRole assigns the role name of ref's persona with system authority.
func grantRole(t testing.TB, auth *authkit.Client, ref iam.GroupRef, subject iam.Subject, name string) {
	t.Helper()
	authtest.GrantRole(t, auth, ref, subject, roleIn(t, auth, ref, name))
}

// revokeRole unassigns the role name of ref's persona with system authority.
func revokeRole(t testing.TB, auth *authkit.Client, ref iam.GroupRef, subject iam.Subject, name string) {
	t.Helper()
	authtest.RevokeRole(t, auth, ref, subject, roleIn(t, auth, ref, name))
}
