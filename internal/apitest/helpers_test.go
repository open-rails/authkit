package apitest_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
)

// api drives a Client's HTTP surface in process, as one client at one address.
type api struct {
	t      testing.TB
	h      http.Handler
	prefix string // where the JSON API is mounted
}

// newAPI serves auth's handler. The JSON API's prefix is read from the catalog
// (the password sign-in route); without that route paths start at the root.
func newAPI(t testing.TB, auth *authkit.Client) *api {
	t.Helper()
	require.NotNil(t, auth.Handler(), "the Client serves no HTTP")
	a := &api{t: t, h: auth.Handler()}
	for _, route := range auth.Routes() {
		if prefix, ok := strings.CutSuffix(route.Path, "/password/login"); ok && route.Method == http.MethodPost {
			a.prefix = prefix
		}
	}
	return a
}

// request is one HTTP request. path is relative to the API prefix, unless it
// starts with "//", which names a path from the root ("//oidc/x/login").
type request struct {
	method string
	path   string
	body   any // nil; a string or []byte sent as is; any other value as JSON
	token  string
	header http.Header
}

type response struct {
	status  int
	body    []byte
	header  http.Header
	cookies []*http.Cookie
}

func (r response) String() string { return string(r.body) }

// code is the error envelope's code; "" when the body is not an error.
func (r response) code() string {
	var env iam.ErrorEnvelope
	_ = json.Unmarshal(r.body, &env)
	return env.Error.Code
}

func (r response) decode(t testing.TB, v any) {
	t.Helper()
	require.NoError(t, json.Unmarshal(r.body, v), r.String())
}

// send runs one request and reports failures instead of failing the test, so
// goroutines may call it.
func (a *api) send(r request) (response, error) {
	var body io.Reader
	switch b := r.body.(type) {
	case nil:
	case string:
		body = strings.NewReader(b)
	case []byte:
		body = bytes.NewReader(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			return response{}, err
		}
		body = bytes.NewReader(raw)
	}
	target := a.prefix + r.path
	if rooted, ok := strings.CutPrefix(r.path, "//"); ok {
		target = "/" + rooted
	}
	req, err := http.NewRequest(r.method, "http://apitest"+target, body)
	if err != nil {
		return response{}, err
	}
	req.RemoteAddr = "192.0.2.1:1234"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	for k, vs := range r.header {
		req.Header.Del(k)
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, req)
	res := w.Result()
	defer res.Body.Close()
	raw, err := io.ReadAll(res.Body)
	return response{status: res.StatusCode, body: raw, header: res.Header, cookies: res.Cookies()}, err
}

func (a *api) do(r request) response {
	a.t.Helper()
	res, err := a.send(r)
	require.NoError(a.t, err)
	return res
}

func (a *api) post(path, token string, body any) response {
	a.t.Helper()
	return a.do(request{method: http.MethodPost, path: path, body: body, token: token})
}

func (a *api) get(path, token string) response {
	a.t.Helper()
	return a.do(request{method: http.MethodGet, path: path, token: token})
}

var bareSigner = sync.OnceValue(func() *jwtkit.RSASigner {
	s, err := jwtkit.NewRSASigner(2048, "apitest")
	if err != nil {
		panic(err)
	}
	return s
})

// bareConfig is a Config and Deps on a fresh, migrated database no Client has
// opened yet, for tests of what authkit.New itself builds or refuses.
func bareConfig(t testing.TB) (authkit.Config, authkit.Deps) {
	t.Helper()
	pg := testdb.ScratchPostgres(t)
	s := bareSigner()
	return authkit.Config{
		Keys:  authkit.KeysConfig{Source: jwtkit.StaticKeySource{Active: s, Pubs: map[string]crypto.PublicKey{s.KID(): s.PublicKey()}}},
		Token: authkit.TokenConfig{Issuer: authtest.Issuer, IssuedAudiences: []string{authtest.Audience}},
	}, authkit.Deps{Postgres: pg.Pool}
}

// newClient is authkit.New on cfg and deps, closed at cleanup.
func newClient(t testing.TB, cfg authkit.Config, deps authkit.Deps) (*authkit.Client, error) {
	t.Helper()
	auth, err := authkit.New(context.Background(), cfg, deps)
	if err == nil {
		t.Cleanup(auth.Close)
	}
	return auth, err
}
