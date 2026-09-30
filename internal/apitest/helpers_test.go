package apitest_test

import (
	"bytes"
	"context"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testidp"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"
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

// restart builds a Client on auth's schema after closing auth, as a new
// release boots.
func restart(t *testing.T, auth *authkit.Client, opts ...authtest.Option) *authkit.Client {
	t.Helper()
	auth.Close()
	return authtest.Replica(t, auth, opts...)
}

// expect checks res has status and returns it.
func expect(t *testing.T, status int, res response) response {
	t.Helper()
	require.Equal(t, status, res.status, res.String())
	return res
}

// authAnswer is a sign-in, factor or credential route's answer, decoded as far
// as the tests read it: a session (flat, or nested with the signed-in user and
// where to return to), an enrollment's secret and backup codes, or the error
// that continues the flow.
type authAnswer struct {
	status int
	raw    string
	iam.TokenSet
	Nested      iam.TokenSet `json:"token_set"`
	ReturnTo    string       `json:"return_to"`
	Secret      string       `json:"secret"`
	BackupCodes []string     `json:"backup_codes"`
	User        struct {
		ID    string  `json:"id"`
		Email *string `json:"email"`
	} `json:"user"`
	Error struct {
		Code     string `json:"code"`
		Metadata struct {
			UserID           string       `json:"user_id"`
			Challenge        string       `json:"challenge"`
			Method           string       `json:"method"`
			TokenSet         iam.TokenSet `json:"token_set"`
			AllowedMethods   []string     `json:"allowed_methods"`
			AvailableFactors []struct {
				ID     string `json:"id"`
				Method string `json:"method"`
			} `json:"available_factors"`
			Recovery struct {
				Token string `json:"token"`
			} `json:"recovery"`
		} `json:"metadata"`
	} `json:"error"`
}

// tokens is the answer's session.
func (s authAnswer) tokens() iam.TokenSet {
	if s.Nested.AccessToken != "" {
		return s.Nested
	}
	return s.TokenSet
}

// answer decodes the body, which must be JSON unless empty.
func (r response) answer(t testing.TB) authAnswer {
	t.Helper()
	out := authAnswer{status: r.status, raw: r.String()}
	if len(r.body) > 0 {
		r.decode(t, &out)
	}
	return out
}

// expectAnswer requires res to have status and decodes its body.
func expectAnswer(t *testing.T, res response, status int) authAnswer {
	t.Helper()
	require.Equal(t, status, res.status, res.String())
	return res.answer(t)
}

// requireSessionWith requires tokens to be a working session whose sign-in
// used the methods amr.
func requireSessionWith(t *testing.T, a *api, auth *authkit.Client, tokens iam.TokenSet, amr ...string) verify.Claims {
	t.Helper()
	require.NotEmpty(t, tokens.RefreshToken)
	require.Greater(t, tokens.ExpiresIn, int64(0))
	claims, err := auth.Verifier().Verify(t.Context(), tokens.AccessToken)
	require.NoError(t, err)
	require.NotEmpty(t, claims.UserID)
	require.ElementsMatch(t, amr, claims.AMR)
	me := a.get("/me", tokens.AccessToken)
	require.Equal(t, http.StatusOK, me.status, me.String())
	return claims
}

// accessClaims reads an access token's claims without verifying it,
// requiring its header to match the access-header golden.
func accessClaims(t testing.TB, token string) jwt.MapClaims {
	t.Helper()
	claims := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(token, claims)
	require.NoError(t, err)
	wireGolden(t, "access-header", parsed.Header)
	return claims
}

// wireGolden requires value, as JSON, to have the fields and types of
// testdata/wire/<name>.json, allowing additive keys: "$string" is a nonempty
// string, "$text" any string, "$number" a positive number, "$strings" a
// nonempty list of nonempty strings; a one-object list is an item schema;
// anything else, scalar lists included, is exact.
func wireGolden(t testing.TB, name string, value any) {
	t.Helper()
	fixture, err := os.ReadFile(filepath.Join("testdata", "wire", name+".json"))
	require.NoError(t, err)
	var expected, actual any
	require.NoError(t, json.Unmarshal(fixture, &expected))
	encoded, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(encoded, &actual))
	var match func(want, got any, path string)
	match = func(want, got any, path string) {
		switch want := want.(type) {
		case map[string]any:
			require.IsType(t, want, got, path)
			fields := got.(map[string]any)
			for key, value := range want {
				require.Contains(t, fields, key, path)
				match(value, fields[key], path+"."+key)
			}
		case string:
			switch want {
			case "$string":
				require.IsType(t, "", got, path)
				require.NotEmpty(t, got, path)
			case "$text":
				require.IsType(t, "", got, path)
			case "$number":
				require.IsType(t, float64(0), got, path)
				require.Greater(t, got.(float64), float64(0), path)
			case "$strings":
				require.IsType(t, []any{}, got, path)
				require.NotEmpty(t, got, path)
				for _, item := range got.([]any) {
					match("$string", item, path+"[]")
				}
			default:
				require.Equal(t, want, got, path)
			}
		case []any:
			if len(want) == 1 {
				if _, object := want[0].(map[string]any); object {
					require.IsType(t, []any{}, got, path)
					require.NotEmpty(t, got, path)
					for _, item := range got.([]any) {
						match(want[0], item, path+"[]")
					}
					return
				}
			}
			require.Equal(t, want, got, path)
		default:
			require.Equal(t, want, got, path)
		}
	}
	match(expected, actual, name)
}

const appURL = "https://app.example"

// withAppLinks points delivered links at the host's app, so a test can follow
// them.
func withAppLinks(c *authkit.Config) {
	c.Frontend.BaseURL = appURL
	c.Frontend.VerifyPath, c.Frontend.PasswordlessPath, c.Frontend.PasswordResetPath = "/verify", "/login/link", "/reset"
}

// deliveredLink checks a delivered link opens path in the app with its
// status and channel, and returns its token.
func deliveredLink(t testing.TB, raw, path, channel string) string {
	t.Helper()
	u, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, appURL+path, u.Scheme+"://"+u.Host+u.Path)
	require.Empty(t, u.RawQuery)
	fragment, err := url.ParseQuery(u.Fragment)
	require.NoError(t, err)
	require.Equal(t, "ready", fragment.Get("status"))
	require.Equal(t, channel, fragment.Get("channel"))
	require.NotEmpty(t, fragment.Get("token"))
	return fragment.Get("token")
}

// requireIAMCode asserts err carries the AuthKit wire code and returns it.
func requireIAMCode(t testing.TB, err error, code string) iam.Error {
	t.Helper()
	e, ok := iam.AsError(err)
	require.True(t, ok, "not an AuthKit error: %v", err)
	require.Equal(t, code, e.Code())
	return e
}

// opErr is the outcome of a one-subject batch call.
func opErr(res []iam.OpResult, err error) error {
	if err != nil {
		return err
	}
	return res[0].Err
}

func assign(auth *authkit.Client, actor iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return opErr(auth.AssignGroupRoles(context.Background(), actor, ref, []iam.Subject{subject}, role))
}

func unassign(auth *authkit.Client, actor iam.Actor, ref iam.GroupRef, subject iam.Subject, role iam.Role) error {
	return opErr(auth.UnassignGroupRoles(context.Background(), actor, ref, []iam.Subject{subject}, role))
}

func removeMember(auth *authkit.Client, actor iam.Actor, ref iam.GroupRef, subject iam.Subject) error {
	return opErr(auth.RemoveGroupMembers(context.Background(), actor, ref, []iam.Subject{subject}))
}

// wire reads a persona, permission or role as it arrives off the wire: its
// syntax is checked, the schema is not.
func wire[T any, P interface {
	*T
	UnmarshalText([]byte) error
}](t testing.TB, text string) T {
	t.Helper()
	var v T
	require.NoError(t, P(&v).UnmarshalText([]byte(text)))
	return v
}

// factorFlow drives a Client's sign-in, second-factor and credential routes
// as one browser would, and reads what its outbox delivered.
type factorFlow struct {
	t      *testing.T
	auth   *authkit.Client
	outbox *authtest.Outbox
	api    *api
}

func newFactorFlow(t *testing.T, auth *authkit.Client, outbox *authtest.Outbox) *factorFlow {
	t.Helper()
	return &factorFlow{t: t, auth: auth, outbox: outbox, api: newAPI(t, auth)}
}

// request decodes a JSON answer; any other body is only its raw text.
func (f *factorFlow) request(method, path, token string, body any) authAnswer {
	f.t.Helper()
	res := f.api.do(request{method: method, path: path, token: token, body: body})
	out := authAnswer{status: res.status, raw: res.String()}
	if len(res.body) > 0 && res.header.Get("Content-Type") == "application/json" {
		require.NoError(f.t, json.Unmarshal(res.body, &out), out.raw)
	}
	return out
}

func (f *factorFlow) post(path string, body any) authAnswer {
	f.t.Helper()
	return f.request(http.MethodPost, path, "", body)
}

func (f *factorFlow) expect(status int, r authAnswer) authAnswer {
	f.t.Helper()
	require.Equal(f.t, status, r.status, r.raw)
	return r
}

// code is the code of the newest kind message to to; the test fails without one.
func (f *factorFlow) code(kind authtest.Kind, to string) string {
	f.t.Helper()
	code := f.outbox.Last(f.t, kind, to).Code
	require.NotEmpty(f.t, code)
	return code
}

// session is requireSessionWith on f's Client.
func (f *factorFlow) session(tokens iam.TokenSet, amr ...string) {
	f.t.Helper()
	requireSessionWith(f.t, f.api, f.auth, tokens, amr...)
}

// withProviders configures the Client's identity providers.
func withProviders(providers ...authprovider.Provider) authtest.Option {
	return authtest.WithConfig(func(c *authkit.Config) { c.Identity.Providers = providers })
}

// providerFlow is a provider flow a browser started: the IdP authorization
// request and the state cookie bound to that browser.
type providerFlow struct {
	authURL string
	cookies []*http.Cookie
}

// startProviderFlow reads a flow start's answer: a browser redirect, or a
// page's JSON {"auth_url"}.
func startProviderFlow(t *testing.T, res response) providerFlow {
	t.Helper()
	f := providerFlow{authURL: res.header.Get("Location"), cookies: res.cookies}
	if res.status == http.StatusOK {
		var begun struct {
			AuthURL string `json:"auth_url"`
		}
		res.decode(t, &begun)
		f.authURL = begun.AuthURL
	} else {
		require.Equal(t, http.StatusFound, res.status, res.String())
	}
	require.NotEmpty(t, f.authURL)
	return f
}

// callback replays the IdP's redirect to provider's callback, carrying q, in
// the browser that started f. No callback response may be cached.
func (f providerFlow) callback(a *api, provider string, q url.Values) response {
	a.t.Helper()
	jar := &http.Request{Header: http.Header{}}
	for _, c := range f.cookies {
		jar.AddCookie(c)
	}
	res := a.do(request{method: http.MethodGet, path: "//oidc/" + provider + "/callback?" + q.Encode(), header: jar.Header})
	require.Equal(a.t, "no-store", res.header.Get("Cache-Control"))
	return res
}

// callbackFragment is what a browser callback hands the page: the fragment of
// its redirect, which never carries a query.
func callbackFragment(t *testing.T, res response) url.Values {
	t.Helper()
	require.Equal(t, http.StatusFound, res.status, res.String())
	target, err := url.Parse(res.header.Get("Location"))
	require.NoError(t, err)
	require.Empty(t, target.RawQuery)
	fragment, err := url.ParseQuery(target.EscapedFragment())
	require.NoError(t, err)
	return fragment
}

// providerSignIn signs id in at provider as a page does: a POST start
// (returning to /checkout, carrying invite), the IdP's redirect back, and the
// callback answered as JSON.
func providerSignIn(t *testing.T, a *api, idp *testidp.IdP, provider string, id testidp.Identity, invite string) response {
	t.Helper()
	f := startProviderFlow(t, a.post("//oidc/"+provider+"/login", "", map[string]string{"return_to": "/checkout", "account_invite_token": invite}))
	q := idp.Redirect(t, f.authURL, id)
	q.Set("format", "json")
	return f.callback(a, provider, q)
}

// providerBrowserSignIn is providerSignIn answered as a browser redirect: the
// fragment it hands the page.
func providerBrowserSignIn(t *testing.T, a *api, idp *testidp.IdP, provider string, id testidp.Identity) url.Values {
	t.Helper()
	f := startProviderFlow(t, a.post("//oidc/"+provider+"/login", "", map[string]string{"return_to": "/checkout"}))
	return callbackFragment(t, f.callback(a, provider, idp.Redirect(t, f.authURL, id)))
}
