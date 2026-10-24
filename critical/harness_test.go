package critical_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// The published bootstrap creates a real Client and PostgreSQL schema. Its
// Outbox captures only the external email/SMS boundary; no AuthKit service or
// authorization result is replaced. Every journey owns its schema and server.
type fixture struct {
	auth         *authkit.Client
	out          *authtest.Outbox
	server       *httptest.Server
	roles        *authkit.Roles
	shop         *authkit.PersonaDef
	read         iam.Perm
	write        iam.Perm
	reader       iam.Role
	writer       iam.Role
	tenant       iam.TenantID
	pool         *pgxpool.Pool
	rootReader   iam.Role
	tenantReader iam.Role
	schema       string
	cfg          authkit.Config
	deps         authkit.Deps
	team         *authkit.PersonaDef
	teamRead     iam.Perm
	teamWrite    iam.Perm
	teamReader   iam.Role
	teamWriter   iam.Role
}

func newFixture(t *testing.T, options ...authtest.Option) *fixture {
	t.Helper()
	if os.Getenv("AUTHKIT_TEST_DATABASE_URL") == "" {
		t.Fatal("critical journeys require AUTHKIT_TEST_DATABASE_URL; skipping is not qualification")
	}
	roles := authkit.NewRoles(authkit.CustomRoles)
	shop := roles.Persona("shop", authkit.APIKeys, authkit.CustomRoles, authkit.RemoteApplications)
	read, write := shop.Permission("orders", "read"), shop.Permission("orders", "write")
	f := &fixture{roles: roles, shop: shop, read: read, write: write, tenant: iam.NewTenantID()}
	f.rootReader = roles.Root.Role("auditor", roles.Root.Users.Read)
	f.tenantReader = roles.Tenant.Role("directoryreader", roles.Tenant.Users.Read)
	f.reader = shop.Role("reader", read)
	f.writer = shop.Role("writer", read, write)
	f.team = roles.Persona("team", authkit.APIKeys, authkit.CustomRoles, authkit.RemoteApplications)
	f.teamRead, f.teamWrite = f.team.Permission("orders", "read"), f.team.Permission("orders", "write")
	f.teamReader = f.team.Role("reader", f.teamRead)
	f.teamWriter = f.team.Role("writer", f.teamRead, f.teamWrite)
	var err error
	f.pool, err = pgxpool.New(t.Context(), os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	noError(t, err)
	t.Cleanup(f.pool.Close)
	f.schema = "critical_" + strings.ReplaceAll(iam.NewTenantID().String(), "-", "")
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if _, err := f.pool.Exec(ctx, "DROP SCHEMA IF EXISTS "+pgx.Identifier{f.schema}.Sanitize()+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	base := authtest.WithConfig(func(c *authkit.Config) {
		c.Database = authkit.DatabaseConfig{Schema: f.schema, RiverSchema: f.schema}
		c.DefaultTenantID = f.tenant
		c.Roles = roles
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Registration.PasswordlessLogin = true
		c.PersonalAccessTokens.Enabled = true
	})
	opts := append([]authtest.Option{base, authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = f.pool })}, options...)
	opts = append(opts, authtest.WithConfig(func(c *authkit.Config) { f.cfg = *c }), authtest.WithDeps(func(d *authkit.Deps) { f.deps = *d }))
	f.auth, f.out = authtest.New(t, opts...)
	f.server = httptest.NewServer(f.auth.Handler())
	t.Cleanup(f.server.Close)
	return f
}

type response struct {
	status int
	header http.Header
	body   []byte
}

func (f *fixture) call(t *testing.T, method, path, credential string, body any) response {
	t.Helper()
	r, err := f.request(t.Context(), method, path, credential, body)
	noError(t, err)
	return r
}

// request returns errors to the caller so concurrent public requests never
// call testing.Fatal from a worker goroutine.
func (f *fixture) request(ctx context.Context, method, path, credential string, body any) (response, error) {
	return f.requestHeaders(ctx, method, path, credential, body, nil)
}

func (f *fixture) requestHeaders(ctx context.Context, method, path, credential string, body any, headers http.Header) (response, error) {
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		if err != nil {
			return response{}, err
		}
	}
	r, err := http.NewRequestWithContext(ctx, method, f.server.URL+f.auth.APIBase()+path, bytes.NewReader(data))
	if err != nil {
		return response{}, err
	}
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		r.Header.Set("Authorization", "Bearer "+credential)
	}
	for k, values := range headers {
		r.Header[k] = append([]string(nil), values...)
	}
	c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(r)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	data, err = io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return response{}, err
	}
	return response{status: res.StatusCode, header: res.Header, body: data}, nil
}

type signInResult struct {
	Status string        `json:"status"`
	Tokens *iam.TokenSet `json:"token_set"`
	User   *iam.User     `json:"user"`
}

func tokensFrom(t *testing.T, r response, userID string) iam.TokenSet {
	t.Helper()
	r.want(t, http.StatusOK, "")
	var result signInResult
	decode(t, r.body, &result)
	if result.Status != "complete" || result.Tokens == nil || result.User == nil || result.User.ID != userID || result.Tokens.AccessToken == "" {
		t.Fatalf("response did not establish the expected account session: %s", r.body)
	}
	return *result.Tokens
}

func (r response) want(t *testing.T, status int, code string) {
	t.Helper()
	if r.status != status {
		t.Fatalf("HTTP status = %d, want %d: %s", r.status, status, r.body)
	}
	if code != "" {
		var env iam.ErrorEnvelope
		decode(t, r.body, &env)
		if env.Error.Code != code {
			t.Fatalf("error code = %q, want %q: %s", env.Error.Code, code, r.body)
		}
	}
}

func decode(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode public response: %v: %s", err, body)
	}
}
func noError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Wait for an observable asynchronous outcome, not for an assumed processing
// duration. A missing transition fails with its own bounded deadline.
func eventually(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.NewTimer(10 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		if ready() {
			return
		}
		select {
		case <-deadline.C:
			t.Fatalf("timed out observing %s", description)
		case <-tick.C:
		}
	}
}

func (f *fixture) user(t *testing.T) authtest.User { t.Helper(); return authtest.NewUser(t, f.auth) }
func (f *fixture) signIn(t *testing.T, user authtest.User) iam.TokenSet {
	t.Helper()
	r := f.call(t, "POST", "/password/login", "", map[string]string{"identifier": user.Email, "password": user.Password})
	r.want(t, http.StatusOK, "")
	var result struct {
		Status string        `json:"status"`
		Tokens *iam.TokenSet `json:"token_set"`
		User   *iam.User     `json:"user"`
	}
	decode(t, r.body, &result)
	if result.Status != "complete" || result.Tokens == nil || result.User == nil || result.User.ID != user.ID || result.Tokens.AccessToken == "" {
		t.Fatalf("sign-in did not establish this user's session: %s", r.body)
	}
	return *result.Tokens
}

func (f *fixture) identity(t *testing.T, token string) auth.Identity {
	t.Helper()
	r, err := http.NewRequestWithContext(context.Background(), "GET", f.server.URL+"/identity", nil)
	noError(t, err)
	r.Header.Set("Authorization", "Bearer "+token)
	v, err := f.auth.Authenticator().Authenticate(r)
	noError(t, err)
	return v.Identity()
}
