package critical_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

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
	auth       *authkit.Client
	out        *authtest.Outbox
	server     *httptest.Server
	roles      *authkit.Roles
	shop       *authkit.PersonaDef
	read       iam.Perm
	write      iam.Perm
	reader     iam.Role
	writer     iam.Role
	tenant     iam.TenantID
	pool       *pgxpool.Pool
	rootReader iam.Role
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
	f.reader = shop.Role("reader", read)
	f.writer = shop.Role("writer", read, write)
	var err error
	f.pool, err = pgxpool.New(t.Context(), os.Getenv("AUTHKIT_TEST_DATABASE_URL"))
	noError(t, err)
	t.Cleanup(f.pool.Close)
	base := authtest.WithConfig(func(c *authkit.Config) {
		c.DefaultTenantID = f.tenant
		c.Roles = roles
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		c.Registration.PasswordlessLogin = true
		c.PersonalAccessTokens.Enabled = true
	})
	f.auth, f.out = authtest.New(t, append([]authtest.Option{base, authtest.WithDeps(func(d *authkit.Deps) { d.Postgres = f.pool })}, options...)...)
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
	var data []byte
	var err error
	if body != nil {
		data, err = json.Marshal(body)
		noError(t, err)
	}
	r, err := http.NewRequestWithContext(t.Context(), method, f.server.URL+f.auth.APIBase()+path, bytes.NewReader(data))
	noError(t, err)
	if body != nil {
		r.Header.Set("Content-Type", "application/json")
	}
	if credential != "" {
		r.Header.Set("Authorization", "Bearer "+credential)
	}
	c := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := c.Do(r)
	noError(t, err)
	defer res.Body.Close()
	data, err = io.ReadAll(io.LimitReader(res.Body, 1<<20))
	noError(t, err)
	return response{status: res.StatusCode, header: res.Header, body: data}
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
