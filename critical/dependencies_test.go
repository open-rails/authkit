package critical_test

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/provider"
	"github.com/redis/go-redis/v9"
)

// One representative of each bucket used by the selected functional routes.
// Independent fixed expectations: initial request reaches its auth/domain
// boundary, the second is throttled, and unrelated capabilities remain usable.
//
//go:embed testdata/rate-buckets.json
var rateBucketRows []byte

func criticalDependencyBoundaries(t *testing.T) {
	t.Helper()
	t.Run("Redis_disconnect_keeps_a_bounded_process_local_budget", func(t *testing.T) {
		if os.Getenv("AUTHKIT_TEST_REDIS_URL") == "" {
			t.Fatal("Redis fixture required")
		}
		u, err := url.Parse(os.Getenv("AUTHKIT_TEST_REDIS_URL"))
		noError(t, err)
		link := newDatabaseLink(t, u.Host)
		u.Host = link.listener.Addr().String()
		opts, err := redis.ParseURL(u.String())
		noError(t, err)
		opts.MaxRetries = -1
		opts.DialTimeout = time.Second
		opts.ReadTimeout = time.Second
		opts.WriteTimeout = time.Second
		rdb := redis.NewClient(opts)
		t.Cleanup(func() { _ = rdb.Close() })
		noError(t, rdb.Ping(t.Context()).Err())
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.HTTP.RateLimits = map[string]authkit.RateLimit{"capabilities_read": {Limit: 1, Window: time.Minute}}
		}), authtest.WithDeps(func(d *authkit.Deps) { d.Redis = rdb }))
		f.call(t, "GET", "/capabilities", "", nil).want(t, 200, "")
		link.cut()
		// The fallback has its own counters: shared history is not copied.
		// It allows its one local request, then keeps the configured limit.
		f.call(t, "GET", "/capabilities", "", nil).want(t, 200, "")
		f.call(t, "GET", "/capabilities", "", nil).want(t, 429, "rate_limited")
		found := false
		for _, probe := range f.auth.Probes() {
			if probe.Name == "authkit_redis" {
				found = true
				if probe.Check(t.Context()) == nil {
					t.Fatal("Redis probe hid the actual connection failure")
				}
			}
		}
		if !found {
			t.Fatal("configured Redis omitted its public probe")
		}
	})
	t.Run("each_selected_route_bucket_limits_before_authentication", func(t *testing.T) {
		f := fullSurfaceFixture(t)
		var rows []struct{ Bucket, Method, Path string }
		noError(t, json.Unmarshal(rateBucketRows, &rows))
		for _, row := range rows {
			t.Run(row.Bucket, func(t *testing.T) {
				limited := authtest.Replica(t, f.auth, authtest.WithConfig(func(c *authkit.Config) {
					c.HTTP.RateLimits = map[string]authkit.RateLimit{row.Bucket: {Limit: 1, Window: time.Minute}}
				}))
				server := httptest.NewServer(limited.Handler())
				t.Cleanup(server.Close)
				path := strings.NewReplacer("{id}", iam.NewTenantID().String(), "{user_id}", iam.NewTenantID().String(), "{group_id}", iam.NewTenantID().String(), "{kind}", "users").Replace(row.Path)
				for i := range 2 {
					r := wire(t, server.Client(), row.Method, server.URL+path, "", "application/json", "{}", nil)
					if i == 0 {
						if r.status == 404 || r.status == 429 || r.status >= 500 {
							t.Fatalf("initial request did not reach the expected mounted boundary:%d %s", r.status, r.body)
						}
					} else {
						r.want(t, 429, "rate_limited")
						if r.header.Get("Retry-After") == "" {
							t.Fatal("throttle omitted retry guidance")
						}
					}
				}
			})
		}
	})
	t.Run("sender_health_and_real_provider_outage_do_not_issue_authority", func(t *testing.T) {
		idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "external provider unavailable", 503) }))
		t.Cleanup(idp.Close)
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.TwoFactor.Mode = iam.TwoFactorOptional
			c.TwoFactor.Methods = []iam.TwoFactorMethod{iam.TwoFactorTOTP, iam.TwoFactorSMS}
			c.SenderHealthRecheck = 100 * time.Millisecond
		}), authtest.WithDeps(func(d *authkit.Deps) {
			d.Providers = []provider.Provider{provider.OIDC("unavailable", idp.URL, "critical-client", "critical-secret", provider.WithHTTPClient(idp.Client()))}
		}))
		u := f.user(t)
		if !f.auth.EmailAvailable() || !f.auth.SMSAvailable() {
			t.Fatal("healthy external senders were unavailable before failure")
		}
		if !slices.Contains(f.auth.TwoFactorMethods(), iam.TwoFactorTOTP) || !slices.Contains(f.auth.TwoFactorMethods(), iam.TwoFactorSMS) {
			t.Fatal("configured strong-factor methods were not exposed")
		}
		outage := errors.New("owned external delivery outage")
		f.out.SetEmailHealth(outage)
		f.out.SetSMSHealth(outage)
		noError(t, f.auth.Start(context.Background()))
		eventually(t, "sender health failure", func() bool { return !f.auth.EmailAvailable() && !f.auth.SMSAvailable() })
		for _, health := range []func() (time.Time, error){f.auth.EmailHealth, f.auth.SMSHealth} {
			at, err := health()
			if at.IsZero() || !errors.Is(err, outage) {
				t.Fatalf("sender health lost checked time or cause: %s %v", at, err)
			}
		}
		probes := map[string]error{}
		for _, probe := range f.auth.Probes() {
			probes[probe.Name] = probe.Check(t.Context())
		}
		if !errors.Is(probes["authkit_email"], outage) || !errors.Is(probes["authkit_sms"], outage) {
			t.Fatal("public probes concealed external sender failures")
		}
		f.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": u.Email, "mode": "login"}).want(t, 503, "email_unavailable")
		if len(f.out.Messages(iam.MessageVerification, u.Email)) != 0 {
			t.Fatal("unavailable sender claimed delivery")
		}
		f.call(t, "POST", "/oidc/unavailable/login/start", "", map[string]string{"return_to": "/"}).want(t, 503, "provider_unavailable")
		sessions, err := f.auth.Sessions(t.Context(), u.ID)
		noError(t, err)
		if len(sessions) != 0 {
			t.Fatal("dependency failure created a session")
		}
		f.signIn(t, u) // unaffected native password boundary remains available
	})
}
