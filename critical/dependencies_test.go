package critical_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/provider"
	"github.com/redis/go-redis/v9"
)

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
			config.Tune(c, func(tn *config.Tuning) {
				tn.RateLimits = map[string]config.RateLimit{"capabilities_read": {Limit: 1, Window: time.Minute}}
			})
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
	t.Run("every_bucket_limits_at_its_own_boundary", func(t *testing.T) {
		f := fullSurfaceFixture(t)
		mounted := map[string]iam.Route{}
		for _, route := range f.auth.Routes() {
			mounted[route.Pattern()] = route
		}
		// One mounted route per route bucket, from the catalog: a gated one
		// when there is one, refused before its handler spends anything else.
		routes := map[string]iam.Route{}
		for _, spec := range httpapi.Catalog() {
			path := spec.Path
			switch spec.Surface {
			case httpapi.SurfaceAPI:
				path = f.auth.APIBase() + spec.Path
			case httpapi.SurfaceOIDC:
				path = httpapi.OIDCPath + spec.Path
			}
			route, ok := mounted[spec.Method+" "+path]
			if !ok || spec.Method == http.MethodOptions {
				continue
			}
			if have, ok := routes[spec.Bucket]; !ok || have.Auth == iam.AuthPublic && route.Auth != iam.AuthPublic {
				routes[spec.Bucket] = route
			}
		}
		client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		param := regexp.MustCompile(`\{[a-z_]+\}`)
		for bucket := range httpapi.DefaultRateLimits() {
			if bucket == "default" {
				continue
			}
			route, routed := routes[bucket]
			probe, inner := innerBuckets[bucket]
			if routed == inner {
				t.Errorf("bucket %s: a mounted route %v, an in-handler probe %v; want exactly one", bucket, routed, inner)
				continue
			}
			t.Run(bucket, func(t *testing.T) {
				g := f.limitedTo(t, bucket)
				if inner {
					probe(t, g)
					return
				}
				path := param.ReplaceAllString(strings.ReplaceAll(route.Path, "{provider}", "unconfigured"), iam.NewTenantID().String())
				for i := range 2 {
					r := wire(t, client, route.Method, g.server.URL+path, "", "application/json", "{}", nil)
					if i == 0 && (r.status == http.StatusTooManyRequests || r.status >= 500) {
						t.Fatalf("%s %s: the first request was refused: %d %s", route.Method, path, r.status, r.body)
					}
					if i == 1 {
						limitedBy(t, r)
					}
				}
			})
		}
		for bucket := range innerBuckets {
			if _, ok := httpapi.DefaultRateLimits()[bucket]; !ok {
				t.Errorf("probe for unknown bucket %s", bucket)
			}
		}
	})
	t.Run("sender_health_and_real_provider_outage_do_not_issue_authority", func(t *testing.T) {
		idp := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "external provider unavailable", 503) }))
		t.Cleanup(idp.Close)
		f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) {
			c.TwoFactor = iam.TwoFactorOptional
			config.Tune(c, func(tn *config.Tuning) { tn.SenderHealthRecheck = 100 * time.Millisecond })
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

// limitedTo is a replica of f whose bucket allows one request a minute and
// every other bucket is lifted, so only bucket can refuse.
func (f *fixture) limitedTo(t *testing.T, bucket string, opts ...authtest.Option) *fixture {
	t.Helper()
	opts = append([]authtest.Option{authtest.WithConfig(func(c *authkit.Config) {
		config.Tune(c, func(tn *config.Tuning) {
			tn.NoRateLimits = true
			tn.RateLimits = map[string]config.RateLimit{bucket: {Limit: 1, Window: time.Minute}}
		})
	})}, opts...)
	replica := authtest.Replica(t, f.auth, opts...)
	g := &fixture{auth: replica, out: f.out, cfg: f.cfg, deps: f.deps, dpop: f.dpop, t: t, tenant: f.tenant, pool: f.pool, schema: f.schema, roles: f.roles}
	g.server = httptest.NewServer(replica.Handler())
	t.Cleanup(g.server.Close)
	return g
}

// limitedBy checks r is the one-a-minute limit limitedTo set refusing.
func limitedBy(t *testing.T, r response) {
	t.Helper()
	r.want(t, http.StatusTooManyRequests, "rate_limited")
	var env iam.ErrorEnvelope
	decode(t, r.body, &env)
	if r.header.Get("Retry-After") == "" || env.Error.Metadata["limit"] != 1.0 || env.Error.Metadata["window_seconds"] != 60.0 {
		t.Fatalf("refusal is not the bucket's own limit: Retry-After %q, %v", r.header.Get("Retry-After"), env.Error.Metadata)
	}
}

// sendsOnce checks that two starts toward to answer alike and only the
// first sends: a quota per destination never refuses.
func sendsOnce(t *testing.T, g *fixture, to string, start func() response) {
	t.Helper()
	before := len(g.out.Messages("", to))
	first, second := start(), start()
	if first.status != second.status || first.status >= 400 {
		t.Fatalf("starts answered %d then %d: %s", first.status, second.status, second.body)
	}
	if got := len(g.out.Messages("", to)) - before; got != 1 {
		t.Fatalf("two starts to %s sent %d messages, want 1", to, got)
	}
}

// innerBuckets probe the buckets a handler or sender spends, beside its
// route's: each request names what the bucket counts.
var innerBuckets = map[string]func(t *testing.T, g *fixture){
	"password_login_identifier": func(t *testing.T, g *fixture) {
		u := g.user(t)
		login := map[string]string{"identifier": u.Email, "password": "not-" + authtest.Password}
		g.call(t, "POST", "/password/login", "", login).want(t, http.StatusUnauthorized, "")
		limitedBy(t, g.call(t, "POST", "/password/login", "", login))
	},
	"passwordless_start_identifier": func(t *testing.T, g *fixture) {
		u := g.user(t)
		sendsOnce(t, g, u.Email, func() response {
			return g.call(t, "POST", "/passwordless/start", "", map[string]string{"identifier": u.Email, "mode": "code"})
		})
	},
	"register_create_identifier": func(t *testing.T, g *fixture) {
		const email = "bucket-register@example.com"
		sendsOnce(t, g, email, func() response {
			r := g.call(t, "POST", "/register", "", map[string]string{"identifier": email, "username": "bucket" + strings.ToLower(rand.Text()[:8]), "password": authtest.Password})
			g.call(t, "POST", "/register/abandon", "", map[string]string{"identifier": email, "password": authtest.Password}).want(t, http.StatusNoContent, "")
			return r
		})
	},
	"verify_request_identifier": func(t *testing.T, g *fixture) {
		const email = "bucket-verify@example.com"
		challengeOf(t, g.call(t, "POST", "/register", "", map[string]string{"identifier": email, "username": "bucketverify", "password": authtest.Password}))
		sendsOnce(t, g, email, func() response {
			return g.call(t, "POST", "/verify/request", "", map[string]string{"identifier": email})
		})
	},
	"password_reset_request_identifier": func(t *testing.T, g *fixture) {
		u := g.user(t)
		sendsOnce(t, g, u.Email, func() response {
			return g.call(t, "POST", "/password/reset/request", "", map[string]string{"identifier": u.Email})
		})
	},
	"device_key_enroll_begin_identifier": func(t *testing.T, g *fixture) {
		u := g.user(t)
		sendsOnce(t, g, u.Email, func() response {
			pub, _, err := ed25519.GenerateKey(nil)
			noError(t, err)
			return g.call(t, "POST", "/device-keys/enroll/begin", "", map[string]string{"email": u.Email, "public_key": base64.RawURLEncoding.EncodeToString(pub), "label": "bucket"})
		})
	},
	// Per inviting account, and per invited address whoever invites.
	"invite_create_account": func(t *testing.T, g *fixture) {
		token, path := inviter(t, g)
		link := map[string]string{"role": "shop:reader"}
		g.call(t, "POST", path, token, link).want(t, http.StatusCreated, "")
		limitedBy(t, g.call(t, "POST", path, token, link))
	},
	"invite_create_identifier": func(t *testing.T, g *fixture) {
		emailed := map[string]string{"email": "bucket-invitee@example.com", "role": "shop:reader"}
		token, path := inviter(t, g)
		g.call(t, "POST", path, token, emailed).want(t, http.StatusAccepted, "")
		token, path = inviter(t, g)
		limitedBy(t, g.call(t, "POST", path, token, emailed))
	},
	"2fa_setup_totp": func(t *testing.T, g *fixture) {
		token := g.signIn(t, g.user(t)).AccessToken
		g.call(t, "POST", "/me/2fa/setup", token, map[string]string{"method": "totp"}).want(t, http.StatusOK, "")
		limitedBy(t, g.call(t, "POST", "/me/2fa/setup", token, map[string]string{"method": "totp"}))
	},
	"2fa_setup_email": func(t *testing.T, g *fixture) {
		token := g.signIn(t, g.user(t)).AccessToken
		// The bucket is spent before the method is weighed: a deployment may
		// refuse email as a factor.
		if r := g.call(t, "POST", "/me/2fa/setup", token, map[string]string{"method": "email"}); r.status == http.StatusTooManyRequests || r.status >= 500 {
			t.Fatalf("first email setup refused: %d %s", r.status, r.body)
		}
		limitedBy(t, g.call(t, "POST", "/me/2fa/setup", token, map[string]string{"method": "email"}))
	},
	"2fa_setup_sms": func(t *testing.T, g *fixture) {
		token := g.signIn(t, g.user(t)).AccessToken
		setup := map[string]string{"method": "sms", "phone_number": "+12025550140"}
		g.call(t, "POST", "/me/2fa/setup", token, setup).want(t, http.StatusOK, "")
		limitedBy(t, g.call(t, "POST", "/me/2fa/setup", token, setup))
	},
	// Each text: per number and account the start answers alike and sends
	// nothing; per address, country, block and client it is refused.
	"sms_number": func(t *testing.T, g *fixture) {
		sendsOnce(t, g, "+12025550141", func() response { return smsStart(t, g, "+12025550141", nil) })
	},
	"sms_account": func(t *testing.T, g *fixture) {
		_, err := g.auth.CreateUser(t.Context(), iam.NewUser{Phone: "+12025550142", PhoneVerified: true, Username: "bucketsmsaccount"})
		noError(t, err)
		sendsOnce(t, g, "+12025550142", func() response { return smsStart(t, g, "+12025550142", nil) })
	},
	"sms_address": func(t *testing.T, g *fixture) {
		challengeOf(t, smsStart(t, g, "+12025610143", nil))
		limitedBy(t, smsStart(t, g, "+12025620143", nil))
	},
	"sms_country": func(t *testing.T, g *fixture) {
		challengeOf(t, smsStart(t, g, "+12025630144", nil))
		limitedBy(t, smsStart(t, g, "+12025640144", nil))
	},
	"sms_range": func(t *testing.T, g *fixture) {
		challengeOf(t, smsStart(t, g, "+12025650145", nil))
		limitedBy(t, smsStart(t, g, "+12025650146", nil))
	},
	"sms_client": func(t *testing.T, g *fixture) {
		g = g.limitedTo(t, "sms_client", authtest.WithDeps(func(d *authkit.Deps) {
			d.RequestClient = func(r *http.Request) string { return r.Header.Get("X-Bucket-Client") }
		}))
		client := http.Header{"X-Bucket-Client": {"bucket-client"}}
		challengeOf(t, smsStart(t, g, "+12025660147", client))
		limitedBy(t, smsStart(t, g, "+12025670147", client))
	},
}

// inviter is a signed-in account's session and the invitations path of a
// shop group it owns.
func inviter(t *testing.T, g *fixture) (string, string) {
	t.Helper()
	u := g.user(t)
	token := g.signIn(t, u).AccessToken
	persona, err := g.auth.Persona("shop")
	noError(t, err)
	owner := iam.UserSubject(u.ID)
	group, err := g.auth.CreateGroup(t.Context(), iam.NewGroup{Persona: persona, Owner: &owner})
	noError(t, err)
	return token, "/groups/" + group.ID + "/invitations"
}

// smsStart starts a code sign-in by text to number.
func smsStart(t *testing.T, g *fixture, number string, headers http.Header) response {
	t.Helper()
	r, err := g.requestHeaders(t.Context(), "POST", "/passwordless/start", "", map[string]string{"identifier": number, "mode": "code"}, headers)
	noError(t, err)
	return r
}
