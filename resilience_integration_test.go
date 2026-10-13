package authkit_test

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	hauth "github.com/open-rails/authkit/auth"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/keys"
	"github.com/open-rails/authkit/provider"
)

// closedAddr is a loopback address nothing listens on: dialing it is refused.
func closedAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

// unreachablePool is a pool whose PostgreSQL never answers.
func unreachablePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(t.Context(), "postgres://admin:secret@"+closedAddr(t)+"/authkit?connect_timeout=1")
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

// probe runs auth's probe named name.
func probe(t *testing.T, auth *authkit.Client, name string) error {
	t.Helper()
	for _, p := range auth.Probes() {
		if p.Name == name {
			return p.Check(t.Context())
		}
	}
	t.Fatalf("no probe %q", name)
	return nil
}

func probeNames(auth *authkit.Client) []string {
	var names []string
	for _, p := range auth.Probes() {
		names = append(names, p.Name)
	}
	return names
}

// A PostgreSQL that never answers is waited for, with retries, until ctx (or
// 30 seconds) ends, then fails the boot naming it.
func TestNewRefusesUnreachablePostgres(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	start := time.Now()
	auth, err := authkit.New(ctx, minimalConfig(), authkit.Deps{Postgres: unreachablePool(t), KeySource: testKeys()})
	require.Nil(t, auth)
	require.ErrorContains(t, err, "authkit: PostgreSQL unreachable after ")
	require.NotContains(t, err.Error(), "after 1 attempts", "it retries before giving up")
	require.Less(t, time.Since(start), 5*time.Second, "ctx bounds the wait")
}

// No usable signing key fails the boot, before PostgreSQL is waited for:
// tokens could not be signed.
func TestNewRefusesMissingSigningKey(t *testing.T) {
	pool := unreachablePool(t)
	for name, tc := range map[string]struct {
		edit func(*authkit.Config, *authkit.Deps)
		err  string
	}{
		"no keys.json": {
			edit: func(c *authkit.Config, _ *authkit.Deps) { c.Keys.Path = t.TempDir() },
			err:  "authkit: failed to resolve JWT signing keys",
		},
		"a malformed keys.json": {
			edit: func(c *authkit.Config, _ *authkit.Deps) {
				c.Keys.Path = t.TempDir()
				require.NoError(t, os.WriteFile(filepath.Join(c.Keys.Path, "keys.json"), []byte("{"), 0o600))
			},
			err: "authkit: failed to resolve JWT signing keys",
		},
		"a key source without an active key": {
			edit: func(_ *authkit.Config, d *authkit.Deps) { d.KeySource = keys.Static{} },
			err:  "authkit: Deps.KeySource has no active signing key",
		},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, deps := minimalConfig(), authkit.Deps{Postgres: pool}
			tc.edit(&cfg, &deps)
			start := time.Now()
			auth, err := authkit.New(t.Context(), cfg, deps)
			require.Nil(t, auth)
			require.ErrorContains(t, err, tc.err)
			require.Less(t, time.Since(start), 2*time.Second, "refused before waiting for PostgreSQL")
		})
	}
}

// AuthKit boots and serves sign-ins, sessions and tokens while its optional
// dependencies are down or misconfigured. Each failure switches off only what
// needs it and shows on its probe: an identity provider whose discovery is
// unreachable answers provider_unavailable and a misconfigured one is
// disabled; with no email sender, email flows answer email_unavailable; a
// remote issuer whose JWKS is unreachable has only its tokens refused, and a
// declared application the configuration gets wrong is disabled; with Redis
// down the limits still hold, per process.
func TestDegradedDependenciesKeepAuthServing(t *testing.T) {
	ctx := t.Context()
	idp := authtest.NewIdP(t)
	peer := newRotatingIssuer(t)
	peerKey := rsaKey(t)
	peer.publish(map[string]*rsa.PrivateKey{"k1": peerKey})
	unreachable := &rotatingIssuer{url: "http://" + closedAddr(t)}
	redisDown := redis.NewClient(&redis.Options{Addr: closedAddr(t), MaxRetries: -1})
	t.Cleanup(func() { _ = redisDown.Close() })

	d := newResourceDeployment(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.Verification = iam.RegistrationVerificationRequired
		c.Languages = authkit.LanguageConfig{Supported: []string{"en", "not a language"}}
		c.RemoteApplications = []authkit.RemoteApplicationConfig{
			{Issuer: peer.url, JWKSURI: peer.url + "/keys"},
			{Issuer: unreachable.url, JWKSURI: unreachable.url + "/keys"},
			{Issuer: "not-a-url", JWKSURI: "https://shop.example/keys"},
		}
		limits := authkit.DefaultRateLimits()
		for bucket := range limits {
			limits[bucket] = authkit.RateLimit{Limit: 10000, Window: time.Minute}
		}
		limits["password_login"] = authkit.RateLimit{Limit: 3, Window: time.Minute}
		c.HTTP.RateLimits = limits
	}), authtest.WithDeps(func(d *authkit.Deps) {
		d.Email, d.SMS = nil, nil
		d.Redis = redisDown
		d.Providers = []provider.Provider{
			idp.Provider("good"),
			provider.OIDC("down", "https://"+closedAddr(t), "client", "secret"),
			provider.Google("google-client", ""),
			provider.OIDC("squatter", authtest.Issuer, "client", "secret"),
		}
	}))
	auth := d.auth
	require.Error(t, auth.Ready(ctx), "River runs only after Start")
	require.NoError(t, auth.Start(ctx))
	require.NoError(t, auth.Ready(ctx), "optional dependencies never fail readiness")

	u := authtest.NewUser(t, auth)
	tokens := authtest.SignIn(t, auth, u)
	me := func(accessToken string) int {
		r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
		r.Header.Set("Authorization", "Bearer "+accessToken)
		w := httptest.NewRecorder()
		auth.Handler().ServeHTTP(w, r)
		return w.Code
	}
	require.Equal(t, http.StatusOK, me(tokens.AccessToken))

	t.Run("sessions refresh", func(t *testing.T) {
		require.NotNil(t, tokens.RefreshToken)
		w := serve(auth, http.MethodPost, "/api/v1/token", `{"grant_type":"refresh_token","refresh_token":"`+*tokens.RefreshToken+`"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var refreshed struct {
			TokenSet iam.TokenSet `json:"token_set"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshed), w.Body.String())
		require.NotEmpty(t, refreshed.TokenSet.AccessToken, w.Body.String())
		require.Equal(t, http.StatusOK, me(refreshed.TokenSet.AccessToken))
	})

	t.Run("identity providers", func(t *testing.T) {
		var ids []string
		for _, p := range capabilitiesOf(t, auth).ExternalLoginProviders {
			ids = append(ids, p.ID)
		}
		require.ElementsMatch(t, []string{"good", "down"}, ids, "misconfigured providers are disabled")

		start := func(name string) *httptest.ResponseRecorder {
			return serve(auth, http.MethodPost, "/api/v1/oidc/"+name+"/login/start", `{}`)
		}
		require.Equal(t, http.StatusOK, start("good").Code, "a healthy provider signs in")
		expectUnavailable(t, start("down"), errmodel.CodeProviderUnavailable)
		w := start("google")
		require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
		require.Contains(t, w.Body.String(), `"unknown_provider"`)

		require.NoError(t, probe(t, auth, "authkit_provider_good"))
		require.ErrorIs(t, probe(t, auth, "authkit_provider_down"), provider.ErrUnavailable)
		require.ErrorContains(t, probe(t, auth, "authkit_provider_google"), `identity provider "google" is disabled`)
		require.ErrorContains(t, probe(t, auth, "authkit_provider_squatter"), "reserved issuer")
	})

	t.Run("no email sender", func(t *testing.T) {
		require.False(t, auth.EmailAvailable())
		body := `{"identifier":"` + u.Email + `"}`
		expectUnavailable(t, serve(auth, http.MethodPost, "/api/v1/verify/request", body), errmodel.CodeEmailUnavailable)
		expectUnavailable(t, serve(auth, http.MethodPost, "/api/v1/password/reset/request", body), errmodel.CodeEmailUnavailable)
		names := probeNames(auth)
		require.NotContains(t, names, "authkit_email")
		require.NotContains(t, names, "authkit_sms")
		problems := probe(t, auth, "authkit_config")
		require.ErrorContains(t, problems, "Deps.Email is not set")
		require.ErrorContains(t, problems, `registration verification policy is "required" but no email or SMS sender is configured`)
		require.ErrorContains(t, problems, `Languages.Supported "not a language"`)
	})

	t.Run("remote issuers", func(t *testing.T) {
		authenticate := func(token string) error {
			r := httptest.NewRequest(http.MethodGet, oauthResource+"/v1/things", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			_, err := auth.Authenticator().Authenticate(r)
			return err
		}
		require.NoError(t, authenticate(peer.token(t, "k1", peerKey)), "a reachable issuer's tokens verify")
		err := authenticate(unreachable.token(t, "k1", rsaKey(t)))
		require.ErrorIs(t, err, hauth.ErrUnavailable, "an unreachable issuer's tokens are refused")
		require.ErrorContains(t, probe(t, auth, "authkit_issuer_keys"), "issuer "+unreachable.url)
		require.NoError(t, authenticate(peer.token(t, "k1", peerKey)), "other issuers are unaffected")
		require.Equal(t, http.StatusOK, me(tokens.AccessToken), "local sessions are unaffected")

		_, err = auth.RemoteApplication(ctx, iam.AppByIssuer("not-a-url"))
		require.ErrorIs(t, err, iam.ErrRemoteApplicationNotFound)
		require.ErrorContains(t, probe(t, auth, "authkit_config"), `Config.RemoteApplications "not-a-url" is disabled`)

		// A later boot whose configuration breaks the peer disables it.
		broken := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) {
			c.RemoteApplications = []authkit.RemoteApplicationConfig{{Issuer: peer.url, JWKSURI: "ftp://" + peer.url[len("http://"):] + "/keys"}}
		}))
		require.ErrorContains(t, probe(t, broken, "authkit_config"), `"`+peer.url+`" is disabled`)
		app, err := broken.RemoteApplication(ctx, iam.AppByIssuer(peer.url))
		require.NoError(t, err)
		require.False(t, app.Enabled)
		require.ErrorIs(t, authenticate(peer.token(t, "k1", peerKey)), hauth.ErrUnauthenticated, "its tokens are refused")
	})

	t.Run("Redis down", func(t *testing.T) {
		require.ErrorContains(t, probe(t, auth, "authkit_redis"), "Redis unreachable")
		var codes []int
		for range 4 {
			codes = append(codes, serve(auth, http.MethodPost, "/api/v1/password/login",
				`{"identifier":"`+u.Email+`","password":"wrong-password-1"}`).Code)
		}
		require.True(t, slices.Contains(codes, http.StatusTooManyRequests), "limits hold per process: %v", codes)
	})
}
