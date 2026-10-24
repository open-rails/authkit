package critical_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
	"github.com/redis/go-redis/v9"
)

const proofOrigin = "https://resource.example"

func proofFixture(t *testing.T, rdb redis.UniversalClient) (*fixture, *authtest.DPoPKey, authtest.User, iam.TokenSet) {
	t.Helper()
	f := newFixture(t, authtest.WithConfig(func(c *authkit.Config) { c.SignIn.DPoP = authkit.DPoPRequired }), authtest.WithDeps(func(d *authkit.Deps) { d.Redis = rdb }))
	key := authtest.NewDPoPKey(t)
	u := f.user(t)
	headers := http.Header{"DPoP": {key.Proof(t, "POST", authtest.Issuer+f.auth.APIBase()+"/password/login", "", "")}}
	r, err := f.requestHeaders(t.Context(), "POST", "/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}, headers)
	noError(t, err)
	tokens := tokensFrom(t, r, u.ID)
	// Native TokenSet retains its historical token_type label; sender
	// binding is the cryptographically protected cnf.jkt that the shipped
	// browser client also uses to select DPoP.
	_, claims := jwtParts(t, tokens.AccessToken)
	cnf, ok := claims["cnf"].(map[string]any)
	if !ok || cnf["jkt"] != key.Thumbprint() {
		t.Fatal("required sender-bound login did not bind the real client key")
	}
	return f, key, u, tokens
}
func proofServer(t *testing.T, f *fixture, opts []verify.VerifierOption, handler http.Handler) (*authkit.Verifier, *httptest.Server) {
	t.Helper()
	v, err := f.auth.NewVerifier([]string{authtest.Audience}, append([]verify.VerifierOption{verify.WithPublicURL(proofOrigin)}, opts...)...)
	noError(t, err)
	if handler == nil {
		handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	s := httptest.NewServer(verify.RequireSession(v)(handler))
	t.Cleanup(s.Close)
	return v, s
}
func sendProof(ctx context.Context, server, method, path, token, proof, host string) (response, error) {
	r, err := http.NewRequestWithContext(ctx, method, server+path, nil)
	if err != nil {
		return response{}, err
	}
	if host != "" {
		r.Host = host
	}
	r.Header.Set("Authorization", "DPoP "+token)
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	c := &http.Client{Timeout: 5 * time.Second}
	res, err := c.Do(r)
	if err != nil {
		return response{}, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	return response{status: res.StatusCode, header: res.Header, body: body}, err
}
func proofCall(t *testing.T, s *httptest.Server, method, path, token, proof, host string) response {
	t.Helper()
	r, err := sendProof(t.Context(), s.URL, method, path, token, proof, host)
	noError(t, err)
	return r
}
func realRedis(t *testing.T) *redis.Client {
	t.Helper()
	value := os.Getenv("AUTHKIT_TEST_REDIS_URL")
	if value == "" {
		t.Fatal("critical cross-replica cases require AUTHKIT_TEST_REDIS_URL")
	}
	opts, err := redis.ParseURL(value)
	noError(t, err)
	opts.MaxRetries = -1
	opts.DialTimeout = time.Second
	opts.ReadTimeout = time.Second
	opts.WriteTimeout = time.Second
	c := redis.NewClient(opts)
	t.Cleanup(func() { _ = c.Close() })
	noError(t, c.Ping(t.Context()).Err())
	return c
}

func TestCriticalSenderProofs(t *testing.T) {
	t.Run("AK-J14-C01_bound_token_requires_proof_and_server_nonce", func(t *testing.T) {
		f, key, _, tokens := proofFixture(t, nil)
		_, s := proofServer(t, f, []verify.VerifierOption{verify.WithDPoPNonce(bytes.Repeat([]byte{7}, 32))}, nil)
		missing := proofCall(t, s, "GET", "/protected", tokens.AccessToken, "", "")
		if missing.status != http.StatusUnauthorized {
			t.Fatal("sender-bound token worked without proof")
		}
		proof := key.Proof(t, "GET", proofOrigin+"/protected", tokens.AccessToken, "")
		r := proofCall(t, s, "GET", "/protected", tokens.AccessToken, proof, "")
		if r.status != http.StatusUnauthorized || r.header.Get("DPoP-Nonce") == "" || !strings.Contains(r.header.Get("WWW-Authenticate"), "use_dpop_nonce") {
			t.Fatalf("missing nonce challenge: %d %s", r.status, r.body)
		}
		valid := key.Proof(t, "GET", proofOrigin+"/protected", tokens.AccessToken, r.header.Get("DPoP-Nonce"))
		proofCall(t, s, "GET", "/protected", tokens.AccessToken, valid, "").want(t, http.StatusNoContent, "")
	})
	t.Run("AK-J14-C02_key_method_URI_and_access_hash_are_bound", func(t *testing.T) {
		f, key, _, tokens := proofFixture(t, nil)
		_, s := proofServer(t, f, nil, nil)
		wrong := authtest.NewDPoPKey(t)
		for _, tc := range []struct {
			name  string
			proof string
		}{{"key", wrong.Proof(t, "POST", proofOrigin+"/protected", tokens.AccessToken, "")}, {"method", key.Proof(t, "GET", proofOrigin+"/protected", tokens.AccessToken, "")}, {"URI", key.Proof(t, "POST", proofOrigin+"/elsewhere", tokens.AccessToken, "")}, {"access-hash", key.Proof(t, "POST", proofOrigin+"/protected", "another-access-token", "")}} {
			t.Run(tc.name, func(t *testing.T) {
				r := proofCall(t, s, "POST", "/protected", tokens.AccessToken, tc.proof, "")
				if r.status != http.StatusUnauthorized || !strings.Contains(r.header.Get("WWW-Authenticate"), "invalid_dpop_proof") {
					t.Fatalf("sender mismatch accepted or wrong challenge: %d %s", r.status, r.body)
				}
			})
		}
		proofCall(t, s, "POST", "/protected", tokens.AccessToken, key.Proof(t, "POST", proofOrigin+"/protected", tokens.AccessToken, ""), "").want(t, http.StatusNoContent, "")
	})
	t.Run("AK-J14-C03_shared_redis_consumes_one_proof_across_replicas", func(t *testing.T) {
		rdb := realRedis(t)
		f, key, _, tokens := proofFixture(t, rdb)
		_, a := proofServer(t, f, nil, nil)
		_, b := proofServer(t, f, nil, nil)
		proof := key.Proof(t, "GET", proofOrigin+"/protected", tokens.AccessToken, "")
		servers := []string{a.URL, b.URL}
		answers := make([]response, 2)
		errs := make([]error, 2)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range servers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				answers[i], errs[i] = sendProof(t.Context(), servers[i], "GET", "/protected", tokens.AccessToken, proof, "")
			}()
		}
		close(start)
		wg.Wait()
		accepted := 0
		for i, r := range answers {
			noError(t, errs[i])
			if r.status == http.StatusNoContent {
				accepted++
			} else if r.status != http.StatusUnauthorized {
				t.Fatalf("unexpected replay response%d", r.status)
			}
		}
		if accepted != 1 {
			t.Fatalf("same proof authorized%d replicas", accepted)
		}
	})
	t.Run("AK-J14-C04_nonce_retry_has_one_authorized_mutation", func(t *testing.T) {
		f, key, u, tokens := proofFixture(t, nil)
		var calls atomic.Int32
		var v *authkit.Verifier
		h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			identity, ok := verify.VerifiedIdentity(r.Context(), v)
			if !ok {
				http.Error(w, "missing verified identity", 500)
				return
			}
			language := "en"
			if _, err := f.auth.UpdateUser(r.Context(), identity, u.ID, iam.UserUpdate{PreferredLanguage: &language}); err != nil {
				iam.WriteError(w, err)
				return
			}
			calls.Add(1)
			w.WriteHeader(http.StatusNoContent)
		})
		var s *httptest.Server
		v, s = proofServer(t, f, []verify.VerifierOption{verify.WithDPoPNonce(bytes.Repeat([]byte{9}, 32))}, h)
		r := proofCall(t, s, "POST", "/mutate", tokens.AccessToken, key.Proof(t, "POST", proofOrigin+"/mutate", tokens.AccessToken, ""), "")
		if r.status != http.StatusUnauthorized || calls.Load() != 0 {
			t.Fatal("nonce challenge executed the mutation")
		}
		before, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if before.PreferredLanguage != nil {
			t.Fatal("failed proof changed state")
		}
		proof := key.Proof(t, "POST", proofOrigin+"/mutate", tokens.AccessToken, r.header.Get("DPoP-Nonce"))
		proofCall(t, s, "POST", "/mutate", tokens.AccessToken, proof, "").want(t, http.StatusNoContent, "")
		if repeated := proofCall(t, s, "POST", "/mutate", tokens.AccessToken, proof, ""); repeated.status != http.StatusUnauthorized {
			t.Fatal("replayed proof authorized a second mutation")
		}
		after, err := f.auth.User(t.Context(), iam.UserByID(u.ID))
		noError(t, err)
		if calls.Load() != 1 || after.PreferredLanguage == nil || *after.PreferredLanguage != "en" {
			t.Fatal("nonce retry did not commit exactly its one accepted change")
		}
	})
	t.Run("AK-J14-C05_only_declared_public_hosts_change_the_signed_URL", func(t *testing.T) {
		f, key, _, tokens := proofFixture(t, nil)
		_, s := proofServer(t, f, []verify.VerifierOption{verify.WithPublicHosts(func(_ context.Context, host string) (bool, error) { return host == "tenant.example", nil })}, nil)
		proofCall(t, s, "GET", "/protected", tokens.AccessToken, key.Proof(t, "GET", "https://tenant.example/protected", tokens.AccessToken, ""), "tenant.example").want(t, http.StatusNoContent, "")
		r := proofCall(t, s, "GET", "/protected", tokens.AccessToken, key.Proof(t, "GET", "https://attacker.example/protected", tokens.AccessToken, ""), "attacker.example")
		if r.status != http.StatusUnauthorized {
			t.Fatal("arbitrary Host became a trusted proof target")
		}
	})
	t.Run("AK-J14-C06_redis_outage_retains_only_documented_process_local_replay", func(t *testing.T) {
		value := os.Getenv("AUTHKIT_TEST_REDIS_URL")
		if value == "" {
			t.Fatal("Redis fixture required")
		}
		u, err := url.Parse(value)
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
		f, key, _, tokens := proofFixture(t, rdb)
		_, a := proofServer(t, f, nil, nil)
		_, b := proofServer(t, f, nil, nil)
		link.cut()
		proof := key.Proof(t, "GET", proofOrigin+"/protected", tokens.AccessToken, "")
		proofCall(t, a, "GET", "/protected", tokens.AccessToken, proof, "").want(t, http.StatusNoContent, "")
		if r := proofCall(t, a, "GET", "/protected", tokens.AccessToken, proof, ""); r.status != http.StatusUnauthorized {
			t.Fatal("process-local fallback forgot its own spent proof")
		}
		// This is the documented fallback boundary, not a cross-replica
		// exactly-once claim while the shared replay store is unavailable.
		proofCall(t, b, "GET", "/protected", tokens.AccessToken, proof, "").want(t, http.StatusNoContent, "")
	})
}
