package authhttp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/redis/go-redis/v9"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/documents"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/open-rails/authkit/verify"

	"github.com/stretchr/testify/require"
)

// Real HTTP issuer -> resource requests on both ephemeral backends prove that
// delegated authority still comes only from the host grant, with browser key
// possession enforced on issuance and every protected request.
func TestBrowserDelegationWorkflow(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		pg := testdb.ScratchPostgres(t)
		ctx := context.Background()
		cfg := newServerTestConfig()
		cfg.Delegated = embedded.DelegatedConfig{Audiences: []string{"platform"}, AllowDPoP: true}
		var authorizations atomic.Int32
		var observed authkit.DelegationRequest
		var mu sync.Mutex
		opts := append(store.engineOpts(), withDelegatedAuthorization(func(_ context.Context, req authkit.DelegationRequest) (authkit.DelegationGrant, error) {
			authorizations.Add(1)
			mu.Lock()
			observed = req
			mu.Unlock()
			if string(req.RequestedGrant) == `{"refuse":true}` {
				return authkit.DelegationGrant{}, authkit.ErrDelegationRefused
			}
			return authkit.DelegationGrant{Permissions: []string{"resource:read"}, Attributes: map[string]any{"tenant": "cozy"}, Documents: map[string]string{"example.policy/v1": documents.Digest([]byte("policy"))}}, nil
		}))
		engine := newServerClient(t, cfg, pg.Pool, opts...)
		service, err := New(engine, Config{DirectPeerIP: true, DisableRateLimiting: true})
		require.NoError(t, err)
		t.Cleanup(service.Close)
		handler, err := MountHandler(service, MountOptions{})
		require.NoError(t, err)
		issuer := httptest.NewServer(handler)
		t.Cleanup(issuer.Close)
		user, err := engine.CreateUser(ctx, uniqueEmail("dpop"), "dpop"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, engine.AdminSetPassword(ctx, user.ID, "Browser-profile-pass1!"))
		login, err := issuer.Client().Post(issuer.URL+"/api/v1/password/login", "application/json", strings.NewReader(`{"identifier":"`+*user.Email+`","password":"Browser-profile-pass1!"}`))
		require.NoError(t, err)
		var session authkit.TokenSet
		require.NoError(t, json.NewDecoder(login.Body).Decode(&session))
		login.Body.Close()
		require.Equal(t, 200, login.StatusCode)
		require.NotEmpty(t, session.AccessToken)
		browserKey := testdpop.Key(t)
		target := cfg.Token.Issuer + "/api/v1/delegated/token"
		body := `{"requested_grant":{"permissions":["root:all"]},"audiences":["platform"],"ttl_seconds":1}`
		var lastChallenge string
		post := func(body, token, proof string, headers map[string]string) (int, []byte) {
			req, err := http.NewRequest("POST", issuer.URL+"/api/v1/delegated/token", strings.NewReader(body))
			require.NoError(t, err)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+token)
			if proof != "" {
				req.Header.Set("DPoP", proof)
			}
			for k, v := range headers {
				if k == "Host" {
					req.Host = v
				} else {
					req.Header.Set(k, v)
				}
			}
			resp, err := issuer.Client().Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			lastChallenge = resp.Header.Get("WWW-Authenticate")
			raw, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			return resp.StatusCode, raw
		}
		proof := testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil)
		status, raw := post(body, session.AccessToken, proof, map[string]string{"Host": "evil.example", "Forwarded": "host=evil.example;proto=http", "X-Forwarded-Host": "evil.example"})
		require.Equal(t, 200, status, string(raw))
		var minted delegatedTokenResponse
		require.NoError(t, json.Unmarshal(raw, &minted))
		require.Equal(t, "DPoP", minted.TokenType)
		assertWireGolden(t, "delegated-dpop-response", json.RawMessage(raw))
		claims := unverifiedClaims(t, minted.Token)
		assertWireGolden(t, "delegated-dpop-claims", claims)
		mu.Lock()
		requestFacts := observed
		mu.Unlock()
		require.Equal(t, map[string]any{"jkt": jwtkit.CertificateThumbprint(*requestFacts.ConfirmationJWKThumbprintSHA256)}, claims["cnf"])
		require.Nil(t, requestFacts.DelegateCertificate)
		require.Equal(t, [32]byte{}, requestFacts.ConfirmationCertificateSHA256)
		require.Equal(t, user.ID, requestFacts.UserID)
		require.Equal(t, []any{"resource:read"}, claims["permissions"])
		require.Nil(t, claims["sub"])
		require.Equal(t, user.ID, claims["delegated_sub"])
		require.Equal(t, float64(60), claims["exp"].(float64)-claims["iat"].(float64))
		require.NotEmpty(t, claims["documents"])
		status, _ = post(body, session.AccessToken, proof, nil)
		require.Equal(t, 401, status)
		require.Equal(t, `DPoP error="invalid_dpop_proof", algs="ES256"`, lastChallenge)
		status, _ = post(body, session.AccessToken, "", nil)
		require.Equal(t, 400, status)
		status, _ = post(body, "", testdpop.Proof(t, browserKey, "POST", target, "", nil), nil)
		require.Equal(t, 401, status)
		status, _ = post(body, session.AccessToken, testdpop.Proof(t, browserKey, "POST", target, "wrong-parent", nil), nil)
		require.Equal(t, 401, status)
		status, _ = post(mintBody(newDelegateCertificate(t, nil), ""), session.AccessToken, testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil), nil)
		require.Equal(t, 400, status)
		status, _ = post(`{"audiences":["other"],"requested_grant":{}}`, session.AccessToken, testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil), nil)
		require.Equal(t, 400, status)
		require.EqualValues(t, 1, authorizations.Load())
		status, _ = post(`{"requested_grant":{"refuse":true}}`, session.AccessToken, testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil), nil)
		require.Equal(t, 403, status)

		// A proxy may remove an external prefix. Its configured resolver supplies
		// that path explicitly; neither Host nor Forwarded selects the proof target.
		rewrittenHTTP, err := New(engine, Config{DirectPeerIP: true, DisableRateLimiting: true, DPoPRequestURL: func(*http.Request) string { return cfg.Token.Issuer + "/external/api/v1/delegated/token" }})
		require.NoError(t, err)
		t.Cleanup(rewrittenHTTP.Close)
		rewrittenHandler, err := MountHandler(rewrittenHTTP, MountOptions{})
		require.NoError(t, err)
		issuer = httptest.NewServer(rewrittenHandler)
		t.Cleanup(issuer.Close)
		status, _ = post(body, session.AccessToken, testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil), nil)
		require.Equal(t, 401, status)
		status, _ = post(body, session.AccessToken, testdpop.Proof(t, browserKey, "POST", cfg.Token.Issuer+"/external/api/v1/delegated/token", session.AccessToken, nil), nil)
		require.Equal(t, 200, status)

		// A receiver owns trusted URLs and its shared replay storage. Here the same
		// engine backs the replay guard; namespaces remain bounded by key and TTL.
		var resource *httptest.Server
		verifier := verify.NewVerifier(verify.WithDPoP(engine.ClaimDPoPProof, func(r *http.Request) string { return resource.URL + r.URL.EscapedPath() }))
		require.NoError(t, verifier.AddIssuer(cfg.Token.Issuer, []string{"platform"}, verify.IssuerOptions{PublicKeys: cfg.Keys.Source.PublicKeys}))
		resourceMux := http.NewServeMux()
		resourceMux.Handle("/", resourceHandler(verifier))
		live, err := verify.RequiredLive(verifier.WithLiveness(engine))
		require.NoError(t, err)
		resourceMux.Handle("/live", live(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) })))
		resource = httptest.NewTLSServer(resourceMux)
		t.Cleanup(resource.Close)
		call := func(scheme, token, proof, path string) int {
			req, err := http.NewRequest("GET", resource.URL+path, nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", scheme+" "+token)
			if proof != "" {
				req.Header.Set("DPoP", proof)
			}
			resp, err := resource.Client().Do(req)
			require.NoError(t, err)
			if resp.StatusCode == 401 {
				require.Equal(t, `DPoP error="invalid_dpop_proof", algs="ES256"`, resp.Header.Get("WWW-Authenticate"))
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			return resp.StatusCode
		}
		resourceProof := func(token string) string {
			return testdpop.Proof(t, browserKey, "GET", resource.URL+"/tasks", token, nil)
		}
		require.Equal(t, 200, call("DPoP", minted.Token, resourceProof(minted.Token), "/tasks?cursor=next"))
		require.Equal(t, 401, call("DPoP", minted.Token, resourceProof(minted.Token), "/live"))
		require.Equal(t, 200, call("DPoP", minted.Token, testdpop.Proof(t, browserKey, "GET", resource.URL+"/live", minted.Token, nil), "/live"))
		require.Equal(t, 401, call("Bearer", minted.Token, resourceProof(minted.Token), "/tasks"))
		require.Equal(t, 401, call("DPoP", minted.Token, "", "/tasks"))
		require.Equal(t, 401, call("DPoP", minted.Token, resourceProof("other-token"), "/tasks"))
		require.Equal(t, 401, call("DPoP", minted.Token, resourceProof(minted.Token), "/other"))
		require.Equal(t, 401, call("DPoP", minted.Token, testdpop.Proof(t, browserKey, "POST", resource.URL+"/tasks", minted.Token, nil), "/tasks"))
		require.Equal(t, 401, call("DPoP", minted.Token, testdpop.Proof(t, testdpop.Key(t), "GET", resource.URL+"/tasks", minted.Token, nil), "/tasks"))
		_, err = verifier.Verify(ctx, minted.Token)
		require.ErrorIs(t, err, verify.ErrSenderProofRequired)
		detached, err := engine.MintDelegatedAccessToken(ctx, authkit.DelegatedAccessParams{Audiences: []string{"platform"}, DelegatedSubject: user.ID, Permissions: []string{"resource:read"}})
		require.NoError(t, err)
		require.Equal(t, 401, call("DPoP", detached, resourceProof(detached), "/tasks"))
		certHash := [32]byte{1}
		_, err = engine.MintDelegatedAccessToken(ctx, authkit.DelegatedAccessParams{DelegatedSubject: user.ID, ConfirmationCertificateSHA256: &certHash, ConfirmationJWKThumbprintSHA256: requestFacts.ConfirmationJWKThumbprintSHA256})
		require.Error(t, err)
		oneProof := resourceProof(minted.Token)
		var successes atomic.Int32
		var wg sync.WaitGroup
		for range 12 {
			wg.Go(func() {
				if call("DPoP", minted.Token, oneProof, "/tasks") == 200 {
					successes.Add(1)
				}
			})
		}
		wg.Wait()
		require.EqualValues(t, 1, successes.Load())

		// Disabling DPoP protects existing native authorizers from nil certificates.
		cfg.Delegated.AllowDPoP = false
		native := newServerClient(t, cfg, pg.Pool, opts...)
		nativeHTTP, err := New(native, Config{DirectPeerIP: true, DisableRateLimiting: true})
		require.NoError(t, err)
		t.Cleanup(nativeHTTP.Close)
		nativeHandler, err := MountHandler(nativeHTTP, MountOptions{})
		require.NoError(t, err)
		req := httptest.NewRequest("POST", target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+session.AccessToken)
		req.Header.Set("DPoP", testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil))
		rec := httptest.NewRecorder()
		nativeHandler.ServeHTTP(rec, req)
		require.Equal(t, 400, rec.Code)

		if store.rdb != nil {
			// Actual denied Lua execution is an operational failure, never an invalid
			// proof and never a non-atomic fallback. A restored backend can accept it.
			name, password := "dpop_"+uniqueSuffix(), uniqueSuffix()+uniqueSuffix()
			require.NoError(t, store.rdb.Do(ctx, "ACL", "SETUSER", name, "on", ">"+password, "~*", "+@all", "-eval", "-evalsha").Err())
			t.Cleanup(func() { require.NoError(t, store.rdb.Do(ctx, "ACL", "DELUSER", name).Err()) })
			redisOptions := *store.rdb.Options()
			redisOptions.Username, redisOptions.Password = name, password
			denied := redis.NewClient(&redisOptions)
			t.Cleanup(func() { _ = denied.Close() })
			cfg.Delegated.AllowDPoP = true
			broken := newServerClient(t, cfg, pg.Pool, append(opts, withRedis(denied))...)
			brokenHTTP, err := New(broken, Config{DirectPeerIP: true, DisableRateLimiting: true})
			require.NoError(t, err)
			t.Cleanup(brokenHTTP.Close)
			brokenHandler, err := MountHandler(brokenHTTP, MountOptions{})
			require.NoError(t, err)
			issuer = httptest.NewServer(brokenHandler)
			t.Cleanup(issuer.Close)
			mintProof := testdpop.Proof(t, browserKey, "POST", target, session.AccessToken, nil)
			status, raw := post(body, session.AccessToken, mintProof, nil)
			require.Equal(t, 500, status, string(raw))
			require.Contains(t, string(raw), "internal_error")
			require.Empty(t, lastChallenge)
			v := verify.NewVerifier(verify.WithDPoP(broken.ClaimDPoPProof, func(r *http.Request) string { return resource.URL + r.URL.EscapedPath() }))
			require.NoError(t, v.AddIssuer(cfg.Token.Issuer, []string{"platform"}, verify.IssuerOptions{PublicKeys: cfg.Keys.Source.PublicKeys}))
			req := httptest.NewRequest("GET", resource.URL+"/tasks", nil)
			req.Header.Set("Authorization", "DPoP "+minted.Token)
			req.Header.Set("DPoP", resourceProof(minted.Token))
			_, err = v.VerifyRequest(req)
			require.Error(t, err)
			require.Equal(t, authkit.CodeInternalError, authkit.AsError(err).Code)
			rejected := httptest.NewRecorder()
			verify.Required(v)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("storage outage admitted request") })).ServeHTTP(rejected, req)
			require.Equal(t, 500, rejected.Code)
			require.Empty(t, rejected.Header().Get("WWW-Authenticate"))
			require.NoError(t, store.rdb.Do(ctx, "ACL", "SETUSER", name, "+eval", "+evalsha").Err())
			status, raw = post(body, session.AccessToken, mintProof, nil)
			require.Equal(t, 200, status, string(raw))
			cl, err := v.VerifyRequest(req)
			require.NoError(t, err)
			require.NotNil(t, cl.ConfirmationJWKThumbprintSHA256)
		}
	})
}
