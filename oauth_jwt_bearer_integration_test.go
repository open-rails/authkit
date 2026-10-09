package authkit_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/devicekey"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/verify"
)

const (
	workloadClient     = "tensord"
	workloadJobs       = "jobs-runner"
	workloadJobsSecret = "jobs-secret-0123456789-abcdefghij-0123456789"
	workloadOp         = "hub_operation"
	workloadRunClaim   = "https://hub.example.com/run"
	workloadRead       = `{"type":"hub_operation","action":"read","resource":"pkg:acme/private"}`
	workloadPublish    = `{"type":"hub_operation","action":"publish","resource":"ns:acme"}`
	workloadOps        = `[` + workloadRead + `,` + workloadPublish + `]`
)

// newWorkloadServer is newOAuthServer with device keys, g deciding every
// grant, and two jwt-bearer clients for workloads: a public one and a
// confidential one.
func newWorkloadServer(t *testing.T, g *authtest.GrantAuthorizer) (*authtest.AuthorizationServer, iam.Role, iam.Role) {
	t.Helper()
	return newOAuthServer(t,
		authtest.WithDeps(func(d *authkit.Deps) { d.OAuthGrants = g.Authorize }),
		authtest.WithConfig(func(c *authkit.Config) {
			c.DeviceKeys.Enabled = true
			as := &c.AuthorizationServer
			as.Clients = append(as.Clients, authkit.OAuthClientConfig{
				ID: workloadClient, Resources: []string{oauthResource}, AuthorizationDetailsTypes: []string{workloadOp},
				GrantTypes: []authkit.OAuthGrantType{authkit.GrantJWTBearer},
			}, authkit.OAuthClientConfig{
				ID: workloadJobs, SecretSHA256: authtest.ClientSecretSHA256(workloadJobsSecret), Resources: []string{oauthResource},
				AuthorizationDetailsTypes: []string{workloadOp}, GrantTypes: []authkit.OAuthGrantType{authkit.GrantJWTBearer},
			})
		}),
	)
}

// jwtBearerRefusal runs r and returns the status, the OAuth error and its
// reason.
func jwtBearerRefusal(t *testing.T, as *authtest.AuthorizationServer, r authtest.JWTBearerRequest) (int, string, string) {
	t.Helper()
	if r.ClientID == "" {
		r.ClientID = workloadClient
	}
	status, body := as.JWTBearerToken(t, r)
	require.NotEqual(t, http.StatusOK, status, string(body))
	var out struct {
		Error  string `json:"error"`
		Reason string `json:"reason"`
	}
	require.NoError(t, json.Unmarshal(body, &out), string(body))
	return status, out.Error, out.Reason
}

// TestOAuthJWTBearerGrant: a workload presents the capability its user's
// device key signed for its key and gets an at+jwt acting for the user,
// bound to the key, carrying the operations the host kept, until the
// capability expires. A resource server in the issuer's process sees the
// user, the workload and the device key, and stops accepting the token the
// moment the device key is revoked.
func TestOAuthJWTBearerGrant(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, admin, _ := newWorkloadServer(t, g)
	owner := authtest.NewUser(t, as.Client)
	authtest.GrantRole(t, as.Client, iam.RootGroup(), iam.UserSubject(owner.ID), admin)
	device := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)
	worker := authtest.NewDPoPKey(t)
	g.Decide = func(r iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		// The host keeps the read and drops the publish.
		return iam.OAuthGrantDecision{
			AuthorizationDetails: json.RawMessage(`[` + workloadRead + `]`),
			Claims:               map[string]any{workloadRunClaim: json.RawMessage(r.Capability.Claims["run"])},
		}, nil
	}

	var meta map[string]any
	require.Equal(t, http.StatusOK, getJSON(t, as, as.URL+iam.OpenIDConfigurationPath, &meta))
	require.Contains(t, meta["grant_types_supported"], "urn:ietf:params:oauth:grant-type:jwt-bearer")
	require.Equal(t, as.TokenEndpoint(), meta["token_endpoint"])
	require.Contains(t, meta["authorization_details_types_supported"], workloadOp)

	capability := device.Capability(t, authtest.Capability{
		Audience: oauthResource, Workload: worker, AuthorizationDetails: workloadOps, Lifetime: 2 * time.Hour,
		Claims: map[string]any{"run": "run-1"},
	})
	tokens := as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: workloadClient, Key: worker, Capability: capability})
	require.Equal(t, "DPoP", tokens.TokenType)
	require.Empty(t, tokens.RefreshToken, "one exchange per run")
	require.Empty(t, tokens.IDToken)
	require.Empty(t, tokens.Scope)
	require.InDelta(t, (2 * time.Hour).Seconds(), float64(tokens.ExpiresIn), 5, "the capability's exp, not the client's lifetime")
	require.JSONEq(t, `[`+workloadRead+`]`, string(tokens.AuthorizationDetails))

	req, ok := g.Last(iam.OAuthGrantJWTBearer)
	require.True(t, ok)
	require.Equal(t, workloadClient, req.ClientID)
	require.Equal(t, owner.ID, req.UserID)
	require.Equal(t, device.ID, req.DeviceKeyID)
	require.Equal(t, oauthResource, req.Resource)
	require.JSONEq(t, workloadOps, string(req.AuthorizationDetails))
	require.Equal(t, worker.Thumbprint(), req.JWKThumbprint)
	require.Empty(t, req.Scopes)
	require.Empty(t, req.GrantID)
	require.Equal(t, worker.Thumbprint(), req.Assertion.Subject)
	require.WithinDuration(t, time.Now().Add(time.Minute), req.Assertion.ExpiresAt, 5*time.Second)
	require.Nil(t, req.Assertion.Claims)
	require.Len(t, req.Capability.ID, 22)
	require.WithinDuration(t, time.Now().Add(2*time.Hour), req.Capability.ExpiresAt, 5*time.Second)
	require.WithinDuration(t, time.Now(), req.Capability.IssuedAt, 5*time.Second)
	require.Equal(t, map[string]json.RawMessage{"run": json.RawMessage(`"run-1"`)}, req.Capability.Claims)

	at := verifyIssued(t, as, tokens.AccessToken, "at+jwt")
	require.Equal(t, owner.ID, at["sub"])
	require.Equal(t, map[string]any{"sub": worker.Thumbprint()}, at["act"], "the workload key names the invoker by default")
	require.Equal(t, map[string]any{"jkt": worker.Thumbprint()}, at["cnf"])
	require.Equal(t, device.ID, at["device_key_id"])
	require.Equal(t, workloadClient, at["client_id"])
	require.Equal(t, oauthResource, at["aud"])
	require.Equal(t, []any{map[string]any{"type": workloadOp, "action": "read", "resource": "pkg:acme/private"}}, at["authorization_details"])
	require.Equal(t, []any{}, at["permissions"], "the capability's operations are its only authority")
	require.Equal(t, "run-1", at[workloadRunClaim])
	for _, absent := range []string{"scope", "sid", "auth_time", "amr", "acr"} {
		require.NotContains(t, at, absent, "no sign-in stands behind a workload's token")
	}

	// A capability redeems once, whatever the assertion.
	_, code, reason := jwtBearerRefusal(t, as, authtest.JWTBearerRequest{Key: worker, Capability: capability})
	require.Equal(t, "invalid_grant", code)
	require.Equal(t, "capability_replayed", reason)

	// A resource server in the issuer's process.
	resource := httptest.NewUnstartedServer(nil)
	t.Cleanup(resource.Close)
	v, err := as.Client.NewVerifier([]string{oauthResource}, verify.WithPublicURL("http://"+resource.Listener.Addr().String()))
	require.NoError(t, err)
	resource.Config.Handler = verify.RequireSession(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := verify.ClaimsFromContext(r.Context())
		id, _ := verify.VerifiedIdentity(r.Context(), v)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"sub": cl.Subject, "invoker": cl.Invoker, "jkt": cl.JWKThumbprint, "device_key_id": cl.DeviceKeyID, "client_id": cl.ClientID,
			"details": cl.AuthorizationDetails, "subject": id.Subject, "identity_invoker": id.Invoker.ID, "run": string(cl.CustomClaims[workloadRunClaim]),
		})
	}))
	resource.Start()
	call := func(key *authtest.DPoPKey) (int, map[string]any) {
		req, _ := http.NewRequest(http.MethodGet, resource.URL+"/v1/packages/acme/private", nil)
		if key != nil {
			key.Authorize(t, req, tokens.AccessToken, "")
		} else {
			req.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
		}
		res, err := resource.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		var out map[string]any
		require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
		return res.StatusCode, out
	}
	status, got := call(worker)
	require.Equal(t, http.StatusOK, status, got)
	require.Equal(t, owner.ID, got["sub"])
	require.Equal(t, worker.Thumbprint(), got["invoker"])
	require.Equal(t, worker.Thumbprint(), got["jkt"])
	require.Equal(t, device.ID, got["device_key_id"])
	require.Equal(t, workloadClient, got["client_id"])
	require.Equal(t, owner.ID, got["subject"])
	require.Equal(t, worker.Thumbprint(), got["identity_invoker"])
	require.Equal(t, `"run-1"`, got["run"])
	status, _ = call(nil)
	require.Equal(t, http.StatusUnauthorized, status, "a stolen token without the workload key")
	status, _ = call(authtest.NewDPoPKey(t))
	require.Equal(t, http.StatusUnauthorized, status, "nor with another key")

	authtest.RevokeDeviceKey(t, as.Client, device)
	status, got = call(worker)
	require.Equal(t, http.StatusUnauthorized, status, "revoking the device key ends the token at once")
	require.Equal(t, "session_revoked", got["error"].(map[string]any)["code"])

	// A confidential client authenticates too; the host may name the
	// invoker and cap the lifetime.
	device = authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)
	g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{Invoker: "worker:w-1", MaxLifetime: 10 * time.Minute}, nil
	}
	jobs := as.JWTBearer(t, authtest.JWTBearerRequest{
		ClientID: workloadJobs, ClientSecret: workloadJobsSecret, Key: worker, Resource: oauthResource,
		Capability: device.Capability(t, authtest.Capability{Audience: oauthResource, Workload: worker, AuthorizationDetails: workloadOps}),
	})
	require.Equal(t, int64(600), jobs.ExpiresIn)
	at = verifyIssued(t, as, jobs.AccessToken, "at+jwt")
	require.Equal(t, map[string]any{"sub": "worker:w-1"}, at["act"])
	require.JSONEq(t, workloadOps, string(jobs.AuthorizationDetails), "nil keeps every operation")
}

// TestOAuthJWTBearerRefusals pins every refusal of the jwt-bearer grant and
// its reason.
func TestOAuthJWTBearerRefusals(t *testing.T) {
	g := &authtest.GrantAuthorizer{}
	as, _, _ := newWorkloadServer(t, g)
	owner := authtest.NewUser(t, as.Client)
	device := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)
	worker := authtest.NewDPoPKey(t)
	capability := func(c authtest.Capability) string {
		if c.Audience == "" {
			c.Audience = oauthResource
		}
		if c.Workload == nil {
			c.Workload = worker
		}
		if c.AuthorizationDetails == "" {
			c.AuthorizationDetails = workloadOps
		}
		return device.Capability(t, c)
	}
	assertion := func(a authtest.Assertion) string {
		if a.Issuer == "" {
			a.Issuer = workloadClient
		}
		if a.Audience == "" {
			a.Audience = as.TokenEndpoint()
		}
		if a.Capability == "" {
			a.Capability = capability(authtest.Capability{})
		}
		return worker.Assertion(t, a)
	}
	refuse := func(r authtest.JWTBearerRequest, wantStatus int, wantCode, wantReason, why string) {
		t.Helper()
		if r.Key == nil && r.Assertion == "" {
			r.Key = worker
		}
		if r.Capability == "" && r.Assertion == "" {
			r.Capability = capability(authtest.Capability{})
		}
		status, code, reason := jwtBearerRefusal(t, as, r)
		require.Equal(t, wantStatus, status, why)
		require.Equal(t, wantCode, code, why)
		require.Equal(t, wantReason, reason, why)
	}

	// A failed request spends nothing: the same capability redeems after.
	once := capability(authtest.Capability{})
	refuse(authtest.JWTBearerRequest{Key: worker, Capability: once, Scopes: []string{"api:merchant"}}, 400, "invalid_scope", "", "a scope")
	g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{}, errors.New("hub database down")
	}
	refuse(authtest.JWTBearerRequest{Key: worker, Capability: once}, 503, "temporarily_unavailable", "", "an authorizer outage")
	g.Decide = nil
	sent := worker.Assertion(t, authtest.Assertion{Issuer: workloadClient, Audience: as.TokenEndpoint(), Capability: once})
	as.JWTBearer(t, authtest.JWTBearerRequest{ClientID: workloadClient, Key: worker, Assertion: sent})
	refuse(authtest.JWTBearerRequest{Key: worker, Assertion: sent}, 400, "invalid_grant", "assertion_replayed", "a replayed assertion")
	refuse(authtest.JWTBearerRequest{Key: worker, Capability: once}, 400, "invalid_grant", "capability_replayed", "a redeemed capability")

	// The keys: the DPoP proof, the assertion and the capability name one.
	refuse(authtest.JWTBearerRequest{Key: authtest.NewDPoPKey(t), Assertion: assertion(authtest.Assertion{})}, 400, "invalid_dpop_proof", "key_mismatch", "another key's proof")
	refuse(authtest.JWTBearerRequest{Assertion: assertion(authtest.Assertion{})}, 400, "invalid_dpop_proof", "", "a public client without a proof")
	refuse(authtest.JWTBearerRequest{ClientID: workloadJobs, ClientSecret: workloadJobsSecret,
		Assertion: assertion(authtest.Assertion{Issuer: workloadJobs})}, 400, "invalid_dpop_proof", "", "a confidential client without a proof")
	refuse(authtest.JWTBearerRequest{Capability: capability(authtest.Capability{Workload: authtest.NewDPoPKey(t)})}, 400, "invalid_grant", "key_mismatch", "a capability for another workload")

	// The assertion.
	for why, a := range map[string]string{
		"expired":                assertion(authtest.Assertion{Lifetime: -time.Minute}),
		"too long-lived":         assertion(authtest.Assertion{Lifetime: 10 * time.Minute}),
		"the issuer as audience": assertion(authtest.Assertion{Audience: as.URL}),
		"another server":         assertion(authtest.Assertion{Audience: "https://other.example/oauth2/token"}),
		"another client's":       assertion(authtest.Assertion{Issuer: workloadJobs}),
		"a short jti":            assertion(authtest.Assertion{ID: "short"}),
		"no capability":          worker.Assertion(t, authtest.Assertion{Issuer: workloadClient, Audience: as.TokenEndpoint()}),
		"a DPoP proof":           worker.Proof(t, http.MethodPost, as.TokenEndpoint(), "", ""),
		"not a JWT":              "not-a-jwt",
	} {
		refuse(authtest.JWTBearerRequest{Key: worker, Assertion: a}, 400, "invalid_grant", "assertion_invalid", why)
	}

	// The capability.
	signed := func(key devicekey.Capability, id string, signer authtest.DeviceKey) string {
		raw, err := devicekey.SignCapability(signer.Key, id, key)
		require.NoError(t, err)
		return raw
	}
	base := devicekey.Capability{
		UserID: owner.ID, Audience: oauthResource, WorkloadThumbprint: worker.Thumbprint(),
		AuthorizationDetails: json.RawMessage(workloadOps), ExpiresAt: time.Now().Add(time.Hour),
	}
	other := base
	other.UserID = authtest.NewUser(t, as.Client).ID
	_, strangerKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	stranger := authtest.DeviceKey{ID: uuid.NewString(), Key: strangerKey}
	for why, tc := range map[string]struct {
		capability, reason string
	}{
		"expired":                 {capability(authtest.Capability{Lifetime: -2 * time.Minute}), "capability_expired"},
		"longer than a day":       {capability(authtest.Capability{Lifetime: 25 * time.Hour}), "capability_invalid"},
		"an undeclared operation": {capability(authtest.Capability{AuthorizationDetails: `[{"type":"payout"}]`}), "capability_invalid"},
		"not a JWT":               {"a.b.c", "capability_invalid"},
		"for another user":        {signed(other, device.ID, device), "capability_invalid"},
		"an unknown device key":   {signed(base, stranger.ID, stranger), "device_key_revoked"},
		"another key's signature": {signed(base, device.ID, stranger), "capability_invalid"},
	} {
		refuse(authtest.JWTBearerRequest{Key: worker, Capability: tc.capability}, 400, "invalid_grant", tc.reason, why)
	}
	refuse(authtest.JWTBearerRequest{Capability: capability(authtest.Capability{Audience: "https://other.example"})}, 400, "invalid_target", "", "a resource the client may not reach")
	refuse(authtest.JWTBearerRequest{Resource: "https://other.example"}, 400, "invalid_target", "", "a resource other than the capability's")

	// The host's decision: refusal, or a decision that would widen.
	g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{}, iam.ErrOAuthGrantRefused
	}
	refuse(authtest.JWTBearerRequest{}, 400, "invalid_grant", "refused", "the host refuses")
	for why, d := range map[string]iam.OAuthGrantDecision{
		"permissions":          {Permissions: []string{"merchant:*"}},
		"an added operation":   {AuthorizationDetails: json.RawMessage(`[` + workloadRead + `,{"type":"hub_operation","action":"delete","resource":"ns:acme"}]`)},
		"a changed operation":  {AuthorizationDetails: json.RawMessage(`[{"type":"hub_operation","action":"read","resource":"pkg:acme/*"}]`)},
		"an invoker w/ spaces": {Invoker: "a worker"},
	} {
		g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) { return d, nil }
		refuse(authtest.JWTBearerRequest{}, 503, "temporarily_unavailable", "", why)
	}
	g.Decide = func(iam.OAuthGrantRequest) (iam.OAuthGrantDecision, error) {
		return iam.OAuthGrantDecision{Invoker: "worker"}, nil
	}
	status, code := tokenError(t, as, authtest.TokenRequest{ClientID: oauthWorker, ClientSecret: oauthWorkerSecret, Params: url.Values{"grant_type": {"client_credentials"}}})
	require.Equal(t, http.StatusServiceUnavailable, status, "Invoker answers only a jwt-bearer grant")
	require.Equal(t, "temporarily_unavailable", code)
	g.Decide = nil

	// The device key and its account.
	second := authtest.EnrollDeviceKey(t, as.Client, as.Outbox, owner)
	revoked := second.Capability(t, authtest.Capability{Audience: oauthResource, Workload: worker, AuthorizationDetails: workloadOps})
	authtest.RevokeDeviceKey(t, as.Client, second)
	refuse(authtest.JWTBearerRequest{Capability: revoked}, 400, "invalid_grant", "device_key_revoked", "a revoked device key")
	pending := capability(authtest.Capability{})
	require.NoError(t, as.Client.Ban(context.Background(), iam.SystemIdentity(), owner.ID, iam.Ban{}))
	refuse(authtest.JWTBearerRequest{Capability: pending}, 400, "invalid_grant", "device_key_revoked", "a ban revokes the user's device keys")

	// The request.
	jwtBearer := func(clientID, secret string, params url.Values) (int, string) {
		params.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
		return tokenError(t, as, authtest.TokenRequest{ClientID: clientID, ClientSecret: secret, DPoP: worker, Params: params})
	}
	_, code = jwtBearer(oauthWorker, oauthWorkerSecret, url.Values{"assertion": {"x"}})
	require.Equal(t, "unauthorized_client", code, "a client without the grant")
	_, code = jwtBearer(workloadClient, "", url.Values{})
	require.Equal(t, "invalid_request", code, "no assertion")
	_, code = jwtBearer(workloadClient, "", url.Values{"assertion": {"x"}, "authorization_details": {`[{"type":"hub_operation"}]`}})
	require.Equal(t, "invalid_request", code, "authorization_details")
	status, code = jwtBearer(workloadClient, "a-secret", url.Values{"assertion": {"x"}})
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid_client", code, "a public client sends no secret")
}
