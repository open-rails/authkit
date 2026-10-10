package verify

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/ident"
	"github.com/open-rails/authkit/internal/jose"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/open-rails/helpers/auth"
	"github.com/stretchr/testify/require"
)

// A resource access token (RFC 9068) names its user and client and carries
// the issuer's grant for this audience; it is never a sign-in here, even
// from the local issuer.
func TestResourceAccessTokens(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	now := time.Now()
	user := map[string]any{
		"sub": "user-1", "client_id": "console", "scope": "openid openrails:self", "jti": "at-1",
		"permissions": []string{"merchant:*"}, "roles": []string{"admin"}, "sid": "s-1",
		"auth_time": now.Unix(), "acr": "urn:authkit:acr:mfa", "amr": []string{"pwd", "otp"},
	}
	for _, typ := range []string{jose.ResourceAccessTokenType, "application/at+jwt"} {
		cl, err := f.v.Verify(ctx, sign(t, f.peer, typ, peerIssuer, user))
		require.NoError(t, err, typ)
		require.Equal(t, TokenUser, cl.Kind)
		require.True(t, cl.IsResourceToken())
		require.Equal(t, "user-1", cl.Subject)
		require.Empty(t, cl.UserID)
		require.Equal(t, "console", cl.ClientID)
		require.Equal(t, []string{"openid", "openrails:self"}, cl.Scopes)
		require.True(t, cl.HasScope("openrails:self") && !cl.HasScope("openrails"))
		require.Equal(t, []string{"admin"}, cl.Roles)
		require.True(t, cl.HasPermission(ident.Perm("merchant:subscriptions:update")))
		require.False(t, cl.HasPermission(ident.Perm("root:users:ban")))
		require.Equal(t, "s-1", cl.SessionID)
		require.Equal(t, now.Unix(), cl.AuthTime.Unix())
		require.Equal(t, "urn:authkit:acr:mfa", cl.ACR)
		require.True(t, cl.HasAMR("otp"))
		require.Equal(t, "at-1", cl.JTI)
		_, ok := boundIdentity(cl)
		require.False(t, ok, "its authority is Permissions, for the resource server")
		id, ok := cl.Identity()
		require.True(t, ok)
		require.Equal(t, auth.Identity{Issuer: peerIssuer, Subject: "user-1", SubjectKind: auth.SubjectUser,
			Invoker: auth.Invoker{Issuer: peerIssuer, ID: "user-1"}, Credential: auth.Credential{Kind: auth.CredentialAccessToken, ID: "at-1"}}, id,
			"the user acts themself: the client is their agent, not an invoker (RFC 8693 act names one)")
	}

	cl, err := f.v.Verify(ctx, sign(t, f.local, jose.ResourceAccessTokenType, localIssuer, user))
	require.NoError(t, err)
	require.Empty(t, cl.UserID, "the local issuer's resource token is no sign-in")
	require.Equal(t, "user-1", cl.Subject)
	require.Equal(t, []string{"merchant:*"}, cl.Permissions)
	cl, err = f.v.Verify(ctx, sign(t, f.local, jose.ResourceAccessTokenType, localIssuer, map[string]any{
		"sub": "user-1", "client_id": "tensord", "device_key_id": "dk-1", "act": map[string]any{"sub": "worker-1"},
	}))
	require.NoError(t, err)
	require.Equal(t, "dk-1", cl.DeviceKeyID, "a jwt-bearer token's device key, for the session check")
	require.Equal(t, "worker-1", cl.Invoker)

	cl, err = f.v.Verify(ctx, sign(t, f.peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{
		"sub": "billing-worker", "client_id": "billing-worker", "permissions": []string{"merchant:payouts:read"},
	}))
	require.NoError(t, err)
	require.Equal(t, TokenOAuthClient, cl.Kind, "sub == client_id: the client acting for itself")
	require.True(t, cl.HasPermission(ident.Perm("merchant:payouts:read")))
	_, ok := boundIdentity(cl)
	require.False(t, ok)
	id, ok := cl.Identity()
	require.True(t, ok)
	require.Equal(t, auth.Identity{Issuer: peerIssuer, Subject: "billing-worker", SubjectKind: auth.SubjectApplication,
		Invoker: auth.Invoker{Issuer: peerIssuer, ID: "billing-worker"}, Credential: auth.Credential{Kind: auth.CredentialAccessToken}}, id)

	cl, err = f.v.Verify(ctx, sign(t, f.peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{
		"sub": "user-1", "client_id": "console", "root_role": "root:admin", "2fa_enrollment": true, "device_key_id": "dk-1",
	}))
	require.NoError(t, err)
	require.Empty(t, cl.RootRole)
	require.False(t, cl.TwoFAEnrollment)
	require.Empty(t, cl.DeviceKeyID, "AuthKit's sign-in claims mean nothing on a resource token")

	for name, tc := range map[string]struct {
		claims map[string]any
		want   errmodel.Code
	}{
		"no client_id":     {map[string]any{"sub": "user-1"}, errmodel.CodeMissingClientID},
		"no sub":           {map[string]any{"client_id": "console"}, errmodel.CodeMissingSub},
		"no aud":           {map[string]any{"sub": "user-1", "client_id": "console", "aud": nil}, errmodel.CodeBadAudience},
		"another resource": {map[string]any{"sub": "user-1", "client_id": "console", "aud": "https://other.example"}, errmodel.CodeBadAudience},
		"expired":          {map[string]any{"sub": "user-1", "client_id": "console", "exp": time.Now().Add(-time.Hour).Unix()}, errmodel.CodeTokenExpired},
		"malformed cnf":    {map[string]any{"sub": "user-1", "client_id": "console", "cnf": map[string]any{"jkt": "short"}}, errmodel.CodeInvalidConfirmation},
	} {
		_, err := f.v.Verify(ctx, sign(t, f.peer, jose.ResourceAccessTokenType, peerIssuer, tc.claims))
		require.Equal(t, tc.want, codeOf(err), name)
	}
}

// A resource server behind Required accepts a DPoP-bound resource token only
// with a fresh, single-use proof of its key carrying a current server nonce,
// and tells the client how to recover from each refusal (RFC 9449 §7, §8).
func TestDPoPBoundResourceTokenOverHTTP(t *testing.T) {
	nonceKey := make([]byte, 32)
	_, _ = rand.Read(nonceKey)

	server := httptest.NewUnstartedServer(nil)
	t.Cleanup(server.Close)
	base := "http://" + server.Listener.Addr().String()
	v := NewVerifier(WithDPoP(nil), WithPublicURL(base), WithDPoPNonce(nonceKey))
	peer := newFixture(t).peer
	require.NoError(t, v.AddIssuer(peerIssuer, []string{audience}, IssuerOptions{Keys: []iam.RemoteApplicationKey{pemKey(t, peer)}}))
	server.Config.Handler = Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, _ := ClaimsFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": cl.Subject, "jkt": cl.JWKThumbprint, "permissions": cl.Permissions})
	}))
	server.Start()
	target := base + "/v1/merchant/subscriptions"

	key := testdpop.Key(t)
	jkt := testdpop.Thumbprint(t, key)
	bound := sign(t, peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{
		"sub": "user-1", "client_id": "console", "permissions": []string{"merchant:*"}, "cnf": map[string]any{"jkt": jkt},
	})
	withNonce := func(nonce string) func(*jwt.Token) {
		return func(tok *jwt.Token) { tok.Claims.(jwt.MapClaims)["nonce"] = nonce }
	}
	type answer struct {
		status          int
		code, challenge string
		nonce           string
		body            map[string]any
	}
	call := func(scheme, token, proof string) answer {
		req, _ := http.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("Authorization", scheme+" "+token)
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		res, err := server.Client().Do(req)
		require.NoError(t, err)
		defer res.Body.Close()
		a := answer{status: res.StatusCode, challenge: res.Header.Get("WWW-Authenticate"), nonce: res.Header.Get("DPoP-Nonce")}
		if res.StatusCode == http.StatusOK {
			require.NoError(t, json.NewDecoder(res.Body).Decode(&a.body))
		} else {
			var env iam.ErrorEnvelope
			require.NoError(t, json.NewDecoder(res.Body).Decode(&env))
			a.code = env.Error.Code
		}
		return a
	}

	// The first proof carries no nonce: the server hands one out.
	first := call("DPoP", bound, testdpop.Proof(t, key, http.MethodGet, target, bound, nil))
	require.Equal(t, http.StatusUnauthorized, first.status)
	require.Equal(t, string(errmodel.CodeUseDPoPNonce), first.code)
	require.Contains(t, first.challenge, `DPoP error="use_dpop_nonce"`)
	require.NotEmpty(t, first.nonce)

	ok := call("DPoP", bound, testdpop.Proof(t, key, http.MethodGet, target, bound, withNonce(first.nonce)))
	require.Equal(t, http.StatusOK, ok.status)
	require.Equal(t, jkt, ok.body["jkt"])
	require.Equal(t, "user-1", ok.body["sub"])
	require.Equal(t, []any{"merchant:*"}, ok.body["permissions"])

	proof := testdpop.Proof(t, key, http.MethodGet, target, bound, withNonce(first.nonce))
	require.Equal(t, http.StatusOK, call("DPoP", bound, proof).status, "a nonce serves many proofs")
	replayed := call("DPoP", bound, proof)
	require.Equal(t, http.StatusUnauthorized, replayed.status, "a proof is single-use")
	require.Equal(t, string(errmodel.CodeSenderProofRequired), replayed.code)
	require.Contains(t, replayed.challenge, `DPoP error="invalid_dpop_proof"`)

	otherKey := make([]byte, 32)
	_, _ = rand.Read(otherKey)
	foreign, err := dpop.NewNonces(otherKey)
	require.NoError(t, err)
	for name, nonce := range map[string]string{
		"another server's nonce": foreign.Issue(time.Now()),
		"tampered nonce":         strings.ToUpper(first.nonce),
		"garbage nonce":          "nonce",
	} {
		got := call("DPoP", bound, testdpop.Proof(t, key, http.MethodGet, target, bound, withNonce(nonce)))
		require.Equal(t, string(errmodel.CodeUseDPoPNonce), got.code, name)
		require.NotEmpty(t, got.nonce, name)
	}

	for name, got := range map[string]answer{
		"another key's proof": call("DPoP", bound, testdpop.Proof(t, testdpop.Key(t), http.MethodGet, target, bound, withNonce(first.nonce))),
		"another URL":         call("DPoP", bound, testdpop.Proof(t, key, http.MethodGet, base+"/v1/merchant/payouts", bound, withNonce(first.nonce))),
		"another method":      call("DPoP", bound, testdpop.Proof(t, key, http.MethodPost, target, bound, withNonce(first.nonce))),
		"no proof":            call("DPoP", bound, ""),
		"as a bearer token":   call("Bearer", bound, ""),
	} {
		require.Equal(t, http.StatusUnauthorized, got.status, name)
		require.Equal(t, string(errmodel.CodeSenderProofRequired), got.code, name)
		require.Contains(t, got.challenge, `DPoP error="invalid_dpop_proof"`, name)
	}

	unbound := sign(t, peer, jose.ResourceAccessTokenType, peerIssuer, map[string]any{"sub": "user-1", "client_id": "backend"})
	require.Equal(t, http.StatusOK, call("Bearer", unbound, "").status, "an unbound token is a bearer token")
	got := call("DPoP", unbound, testdpop.Proof(t, key, http.MethodGet, target, unbound, withNonce(first.nonce)))
	require.Equal(t, string(errmodel.CodeSenderProofRequired), got.code, "a DPoP request needs a DPoP-bound token")

	got = call("DPoP", "garbage", testdpop.Proof(t, key, http.MethodGet, target, "garbage", nil))
	require.Equal(t, string(errmodel.CodeInvalidToken), got.code)
	require.Contains(t, got.challenge, `DPoP error="invalid_token"`)

	require.Panics(t, func() { NewVerifier(WithDPoPNonce([]byte("short"))) })
}
