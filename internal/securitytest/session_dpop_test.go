package securitytest

import (
	"context"
	"crypto/ecdsa"
	"net/http"
	"testing"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/testdpop"
)

// signInProof is a DPoP proof for a request carrying no token: a sign-in or
// a refresh (RFC 9449 §5).
func signInProof(t *testing.T, key *ecdsa.PrivateKey, method, path string) http.Header {
	t.Helper()
	proof := testdpop.Proof(t, key, method, issuer+apiPrefix+path, "", func(tok *jwt.Token) {
		delete(tok.Claims.(jwt.MapClaims), "ath")
	})
	return http.Header{"DPoP": {proof}}
}

// boundCall calls path with a DPoP-bound access token and a fresh proof of
// key.
func (h *host) boundCall(method, path, token string, key *ecdsa.PrivateKey) response {
	h.t.Helper()
	return h.do(request{method: method, path: path, header: http.Header{
		"Authorization": {"DPoP " + token},
		"DPoP":          {testdpop.Proof(h.t, key, method, issuer+apiPrefix+path, token, nil)},
	}})
}

// TestSecuritySignInDPoP: SignIn.DPoP optional, the default. A sign-in that
// proves a DPoP key binds its session for good (RFC 9449 §5): its access
// tokens carry cnf.jkt and need a proof of the key (never accepted as
// Bearer, §7.2), and each refresh proves the same key. A sign-in without
// one gets bearer tokens.
func TestSecuritySignInDPoP(t *testing.T) {
	h := newHost(t)
	a := h.newAccount("dpopsession")
	key, other := testdpop.Key(t), testdpop.Key(t)

	resp := h.do(request{method: http.MethodPost, path: "/password/login", body: map[string]string{"identifier": a.email, "password": password},
		header: signInProof(t, key, http.MethodPost, "/password/login")})
	bound := session(t, resp)
	_, claims := splitToken(t, bound.AccessToken)
	require.Equal(t, map[string]any{"jkt": testdpop.Thumbprint(t, key)}, claims["cnf"])

	require.Equal(t, http.StatusUnauthorized, h.get("/me", bound.AccessToken).status, "a bound token as Bearer")
	require.Equal(t, http.StatusOK, h.boundCall(http.MethodGet, "/me", bound.AccessToken, key).status)
	require.Equal(t, http.StatusUnauthorized, h.boundCall(http.MethodGet, "/me", bound.AccessToken, other).status, "another key's proof")

	refresh := func(proof http.Header) response {
		return h.do(request{method: http.MethodPost, path: "/token", body: map[string]string{"grant_type": "refresh_token", "refresh_token": bound.RefreshToken}, header: proof})
	}
	require.Equal(t, http.StatusUnauthorized, refresh(nil).status, "a bound session's refresh without a proof")
	require.Equal(t, http.StatusUnauthorized, refresh(signInProof(t, other, http.MethodPost, "/token")).status, "another key")
	rotated := session(t, refresh(signInProof(t, key, http.MethodPost, "/token")))
	_, claims = splitToken(t, rotated.AccessToken)
	require.Equal(t, map[string]any{"jkt": testdpop.Thumbprint(t, key)}, claims["cnf"], "bound for good")
	require.Equal(t, http.StatusOK, h.boundCall(http.MethodGet, "/me", rotated.AccessToken, key).status)

	replayed := signInProof(t, key, http.MethodPost, "/password/login")
	ok := h.do(request{method: http.MethodPost, path: "/password/login", body: map[string]string{"identifier": a.email, "password": password}, header: replayed})
	require.Equal(t, http.StatusOK, ok.status, ok.String())
	again := h.do(request{method: http.MethodPost, path: "/password/login", body: map[string]string{"identifier": a.email, "password": password}, header: replayed})
	require.Equal(t, http.StatusUnauthorized, again.status, "a replayed sign-in proof")

	plain := h.login(h.newAccount("dpopbearer"))
	_, claims = splitToken(t, plain.AccessToken)
	require.Nil(t, claims["cnf"], "no proof, bearer tokens")
	require.Equal(t, http.StatusOK, h.get("/me", plain.AccessToken).status)
	require.Equal(t, http.StatusOK, h.refresh(plain.RefreshToken).status)

	var caps struct {
		DPoP string `json:"dpop"`
	}
	h.get("/capabilities", "").json(t, &caps)
	require.Equal(t, "optional", caps.DPoP)
}

// TestSecuritySignInDPoPRequired: SignIn.DPoP required refuses a sign-in
// and a refresh without a proof. It covers only this deployment's sign-ins:
// an API key is still a bearer credential.
func TestSecuritySignInDPoPRequired(t *testing.T) {
	ctx := context.Background()
	h := newHost(t, authtest.WithConfig(withBillingHost), authtest.WithConfig(func(c *authkit.Config) { c.SignIn.DPoP = authkit.DPoPRequired }))
	a := h.newAccount("dpoprequired")
	key := testdpop.Key(t)
	body := map[string]string{"identifier": a.email, "password": password}

	refused := h.post("/password/login", body, "")
	require.Equal(t, http.StatusUnauthorized, refused.status, refused.String())
	require.Equal(t, "sender_proof_required", refused.errorCode())

	bound := session(t, h.do(request{method: http.MethodPost, path: "/password/login", body: body, header: signInProof(t, key, http.MethodPost, "/password/login")}))
	require.Equal(t, http.StatusOK, h.boundCall(http.MethodGet, "/me", bound.AccessToken, key).status)

	var caps struct {
		DPoP string `json:"dpop"`
	}
	h.get("/capabilities", "").json(t, &caps)
	require.Equal(t, "required", caps.DPoP)

	_, secret, err := createKey(h.auth, ctx, iam.SystemIdentity(), iam.RootGroup(), iam.NewAPIKey{Name: "service", Role: roleIn(t, h.auth, iam.RootGroup(), "billing")})
	require.NoError(t, err)
	v, err := h.auth.Authenticator().Authenticate(bearerRequest(secret)())
	require.NoError(t, err, "an API key is never covered")
	require.Equal(t, "api_key", string(v.Identity().Credential.Kind))
}
