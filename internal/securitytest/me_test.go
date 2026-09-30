package securitytest

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
)

// TestSecurityRemovedSelfRoutesAreGone: the caller's account lives under /me;
// with every capability on, none of the routes it replaced answers.
func TestSecurityRemovedSelfRoutesAreGone(t *testing.T) {
	h := newHost(t, append(withEveryRoute(t), withHTTP(generousLimits))...)
	token := h.login(h.newAccount("gone")).AccessToken
	for _, req := range []request{
		{method: http.MethodGet, path: "/user/2fa"},
		{method: http.MethodPost, path: "/user/2fa", body: map[string]string{"method": "totp"}},
		{method: http.MethodPost, path: "/user/password", body: map[string]string{"new_password": "Removed-route-passphrase-1"}},
		{method: http.MethodPatch, path: "/user/username", body: map[string]string{"username": unique("gone")}},
		{method: http.MethodGet, path: "/user/sessions"},
		{method: http.MethodDelete, path: "/user"},
		{method: http.MethodPost, path: "/step-up/password", body: map[string]string{"password": password}},
		{method: http.MethodGet, path: "/passkeys"},
		{method: http.MethodPost, path: "/passkeys/register/begin"},
		{method: http.MethodDelete, path: "/device-keys/00000000-0000-0000-0000-000000000000"},
		{method: http.MethodPost, path: "/solana/link", body: map[string]any{}},
	} {
		req.token = token
		resp := h.do(req)
		require.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, resp.status, "%s %s: %s", req.method, req.path, resp)
	}
}

// TestSecurityVerifyRequestIsNeverAContactChange: a signed-in POST
// /verify/request cannot start a change of the caller's address; only PUT
// /me/email|phone, behind a recent sign-in, can.
func TestSecurityVerifyRequestIsNeverAContactChange(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	a := h.newAccount("notachange")
	token := h.login(a).AccessToken
	moved := unique("moved") + "@security.test"
	resp := h.post("/verify/request", map[string]string{"identifier": moved}, token)
	require.Equal(t, http.StatusAccepted, resp.status, resp.String())
	require.Empty(t, h.mail.Messages(iam.MessageVerification, moved), "a code went to an address no account asked for")
	u, err := h.auth.User(t.Context(), iam.UserByID(a.id))
	require.NoError(t, err)
	require.Equal(t, a.email, *u.Email)
}

// TestSecurityOwnSessionsOnly: DELETE /me/sessions/{id} ends only the
// caller's sessions; naming another account's session changes nothing.
func TestSecurityOwnSessionsOnly(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	victim := h.login(h.newAccount("sessvictim"))
	_, claims := splitToken(t, victim.AccessToken)
	sid, _ := claims["sid"].(string)
	require.NotEmpty(t, sid)
	attacker := h.login(h.newAccount("sessattacker")).AccessToken
	resp := h.do(request{method: http.MethodDelete, path: "/me/sessions/" + sid, token: attacker})
	require.Equal(t, http.StatusNoContent, resp.status, resp.String())
	require.Equal(t, http.StatusOK, h.refresh(victim.RefreshToken).status, "another account's session ended")
}
