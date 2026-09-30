package apitest_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/testidp"
)

// recoveryToken is the confirmation token of a sign-in that proved a deleted
// account's credentials: account_recovery_required, carrying no session.
func recoveryToken(t *testing.T, res response) string {
	t.Helper()
	answer := expectAnswer(t, res, http.StatusConflict)
	require.Equal(t, "account_recovery_required", answer.Error.Code)
	require.NotEmpty(t, answer.Error.Metadata.Recovery.Token)
	require.NotContains(t, res.String(), "access_token")
	require.NotContains(t, res.String(), "refresh_token")
	return answer.Error.Metadata.Recovery.Token
}

// A deleted account is recovered only through the ceremonies that sign it in
// (password with its second factor, passwordless with a backup code, a
// passkey, a provider), and each yields a single-use confirmation, never a
// session; another issuer sharing the store cannot confirm it. The wallet
// ceremony is engine's TestSolanaRecoveryUsesTheWalletCeremony, since SNS
// resolution cannot be stubbed through authkit.Deps.
func TestAccountRecoveryUsesExistingCredentialAndMFACeremonies(t *testing.T) {
	oidc, oauth2 := testidp.New(t), testidp.New(t)
	auth, outbox := authtest.New(t, withProviders(oidc.OIDC("oidc"), oauth2.OAuth2("oauth2")), authtest.WithConfig(func(c *authkit.Config) {
		c.Registration.PasswordlessLogin = true
		c.Passkeys = authkit.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
		c.Frontend.BaseURL = "https://app.example"
	}))
	a := newAPI(t, auth)
	ctx := t.Context()
	remove := func(id string) {
		t.Helper()
		results, err := auth.DeleteUsers(ctx, iam.UserActor(id), []string{id})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
	}
	confirmRecovery := func(token string) response {
		return a.post("/account/recovery/confirm", "", map[string]any{"token": token})
	}
	confirm := func(res response) {
		t.Helper()
		token := recoveryToken(t, res)
		require.Equal(t, http.StatusNoContent, confirmRecovery(token).status)
		require.Equal(t, http.StatusUnauthorized, confirmRecovery(token).status)
	}

	// Password and the email second factor.
	u := authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, u).AccessToken
	res := a.post("/user/2fa", token, map[string]string{"method": "email"})
	require.Equal(t, http.StatusAccepted, res.status, res.String())
	res = a.post("/user/2fa", token, map[string]string{"method": "email", "code": outbox.Last(t, iam.MessageVerification, u.Email).Code})
	require.Equal(t, http.StatusOK, res.status, res.String())
	var enrolled struct {
		BackupCodes []string `json:"backup_codes"`
	}
	res.decode(t, &enrolled)
	require.NotEmpty(t, enrolled.BackupCodes)
	login := func() authAnswer {
		t.Helper()
		answer := expectAnswer(t, a.post("/password/login", "", map[string]string{"identifier": u.Email, "password": u.Password}), http.StatusForbidden)
		require.Equal(t, "2fa_required", answer.Error.Code)
		return answer
	}
	verify2FA := func(challenge authAnswer, code string) response {
		return a.post("/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": challenge.Error.Metadata.Challenge, "code": code})
	}
	beforeDelete := login()
	beforeCode := outbox.Last(t, iam.MessageLoginCode, u.Email).Code
	remove(u.ID)
	require.Equal(t, http.StatusUnauthorized, verify2FA(beforeDelete, beforeCode).status, "a challenge issued before the deletion is void")
	challenge := login()
	require.NotContains(t, challenge.raw, "recovery")
	require.Equal(t, http.StatusUnauthorized, confirmRecovery(challenge.Error.Metadata.Challenge).status)
	require.Equal(t, http.StatusUnauthorized, verify2FA(challenge, "wrong").status)
	challenge = login()
	code := outbox.Last(t, iam.MessageLoginCode, u.Email).Code
	confirmed := verify2FA(challenge, code)
	require.Equal(t, http.StatusUnauthorized, verify2FA(challenge, code).status)
	// Another issuer on the same store refuses the confirmation without
	// consuming it.
	other := authtest.Replica(t, auth, authtest.WithConfig(func(c *authkit.Config) { c.Token.Issuer += "/other" }))
	res = newAPI(t, other).post("/account/recovery/confirm", "", map[string]any{"token": recoveryToken(t, confirmed)})
	require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	confirm(confirmed)

	// Passwordless: one mailbox cannot supply both factors, so the second is
	// a backup code.
	remove(u.ID)
	res = a.post("/passwordless/start", "", map[string]any{"identifier": u.Email, "mode": "code"})
	require.Equal(t, http.StatusAccepted, res.status, res.String())
	challenge = expectAnswer(t, a.post("/passwordless/confirm", "", map[string]any{"identifier": u.Email,
		"code": outbox.Last(t, iam.MessageVerification, u.Email).Code}), http.StatusForbidden)
	require.Equal(t, "backup_code", challenge.Error.Metadata.Method, "one mailbox cannot supply both factors")
	confirm(a.post("/2fa/verify", "", map[string]any{"user_id": u.ID, "challenge": challenge.Error.Metadata.Challenge,
		"code": enrolled.BackupCodes[0], "backup_code": true}))

	// A user-verifying passkey assertion is a complete proof; it too yields
	// only a confirmation while the account is deleted.
	keyUser := authtest.NewUser(t, auth)
	keyToken := authtest.SignIn(t, auth, keyUser).AccessToken
	authn := passkeytest.New(t, "https://app.example")
	res = a.post("/passkeys/register/begin", keyToken, map[string]any{})
	require.Equal(t, http.StatusOK, res.status, res.String())
	var creation protocol.CredentialCreation
	res.decode(t, &creation)
	res = a.post("/passkeys/register/finish", keyToken, authn.Register(t, &creation))
	require.Equal(t, http.StatusCreated, res.status, res.String())
	remove(keyUser.ID)
	res = a.post("/passkeys/login/begin", "", map[string]any{})
	require.Equal(t, http.StatusOK, res.status, res.String())
	var assertion protocol.CredentialAssertion
	res.decode(t, &assertion)
	proof := authn.Assert(t, &assertion, 1)
	confirmed = a.post("/passkeys/login/finish", "", proof)
	res = a.post("/passkeys/login/finish", "", proof)
	require.Equal(t, http.StatusUnauthorized, res.status, res.String())
	confirm(confirmed)

	// A provider sign-in lands on the page with a confirmation and no tokens.
	for name, idp := range map[string]*testidp.IdP{"oidc": oidc, "oauth2": oauth2} {
		id := testidp.Identity{Subject: "recovery-" + name, Email: "recover-" + name + "@example.com", EmailVerified: true}
		first := expectAnswer(t, providerSignIn(t, a, idp, name, id, ""), http.StatusOK)
		remove(first.User.ID)
		fragment := providerBrowserSignIn(t, a, idp, name, id)
		require.Equal(t, "account_recovery_required", fragment.Get("error"))
		require.Empty(t, fragment.Get("access_token"))
		var recovery struct {
			Token string `json:"token"`
		}
		require.NoError(t, json.Unmarshal([]byte(fragment.Get("recovery")), &recovery))
		require.NotEmpty(t, recovery.Token)
		require.Equal(t, http.StatusNoContent, confirmRecovery(recovery.Token).status)
	}
}
