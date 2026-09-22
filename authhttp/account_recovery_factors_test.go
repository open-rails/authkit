package authhttp

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

func accountRecoveryToken(t *testing.T, raw string) string {
	t.Helper()
	var body struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				Recovery embedded.AccountRecoveryConfirmation `json:"recovery"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &body))
	require.Equal(t, string(authkit.CodeAccountRecoveryRequired), body.Error.Code)
	require.NotEmpty(t, body.Error.Metadata.Recovery.Token)
	require.NotContains(t, raw, "access_token")
	require.NotContains(t, raw, "refresh_token")
	return body.Error.Metadata.Recovery.Token
}

func TestAccountRecoveryUsesExistingCredentialAndMFACeremonies(t *testing.T) {
	forEachStore(t, func(t *testing.T, store ephemeralStore) {
		pg := testdb.ScratchPostgres(t)
		cfg := newServerTestConfig()
		cfg.Registration.PasswordlessLogin = true
		cfg.Passkeys = embedded.PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
		cfg.SolanaNetwork = "devnet"
		f := newAccountFlow(t, pg.Pool, store, cfg, withSolanaSNSResolver(noSNSResolver{}))
		remove := func(id string) {
			t.Helper()
			results, err := f.service.svc.SoftDeleteUsers(t.Context(), []string{id})
			require.NoError(t, err)
			require.NoError(t, results[0].Err)
		}
		confirm := func(raw string) {
			t.Helper()
			token := accountRecoveryToken(t, raw)
			f.expect(204, f.post("/account/recovery/confirm", map[string]any{"token": token}))
			f.expect(401, f.post("/account/recovery/confirm", map[string]any{"token": token}))
		}
		user, err := f.service.svc.CreateUser(t.Context(), uniqueEmail("recover-mfa"), "recmfa"+uniqueSuffix())
		require.NoError(t, err)
		require.NoError(t, f.service.svc.AdminSetPassword(t.Context(), user.ID, "Correct-recovery-password-1"))
		require.NoError(t, f.service.svc.MarkEmailVerified(t.Context(), user.ID))
		backups, err := fixtureBackend(f.service.svc).Enable2FA(t.Context(), user.ID, "email", nil, embedded.AllowAdditionalFactors)
		require.NoError(t, err)
		beforeDelete := f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-recovery-password-1"}))
		beforeCode := f.email.lastLoginCode()
		remove(user.ID)
		f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": beforeDelete.Error.Metadata.Challenge, "code": beforeCode}))
		challenge := f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-recovery-password-1"}))
		require.Equal(t, "2fa_required", challenge.Error.Code)
		require.NotContains(t, challenge.raw, "recovery")
		f.expect(401, f.post("/account/recovery/confirm", map[string]any{"token": challenge.Error.Metadata.Challenge}))
		f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": challenge.Error.Metadata.Challenge, "code": "wrong"}))
		challenge = f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-recovery-password-1"}))
		code := f.email.lastLoginCode()
		second := map[string]any{"user_id": user.ID, "challenge": challenge.Error.Metadata.Challenge, "code": code}
		confirmed := f.expect(409, f.post("/2fa/verify", second))
		f.expect(401, f.post("/2fa/verify", second))
		// The Redis leg deliberately shares the same store: issuer binding must
		// reject another site's confirmation without consuming the original.
		otherConfig := cfg
		otherConfig.Token.Issuer += "/other"
		other := newServerClient(t, otherConfig, pg.Pool, store.engineOpts()...)
		t.Cleanup(other.Close)
		require.Error(t, other.ConfirmAccountRecovery(t.Context(), accountRecoveryToken(t, confirmed.raw)))
		confirm(confirmed.raw)
		remove(user.ID)
		f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": *user.Email, "mode": "code"}))
		challenge = f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": *user.Email, "code": f.email.verificationCode(t)}))
		require.Equal(t, "backup_code", challenge.Error.Metadata.Method, "one mailbox cannot supply both factors")
		confirmed = f.expect(409, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": challenge.Error.Metadata.Challenge, "code": backups[0], "backup_code": true}))
		confirm(confirmed.raw)

		// The existing UV passkey assertion is a complete proof; it still produces
		// only a recovery confirmation while the account is deleted.
		keyUser, err := f.service.svc.CreateUser(t.Context(), uniqueEmail("recover-key"), "reckey"+uniqueSuffix())
		require.NoError(t, err)
		authn := passkeytest.New(t, "https://app.example")
		creation, err := f.service.svc.BeginPasskeyRegistration(t.Context(), keyUser.ID)
		require.NoError(t, err)
		_, err = f.service.svc.FinishPasskeyRegistration(t.Context(), keyUser.ID, authn.Register(t, creation))
		require.NoError(t, err)
		remove(keyUser.ID)
		start := f.expect(200, f.post("/passkeys/login/begin", map[string]any{}))
		var assertion protocol.CredentialAssertion
		require.NoError(t, json.Unmarshal([]byte(start.raw), &assertion))
		proof := json.RawMessage(authn.Assert(t, &assertion, 1))
		confirmed = f.expect(409, f.post("/passkeys/login/finish", proof))
		f.expect(401, f.post("/passkeys/login/finish", proof))
		confirm(confirmed.raw)

		for _, oidc := range []bool{true, false} {
			provider := newSecurityTestProvider(t, f.service, oidc)
			f.mount()
			verified := true
			identity := providerTestIdentity{Subject: "recovery-" + uniqueSuffix(), Email: uniqueEmail("recover-idp"), Verified: &verified}
			first, _ := f.providerLogin(provider, identity, "", false)
			f.expect(200, first)
			id, _, err := f.service.svc.GetProviderLinkByIssuer(t.Context(), provider.Issuer(), identity.Subject)
			require.NoError(t, err)
			remove(id)
			next, fragment := f.providerLogin(provider, identity, "", true)
			f.expect(302, next)
			require.Equal(t, string(authkit.CodeAccountRecoveryRequired), fragment.Get("error"))
			require.Empty(t, fragment.Get("access_token"))
			var recovery embedded.AccountRecoveryConfirmation
			require.NoError(t, json.Unmarshal([]byte(fragment.Get("recovery")), &recovery))
			require.NotEmpty(t, recovery.Token)
			f.expect(204, f.post("/account/recovery/confirm", map[string]any{"token": recovery.Token}))
		}

		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		address := siws.PublicKeyToBase58(pub)
		walletProof := func() json.RawMessage {
			t.Helper()
			start := f.expect(200, f.post("/solana/challenge", map[string]any{"address": address}))
			var body struct {
				Message string `json:"message"`
			}
			require.NoError(t, json.Unmarshal([]byte(start.raw), &body))
			b64 := base64.StdEncoding.EncodeToString
			return json.RawMessage(fmt.Sprintf(`{"output":{"account":{"address":%q,"publicKey":%q},"signature":%q,"signedMessage":%q}}`, address, b64(pub), b64(ed25519.Sign(priv, []byte(body.Message))), b64([]byte(body.Message))))
		}
		f.expect(200, f.post("/solana/login", walletProof()))
		var walletUser string
		require.NoError(t, f.service.svc.Postgres().QueryRow(t.Context(), `SELECT user_id::text FROM user_providers WHERE subject=$1`, address).Scan(&walletUser))
		remove(walletUser)
		wallet := walletProof()
		confirmed = f.expect(409, f.post("/solana/login", wallet))
		f.expect(401, f.post("/solana/login", wallet))
		confirm(confirmed.raw)
	})
}
