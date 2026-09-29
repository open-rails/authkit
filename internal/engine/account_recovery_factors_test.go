package engine

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/passkeytest"
	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

func accountRecoveryToken(t *testing.T, raw string) string {
	t.Helper()
	var body struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				Recovery authflow.AccountRecoveryConfirmation `json:"recovery"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &body))
	require.Equal(t, string(errmodel.CodeAccountRecoveryRequired), body.Error.Code)
	require.NotEmpty(t, body.Error.Metadata.Recovery.Token)
	require.NotContains(t, raw, "access_token")
	require.NotContains(t, raw, "refresh_token")
	return body.Error.Metadata.Recovery.Token
}

func TestAccountRecoveryUsesExistingCredentialAndMFACeremonies(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin = true
	cfg.Passkeys = PasskeyConfig{RPID: "app.example", Origins: []string{"https://app.example"}}
	cfg.SolanaNetwork = "devnet"
	f := newAccountFlow(t, pg.Pool, cfg, withSolanaSNSResolver(noSNSResolver{}))
	remove := func(id string) {
		t.Helper()
		results, err := fixtureBackend(f.service.Backend()).DeleteUsers(t.Context(), iam.UserActor(id), []string{id})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
	}
	confirm := func(raw string) {
		t.Helper()
		token := accountRecoveryToken(t, raw)
		f.expect(204, f.post("/account/recovery/confirm", map[string]any{"token": token}))
		f.expect(401, f.post("/account/recovery/confirm", map[string]any{"token": token}))
	}
	user, err := fixtureBackend(f.service.Backend()).createUser(t.Context(), uniqueEmail("recover-mfa"), "recmfa"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(t.Context(), user.ID, "Correct-recovery-password-1"))
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(t.Context(), user.ID))
	backups, err := fixtureBackend(f.service.Backend()).enableFactor(t.Context(), user.ID, "email", nil, authflow.AllowAdditionalFactors)
	require.NoError(t, err)
	beforeDelete := f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-recovery-password-1"}))
	beforeCode := lastSent(f.email, testoutbox.LoginCode).Code
	remove(user.ID)
	f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": beforeDelete.Error.Metadata.Challenge, "code": beforeCode}))
	challenge := f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-recovery-password-1"}))
	require.Equal(t, "2fa_required", challenge.Error.Code)
	require.NotContains(t, challenge.raw, "recovery")
	f.expect(401, f.post("/account/recovery/confirm", map[string]any{"token": challenge.Error.Metadata.Challenge}))
	f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": challenge.Error.Metadata.Challenge, "code": "wrong"}))
	challenge = f.expect(403, f.post("/password/login", map[string]any{"identifier": *user.Email, "password": "Correct-recovery-password-1"}))
	code := lastSent(f.email, testoutbox.LoginCode).Code
	second := map[string]any{"user_id": user.ID, "challenge": challenge.Error.Metadata.Challenge, "code": code}
	confirmed := f.expect(409, f.post("/2fa/verify", second))
	f.expect(401, f.post("/2fa/verify", second))
	// The Redis leg deliberately shares the same store: issuer binding must
	// reject another site's confirmation without consuming the original.
	otherConfig := cfg
	otherConfig.Token.Issuer += "/other"
	other := newServerClient(t, otherConfig, pg.Pool)
	t.Cleanup(other.Close)
	require.Error(t, other.ConfirmAccountRecovery(t.Context(), accountRecoveryToken(t, confirmed.raw)))
	confirm(confirmed.raw)
	remove(user.ID)
	f.expect(202, f.post("/passwordless/start", map[string]any{"identifier": *user.Email, "mode": "code"}))
	challenge = f.expect(403, f.post("/passwordless/confirm", map[string]any{"identifier": *user.Email, "code": sentCode(t, f.email, testoutbox.Verification)}))
	require.Equal(t, "backup_code", challenge.Error.Metadata.Method, "one mailbox cannot supply both factors")
	confirmed = f.expect(409, f.post("/2fa/verify", map[string]any{"user_id": user.ID, "challenge": challenge.Error.Metadata.Challenge, "code": backups[0], "backup_code": true}))
	confirm(confirmed.raw)

	// The existing UV passkey assertion is a complete proof; it still produces
	// only a recovery confirmation while the account is deleted.
	keyUser, err := fixtureBackend(f.service.Backend()).createUser(t.Context(), uniqueEmail("recover-key"), "reckey"+uniqueSuffix())
	require.NoError(t, err)
	require.NoError(t, fixtureBackend(f.service.Backend()).markEmailVerified(t.Context(), keyUser.ID))
	authn := passkeytest.New(t, "https://app.example")
	creation, err := f.service.Backend().BeginPasskeyRegistration(t.Context(), keyUser.ID)
	require.NoError(t, err)
	_, err = f.service.Backend().FinishPasskeyRegistration(t.Context(), keyUser.ID, authn.Register(t, creation))
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
		id, _, err := f.service.Backend().GetProviderLinkByIssuer(t.Context(), provider.Issuer(), identity.Subject)
		require.NoError(t, err)
		remove(id)
		next, fragment := f.providerLogin(provider, identity, "", true)
		f.expect(302, next)
		require.Equal(t, string(errmodel.CodeAccountRecoveryRequired), fragment.Get("error"))
		require.Empty(t, fragment.Get("access_token"))
		var recovery authflow.AccountRecoveryConfirmation
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
	require.NoError(t, fixtureBackend(f.service.Backend()).pg.QueryRow(t.Context(), `SELECT user_id::text FROM user_providers WHERE subject=$1`, address).Scan(&walletUser))
	remove(walletUser)
	wallet := walletProof()
	confirmed = f.expect(409, f.post("/solana/login", wallet))
	f.expect(401, f.post("/solana/login", wallet))
	confirm(confirmed.raw)
}
