package engine

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/config"
	"github.com/open-rails/authkit/internal/errmodel"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
)

// noSNSResolver resolves no wallet name, so no test reaches the SNS network.
type noSNSResolver struct{}

func (noSNSResolver) ResolvePrimaryName(context.Context, string) (string, error) { return "", nil }

// siwsOutput is a wallet's Sign-In with Solana output: message signed with priv.
func siwsOutput(pub ed25519.PublicKey, priv ed25519.PrivateKey, message string) string {
	b64 := base64.StdEncoding.EncodeToString
	return fmt.Sprintf(`{"output":{"account":{"address":%q,"publicKey":%q},"signature":%q,"signedMessage":%q}}`,
		siws.PublicKeyToBase58(pub), b64(pub), b64(ed25519.Sign(priv, []byte(message))), b64([]byte(message)))
}

// #288/8 over HTTP: /solana/challenge → wallet signs → /solana/login succeeds
// once, on another replica; the identical signed output replayed is refused
// (nonce consumed).
func TestSolanaLoginRejectsReplayedSignature(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := testConfig()
	cfg.SolanaNetwork = "devnet" // mounts /solana/*
	f := newAccountFlow(t, pool, cfg, config.Deps{})
	replica := newAccountFlow(t, pool, cfg, config.Deps{})
	f.engine.solanaSNSResolver, replica.engine.solanaSNSResolver = noSNSResolver{}, noSNSResolver{}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	address := siws.PublicKeyToBase58(pub)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN (SELECT user_id FROM user_providers WHERE subject=$1)`, address)
	})

	w := f.expect(http.StatusOK, f.post("/solana/challenge", map[string]any{"address": address}))
	var challenge struct {
		Nonce   string `json:"nonce"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal([]byte(w.raw), &challenge))
	require.NotEmpty(t, challenge.Message)
	body := json.RawMessage(siwsOutput(pub, priv, challenge.Message))

	first := replica.expect(http.StatusOK, replica.post("/solana/login", body))
	require.Contains(t, first.raw, "access_token")

	replay := f.expect(http.StatusUnauthorized, f.post("/solana/login", body))
	require.Contains(t, replay.raw, string(errmodel.CodeChallengeNotFound))

	var found bool
	require.NoError(t, pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ephemeral_kv WHERE key = 'siws:nonce:' || $1)`, challenge.Nonce).Scan(&found))
	require.False(t, found, "the nonce must be consumed by the first login")
}

// A deleted account's wallet recovers it only through the Sign-In with Solana
// ceremony, which yields a single-use confirmation and never a session. The
// other ceremonies are apitest's
// TestAccountRecoveryUsesExistingCredentialAndMFACeremonies; this one stays
// here because only the engine can stub SNS resolution.
func TestSolanaRecoveryUsesTheWalletCeremony(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig()
	cfg.SolanaNetwork = "devnet"
	f := newAccountFlow(t, pg.Pool, cfg, config.Deps{})
	f.engine.solanaSNSResolver = noSNSResolver{}
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
		return json.RawMessage(siwsOutput(pub, priv, body.Message))
	}
	f.expect(200, f.post("/solana/login", walletProof()))
	var walletUser string
	require.NoError(t, pg.Pool.QueryRow(t.Context(), `SELECT user_id::text FROM user_providers WHERE subject=$1`, address).Scan(&walletUser))
	results, err := f.engine.DeleteUsers(t.Context(), iam.UserIdentity(walletUser), []string{walletUser})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)

	wallet := walletProof()
	confirmed := f.expect(200, f.post("/solana/login", wallet))
	f.expect(401, f.post("/solana/login", wallet))
	require.Equal(t, httpapi.AuthAccountRecoveryRequired, confirmed.Status)
	token := confirmed.Recovery.Token
	require.NotEmpty(t, token)
	require.NotContains(t, confirmed.raw, "access_token")
	require.NotContains(t, confirmed.raw, "refresh_token")
	f.expect(204, f.post("/account/recovery/confirm", map[string]any{"token": token}))
	f.expect(401, f.post("/account/recovery/confirm", map[string]any{"token": token}))
}

// A wallet-only account steps up with its wallet (A1): a signature over a
// challenge bound to the session that asked for it, once, before it expires.
// A sign-in challenge never steps up a session. The account can then delete
// itself, which it could only do right after signing in before.
func TestSolanaStepUp(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := testConfig()
	cfg.SolanaNetwork = "devnet"
	f := newAccountFlow(t, pg.Pool, cfg, config.Deps{})
	f.engine.solanaSNSResolver = noSNSResolver{}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, stranger, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	address := siws.PublicKeyToBase58(pub)
	var challenge struct {
		Nonce   string `json:"nonce"`
		Message string `json:"message"`
	}
	read := func(r flowResponse) {
		t.Helper()
		require.NoError(t, json.Unmarshal([]byte(r.raw), &challenge))
		require.NotEmpty(t, challenge.Message)
	}
	signed := func(key ed25519.PrivateKey) json.RawMessage {
		return json.RawMessage(siwsOutput(pub, key, challenge.Message))
	}
	// stale is a sign-in by the wallet, older than the fresh-auth window.
	stale := func() string {
		t.Helper()
		read(f.expect(200, f.post("/solana/challenge", map[string]any{"address": address})))
		claims, err := f.engine.Verify(t.Context(), f.expect(200, f.post("/solana/login", signed(priv))).tokens().AccessToken)
		require.NoError(t, err)
		_, err = pg.Pool.Exec(t.Context(), `UPDATE refresh_sessions SET last_authenticated_at = now() - interval '1 day' WHERE id = $1::uuid`, claims.SessionID)
		require.NoError(t, err)
		token, err := f.engine.MintAccessToken(t.Context(), claims.UserID, iam.AccessTokenOptions{SessionID: claims.SessionID})
		require.NoError(t, err)
		return token.Value
	}
	session := stale()
	begin := func(token string) {
		t.Helper()
		read(f.expect(200, f.request(http.MethodPost, "/me/step-up/solana/challenge", token, nil)))
	}
	stepUp := func(token string, body json.RawMessage) flowResponse {
		return f.request(http.MethodPost, "/me/step-up/solana", token, body)
	}
	rejected := func(r flowResponse, code errmodel.Code) {
		t.Helper()
		f.expect(http.StatusUnauthorized, r)
		require.Equal(t, string(code), r.Error.Code, r.raw)
	}

	denied := f.expect(http.StatusUnauthorized, f.request(http.MethodDelete, "/me", session, nil))
	require.Equal(t, "step_up_required", denied.Error.Code, denied.raw)
	var offer struct {
		Error struct {
			Metadata authflow.StepUpRequired `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(denied.raw), &offer))
	require.Equal(t, []string{"solana"}, offer.Error.Metadata.StepUpMethods, "the wallet is the account's only step-up")

	read(f.expect(200, f.post("/solana/challenge", map[string]any{"address": address})))
	rejected(stepUp(session, signed(priv)), errmodel.CodeChallengeNotFound)
	other := stale()
	begin(session)
	rejected(stepUp(other, signed(priv)), errmodel.CodeChallengeMismatch)
	begin(session)
	rejected(stepUp(session, signed(stranger)), errmodel.CodeInvalidSignature)
	begin(session)
	_, err = pg.Pool.Exec(t.Context(), `UPDATE ephemeral_kv SET expires_at = now() - interval '1 second' WHERE key = 'siws:step-up:' || $1`, challenge.Nonce)
	require.NoError(t, err)
	rejected(stepUp(session, signed(priv)), errmodel.CodeChallengeNotFound)

	begin(session)
	proof := signed(priv)
	fresh := f.expect(200, stepUp(session, proof)).tokens()
	claims, err := f.engine.Verify(t.Context(), fresh.AccessToken)
	require.NoError(t, err)
	require.Contains(t, claims.AMR, "swk")
	rejected(stepUp(session, proof), errmodel.CodeChallengeNotFound)
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me", fresh.AccessToken, nil))
}
