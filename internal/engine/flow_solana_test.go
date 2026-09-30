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
	"github.com/open-rails/authkit/internal/errmodel"
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
	deps := Deps{SolanaSNSResolver: noSNSResolver{}}
	f := newAccountFlow(t, pool, cfg, deps)
	replica := newAccountFlow(t, pool, cfg, deps)

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
	f := newAccountFlow(t, pg.Pool, cfg, Deps{SolanaSNSResolver: noSNSResolver{}})
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
	results, err := f.engine.DeleteUsers(t.Context(), iam.UserActor(walletUser), []string{walletUser})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)

	wallet := walletProof()
	confirmed := f.expect(409, f.post("/solana/login", wallet))
	f.expect(401, f.post("/solana/login", wallet))
	var answer struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				Recovery authflow.AccountRecoveryConfirmation `json:"recovery"`
			} `json:"metadata"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal([]byte(confirmed.raw), &answer))
	require.Equal(t, string(errmodel.CodeAccountRecoveryRequired), answer.Error.Code)
	token := answer.Error.Metadata.Recovery.Token
	require.NotEmpty(t, token)
	require.NotContains(t, confirmed.raw, "access_token")
	require.NotContains(t, confirmed.raw, "refresh_token")
	f.expect(204, f.post("/account/recovery/confirm", map[string]any{"token": token}))
	f.expect(401, f.post("/account/recovery/confirm", map[string]any{"token": token}))
}
