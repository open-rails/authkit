package authhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

type noSNSResolver struct{}

func (noSNSResolver) ResolvePrimaryName(context.Context, string) (string, error) { return "", nil }

// #288/8 over HTTP: /solana/challenge → wallet signs → /solana/login succeeds
// once, on another replica; the identical signed output replayed is refused
// (nonce consumed).
func TestSolanaLoginRejectsReplayedSignature(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.SolanaNetwork = "devnet" // mounts /solana/*
	opts := []coreOpt{withSolanaSNSResolver(noSNSResolver{})}
	srv, err := newServer(newServerClient(t, cfg, pool, opts...), WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	replica, err := newServer(newServerClient(t, cfg, pool, opts...), WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(replica.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	address := siws.PublicKeyToBase58(pub)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN (SELECT user_id FROM user_providers WHERE subject=$1)`, address)
	})

	w := serveJSON(srv, http.MethodPost, "/solana/challenge", `{"address":"`+address+`"}`)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var challenge struct {
		Nonce   string `json:"nonce"`
		Message string `json:"message"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
	require.NotEmpty(t, challenge.Message)

	b64 := base64.StdEncoding.EncodeToString
	body := fmt.Sprintf(`{"output":{"account":{"address":%q,"publicKey":%q},"signature":%q,"signedMessage":%q}}`,
		address, b64(pub), b64(ed25519.Sign(priv, []byte(challenge.Message))), b64([]byte(challenge.Message)))

	first := serveJSON(replica, http.MethodPost, "/solana/login", body)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	require.Contains(t, first.Body.String(), "access_token")

	replay := serveJSON(srv, http.MethodPost, "/solana/login", body)
	require.Equal(t, http.StatusUnauthorized, replay.Code, replay.Body.String())
	require.Contains(t, replay.Body.String(), string(authkit.CodeChallengeExpired))

	var found bool
	require.NoError(t, srv.svc.Postgres().QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ephemeral_kv WHERE key = 'siws:nonce:' || $1)`, challenge.Nonce).Scan(&found))
	require.False(t, found, "the nonce must be consumed by the first login")
}
