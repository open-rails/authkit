package authhttp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-rails/authkit/internal/siws"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// stalledSNSResolver blocks until released, standing in for an unreachable
// SNS proxy.
type stalledSNSResolver struct {
	release chan struct{}
	calls   atomic.Int32
	exited  atomic.Int32
}

func (r *stalledSNSResolver) ResolvePrimaryName(ctx context.Context, _ string) (string, error) {
	r.calls.Add(1)
	defer r.exited.Add(1)
	select {
	case <-r.release:
		return "wallet.sol", nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// SNS resolution never delays a SIWS login and runs once per user however many
// requests trigger it.
func TestSolanaLoginDoesNotWaitOnSNS(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.SolanaNetwork = "devnet"
	sns := &stalledSNSResolver{release: make(chan struct{})}
	srv, err := newServer(newServerClient(t, cfg, pool, withSolanaSNSResolver(sns)), WithoutRateLimiter())
	require.NoError(t, err)
	t.Cleanup(srv.Close)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	address := siws.PublicKeyToBase58(pub)
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN (SELECT user_id FROM user_providers WHERE subject=$1)`, address)
	})
	login := func() {
		w := serveJSON(srv, http.MethodPost, "/solana/challenge", `{"address":"`+address+`"}`)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		var challenge struct {
			Message string `json:"message"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &challenge))
		b64 := base64.StdEncoding.EncodeToString
		body := fmt.Sprintf(`{"output":{"account":{"address":%q,"publicKey":%q},"signature":%q,"signedMessage":%q}}`,
			address, b64(pub), b64(ed25519.Sign(priv, []byte(challenge.Message))), b64([]byte(challenge.Message)))
		w = serveJSON(srv, http.MethodPost, "/solana/login", body)
		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Zero(t, sns.exited.Load(), "login must not wait for the SNS lookup")
	}

	login()
	login()
	require.Eventually(t, func() bool { return sns.calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	close(sns.release)
	require.Eventually(t, func() bool {
		var name *string
		_ = pool.QueryRow(ctx, `SELECT profile->>'sns_primary_name' FROM user_providers WHERE subject=$1`, address).Scan(&name)
		return name != nil && *name == "wallet.sol"
	}, 5*time.Second, 20*time.Millisecond)
	require.EqualValues(t, 1, sns.calls.Load())
}
