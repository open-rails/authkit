package authhttp

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// An account issuer that never started against the shared database blocks
// deletion. The wire stays internal_error; startup and the 500 log name why.
func TestUserDeleteWithUnboundAccountIssuerLogsCause(t *testing.T) {
	logs := &lockedBuffer{}
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	const peer = "https://peer.example"
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	cfg.Token.AccountIssuers = []string{cfg.Token.Issuer, peer}
	core := newServerClient(t, cfg, pg.Pool)
	t.Cleanup(core.Close)
	require.Contains(t, logs.String(), "account deletion fails until these account issuers start")
	require.Contains(t, logs.String(), peer)

	srv, err := newTestService(core, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	handler := srv.apiHandler()
	user, err := core.CreateUser(t.Context(), "unbound-peer@example.test", "unboundpeer")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("Unbound-peer-password-1"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, core.UpsertPasswordHash(t.Context(), user.ID, string(hash), "bcrypt"))

	r := httptest.NewRequest(http.MethodPost, "/password/login", strings.NewReader(`{"identifier":"unbound-peer@example.test","password":"Unbound-peer-password-1"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var tokens authkit.TokenSet
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokens))

	r = httptest.NewRequest(http.MethodDelete, "/user", nil)
	r.Header.Set("Authorization", "Bearer "+tokens.AccessToken)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	require.Equal(t, http.StatusInternalServerError, w.Code, w.Body.String())
	require.Contains(t, w.Body.String(), `"code":"internal_error"`)
	require.NotContains(t, w.Body.String(), peer, "deployment topology stays off the wire")
	require.Contains(t, logs.String(), `failed_to_delete: authkit: account issuer \"`+peer+`\" must compose its River fleet before account deletion`)
}
