package authhttp

import (
	"encoding/json"
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

func TestAccountRecoveryPasswordConfirmationBoundary(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.TwoFactor.Mode = embedded.TwoFactorDisabled
	core := newServerClient(t, cfg, pg.Pool)
	t.Cleanup(core.Close)
	srv, err := newTestService(core, workflowHTTPConfig())
	require.NoError(t, err)
	t.Cleanup(srv.Close)
	handler := srv.apiHandler()
	user, err := core.CreateUser(t.Context(), "recoverable@example.test", "recoverable")
	require.NoError(t, err)
	hash, err := bcrypt.GenerateFromPassword([]byte("Fresh-recovery-password-1"), bcrypt.MinCost)
	require.NoError(t, err)
	require.NoError(t, core.UpsertPasswordHash(t.Context(), user.ID, string(hash), "bcrypt"))
	call := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	loginBody := `{"identifier":"recoverable@example.test","password":"Fresh-recovery-password-1"}`
	login := call("/password/login", loginBody)
	require.Equal(t, http.StatusOK, login.Code, login.Body.String())
	var old authkit.TokenSet
	require.NoError(t, json.Unmarshal(login.Body.Bytes(), &old))
	remove := func() {
		t.Helper()
		results, err := core.SoftDeleteUsers(t.Context(), []string{user.ID})
		require.NoError(t, err)
		require.NoError(t, results[0].Err)
	}
	proof := func() string {
		t.Helper()
		w := call("/password/login", loginBody)
		require.Equal(t, http.StatusConflict, w.Code, w.Body.String())
		require.NotContains(t, w.Body.String(), "access_token")
		require.NotContains(t, w.Body.String(), "refresh_token")
		var body struct {
			Error struct {
				Code     string `json:"code"`
				Metadata struct {
					Recovery embedded.AccountRecoveryConfirmation `json:"recovery"`
				} `json:"metadata"`
			} `json:"error"`
		}
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
		require.Equal(t, string(authkit.CodeAccountRecoveryRequired), body.Error.Code)
		require.NotEmpty(t, body.Error.Metadata.Recovery.Token)
		return body.Error.Metadata.Recovery.Token
	}
	confirm := func(token string) *httptest.ResponseRecorder {
		return call("/account/recovery/confirm", `{"token":"`+token+`"}`)
	}
	remove()
	wrong := call("/password/login", `{"identifier":"recoverable@example.test","password":"wrong"}`)
	require.Equal(t, http.StatusUnauthorized, wrong.Code)
	token := proof()
	_, err = srv.Verifier().VerifyClaims(t.Context(), token)
	require.Error(t, err, "recovery proof cannot authenticate as a normal access token")
	deleted, err := core.AdminGetUser(t.Context(), user.ID)
	require.NoError(t, err)
	require.NotNil(t, deleted.DeletedAt, "ordinary login never restores an account")
	// Concurrent confirmations have one winner, even with the same valid proof.
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for range 2 {
		wg.Go(func() { statuses <- confirm(token).Code })
	}
	wg.Wait()
	close(statuses)
	winners := 0
	for status := range statuses {
		if status == http.StatusNoContent {
			winners++
		} else {
			require.Equal(t, http.StatusUnauthorized, status)
		}
	}
	require.Equal(t, 1, winners)
	require.Equal(t, http.StatusUnauthorized, confirm(token).Code)
	require.Equal(t, http.StatusUnauthorized, call("/token", `{"grant_type":"refresh_token","refresh_token":"`+old.RefreshToken+`"}`).Code)
	require.Equal(t, http.StatusOK, call("/password/login", loginBody).Code)
	// An operator restore and subsequent deletion cannot reuse an earlier proof.
	remove()
	stale := proof()
	results, err := core.OperatorRestoreUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, results[0].Err)
	remove()
	require.NotEqual(t, http.StatusNoContent, confirm(stale).Code)
	current := proof()
	_, err = core.Postgres().Exec(t.Context(), `UPDATE users SET credential_version=credential_version+1 WHERE id=$1::uuid`, user.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, confirm(current).Code)
	current = proof()
	_, err = core.Postgres().Exec(t.Context(), `UPDATE account_deletions SET purge_at=statement_timestamp() WHERE user_id=$1::uuid AND state='deleted'`, user.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusConflict, confirm(current).Code)
	require.Equal(t, http.StatusConflict, call("/password/login", loginBody).Code)
}
