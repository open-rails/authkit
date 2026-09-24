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
	require.NoError(t, core.MarkEmailVerified(t.Context(), user.ID))
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
	remove()
	bannedProof := proof()
	admin, err := core.CreateUser(t.Context(), "recovery-admin@example.test", "recoveryadmin")
	require.NoError(t, err)
	_, err = core.EnsureRootGroup(t.Context())
	require.NoError(t, err)
	require.NoError(t, core.OperatorAssignGroupRole(t.Context(), authkit.RootGroup(), authkit.UserSubject(admin.ID), "owner"))
	require.NoError(t, core.BanUser(t.Context(), user.ID, nil, nil, admin.ID))
	require.Equal(t, http.StatusUnauthorized, confirm(bannedProof).Code)
	require.Equal(t, http.StatusUnauthorized, call("/password/login", loginBody).Code)
	restored, err := core.OperatorRestoreUsers(t.Context(), []string{user.ID})
	require.NoError(t, err)
	require.NoError(t, restored[0].Err)
	require.Equal(t, http.StatusUnauthorized, call("/password/login", loginBody).Code, "restoring an account never removes a ban")
	require.NoError(t, core.UnbanUser(t.Context(), user.ID))
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
	_, err = core.Postgres().Exec(t.Context(), `WITH expired AS (UPDATE account_deletions SET deleted_at=statement_timestamp()-interval '720 hours',purge_at=statement_timestamp() WHERE user_id=$1::uuid AND state='deleted' RETURNING user_id,deleted_at) UPDATE users u SET deleted_at=e.deleted_at FROM expired e WHERE u.id=e.user_id`, user.ID)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, confirm(current).Code, "moving the fixture deadline also invalidates its credential version")
	require.Equal(t, http.StatusConflict, call("/password/login", loginBody).Code)
}
