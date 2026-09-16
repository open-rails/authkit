//go:build browser

package authhttp

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/password"
	"github.com/stretchr/testify/require"
)

// Run with -tags browser and AUTHKIT_PLAYWRIGHT_MODULE pointing at an installed
// @playwright/test module. Each run launches an isolated headless browser.
func TestCookieLoginBrowserTwoSites(t *testing.T) {
	ctx := context.Background()
	pg := testdb.ScratchPostgres(t)
	mux := http.NewServeMux()
	victim := httptest.NewTLSServer(mux)
	defer victim.Close()
	victimURL := strings.Replace(victim.URL, "127.0.0.1", "localhost", 1)
	cfg := newServerTestConfig()
	cfg.Frontend = embedded.FrontendConfig{BaseURL: victimURL}
	core := newServerClient(t, cfg, pg.Pool, withRedis(testdb.ScratchRedis(t)))
	srv, err := newServer(core, WithoutRateLimiter())
	require.NoError(t, err)
	defer srv.Close()
	accounts := map[string]string{"browser-victim@example.test": "Victim-password-12345", "browser-attacker@example.test": "=Attack-password-12345"}
	var attackerID string
	for email, plain := range accounts {
		user, err := core.CreateUser(ctx, email, strings.Split(email, "@")[0])
		require.NoError(t, err)
		hash, err := password.HashArgon2id(plain)
		require.NoError(t, err)
		require.NoError(t, core.UpsertPasswordHash(ctx, user.ID, hash, "argon2id"))
		if strings.Contains(email, "attacker") {
			attackerID = user.ID
		}
	}
	mounted, err := MountHandler(srv, MountOptions{RefreshCookie: true})
	require.NoError(t, err)
	mux.Handle("/api/", mounted)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<!doctype html><title>Application</title>")
	})
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		enctype := r.URL.Query().Get("encoding")
		if enctype != "text/plain" && enctype != "application/x-www-form-urlencoded" && enctype != "multipart/form-data" {
			http.Error(w, "encoding", 400)
			return
		}
		fmt.Fprintf(w, `<!doctype html><form method="post" action="%s/api/v1/password/login" enctype="%s"><input name="%s" value="%s"><button>Submit</button></form>`, html.EscapeString(victimURL), html.EscapeString(enctype), html.EscapeString(`{"identifier":"browser-attacker@example.test","password":"`), html.EscapeString(`Attack-password-12345"}`))
	}))
	defer attacker.Close()
	browserCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	cmd := exec.CommandContext(browserCtx, "node", "testdata/cookie-origin-browser.cjs")
	cmd.Env = append(os.Environ(), "AUTHKIT_BROWSER_VICTIM_URL="+victimURL, "AUTHKIT_BROWSER_ATTACKER_URL="+attacker.URL)
	output, err := cmd.CombinedOutput()
	require.NoError(t, err, string(output))
	t.Log(strings.TrimSpace(string(output)))
	var sessions int
	require.NoError(t, pg.Pool.QueryRow(ctx, `SELECT count(*) FROM profiles.refresh_sessions WHERE user_id=$1`, attackerID).Scan(&sessions))
	require.Zero(t, sessions, "cross-site submissions cannot create even an unused attacker session")
}
