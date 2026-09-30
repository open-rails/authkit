//go:build browser

package apitest_test

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

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// A real browser signs in with the refresh cookie on one site; another site's
// form posts in every HTML encoding are refused and leave the cookie alone.
// Run with -tags browser and AUTHKIT_PLAYWRIGHT_MODULE pointing at an
// installed @playwright/test module (testdata/README.md). Each run launches an
// isolated headless browser.
func TestCookieLoginBrowserTwoSites(t *testing.T) {
	ctx := t.Context()
	mux := http.NewServeMux()
	victim := httptest.NewTLSServer(mux)
	defer victim.Close()
	victimURL := strings.Replace(victim.URL, "127.0.0.1", "localhost", 1)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Frontend.BaseURL = victimURL
		c.HTTP = &authkit.HTTPConfig{DirectPeerIP: true, RefreshCookie: true}
	}))
	accounts := map[string]string{"browser-victim@example.test": "Victim-password-12345", "browser-attacker@example.test": "=Attack-password-12345"}
	var attackerID string
	for email, password := range accounts {
		u, err := auth.CreateUser(ctx, iam.NewUser{Email: email, Username: strings.Split(email, "@")[0], Password: password, EmailVerified: true})
		require.NoError(t, err)
		if strings.Contains(email, "attacker") {
			attackerID = u.ID
		}
	}
	mux.Handle("/api/", auth.Handler())
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
	sessions, err := auth.Sessions(ctx, attackerID)
	require.NoError(t, err)
	require.Empty(t, sessions, "cross-site submissions cannot create even an unused attacker session")
	events, err := auth.ListSessionEvents(ctx, attackerID, iam.SessionEventQuery{})
	require.NoError(t, err)
	require.Empty(t, events.Items, "no attacker session ever existed")
}
