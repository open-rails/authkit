package authhttp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
)

// #284 pre-hijack chain on the REAL browser routes + Postgres: an attacker's
// Discord account carrying the victim's address with verified=false must not
// bind that address to the new account. The address is kept only on the
// provider link, so (a) a password reset for it is a no-op and (b) the real
// owner's later verified Google login registers a distinct account instead of
// hitting account_exists_link_required.
func TestFederatedRegistration_UnverifiedIdPEmailNeverBecomesAccountEmail(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	emailSender := &captureEmailSender{}
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool, embedded.WithEmailSender(emailSender)), WithoutRateLimiter())
	require.NoError(t, err)

	victim := uniqueEmail("victim")
	discordSubject := "discord-" + uniqueSuffix()
	googleSubject := "google-" + uniqueSuffix()

	discord := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/oauth2/token":
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "discord-token", "token_type": "Bearer"})
		case "/api/users/@me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id": discordSubject, "email": victim, "verified": false,
				"username": "mallory", "global_name": "Mallory",
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(discord.Close)
	discordProvider, ok := authprovider.BuiltIn("discord")
	require.True(t, ok)
	discordProvider.ClientID = "discord-client"
	discordProvider.ClientSecret = authprovider.ClientSecret{Value: "discord-secret"}
	discordProvider.AuthorizeURL = discord.URL + "/api/oauth2/authorize"
	discordProvider.TokenURL = discord.URL + "/api/oauth2/token"
	discordProvider.UserInfoURL = discord.URL + "/api/users/@me"

	google := newFakeOIDCIdP(t, "google-client")
	google.SetIdentity(googleSubject, victim, true, map[string]any{"name": "Real Owner"})

	srv.authProvidersByName = map[string]authprovider.Provider{
		"discord": discordProvider,
		"google":  google.Provider("google"),
	}
	srv.resetOIDCManagerForTest()
	h := srv.OIDCHandler()

	var userIDs []string
	t.Cleanup(func() {
		for _, id := range userIDs {
			_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, id)
		}
	})

	// 1. Attacker: Discord login, verified=false.
	frag := completeBrowserLogin(t, h, "discord", google)
	require.NotEmpty(t, frag.Get("access_token"))
	var attackerID string
	var attackerEmail, emailAtProvider *string
	var attackerVerified bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT u.id::text, u.email, u.email_verified, p.email_at_provider
		   FROM profiles.user_providers p JOIN profiles.users u ON u.id = p.user_id
		  WHERE p.issuer = $1 AND p.subject = $2`, discordProvider.Issuer, discordSubject).
		Scan(&attackerID, &attackerEmail, &attackerVerified, &emailAtProvider))
	userIDs = append(userIDs, attackerID)
	require.Nil(t, attackerEmail, "unverified IdP email must not become the account email")
	require.False(t, attackerVerified)
	require.NotNil(t, emailAtProvider)
	require.Equal(t, victim, *emailAtProvider, "the address is kept only on the provider link")

	_, err = srv.svc.GetUserByEmail(ctx, victim)
	require.ErrorIs(t, err, pgx.ErrNoRows, "the address must not be reserved")

	// 2. Password reset for the address is a no-op: nothing is sent.
	w := httptest.NewRecorder()
	body := strings.NewReader(`{"email":"` + victim + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/email/password/reset/request", body)
	r.Header.Set("Content-Type", "application/json")
	srv.APIHandler().ServeHTTP(w, r)
	require.Equal(t, http.StatusAccepted, w.Code, w.Body.String())
	emailSender.mu.Lock()
	require.Empty(t, emailSender.resetToken, "no reset mail may be sent for an address no account owns")
	emailSender.mu.Unlock()

	// 3. Real owner: verified Google login registers a distinct account owning the address.
	frag = completeBrowserLogin(t, h, "google", google)
	require.NotEmpty(t, frag.Get("access_token"))
	owner, err := srv.svc.GetUserByEmail(ctx, victim)
	require.NoError(t, err)
	require.NotNil(t, owner)
	userIDs = append(userIDs, owner.ID)
	require.NotEqual(t, attackerID, owner.ID, "the owner must get their own account, not the attacker's")
	require.True(t, owner.EmailVerified)
	var ownerLinkUser string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT user_id::text FROM profiles.user_providers WHERE issuer = $1 AND subject = $2`,
		google.Server.URL, googleSubject).Scan(&ownerLinkUser))
	require.Equal(t, owner.ID, ownerLinkUser)
}

// The OIDC branch has the same contract: an OIDC IdP asserting
// email_verified=false yields a NULL-email account with the address only on
// the provider link.
func TestOIDCRegistration_UnverifiedEmailStoredOnlyOnProviderLink(t *testing.T) {
	ctx := context.Background()
	pool := newServerTestPool(t)
	srv, err := NewServer(newServerClient(t, newServerTestConfig(), pool), WithoutRateLimiter())
	require.NoError(t, err)

	email := uniqueEmail("oidc-unverified")
	subject := "oidc-" + uniqueSuffix()
	idp := newFakeOIDCIdP(t, "custom-client")
	idp.SetIdentity(subject, email, false, nil)
	srv.authProvidersByName = map[string]authprovider.Provider{"custom": idp.Provider("custom")}
	srv.resetOIDCManagerForTest()

	frag := completeBrowserLogin(t, srv.OIDCHandler(), "custom", idp)
	require.NotEmpty(t, frag.Get("access_token"))

	var userID string
	var accountEmail, emailAtProvider *string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT u.id::text, u.email, p.email_at_provider
		   FROM profiles.user_providers p JOIN profiles.users u ON u.id = p.user_id
		  WHERE p.issuer = $1 AND p.subject = $2`, idp.Server.URL, subject).
		Scan(&userID, &accountEmail, &emailAtProvider))
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, userID) })
	require.Nil(t, accountEmail)
	require.NotNil(t, emailAtProvider)
	require.Equal(t, email, *emailAtProvider)
	_, err = srv.svc.GetUserByEmail(ctx, email)
	require.ErrorIs(t, err, pgx.ErrNoRows)
}

// completeBrowserLogin drives GET /oidc/{provider}/login and the GET callback
// with the state cookie, returning the parsed token fragment. For OIDC-kind
// providers the nonce from the authorize URL is handed to the fake IdP.
func completeBrowserLogin(t *testing.T, h http.Handler, provider string, idp *fakeOIDCIdP) url.Values {
	t.Helper()
	start := httptest.NewRecorder()
	h.ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oidc/"+provider+"/login", nil))
	require.Equal(t, http.StatusFound, start.Code, start.Body.String())
	authURL, err := url.Parse(start.Header().Get("Location"))
	require.NoError(t, err)
	state := authURL.Query().Get("state")
	require.NotEmpty(t, state)
	if nonce := authURL.Query().Get("nonce"); nonce != "" && idp != nil {
		idp.SetNonce(nonce)
	}
	var stateCookie *http.Cookie
	for _, c := range start.Result().Cookies() {
		if c.Name == oauthStateCookie {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie)

	cb := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oidc/"+provider+"/callback?state="+url.QueryEscape(state)+"&code=idp-code", nil)
	req.AddCookie(stateCookie)
	h.ServeHTTP(cb, req)
	require.Equal(t, http.StatusFound, cb.Code, cb.Body.String())
	target, err := url.Parse(cb.Header().Get("Location"))
	require.NoError(t, err)
	frag, err := url.ParseQuery(target.Fragment)
	require.NoError(t, err)
	require.Empty(t, frag.Get("error"), "callback must succeed: %s", target.String())
	return frag
}
