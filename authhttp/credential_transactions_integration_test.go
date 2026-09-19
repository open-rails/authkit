package authhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestCredentialTransactionsResetGrantsExpireOnCredentialChanges(t *testing.T) {
	for _, change := range []string{"password_change", "contact_change", "other_reset"} {
		t.Run(change, func(t *testing.T) {
			ctx := context.Background()
			srv, sender, _ := passwordlessTestServer(t, true)
			pool := srv.svc.Postgres()
			email := uniqueEmail("audit-old-reset")
			u, err := srv.svc.CreateUser(ctx, email, "auditreset"+uniqueSuffix())
			require.NoError(t, err)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, u.ID) })
			require.NoError(t, srv.svc.RequestPasswordReset(ctx, email, time.Hour, nil, nil))
			stale := sender.passwordResetToken(t)
			switch change {
			case "password_change":
				require.NoError(t, srv.svc.ChangePassword(ctx, u.ID, "", "Defender-password-12345", nil))
			case "contact_change":
				newEmail := uniqueEmail("audit-new-email")
				require.NoError(t, srv.svc.RequestEmailChange(ctx, u.ID, newEmail))
				require.NoError(t, srv.svc.ConfirmEmailChange(ctx, u.ID, newEmail, sender.verificationCode(t), nil))
			case "other_reset":
				require.NoError(t, srv.svc.RequestPasswordReset(ctx, email, time.Hour, nil, nil))
				current := sender.passwordResetToken(t)
				require.NotEqual(t, stale, current)
				_, err = srv.svc.ConfirmPasswordReset(ctx, current, "Defender-password-12345")
				require.NoError(t, err)
			}
			uid, resetErr := srv.svc.ConfirmPasswordReset(ctx, stale, "Attacker-password-12345")
			if resetErr == nil {
				t.Logf("stale grant changed password after %s for user %s; new password check=%v", change, uid, srv.svc.CheckUserPassword(ctx, u.ID, "Attacker-password-12345"))
			}
			require.Error(t, resetErr, "credential change must invalidate previously issued recovery grants")
		})
	}
}

func TestCredentialTransactionsPasswordMutationRollsBackOnFailure(t *testing.T) {
	for _, stage := range []struct{ name, table, columns string }{
		{"password", "user_passwords", "password_hash"},
		{"version", "users", "credential_version"},
		{"revocation", "refresh_sessions", "revoked_at"},
	} {
		for _, method := range []string{"change", "fresh", "admin", "reset"} {
			t.Run(stage.name+"/"+method, func(t *testing.T) {
				ctx := context.Background()
				srv, sender, _ := passwordlessTestServer(t, true)
				pool := srv.svc.Postgres()
				uid := mustPasswordUser(t, srv, "atomic-password")
				user, err := srv.svc.AdminGetUser(ctx, uid)
				require.NoError(t, err)
				require.NoError(t, srv.svc.RequestPasswordReset(ctx, *user.Email, time.Hour, nil, nil))
				reset := sender.passwordResetToken(t)
				_, refresh, _, err := srv.svc.IssueRefreshSession(ctx, uid, "atomic", nil)
				require.NoError(t, err)
				var before, after int64
				require.NoError(t, pool.QueryRow(ctx, `SELECT credential_version FROM users WHERE id=$1`, uid).Scan(&before))
				_, err = pool.Exec(ctx, `CREATE FUNCTION credential_failure() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'injected credential failure'; END $$; CREATE TRIGGER credential_failure BEFORE UPDATE OF `+stage.columns+` ON `+stage.table+` FOR EACH ROW EXECUTE FUNCTION credential_failure()`)
				require.NoError(t, err)
				t.Cleanup(func() {
					_, _ = pool.Exec(ctx, `DROP TRIGGER IF EXISTS credential_failure ON `+stage.table+`; DROP FUNCTION IF EXISTS credential_failure()`)
				})
				var changeErr error
				switch method {
				case "change":
					changeErr = srv.svc.ChangePassword(ctx, uid, "Correct-password-12345", "Replacement-password-12345", nil)
				case "fresh":
					changeErr = srv.svc.SetPasswordAfterFreshAuth(ctx, uid, "Replacement-password-12345", nil)
				case "admin":
					changeErr = srv.svc.AdminSetPassword(ctx, uid, "Replacement-password-12345")
				case "reset":
					_, changeErr = srv.svc.ConfirmPasswordReset(ctx, reset, "Replacement-password-12345")
				}
				require.ErrorContains(t, changeErr, "injected credential failure")
				require.NoError(t, pool.QueryRow(ctx, `SELECT credential_version FROM users WHERE id=$1`, uid).Scan(&after))
				require.Equal(t, before, after, "failed operation cannot invalidate grants")
				require.NoError(t, srv.svc.CheckUserPassword(ctx, uid, "Correct-password-12345"))
				require.Error(t, srv.svc.CheckUserPassword(ctx, uid, "Replacement-password-12345"))
				_, _, _, err = srv.svc.ExchangeRefreshToken(ctx, refresh, "atomic", nil)
				require.NoError(t, err, "the rollback retains the old session")
			})
		}
	}
}

func TestCredentialTransactionsProviderLinkGrantDoesNotOutliveSessionRevocation(t *testing.T) {
	for _, oidc := range []bool{true, false} {
		t.Run(fmt.Sprintf("oidc_%v", oidc), func(t *testing.T) {
			ctx := context.Background()
			srv, _, _ := passwordlessTestServer(t, true)
			provider := newSecurityTestProvider(t, srv, oidc)
			uid := mustPasswordUser(t, srv, "audit-link-revoke")
			_, _, access, _, _, err := srv.svc.IssueAuthenticatedSession(ctx, uid, "audit", nil, []string{"pwd"}, nil)
			require.NoError(t, err)
			start := serveAuthJSON(srv, http.MethodPost, "/oidc/"+provider.Name()+"/link/start", "{}", access)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			require.NoError(t, srv.svc.RevokeIssuerSessions(ctx, uid, nil))
			identity := providerTestIdentity{Subject: "audit-revoked-link-" + uniqueSuffix()}
			callback := completeSecurityProviderCallback(t, srv, provider, start, identity)
			owner, _, linkErr := srv.svc.GetProviderLinkByIssuer(ctx, provider.Issuer(), identity.Subject)
			t.Logf("callback=%d linked owner=%s lookup=%v", callback.Code, owner, linkErr)
			require.Error(t, linkErr, "revoked initiating session must not be able to add a provider and obtain a new session")
		})
	}
}

func TestCredentialTransactionsProviderLinkBrowserRetainsSession(t *testing.T) {
	for _, oidc := range []bool{true, false} {
		t.Run(fmt.Sprintf("oidc_%v", oidc), func(t *testing.T) {
			ctx := context.Background()
			srv, _, _ := passwordlessTestServer(t, true)
			provider := newSecurityTestProvider(t, srv, oidc)
			uid := mustPasswordUser(t, srv, "link-browser")
			sid, _, access, _, _, err := srv.svc.IssueAuthenticatedSession(ctx, uid, "link", nil, []string{"pwd"}, nil)
			require.NoError(t, err)
			start := serveAuthJSON(srv, http.MethodPost, "/oidc/"+provider.Name()+"/link/start", "{}", access)
			require.Equal(t, http.StatusOK, start.Code)
			var startBody struct {
				AuthURL string `json:"auth_url"`
			}
			require.NoError(t, json.Unmarshal(start.Body.Bytes(), &startBody))
			authURL, err := url.Parse(startBody.AuthURL)
			require.NoError(t, err)
			raw, err := json.Marshal(providerTestIdentity{Subject: "browser-link-" + uniqueSuffix(), Nonce: authURL.Query().Get("nonce")})
			require.NoError(t, err)
			query := url.Values{"state": {authURL.Query().Get("state")}, "code": {base64.RawURLEncoding.EncodeToString(raw)}}
			request := httptest.NewRequest(http.MethodGet, "/oidc/"+provider.Name()+"/callback?"+query.Encode(), nil)
			for _, cookie := range start.Result().Cookies() {
				request.AddCookie(cookie)
			}
			callback := httptest.NewRecorder()
			srv.oidcHandler().ServeHTTP(callback, request)
			require.Equal(t, http.StatusFound, callback.Code, callback.Body.String())
			location, err := url.Parse(callback.Header().Get("Location"))
			require.NoError(t, err)
			fragment, err := url.ParseQuery(location.Fragment)
			require.NoError(t, err)
			require.Equal(t, "link", fragment.Get("flow"))
			require.Equal(t, "success", fragment.Get("result"))
			require.Empty(t, fragment.Get("access_token"))
			require.Empty(t, fragment.Get("refresh_token"))
			for _, cookie := range callback.Result().Cookies() {
				require.Negative(t, cookie.MaxAge, "callback may only clear consumed state cookies")
			}
			sessions, err := srv.svc.ListUserSessions(ctx, uid)
			require.NoError(t, err)
			require.Len(t, sessions, 1)
			require.Equal(t, sid, sessions[0].ID)
		})
	}
}
