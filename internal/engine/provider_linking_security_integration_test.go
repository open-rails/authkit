package engine

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/authflow"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/internal/testoutbox"
	"github.com/stretchr/testify/require"
)

func completeSecurityProviderCallback(t *testing.T, srv *httpapi.Service, cfg authprovider.Provider, start *httptest.ResponseRecorder, identity providerTestIdentity) *httptest.ResponseRecorder {
	t.Helper()
	rawURL := start.Header().Get("Location")
	if rawURL == "" {
		var body struct {
			AuthURL string `json:"auth_url"`
		}
		require.NoError(t, json.Unmarshal(start.Body.Bytes(), &body))
		rawURL = body.AuthURL
	}
	authURL, err := url.Parse(rawURL)
	require.NoError(t, err)
	identity.Nonce = authURL.Query().Get("nonce")
	raw, err := json.Marshal(identity)
	require.NoError(t, err)
	query := url.Values{"state": {authURL.Query().Get("state")}, "code": {base64.RawURLEncoding.EncodeToString(raw)}, "format": {"json"}}
	request := httptest.NewRequest(http.MethodGet, "/oidc/"+cfg.Name()+"/callback?"+query.Encode(), nil)
	for _, cookie := range start.Result().Cookies() {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	oidcHandler(srv).ServeHTTP(response, request)
	return response
}

func securityProviderLogin(t *testing.T, srv *httpapi.Service, cfg authprovider.Provider, identity providerTestIdentity, invite string) *httptest.ResponseRecorder {
	t.Helper()
	start := httptest.NewRecorder()
	body, err := json.Marshal(map[string]string{"account_invite_token": invite})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/oidc/"+cfg.Name()+"/login", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	oidcHandler(srv).ServeHTTP(start, req)
	require.Equal(t, http.StatusOK, start.Code, start.Body.String())
	return completeSecurityProviderCallback(t, srv, cfg, start, identity)
}

func TestProviderLinkRequiresFreshAuthAndExplicitUnlink(t *testing.T) {
	for _, kind := range []string{"oidc", "oauth2"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			pool := testdb.Pool(t)
			settings := newServerTestConfig()
			settings.SolanaNetwork = "devnet"
			srv, err := newServer(newServerClient(t, settings, pool), WithoutRateLimiter())
			require.NoError(t, err)
			cfg := newSecurityTestProvider(t, srv, kind == "oidc")
			userID, stale := stalePasswordUserToken(t, srv, pool, "link-guard", "Correct-password-12345")
			denied := serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", stale)
			require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
			require.Contains(t, denied.Body.String(), "step_up_required")
			require.Empty(t, denied.Result().Cookies())
			denied = serveAuthJSON(srv, http.MethodPost, "/solana/link", "{}", stale)
			require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
			require.Contains(t, denied.Body.String(), "step_up_required")
			stepUp := serveAuthJSON(srv, http.MethodPost, "/step-up/password", `{"password":"Correct-password-12345"}`, stale)
			require.Equal(t, http.StatusOK, stepUp.Code, stepUp.Body.String())
			var fresh nestedTokenBody
			require.NoError(t, json.Unmarshal(stepUp.Body.Bytes(), &fresh))
			start := serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", fresh.AccessToken)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			old := providerTestIdentity{Subject: "original-" + uniqueSuffix()}
			callback := completeSecurityProviderCallback(t, srv, cfg, start, old)
			require.Equal(t, http.StatusNoContent, callback.Code, callback.Body.String())
			start = serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", fresh.AccessToken)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			callback = completeSecurityProviderCallback(t, srv, cfg, start, providerTestIdentity{Subject: "replacement-" + uniqueSuffix()})
			require.Equal(t, http.StatusConflict, callback.Code, callback.Body.String())
			require.Contains(t, callback.Body.String(), "provider_change_requires_unlink")
			owner, _, err := srv.Backend().GetProviderLinkByIssuer(ctx, cfg.Issuer(), old.Subject)
			require.NoError(t, err)
			require.Equal(t, userID, owner)
			unlinked := serveAuthJSON(srv, http.MethodDelete, "/user/providers/"+cfg.Name(), "{}", fresh.AccessToken)
			require.Equal(t, http.StatusNoContent, unlinked.Code, unlinked.Body.String())
			start = serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", fresh.AccessToken)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			callback = completeSecurityProviderCallback(t, srv, cfg, start, providerTestIdentity{Subject: "replacement-" + uniqueSuffix()})
			require.Equal(t, http.StatusNoContent, callback.Code, callback.Body.String())
		})
	}
}

func TestFederatedUnverifiedEmailDoesNotReserveAccountAddress(t *testing.T) {
	for _, kind := range []string{"oidc", "oauth2"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			pool := testdb.Pool(t)
			sender := &testoutbox.Outbox{}
			srv, err := newServer(newServerClient(t, newServerTestConfig(), pool, withEmailSender(sender.Email())), WithoutRateLimiter())
			require.NoError(t, err)
			cfg := newSecurityTestProvider(t, srv, kind == "oidc")
			email := uniqueEmail("unverified-provider")
			identity := providerTestIdentity{Subject: "attacker-" + uniqueSuffix(), Email: email}
			callback := securityProviderLogin(t, srv, cfg, identity, "")
			require.Equal(t, http.StatusOK, callback.Code, callback.Body.String())
			var first struct {
				User struct {
					ID    string  `json:"id"`
					Email *string `json:"email"`
				} `json:"user"`
			}
			require.NoError(t, json.Unmarshal(callback.Body.Bytes(), &first))
			require.Nil(t, first.User.Email)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, first.User.ID) })
			user, err := fixtureBackend(srv.Backend()).getUserByID(ctx, first.User.ID)
			require.NoError(t, err)
			require.Nil(t, user.Email)
			owner, providerEmail, err := srv.Backend().GetProviderLinkByIssuer(ctx, cfg.Issuer(), identity.Subject)
			require.NoError(t, err)
			require.Equal(t, first.User.ID, owner)
			require.NotNil(t, providerEmail)
			require.Equal(t, email, *providerEmail)
			require.NoError(t, srv.Backend().RequestPasswordReset(ctx, email, time.Hour, nil, nil))
			require.Empty(t, lastSent(sender, testoutbox.PasswordReset).Link)
			verified := true
			callback = securityProviderLogin(t, srv, cfg, providerTestIdentity{Subject: "owner-" + uniqueSuffix(), Email: email, Verified: &verified}, "")
			require.Equal(t, http.StatusOK, callback.Code, callback.Body.String())
			var second struct {
				User struct {
					ID    string  `json:"id"`
					Email *string `json:"email"`
				} `json:"user"`
			}
			require.NoError(t, json.Unmarshal(callback.Body.Bytes(), &second))
			require.NotEqual(t, first.User.ID, second.User.ID)
			require.NotNil(t, second.User.Email)
			require.Equal(t, email, *second.User.Email)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, second.User.ID) })
			user, err = fixtureBackend(srv.Backend()).getUserByID(ctx, second.User.ID)
			require.NoError(t, err)
			require.True(t, user.EmailVerified)
		})
	}
}

func TestFederatedEmailLessRegistrationRequiresAndConsumesInvite(t *testing.T) {
	for _, kind := range []string{"oidc", "oauth2"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			pool := testdb.Pool(t)
			settings := newServerTestConfig()
			settings.Registration.NativeUserMode = iam.RegistrationModeInviteOnly
			srv, err := newServer(newServerClient(t, settings, pool), WithoutRateLimiter())
			require.NoError(t, err)
			cfg := newSecurityTestProvider(t, srv, kind == "oidc")
			identity := providerTestIdentity{Subject: "invite-user-" + uniqueSuffix(), Email: uniqueEmail("unverified-invite")}
			denied := securityProviderLogin(t, srv, cfg, identity, "")
			require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
			inviter, invite := createAccountInvite(t, srv, pool, uniqueEmail("invite-destination"))
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, inviter) })
			allowed := securityProviderLogin(t, srv, cfg, identity, invite.Code)
			require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())
			var body struct {
				User struct {
					ID    string  `json:"id"`
					Email *string `json:"email"`
				} `json:"user"`
			}
			require.NoError(t, json.Unmarshal(allowed.Body.Bytes(), &body))
			require.Nil(t, body.User.Email)
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM users WHERE id=$1::uuid`, body.User.ID) })
			requireAccountInviteConsumed(t, pool, invite.ID, body.User.ID)
			identity.Subject = "another-" + uniqueSuffix()
			denied = securityProviderLogin(t, srv, cfg, identity, invite.Code)
			require.Equal(t, http.StatusNotFound, denied.Code, denied.Body.String())
		})
	}
}

func TestProviderLinkRequiresMFAWhenEnrolled(t *testing.T) {
	ctx := context.Background()
	pool := testdb.Pool(t)
	settings := newServerTestConfig()
	settings.TwoFactor.TOTPSecretKey = []byte("0123456789abcdef")
	settings.SolanaNetwork = "devnet"
	srv, err := newServer(newServerClient(t, settings, pool), WithoutRateLimiter())
	require.NoError(t, err)
	cfg := newSecurityTestProvider(t, srv, false)
	userID, _ := stalePasswordUserToken(t, srv, pool, "provider-mfa", "Correct-password-12345")
	sid, _, _, err := fixtureBackend(srv.Backend()).issueRefreshSessionWithAuthMethods(ctx, userID, "test", nil, []string{"pwd"})
	require.NoError(t, err)
	secret, _, err := fixtureBackend(srv.Backend()).startTOTPEnrollment(ctx, userID)
	require.NoError(t, err)
	_, err = fixtureBackend(srv.Backend()).enableTOTPFactor(ctx, totpEnrollment{UserID: userID, Code: testTOTPCode(t, secret, time.Now().Unix()/30), MakeDefault: true, Mode: authflow.AllowAdditionalFactors})
	require.NoError(t, err)
	token, _, err := fixtureBackend(srv.Backend()).mintTestAccessToken(ctx, userID, map[string]any{"sid": sid})
	require.NoError(t, err)
	for _, path := range []string{"/oidc/" + cfg.Name() + "/link/start", "/solana/link"} {
		denied := serveAuthJSON(srv, http.MethodPost, path, "{}", token)
		require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
		require.Contains(t, denied.Body.String(), "step_up_required")
		require.Contains(t, denied.Body.String(), `"mfa_required":true`)
	}
	require.NoError(t, srv.Backend().MarkSessionAuthenticatedWithMethods(ctx, userID, sid, []string{"pwd", "otp", "mfa"}))
	token, _, err = fixtureBackend(srv.Backend()).mintTestAccessToken(ctx, userID, map[string]any{"sid": sid})
	require.NoError(t, err)
	allowed := serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", token)
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())
}

// OIDC and OAuth2 run the same continuation workflow, including the actual
// token endpoint, browser state cookie, new account transaction and MFA finish.
func TestProviderAuthenticationWorkflow(t *testing.T) {
	pg := testdb.ScratchPostgres(t)
	cfg := newServerTestConfig()
	cfg.Registration.PasswordlessLogin, cfg.Registration.PasswordlessAutoRegistration = true, true
	cfg.TwoFactor.Mode = iam.TwoFactorRequired
	f := newAccountFlow(t, pg.Pool, cfg)
	for _, oidc := range []bool{true, false} {
		t.Run(fmt.Sprint("oidc=", oidc), func(t *testing.T) {
			f.t = t
			provider := newSecurityTestProvider(t, f.service, oidc)
			f.mount() // providers are configured before the public mount is built
			verified := true
			identity := providerTestIdentity{Subject: "provider-" + uniqueSuffix(), Email: uniqueEmail("provider-flow"), Verified: &verified}
			first, fragment := f.providerLogin(provider, identity, "", true)
			f.expect(302, first)
			require.Equal(t, "2fa_enrollment_required", fragment.Get("error"))
			require.Equal(t, "/checkout", fragment.Get("return_to"))
			require.Equal(t, provider.Name(), fragment.Get("provider"))
			grant := fragment.Get("enrollment_token")
			require.NotEmpty(t, grant)
			require.Empty(t, fragment.Get("access_token"))
			require.Empty(t, fragment.Get("refresh_token"))
			require.ElementsMatch(t, []any{"oauth"}, unverifiedAccessClaims(t, grant)["amr"])
			var methods []string
			require.NoError(t, json.Unmarshal([]byte(fragment.Get("allowed_methods")), &methods))
			require.Contains(t, methods, "sms")
			phone := uniquePhone()
			f.expect(202, f.request("POST", "/user/2fa", grant, map[string]any{"method": "sms", "phone_number": phone}))
			enrolled := f.expect(200, f.request("POST", "/user/2fa", grant, map[string]any{"method": "sms", "phone_number": phone, "code": sentCode(t, f.sms, testoutbox.Verification)}))
			f.session(enrolled.Tokens, "oauth", "sms", "otp", "mfa")
			next, _ := f.providerLogin(provider, identity, "", false)
			f.expect(403, next)
			require.Equal(t, "2fa_required", next.Error.Code)
			require.Equal(t, "sms", next.Error.Metadata.Method)
			finished := f.expect(200, f.post("/2fa/verify", map[string]any{"user_id": next.Error.Metadata.UserID, "challenge": next.Error.Metadata.Challenge, "code": lastSent(f.sms, testoutbox.LoginCode).Code}))
			f.session(finished.TokenSet, "oauth", "sms", "otp", "mfa")
			require.Equal(t, provider.Name(), unverifiedAccessClaims(t, finished.AccessToken)["provider"])
			// A known provider identity never creates a second account or re-enrolls.
			uid, _, err := f.service.Backend().GetProviderLinkByIssuer(t.Context(), provider.Issuer(), identity.Subject)
			require.NoError(t, err)
			require.Equal(t, next.Error.Metadata.UserID, uid)
			// Hold completion after source validation, then unlink concurrently.
			// The source row must remain locked until the session is committed.
			require.NoError(t, fixtureBackend(f.service.Backend()).adminSetPassword(t.Context(), uid, "Provider-backup-password-123"))
			next, _ = f.providerLogin(provider, identity, "", false)
			f.expect(403, next)
			body := map[string]any{"user_id": uid, "challenge": next.Error.Metadata.Challenge, "code": lastSent(f.sms, testoutbox.LoginCode).Code}
			unlink := func(ctx context.Context) error {
				removed, err := f.service.Backend().UnlinkProviderUnlessLast(ctx, uid, provider.Name())
				if err != nil {
					return err
				}
				if !removed {
					return fmt.Errorf("provider unlink refused")
				}
				return nil
			}
			completed := f.completeWhileRevoking(uid, func() flowResponse { return f.post("/2fa/verify", body) }, unlink)
			f.expect(200, completed)
			f.session(completed.TokenSet, "oauth", "sms", "otp", "mfa")
			// Deleting and recreating the same issuer/subject cannot revive a grant
			// that belonged to the previous immutable provider-link row.
			require.NoError(t, fixtureBackend(f.service.Backend()).LinkProvider(t.Context(), uid, iam.ProviderLink{Issuer: provider.Issuer(), Provider: provider.Name(), Subject: identity.Subject}))
			stale, _ := f.providerLogin(provider, identity, "", false)
			f.expect(403, stale)
			code := lastSent(f.sms, testoutbox.LoginCode).Code
			require.NoError(t, unlink(t.Context()))
			require.NoError(t, fixtureBackend(f.service.Backend()).LinkProvider(t.Context(), uid, iam.ProviderLink{Issuer: provider.Issuer(), Provider: provider.Name(), Subject: identity.Subject}))
			f.expect(401, f.post("/2fa/verify", map[string]any{"user_id": uid, "challenge": stale.Error.Metadata.Challenge, "code": code}))

		})
	}
}

func TestCredentialTransactionsProviderLinkGrantDoesNotOutliveSessionRevocation(t *testing.T) {
	for _, oidc := range []bool{true, false} {
		t.Run(fmt.Sprintf("oidc_%v", oidc), func(t *testing.T) {
			ctx := context.Background()
			srv, _, _ := passwordlessTestServer(t, true)
			provider := newSecurityTestProvider(t, srv, oidc)
			uid := mustPasswordUser(t, srv, "audit-link-revoke")
			_, _, access, _, _, err := fixtureBackend(srv.Backend()).issueAuthenticatedSession(ctx, uid, "audit", nil, []string{"pwd"}, nil)
			require.NoError(t, err)
			start := serveAuthJSON(srv, http.MethodPost, "/oidc/"+provider.Name()+"/link/start", "{}", access)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			require.NoError(t, srv.Backend().RevokeIssuerSessions(ctx, uid, nil))
			identity := providerTestIdentity{Subject: "audit-revoked-link-" + uniqueSuffix()}
			callback := completeSecurityProviderCallback(t, srv, provider, start, identity)
			owner, _, linkErr := srv.Backend().GetProviderLinkByIssuer(ctx, provider.Issuer(), identity.Subject)
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
			sid, _, access, _, _, err := fixtureBackend(srv.Backend()).issueAuthenticatedSession(ctx, uid, "link", nil, []string{"pwd"}, nil)
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
			oidcHandler(srv).ServeHTTP(callback, request)
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
			sessions, err := srv.Backend().ListUserSessions(ctx, uid)
			require.NoError(t, err)
			require.Len(t, sessions, 1)
			require.Equal(t, sid, sessions[0].ID)
		})
	}
}
