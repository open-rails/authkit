package authhttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/authprovider"
	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/open-rails/authkit/jwtkit"
	"github.com/stretchr/testify/require"
)

// The local provider exchanges actual HTTP tokens; OIDC additionally signs and
// verifies an ID token through discovery and JWKS. Only the external IdP is fake.
type providerTestIdentity struct {
	Subject  string `json:"sub"`
	Email    string `json:"email"`
	Verified *bool  `json:"email_verified,omitempty"`
	Nonce    string `json:"nonce"`
}

func newSecurityTestProvider(t *testing.T, srv *Service, oidc bool) authprovider.Provider {
	t.Helper()
	signer, err := jwtkit.NewRSASigner(2048, "provider-test")
	require.NoError(t, err)
	var provider *httptest.Server
	provider = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": provider.URL, "authorization_endpoint": provider.URL + "/authorize", "token_endpoint": provider.URL + "/token", "jwks_uri": provider.URL + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"}})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(jwtkit.JWKS{Keys: []jwtkit.JWK{jwtkit.PublicToJWK(signer.PublicKey(), signer.KID(), signer.Algorithm())}})
		case "/token":
			require.NoError(t, r.ParseForm())
			code := r.PostFormValue("code")
			raw, err := base64.RawURLEncoding.DecodeString(code)
			require.NoError(t, err)
			var claims jwt.MapClaims
			require.NoError(t, json.Unmarshal(raw, &claims))
			claims["iss"] = provider.URL
			claims["aud"] = "security-client"
			claims["iat"] = time.Now().Unix()
			claims["exp"] = time.Now().Add(time.Minute).Unix()
			token, err := signer.Sign(r.Context(), claims)
			require.NoError(t, err)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": code, "token_type": "Bearer", "id_token": token})
		case "/me":
			raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
			require.NoError(t, err)
			_, _ = w.Write(raw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(provider.Close)
	var cfg authprovider.Provider
	if oidc {
		cfg = authprovider.OIDC("security-provider", provider.URL, "security-client", "local-secret")
	} else {
		cfg = testOAuth2Provider("security-provider", provider.URL, "security-client", "local-secret", authprovider.WithScopes("openid", "email", "profile"))
	}
	setTestProviders(srv, cfg)
	return cfg
}

func completeSecurityProviderCallback(t *testing.T, srv *Service, cfg authprovider.Provider, start *httptest.ResponseRecorder, identity providerTestIdentity) *httptest.ResponseRecorder {
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
	srv.oidcHandler().ServeHTTP(response, request)
	return response
}

func securityProviderLogin(t *testing.T, srv *Service, cfg authprovider.Provider, identity providerTestIdentity, invite string) *httptest.ResponseRecorder {
	t.Helper()
	start := httptest.NewRecorder()
	srv.oidcHandler().ServeHTTP(start, httptest.NewRequest(http.MethodGet, "/oidc/"+cfg.Name()+"/login?account_invite_token="+url.QueryEscape(invite), nil))
	require.Equal(t, http.StatusFound, start.Code, start.Body.String())
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
			require.Equal(t, http.StatusOK, callback.Code, callback.Body.String())
			start = serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", fresh.AccessToken)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			callback = completeSecurityProviderCallback(t, srv, cfg, start, providerTestIdentity{Subject: "replacement-" + uniqueSuffix()})
			require.Equal(t, http.StatusConflict, callback.Code, callback.Body.String())
			require.Contains(t, callback.Body.String(), "provider_change_requires_unlink")
			owner, _, err := srv.svc.GetProviderLinkByIssuer(ctx, cfg.Issuer(), old.Subject)
			require.NoError(t, err)
			require.Equal(t, userID, owner)
			unlinked := serveAuthJSON(srv, http.MethodDelete, "/user/providers/"+cfg.Name(), "{}", fresh.AccessToken)
			require.Equal(t, http.StatusNoContent, unlinked.Code, unlinked.Body.String())
			start = serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", fresh.AccessToken)
			require.Equal(t, http.StatusOK, start.Code, start.Body.String())
			callback = completeSecurityProviderCallback(t, srv, cfg, start, providerTestIdentity{Subject: "replacement-" + uniqueSuffix()})
			require.Equal(t, http.StatusOK, callback.Code, callback.Body.String())
		})
	}
}

func TestFederatedUnverifiedEmailDoesNotReserveAccountAddress(t *testing.T) {
	for _, kind := range []string{"oidc", "oauth2"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			pool := testdb.Pool(t)
			sender := &captureEmailSender{}
			srv, err := newServer(newServerClient(t, newServerTestConfig(), pool, withEmailSender(sender)), WithoutRateLimiter())
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
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, first.User.ID) })
			user, err := srv.svc.AdminGetUser(ctx, first.User.ID)
			require.NoError(t, err)
			require.Nil(t, user.Email)
			owner, providerEmail, err := srv.svc.GetProviderLinkByIssuer(ctx, cfg.Issuer(), identity.Subject)
			require.NoError(t, err)
			require.Equal(t, first.User.ID, owner)
			require.NotNil(t, providerEmail)
			require.Equal(t, email, *providerEmail)
			require.NoError(t, srv.svc.RequestPasswordReset(ctx, email, time.Hour, nil, nil))
			require.Empty(t, sender.resetURL)
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
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, second.User.ID) })
			user, err = srv.svc.AdminGetUser(ctx, second.User.ID)
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
			settings.Registration.NativeUserMode = embedded.RegistrationModeInviteOnly
			srv, err := newServer(newServerClient(t, settings, pool), WithoutRateLimiter())
			require.NoError(t, err)
			cfg := newSecurityTestProvider(t, srv, kind == "oidc")
			identity := providerTestIdentity{Subject: "invite-user-" + uniqueSuffix(), Email: uniqueEmail("unverified-invite")}
			denied := securityProviderLogin(t, srv, cfg, identity, "")
			require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
			inviter, invite := createAccountInvite(t, srv, pool, uniqueEmail("invite-destination"))
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, inviter) })
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
			t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, body.User.ID) })
			requireAccountInviteConsumed(t, pool, invite.ID, body.User.ID)
			identity.Subject = "another-" + uniqueSuffix()
			denied = securityProviderLogin(t, srv, cfg, identity, invite.Code)
			require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
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
	sid, _, _, err := srv.svc.IssueRefreshSessionWithAuthMethods(ctx, userID, "test", nil, []string{"pwd"})
	require.NoError(t, err)
	secret, _, err := srv.svc.StartTOTPEnrollment(ctx, userID)
	require.NoError(t, err)
	_, err = srv.svc.EnableTOTP2FA(ctx, authcore.TOTPEnrollment{UserID: userID, Code: testTOTPCode(t, secret, time.Now().Unix()/30), MakeDefault: true, Mode: authcore.AllowAdditionalFactors})
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, userID, map[string]any{"sid": sid})
	require.NoError(t, err)
	for _, path := range []string{"/oidc/" + cfg.Name() + "/link/start", "/solana/link"} {
		denied := serveAuthJSON(srv, http.MethodPost, path, "{}", token)
		require.Equal(t, http.StatusForbidden, denied.Code, denied.Body.String())
		require.Contains(t, denied.Body.String(), "step_up_required")
		require.Contains(t, denied.Body.String(), `"mfa_required":true`)
	}
	require.NoError(t, srv.svc.MarkSessionAuthenticatedWithMethods(ctx, userID, sid, []string{"pwd", "otp", "mfa"}))
	token, _, err = srv.svc.MintAccessToken(ctx, userID, map[string]any{"sid": sid})
	require.NoError(t, err)
	allowed := serveAuthJSON(srv, http.MethodPost, "/oidc/"+cfg.Name()+"/link/start", "{}", token)
	require.Equal(t, http.StatusOK, allowed.Code, allowed.Body.String())
}
