package authhttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	authkit "github.com/open-rails/authkit"
	"github.com/open-rails/authkit/embedded"
	"github.com/open-rails/authkit/internal/testdb"
)

// outboundSendRoute is one route that triggers an outbound email or SMS. Every
// such route must be capped per identifier as well as per IP, or N IPs can bomb
// one contact (ak#300).
type outboundSendRoute struct {
	path   string
	bucket string
	ident  func() string
	body   func(ident string) string
	auth   bool
}

func outboundSendRoutes() []outboundSendRoute {
	email := func() string { return uniqueEmail("send-cap") }
	phone := uniquePhone
	return []outboundSendRoute{
		{path: "/register", bucket: RLAuthRegister, ident: email, body: func(id string) string {
			return `{"identifier":"` + id + `","username":"sendcap` + uniqueSuffix()[8:] + `","password":"Correct-password-12345"}`
		}},
		{path: "/register", bucket: RLAuthRegister, ident: phone, body: func(id string) string {
			return `{"identifier":"` + id + `","username":"sendcap` + uniqueSuffix()[8:] + `","password":"Correct-password-12345"}`
		}},
		{path: "/register/resend", bucket: RLRegisterResend, ident: email, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/register/resend", bucket: RLRegisterResend, ident: phone, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/password/reset/request", bucket: RLPasswordResetRequest, ident: email, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/password/reset/request", bucket: RLPasswordResetRequest, ident: phone, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/verify/request", bucket: RLVerifyRequest, ident: email, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/verify/request", bucket: RLVerifyRequest, ident: phone, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/passwordless/start", bucket: RLPasswordlessStart, ident: email, body: func(id string) string { return `{"identifier":"` + id + `"}` }},
		{path: "/device-keys/enroll/begin", bucket: RLDeviceKeyEnrollBegin, ident: email, body: func(id string) string {
			sum := sha256.Sum256([]byte(id))
			pk := hex.EncodeToString(sum[:])[:43]
			return `{"email":"` + id + `","public_key":"` + pk + `"}`
		}},
		{path: "/user/2fa", bucket: RL2FAStartPhone, ident: phone, auth: true, body: func(id string) string { return `{"method":"sms","phone":"` + id + `"}` }},
	}
}

// TestOutboundSendRoutes_PerIdentifierCap drives every outbound-send route on the
// real mount from a fresh IP per request (the per-IP budget never trips) and
// proves the per-identifier budget alone yields 429, while another identifier
// from yet another IP is unaffected.
func TestOutboundSendRoutes_PerIdentifierCap(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	cfg := newServerTestConfig()
	cfg.Frontend.BaseURL = "https://example.com"
	cfg.Registration.Verification = embedded.RegistrationVerificationRequired
	cfg.Registration.PasswordlessLogin = true
	cfg.TwoFactor.Methods = []authkit.TwoFactorMethod{authkit.TwoFactorSMS}
	srv, err := newServer(newServerClient(t, cfg, pool, withEmailSender(&captureEmailSender{}), withSMSSender(&captureSMSSender{})))
	require.NoError(t, err)

	user, err := srv.svc.CreateUser(ctx, uniqueEmail("send-cap-user"), "sendcapuser"+uniqueSuffix()[8:])
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE id=$1::uuid`, user.ID) })
	sid, _, _, err := srv.svc.IssueRefreshSession(ctx, user.ID, "test", nil)
	require.NoError(t, err)
	token, _, err := srv.svc.MintAccessToken(ctx, user.ID, map[string]any{"sid": sid})
	require.NoError(t, err)

	mounted := map[string]bool{}
	for _, rs := range srv.APIRoutes() {
		mounted[rs.Method+" "+rs.Path] = true
	}
	h := srv.apiHandler()
	limits := DefaultRateLimits()
	ipSeq := 0
	send := func(rt outboundSendRoute, body string) int {
		ipSeq++
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, rt.path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.RemoteAddr = fmt.Sprintf("203.0.%d.%d:1234", ipSeq/250, ipSeq%250+1)
		if rt.auth {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		h.ServeHTTP(w, r)
		return w.Code
	}

	for _, rt := range outboundSendRoutes() {
		t.Run(rt.path+"/"+rt.bucket, func(t *testing.T) {
			require.True(t, mounted["POST "+rt.path], "route %s is not mounted", rt.path)
			lim, ok := limits[rt.bucket]
			require.True(t, ok, "bucket %s has no default limit", rt.bucket)
			budget := lim.Limit
			if lim.Cooldown > 0 {
				budget = 1
			}
			ident := rt.ident()
			for i := 0; i < budget; i++ {
				code := send(rt, rt.body(ident))
				require.NotEqual(t, http.StatusTooManyRequests, code, "request %d within the identifier budget was limited", i+1)
			}
			require.Equal(t, http.StatusTooManyRequests, send(rt, rt.body(ident)), "fresh IP, same identifier must be limited")
			require.NotEqual(t, http.StatusTooManyRequests, send(rt, rt.body(rt.ident())), "fresh IP, other identifier must pass")
		})
	}
}
