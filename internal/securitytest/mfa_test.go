package securitytest

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/stretchr/testify/require"
)

// behindProxy lets a test present distinct client addresses through a
// declared loopback proxy.
func behindProxy(c *authkit.HTTPConfig) {
	c.DirectPeerIP = false
	c.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
}

func from(ip string) http.Header { return http.Header{"X-Forwarded-For": {ip}} }

// enrollEmail2FA turns on the email second factor through the public routes
// and returns the backup codes it issued.
func (h *host) enrollEmail2FA(a account) []string {
	h.t.Helper()
	h.verifyEmail(a.id)
	token := h.login(a).AccessToken
	resp := h.post("/me/2fa/setup", map[string]string{"method": "email"}, token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	code := h.mail.Last(h.t, iam.MessageVerification, a.email).Code
	resp = h.post("/me/2fa/factors", map[string]string{"method": "email", "code": code}, token)
	require.Equal(h.t, http.StatusCreated, resp.status, resp.String())
	var out struct {
		BackupCodes []string `json:"backup_codes"`
	}
	resp.json(h.t, &out)
	return out.BackupCodes
}

// enrollTOTP adds an authenticator-app factor with token and returns its
// secret and the confirming response (TwoFactorFactorCreated). The enrollment
// spends the current code; the next one is authtest.TOTPCode(t, secret,
// time.Now().Add(30*time.Second)).
func (h *host) enrollTOTP(token string) (string, response) {
	h.t.Helper()
	resp := h.post("/me/2fa/setup", map[string]string{"method": "totp"}, token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	var start struct {
		Secret string `json:"secret"`
	}
	resp.json(h.t, &start)
	require.NotEmpty(h.t, start.Secret)
	resp = h.post("/me/2fa/factors", map[string]string{"method": "totp", "code": authtest.TOTPCode(h.t, start.Secret, time.Now())}, token)
	require.Equal(h.t, http.StatusCreated, resp.status, resp.String())
	return start.Secret, resp
}

// enrollSMS adds an SMS factor for phone with token.
func (h *host) enrollSMS(token, phone string) {
	h.t.Helper()
	resp := h.post("/me/2fa/setup", map[string]string{"method": "sms", "phone_number": phone}, token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
	code := h.mail.Last(h.t, iam.MessageVerification, phone).Code
	resp = h.post("/me/2fa/factors", map[string]string{"method": "sms", "phone_number": phone, "code": code}, token)
	require.Equal(h.t, http.StatusCreated, resp.status, resp.String())
}

func (h *host) passwordStep(a account, ip string) challenge {
	h.t.Helper()
	resp := h.do(request{method: http.MethodPost, path: "/password/login", header: from(ip),
		body: map[string]string{"identifier": a.email, "password": password}})
	return secondFactor(h.t, resp)
}

func (h *host) secondStep(a account, ch challenge, code, ip string) response {
	h.t.Helper()
	return h.do(request{method: http.MethodPost, path: "/2fa/verify", header: from(ip),
		body: map[string]string{"user_id": a.id, "challenge": ch.Challenge, "code": code}})
}

func wrongCode(code string) string {
	if strings.HasPrefix(code, "0") {
		return "1" + code[1:]
	}
	return "0" + code[1:]
}

// TestSecuritySecondFactorLockout: someone who knows only a user's id must not
// be able to exhaust that user's second-factor budget from other addresses.
func TestSecuritySecondFactorLockout(t *testing.T) {
	h := newHost(t, withHTTP(behindProxy), withHTTP(func(c *authkit.HTTPConfig) {
		c.RateLimits = map[string]authkit.RateLimit{"auth_2fa_verify": {Limit: 3, Window: 10 * time.Minute}}
	}))
	victim := h.newAccount("mfalock")
	h.enrollEmail2FA(victim)
	ch := h.passwordStep(victim, "198.51.100.7")
	code := h.mail.Last(t, iam.MessageLoginCode, victim.email).Code
	for i := range 12 {
		junk := challenge{Challenge: fmt.Sprintf("forged-challenge-%d", i)}
		resp := h.secondStep(victim, junk, "000000", fmt.Sprintf("203.0.113.%d", i+1))
		require.GreaterOrEqual(t, resp.status, 400)
		resp = h.do(request{method: http.MethodPost, path: "/2fa/challenge", header: from(fmt.Sprintf("192.0.2.%d", i+1)),
			body: map[string]string{"user_id": victim.id, "challenge": junk.Challenge, "factor_id": "x"}})
		require.GreaterOrEqual(t, resp.status, 400)
	}
	resp := h.secondStep(victim, ch, code, "198.51.100.7")
	require.Equal(t, http.StatusOK, resp.status, "a stranger locked the victim out: %s", resp)
}

// TestSecuritySecondFactorGuessBudget: resending a code or rotating addresses
// must not reset the number of guesses one first-factor proof allows.
func TestSecuritySecondFactorGuessBudget(t *testing.T) {
	h := newHost(t, withHTTP(behindProxy), withHTTP(generousLimits))
	a := h.newAccount("mfabudget")
	h.enrollEmail2FA(a)
	ch := h.passwordStep(a, "198.51.100.20")
	factor := ch.Factor.ID
	require.NotEmpty(t, factor)
	require.Equal(t, "email", ch.Factor.Method)
	ip := 0
	next := func() string { ip++; return fmt.Sprintf("203.0.113.%d", ip) }
	for round := range 3 {
		code := h.mail.Last(t, iam.MessageLoginCode, a.email).Code
		for range 4 {
			resp := h.secondStep(a, ch, wrongCode(code), next())
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		}
		resp := h.do(request{method: http.MethodPost, path: "/2fa/challenge", header: from(next()),
			body: map[string]string{"user_id": a.id, "challenge": ch.Challenge, "factor_id": factor}})
		if round < 2 {
			// A resend is the sign-in's next step again, not an error.
			resent := secondFactor(t, resp)
			require.Equal(t, ch.Challenge, resent.Challenge)
			require.Equal(t, factor, resent.Factor.ID)
		}
	}
	code := h.mail.Last(t, iam.MessageLoginCode, a.email).Code
	resp := h.secondStep(a, ch, code, next())
	require.Equal(t, http.StatusUnauthorized, resp.status, "12 guesses did not exhaust the proof: %s", resp)
	// A new first factor starts a new proof.
	ch = h.passwordStep(a, "198.51.100.20")
	code = h.mail.Last(t, iam.MessageLoginCode, a.email).Code
	require.Equal(t, http.StatusOK, h.secondStep(a, ch, code, next()).status)
}

// TestSecuritySecondFactorResendIsAStep: switching factor at POST
// /2fa/challenge is the sign-in's next step, not an error: 200 and the same
// second_factor_required AuthResult, with no token or account and only a
// masked destination. A forged challenge is refused.
func TestSecuritySecondFactorResendIsAStep(t *testing.T) {
	h := newHost(t, withHTTP(generousLimits))
	a := h.newAccount("mfaresend")
	h.enrollEmail2FA(a)
	ch := h.passwordStep(a, "198.51.100.30")
	resp := h.post("/2fa/challenge", map[string]string{"user_id": a.id, "challenge": ch.Challenge, "factor_id": ch.Factor.ID}, "")
	res := authResult(t, resp)
	require.Equal(t, httpapi.AuthSecondFactorRequired, res.Status)
	require.Nil(t, res.TokenSet)
	require.Nil(t, res.User)
	require.Equal(t, ch.Challenge, res.SecondFactor.Challenge)
	require.Equal(t, ch.Factor.ID, res.SecondFactor.Factor.ID)
	require.NotNil(t, res.SecondFactor.Factor.Destination)
	require.NotContains(t, resp.String(), a.email, "the destination is masked")
	require.NotContains(t, resp.String(), "access_token")

	forged := h.post("/2fa/challenge", map[string]string{"user_id": a.id, "challenge": "forged-challenge", "factor_id": ch.Factor.ID}, "")
	require.Equal(t, http.StatusUnauthorized, forged.status, forged.String())
	require.Equal(t, "invalid_challenge", forged.errorCode())

	session(t, h.secondStep(a, ch, h.mail.Last(t, iam.MessageLoginCode, a.email).Code, "198.51.100.30"))
}
