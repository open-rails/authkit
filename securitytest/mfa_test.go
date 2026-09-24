package securitytest

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/authhttp"
	"github.com/open-rails/authkit/ratelimit"
	"github.com/stretchr/testify/require"
)

// behindProxy lets a test present distinct client addresses through a
// declared loopback proxy.
func behindProxy(c *authhttp.Config) {
	c.DirectPeerIP = false
	c.TrustedProxies = []string{"127.0.0.0/8", "::1/128"}
}

func from(ip string) http.Header { return http.Header{"X-Forwarded-For": {ip}} }

type challenge struct {
	Error struct {
		Code     string `json:"code"`
		Metadata struct {
			UserID           string `json:"user_id"`
			Challenge        string `json:"challenge"`
			AvailableFactors []struct {
				ID string `json:"id"`
			} `json:"available_factors"`
		} `json:"metadata"`
	} `json:"error"`
}

// enrollEmail2FA turns on the email second factor through the public routes.
func (h *host) enrollEmail2FA(a account) {
	h.t.Helper()
	require.NoError(h.t, h.client.MarkEmailVerified(context.Background(), a.id))
	token := h.login(a).AccessToken
	resp := h.post("/user/2fa", map[string]string{"method": "email"}, token)
	require.Equal(h.t, http.StatusAccepted, resp.status, resp.String())
	code := h.mail.last(h.t, `^verification to=`+a.email+` code=(\S+)`)
	resp = h.post("/user/2fa", map[string]string{"method": "email", "code": code}, token)
	require.Equal(h.t, http.StatusOK, resp.status, resp.String())
}

func (h *host) passwordStep(a account, ip string) challenge {
	h.t.Helper()
	resp := h.do(request{method: http.MethodPost, path: "/password/login", header: from(ip),
		body: map[string]string{"identifier": a.email, "password": password}})
	require.Equal(h.t, http.StatusForbidden, resp.status, resp.String())
	var ch challenge
	resp.json(h.t, &ch)
	require.Equal(h.t, "2fa_required", ch.Error.Code)
	return ch
}

func (h *host) secondStep(a account, ch challenge, code, ip string) response {
	h.t.Helper()
	return h.do(request{method: http.MethodPost, path: "/2fa/verify", header: from(ip),
		body: map[string]string{"user_id": a.id, "challenge": ch.Error.Metadata.Challenge, "code": code}})
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
	h := newHost(t, withHTTP(behindProxy), withHTTP(func(c *authhttp.Config) {
		c.RateLimits = map[string]ratelimit.Limit{authhttp.RL2FAVerify: {Limit: 3, Window: 10 * time.Minute}}
	}))
	victim := h.newAccount("mfalock")
	h.enrollEmail2FA(victim)
	ch := h.passwordStep(victim, "198.51.100.7")
	code := h.mail.last(t, `^login to=`+victim.email+` code=(\S+)`)
	for i := range 12 {
		junk := challenge{}
		junk.Error.Metadata.Challenge = fmt.Sprintf("forged-challenge-%d", i)
		resp := h.secondStep(victim, junk, "000000", fmt.Sprintf("203.0.113.%d", i+1))
		require.GreaterOrEqual(t, resp.status, 400)
		resp = h.do(request{method: http.MethodPost, path: "/2fa/challenge", header: from(fmt.Sprintf("192.0.2.%d", i+1)),
			body: map[string]string{"user_id": victim.id, "challenge": junk.Error.Metadata.Challenge, "factor_id": "x"}})
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
	var factor string
	if len(ch.Error.Metadata.AvailableFactors) > 0 {
		factor = ch.Error.Metadata.AvailableFactors[0].ID
	}
	require.NotEmpty(t, factor)
	ip := 0
	next := func() string { ip++; return fmt.Sprintf("203.0.113.%d", ip) }
	for round := range 3 {
		code := h.mail.last(t, `^login to=`+a.email+` code=(\S+)`)
		for range 4 {
			resp := h.secondStep(a, ch, wrongCode(code), next())
			require.Equal(t, http.StatusUnauthorized, resp.status, resp.String())
		}
		resp := h.do(request{method: http.MethodPost, path: "/2fa/challenge", header: from(next()),
			body: map[string]string{"user_id": a.id, "challenge": ch.Error.Metadata.Challenge, "factor_id": factor}})
		if round < 2 {
			require.Equal(t, http.StatusForbidden, resp.status, resp.String())
		}
	}
	code := h.mail.last(t, `^login to=`+a.email+` code=(\S+)`)
	resp := h.secondStep(a, ch, code, next())
	require.Equal(t, http.StatusUnauthorized, resp.status, "12 guesses did not exhaust the proof: %s", resp)
	// A new first factor starts a new proof.
	ch = h.passwordStep(a, "198.51.100.20")
	code = h.mail.last(t, `^login to=`+a.email+` code=(\S+)`)
	require.Equal(t, http.StatusOK, h.secondStep(a, ch, code, next()).status)
}
