package dpop_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/open-rails/authkit/internal/dpop"
	"github.com/open-rails/authkit/internal/testdpop"
	"github.com/stretchr/testify/require"
)

func TestProofValidationWorkflow(t *testing.T) {
	key := testdpop.Key(t)
	const target = "https://api.example/tasks"
	request := httptest.NewRequest("POST", target+"?page=2", nil)
	guard := func(context.Context, string, time.Duration) (bool, error) { return true, nil }
	good := testdpop.Proof(t, key, "POST", target, "access-token", nil)
	request.Header.Set("DPoP", good)
	thumbprint, err := dpop.Verify(request, dpop.Check{URL: target + "?page=2", AccessToken: "access-token", Replay: guard})
	require.NoError(t, err)
	for name, change := range map[string]func(*jwt.Token){
		"wrong type":           func(t *jwt.Token) { t.Header["typ"] = "JWT" },
		"unsupported critical": func(t *jwt.Token) { t.Header["crit"] = []string{"b64"} },
		"private key":          func(t *jwt.Token) { t.Header["jwk"].(map[string]any)["d"] = "private" },
		"symmetric key":        func(t *jwt.Token) { t.Header["jwk"].(map[string]any)["kty"] = "oct" },
		"unsupported curve":    func(t *jwt.Token) { t.Header["jwk"].(map[string]any)["crv"] = "P-384" },
		"invalid point":        func(t *jwt.Token) { t.Header["jwk"].(map[string]any)["x"] = strings.Repeat("A", 43) },
		"wrong method":         func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["htm"] = "GET" },
		"wrong path":           func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["htu"] = target + "/admin" },
		"wrong origin":         func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["htu"] = "https://evil.example/tasks" },
		"query claim":          func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["htu"] = target + "?page=2" },
		"fragment claim":       func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["htu"] = target + "#" },
		"wrong access token":   func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["ath"] = "other" },
		"missing access hash":  func(t *jwt.Token) { delete(t.Claims.(jwt.MapClaims), "ath") },
		"expired":              func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["iat"] = time.Now().Add(-2 * time.Minute).Unix() },
		"future":               func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["iat"] = time.Now().Add(2 * time.Minute).Unix() },
		"fractional timestamp": func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["iat"] = float64(time.Now().Unix()) + 0.5 },
		"missing id":           func(t *jwt.Token) { delete(t.Claims.(jwt.MapClaims), "jti") },
		"oversized id":         func(t *jwt.Token) { t.Claims.(jwt.MapClaims)["jti"] = strings.Repeat("x", 129) },
	} {
		t.Run(name, func(t *testing.T) {
			request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", target, "access-token", change))
			_, err := dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Thumbprint: thumbprint, Replay: guard})
			require.ErrorIs(t, err, dpop.ErrInvalidProof)
		})
	}
	request.Header.Set("DPoP", testdpop.Proof(t, testdpop.Key(t), "POST", target, "access-token", nil))
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Thumbprint: thumbprint, Replay: guard})
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", "HTTPS://API.EXAMPLE:443/tasks", "access-token", nil))
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Thumbprint: thumbprint, Replay: guard})
	require.NoError(t, err)
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", target+"/a%2Fb", "access-token", nil))
	_, err = dpop.Verify(request, dpop.Check{URL: target + "/a/b", AccessToken: "access-token", Thumbprint: thumbprint, Replay: guard})
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	for _, malformed := range []string{"", "a.b.c.d", strings.Repeat("x", 4097), good + ", " + good,
		base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","typ":"dpop+jwt","alg":"ES256","jwk":{}}`)) + ".e30.AA"} {
		request.Header.Set("DPoP", malformed)
		_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: guard})
		require.ErrorIs(t, err, dpop.ErrInvalidProof)
	}
	request.Header.Set("DPoP", good)
	request.Header.Add("DPoP", good)
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: guard})
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	request.Header.Set("DPoP", good)
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: nil})
	require.ErrorIs(t, err, dpop.ErrReplayUnavailable)
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: func(context.Context, string, time.Duration) (bool, error) { return false, errors.New("offline") }})
	require.ErrorIs(t, err, dpop.ErrReplayUnavailable)
	// Concurrent identical proofs can yield exactly one accepted request.
	var claimed atomic.Bool
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: func(_ context.Context, key string, ttl time.Duration) (bool, error) {
				if len(key) != 43 || ttl <= 0 || ttl > 121*time.Second {
					panic("unbounded replay claim")
				}
				return claimed.CompareAndSwap(false, true), nil
			}})
			if err == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, accepted.Load())
}

func TestNonces(t *testing.T) {
	_, err := dpop.NewNonces(make([]byte, 31))
	require.Error(t, err)
	key := make([]byte, 32)
	key[0] = 1
	nonces, err := dpop.NewNonces(key)
	require.NoError(t, err)
	other, err := dpop.NewNonces(make([]byte, 32))
	require.NoError(t, err)
	now := time.Now()
	require.True(t, nonces.Valid(nonces.Issue(now), now))
	require.True(t, nonces.Valid(nonces.Issue(now.Add(-dpop.NonceLifetime+time.Second)), now))
	require.False(t, nonces.Valid(nonces.Issue(now.Add(-dpop.NonceLifetime-time.Second)), now), "expired")
	require.False(t, nonces.Valid(nonces.Issue(now.Add(2*time.Minute)), now), "from the future")
	require.False(t, nonces.Valid(other.Issue(now), now), "another key")
	require.False(t, nonces.Valid("", now))
	tampered := []byte(nonces.Issue(now))
	tampered[3] ^= 1
	require.False(t, nonces.Valid(string(tampered), now))
}

func TestProofNonceAndTokenEndpoint(t *testing.T) {
	key := testdpop.Key(t)
	const target = "https://as.example/oauth2/token"
	guard := func(context.Context, string, time.Duration) (bool, error) { return true, nil }
	secret := make([]byte, 32)
	nonces, err := dpop.NewNonces(secret)
	require.NoError(t, err)
	request := httptest.NewRequest("POST", target, nil)
	withoutAth := func(t *jwt.Token) { delete(t.Claims.(jwt.MapClaims), "ath") }
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", target, "", withoutAth))
	_, err = dpop.Verify(request, dpop.Check{URL: target, Replay: guard})
	require.NoError(t, err, "a token endpoint proof carries no ath")
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", target, "access-token", nil))
	_, err = dpop.Verify(request, dpop.Check{URL: target, Replay: guard})
	require.ErrorIs(t, err, dpop.ErrInvalidProof, "nor may it")
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: guard, Nonces: nonces})
	require.ErrorIs(t, err, dpop.ErrNonceRequired)
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", target, "access-token", func(t *jwt.Token) {
		t.Claims.(jwt.MapClaims)["nonce"] = nonces.Issue(time.Now())
	}))
	_, err = dpop.Verify(request, dpop.Check{URL: target, AccessToken: "access-token", Replay: guard, Nonces: nonces})
	require.NoError(t, err)
}
