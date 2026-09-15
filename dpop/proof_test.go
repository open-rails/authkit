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
	"github.com/open-rails/authkit/dpop"
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
	thumbprint, err := dpop.VerifyRequest(request, target+"?page=2", "access-token", nil, guard)
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
			_, err := dpop.VerifyRequest(request, target, "access-token", &thumbprint, guard)
			require.ErrorIs(t, err, dpop.ErrInvalidProof)
		})
	}
	request.Header.Set("DPoP", testdpop.Proof(t, testdpop.Key(t), "POST", target, "access-token", nil))
	_, err = dpop.VerifyRequest(request, target, "access-token", &thumbprint, guard)
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", "HTTPS://API.EXAMPLE:443/tasks", "access-token", nil))
	_, err = dpop.VerifyRequest(request, target, "access-token", &thumbprint, guard)
	require.NoError(t, err)
	request.Header.Set("DPoP", testdpop.Proof(t, key, "POST", target+"/a%2Fb", "access-token", nil))
	_, err = dpop.VerifyRequest(request, target+"/a/b", "access-token", &thumbprint, guard)
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	for _, malformed := range []string{"", "a.b.c.d", strings.Repeat("x", 4097), good + ", " + good,
		base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","typ":"dpop+jwt","alg":"ES256","jwk":{}}`)) + ".e30.AA"} {
		request.Header.Set("DPoP", malformed)
		_, err = dpop.VerifyRequest(request, target, "access-token", nil, guard)
		require.ErrorIs(t, err, dpop.ErrInvalidProof)
	}
	request.Header.Set("DPoP", good)
	request.Header.Add("DPoP", good)
	_, err = dpop.VerifyRequest(request, target, "access-token", nil, guard)
	require.ErrorIs(t, err, dpop.ErrInvalidProof)
	request.Header.Set("DPoP", good)
	_, err = dpop.VerifyRequest(request, target, "access-token", nil, nil)
	require.ErrorIs(t, err, dpop.ErrReplayUnavailable)
	_, err = dpop.VerifyRequest(request, target, "access-token", nil, func(context.Context, string, time.Duration) (bool, error) { return false, errors.New("offline") })
	require.ErrorIs(t, err, dpop.ErrReplayUnavailable)
	// Concurrent identical proofs can yield exactly one accepted request.
	var claimed atomic.Bool
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for range 16 {
		wg.Go(func() {
			_, err := dpop.VerifyRequest(request, target, "access-token", nil, func(_ context.Context, key string, ttl time.Duration) (bool, error) {
				if len(key) != 43 || ttl <= 0 || ttl > 121*time.Second {
					panic("unbounded replay claim")
				}
				return claimed.CompareAndSwap(false, true), nil
			})
			if err == nil {
				accepted.Add(1)
			}
		})
	}
	wg.Wait()
	require.EqualValues(t, 1, accepted.Load())
}
