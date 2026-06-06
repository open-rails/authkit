package authhttp

import (
	"testing"
	"time"

	jwtkit "github.com/open-rails/authkit/jwt"
	"github.com/stretchr/testify/require"
)

// VerifyClaims is the generic JWKS-verify primitive: it validates signature +
// issuer + audience + expiry and returns RAW claims, so a host can verify a
// custom token type (e.g. capability tokens) on authkit's JWKS engine without
// authkit's user-token semantics. These tests cover a custom claim shape (no
// `sub`) plus the rejection paths.
func TestVerifyClaims_CustomTokenReturnsRawClaims(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	v := newTestVerifier(t, signer, "https://cap.example", []string{"tensorhub-workers"})

	tok := signToken(t, signer, map[string]any{
		"iss":      "https://cap.example",
		"aud":      "tensorhub-workers",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
		"owner":    "tenant-acme",
		"cap_kind": "repo_write",
		"scopes":   []string{"repo:write"},
		// deliberately no `sub` — a custom (non-user) token shape.
	})

	mc, err := v.VerifyClaims(tok)
	require.NoError(t, err)
	require.Equal(t, "tenant-acme", mc["owner"])
	require.Equal(t, "repo_write", mc["cap_kind"])
}

func TestVerifyClaims_Rejections(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	v := newTestVerifier(t, signer, "https://cap.example", []string{"tensorhub-workers"})

	t.Run("bad audience", func(t *testing.T) {
		tok := signToken(t, signer, map[string]any{
			"iss": "https://cap.example", "aud": "someone-else",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		_, err := v.VerifyClaims(tok)
		require.EqualError(t, err, "bad_audience")
	})

	t.Run("expired", func(t *testing.T) {
		tok := signToken(t, signer, map[string]any{
			"iss": "https://cap.example", "aud": "tensorhub-workers",
			"iat": time.Now().Add(-2 * time.Hour).Unix(), "exp": time.Now().Add(-time.Hour).Unix(),
		})
		_, err := v.VerifyClaims(tok)
		require.EqualError(t, err, "token_expired")
	})

	t.Run("unknown issuer", func(t *testing.T) {
		tok := signToken(t, signer, map[string]any{
			"iss": "https://not-registered.example", "aud": "tensorhub-workers",
			"iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix(),
		})
		_, err := v.VerifyClaims(tok)
		require.Error(t, err)
	})
}
