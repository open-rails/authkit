package authhttp

import (
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	jwtkit "github.com/open-rails/authkit/jwt"
)

func TestRequired_OrgScopedRoles_UsesRolesWhenOrgPresent(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)

	v := NewVerifier(WithOrgMode("multi"))
	err = v.AddIssuer("https://example.com", []string{"test-app"}, IssuerOptions{
		RawKeys: map[string]*rsa.PublicKey{
			signer.KID(): signer.PublicKey(),
		},
	})
	require.NoError(t, err)

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := ClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "acme", cl.Org)
		require.Equal(t, []string{"a", "b"}, cl.OrgRoles)
		require.Empty(t, cl.Roles)
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss":   "https://example.com",
		"sub":   "user",
		"aud":   "test-app",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(1 * time.Hour).Unix(),
		"org":   "acme",
		"roles": []string{"a", "b"},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}
