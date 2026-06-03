package authhttp

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	jwtkit "github.com/open-rails/authkit/jwt"
)

func newClaimVerifier(t *testing.T, orgMode string, signer *jwtkit.RSASigner) *Verifier {
	t.Helper()
	v := NewVerifier(WithOrgMode(orgMode))
	err := v.AddIssuer("https://example.com", []string{"test-app"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	})
	require.NoError(t, err)
	return v
}

// global_roles parses into Claims.GlobalRoles in single mode (no org).
func TestVerify_GlobalRolesClaim_SingleMode(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	v := newClaimVerifier(t, "single", signer)

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := ClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, []string{"admin"}, cl.GlobalRoles)
		require.Equal(t, []string{"admin"}, cl.Roles) // legacy still populated
		require.Empty(t, cl.OrgRoles)
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss":          "https://example.com",
		"sub":          "user",
		"aud":          "test-app",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour).Unix(),
		"roles":        []string{"admin"},
		"global_roles": []string{"admin"},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}

// An org-scoped multi-mode token carries both global_roles and org_roles, and
// the legacy `roles` claim is consumed into OrgRoles (cleared from Roles).
func TestVerify_OrgScoped_GlobalAndOrgRoles(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	v := newClaimVerifier(t, "multi", signer)

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := ClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "acme", cl.Org)
		require.Equal(t, []string{"admin"}, cl.GlobalRoles)
		require.Equal(t, []string{"editor"}, cl.OrgRoles)
		require.Empty(t, cl.Roles) // legacy org-scoped roles moved to OrgRoles
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss":          "https://example.com",
		"sub":          "user",
		"aud":          "test-app",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour).Unix(),
		"org":          "acme",
		"roles":        []string{"editor"},
		"org_roles":    []string{"editor"},
		"global_roles": []string{"admin"},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}
