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

func newClaimVerifier(t *testing.T, tenantMode string, signer *jwtkit.RSASigner) *Verifier {
	t.Helper()
	v := NewVerifier(WithTenantMode(tenantMode))
	err := v.AddIssuer("https://example.com", []string{"test-app"}, IssuerOptions{
		RawKeys: map[string]crypto.PublicKey{signer.KID(): signer.PublicKey()},
	})
	require.NoError(t, err)
	return v
}

// global_roles parses into Claims.GlobalRoles in single mode (no tenant).
func TestVerify_GlobalRolesClaim_SingleMode(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	v := newClaimVerifier(t, "single", signer)

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := ClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, []string{"admin"}, cl.GlobalRoles)
		require.Equal(t, []string{"admin"}, cl.Roles) // legacy still populated
		require.Empty(t, cl.TenantRoles)
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

// An tenant-scoped multi-mode token carries both global_roles and tenant_roles, and
// the legacy `roles` claim is consumed into TenantRoles (cleared from Roles).
func TestVerify_TenantScoped_GlobalAndTenantRoles(t *testing.T) {
	signer, err := jwtkit.NewRSASigner(2048, "kid")
	require.NoError(t, err)
	v := newClaimVerifier(t, "multi", signer)

	protected := Required(v)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cl, ok := ClaimsFromContext(r.Context())
		require.True(t, ok)
		require.Equal(t, "acme", cl.Tenant)
		require.Equal(t, []string{"admin"}, cl.GlobalRoles)
		require.Equal(t, []string{"editor"}, cl.TenantRoles)
		require.Empty(t, cl.Roles) // legacy tenant-scoped roles moved to TenantRoles
		w.WriteHeader(http.StatusOK)
	}))

	token := signToken(t, signer, map[string]any{
		"iss":          "https://example.com",
		"sub":          "user",
		"aud":          "test-app",
		"iat":          time.Now().Unix(),
		"exp":          time.Now().Add(time.Hour).Unix(),
		"tenant":       "acme",
		"roles":        []string{"editor"},
		"tenant_roles": []string{"editor"},
		"global_roles": []string{"admin"},
	})

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	protected.ServeHTTP(w, r)
	require.Equal(t, http.StatusOK, w.Code)
}
