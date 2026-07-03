package authhttp

import (
	"github.com/open-rails/authkit/verify"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func entitlementProtected(mw func(http.Handler) http.Handler) http.Handler {
	return mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
}

func serveWithClaims(h http.Handler, cl *verify.Claims) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if cl != nil {
		r = r.WithContext(verify.SetClaims(r.Context(), *cl))
	}
	h.ServeHTTP(w, r)
	return w
}

func TestRequireEntitlement_AllowsWhenPresent(t *testing.T) {
	h := entitlementProtected(verify.RequireEntitlement("premium"))
	w := serveWithClaims(h, &verify.Claims{UserID: "u1", Entitlements: []string{"premium"}})
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequireEntitlement_CaseInsensitive(t *testing.T) {
	h := entitlementProtected(verify.RequireEntitlement("Premium"))
	w := serveWithClaims(h, &verify.Claims{UserID: "u1", Entitlements: []string{"PREMIUM"}})
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequireEntitlement_DeniesWhenMissing(t *testing.T) {
	h := entitlementProtected(verify.RequireEntitlement("premium"))
	w := serveWithClaims(h, &verify.Claims{UserID: "u1", Entitlements: []string{"basic"}})
	require.Equal(t, http.StatusForbidden, w.Code)
	requireErrorCode(t, w.Body.String(), "forbidden")
}

func TestRequireEntitlement_DeniesWhenNoClaims(t *testing.T) {
	h := entitlementProtected(verify.RequireEntitlement("premium"))
	w := serveWithClaims(h, nil)
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireAnyEntitlement_AllowsOnAnyMatch(t *testing.T) {
	h := entitlementProtected(verify.RequireAnyEntitlement("pro", "premium"))
	w := serveWithClaims(h, &verify.Claims{UserID: "u1", Entitlements: []string{"premium"}})
	require.Equal(t, http.StatusOK, w.Code)
}

func TestRequireAnyEntitlement_FailsClosedWithNoneListed(t *testing.T) {
	h := entitlementProtected(verify.RequireAnyEntitlement())
	w := serveWithClaims(h, &verify.Claims{UserID: "u1", Entitlements: []string{"premium"}})
	require.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequireEntitlement_DeniesAPIKeyPrincipal(t *testing.T) {
	h := entitlementProtected(verify.RequireEntitlement("premium"))
	w := serveWithClaims(h, &verify.Claims{TokenType: verify.APIKeyPrincipalType})
	require.Equal(t, http.StatusForbidden, w.Code)
}
