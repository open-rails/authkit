package authhttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMePermissions_UserIsPrincipalLevelOnly(t *testing.T) {
	s := newTestService(t)
	r := httptest.NewRequest(http.MethodGet, "/me/permissions", nil)
	r = r.WithContext(setClaims(r.Context(), Claims{
		UserID:      "user-1",
		Org:         "acme",
		OrgRoles:    []string{"owner"},
		Roles:       []string{"global-admin"},
		Permissions: []string{"principal:read"},
	}))
	w := httptest.NewRecorder()
	s.handleMePermissionsGET(w, r)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	var out map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &out))
	require.Equal(t, "user", out["principal_type"])
	require.NotContains(t, out, "org")
	require.Equal(t, []any{"global-admin"}, out["roles"])
	require.Equal(t, []any{"principal:read"}, out["permissions"])
}
