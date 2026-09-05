package authhttp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/open-rails/authkit/embedded"
	authcore "github.com/open-rails/authkit/internal/authcore"
	"github.com/open-rails/authkit/internal/testdb"
	"github.com/stretchr/testify/require"
)

// #286: a bounded operator holding every intrinsic root:users:* perm must not be
// able to ban, delete or revoke the sessions of the root owner (a strictly more
// privileged account), while peers and ordinary users stay reachable and the
// owner keeps full reach. Real admin handlers, real permission-group store.
func TestAdminAccountAuthority_BoundedOperatorCannotTargetOwner(t *testing.T) {
	pool := testdb.Pool(t)
	ctx := context.Background()
	s := newAdminServiceWithRoles(t, pool, authcore.RoleDef{Name: "operator", Permissions: authcore.IntrinsicRootPermissions()})

	prefix := fmt.Sprintf("acctauth%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM profiles.users WHERE username LIKE $1`, prefix+"%")
	})
	mk := func(name string) string {
		u, err := s.svc.CreateUser(ctx, fmt.Sprintf("%s-%s@test.example", prefix, name), prefix+name)
		require.NoError(t, err)
		return u.ID
	}
	owner, operator, peer, member := mk("owner"), mk("operator"), mk("peer"), mk("member")
	require.NoError(t, s.svc.AssignGroupRoleGenesis(ctx, embedded.RootPersona, "", owner, embedded.SubjectKindUser, embedded.OwnerRoleName))
	require.NoError(t, s.svc.AssignGroupRoleGenesis(ctx, embedded.RootPersona, "", operator, embedded.SubjectKindUser, "operator"))
	require.NoError(t, s.svc.AssignGroupRoleGenesis(ctx, embedded.RootPersona, "", peer, embedded.SubjectKindUser, "operator"))

	ownerTok, _, err := s.svc.MintAccessToken(ctx, owner, nil)
	require.NoError(t, err)
	operatorTok, _, err := s.svc.MintAccessToken(ctx, operator, nil)
	require.NoError(t, err)

	call := func(token, method, path, body string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+token)
		if body != "" {
			r.Header.Set("Content-Type", "application/json")
		}
		s.apiHandler().ServeHTTP(w, r)
		return w
	}
	ban := func(token, target string) *httptest.ResponseRecorder {
		return call(token, http.MethodPost, "/admin/users/"+target+"/ban", `{"until":"infinite"}`)
	}
	del := func(token, target string) *httptest.ResponseRecorder {
		return call(token, http.MethodDelete, "/admin/users/"+target, "")
	}
	revoke := func(token, target string) *httptest.ResponseRecorder {
		return call(token, http.MethodPost, "/admin/users/"+target+"/sessions/revoke", "")
	}

	t.Run("operator cannot target owner", func(t *testing.T) {
		for name, w := range map[string]*httptest.ResponseRecorder{
			"ban":      ban(operatorTok, owner),
			"delete":   del(operatorTok, owner),
			"sessions": revoke(operatorTok, owner),
		} {
			require.Equal(t, http.StatusForbidden, w.Code, "%s: %s", name, w.Body.String())
			requireErrorCode(t, w.Body.String(), string(ErrAccountAuthorityEscalation))
		}
		u, err := s.svc.AdminGetUser(ctx, owner)
		require.NoError(t, err)
		require.Nil(t, u.BannedAt)
		require.Nil(t, u.DeletedAt)
	})

	t.Run("operator reaches peers and ordinary users", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, revoke(operatorTok, member).Code)
		require.Equal(t, http.StatusNoContent, ban(operatorTok, member).Code)
		require.Equal(t, http.StatusNoContent, del(operatorTok, member).Code)
		require.Equal(t, http.StatusNoContent, ban(operatorTok, peer).Code)
	})

	t.Run("owner reaches operator", func(t *testing.T) {
		require.Equal(t, http.StatusNoContent, revoke(ownerTok, operator).Code)
		require.Equal(t, http.StatusNoContent, ban(ownerTok, operator).Code)
	})
}
