package apitest_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// The HTTP conventions v1 freezes, end to end. Every response any apitest
// suite receives is also checked against the route catalog (conform).
func TestHTTPConventions(t *testing.T) {
	rbac := authkit.NewRoles()
	team := rbac.Persona("team", authkit.APIKeys)
	docs := team.Permission("docs", "read")
	reader := team.Role("reader", docs)
	manager := team.Role("manager", docs, team.Members.Manage, team.Members.Read)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }))
	a := newAPI(t, auth)
	owner, mgr, member := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	token, managerToken := authtest.SignIn(t, auth, owner).AccessToken, authtest.SignIn(t, auth, mgr).AccessToken
	group := newGroup(t, auth, team.Persona, owner.ID)
	authtest.GrantRole(t, auth, group, iam.UserSubject(mgr.ID), manager)
	authtest.GrantRole(t, auth, group, iam.UserSubject(member.ID), reader)
	base := "/groups/" + group.ID()

	errorOf := func(res response) (code, param string) {
		t.Helper()
		var env struct {
			Error struct {
				Code  string  `json:"code"`
				Param *string `json:"param"`
			} `json:"error"`
		}
		res.decode(t, &env)
		if env.Error.Param != nil {
			param = *env.Error.Param
		}
		return env.Error.Code, param
	}

	t.Run("an unknown path or method answers the JSON envelope", func(t *testing.T) {
		res := a.get("/no-such-route", "")
		require.Equal(t, http.StatusNotFound, res.status, res.String())
		require.Equal(t, "not_found", res.code())
		res = a.do(request{method: http.MethodDelete, path: "/capabilities"})
		require.Equal(t, http.StatusMethodNotAllowed, res.status, res.String())
		require.Equal(t, "method_not_allowed", res.code())
		require.Contains(t, res.header.Get("Allow"), http.MethodGet)
	})

	t.Run("a body that is not JSON is 415", func(t *testing.T) {
		res := a.do(request{method: http.MethodPost, path: "/password/login", body: `{"identifier":"x","password":"y"}`, header: http.Header{"Content-Type": {"text/plain"}}})
		require.Equal(t, http.StatusUnsupportedMediaType, res.status, res.String())
		require.Equal(t, "unsupported_media_type", res.code())
	})

	t.Run("one page parser and one opaque cursor", func(t *testing.T) {
		for _, bad := range []string{"0", "501", "-1", "ten"} {
			res := a.get("/me/groups?limit="+bad, token)
			require.Equal(t, http.StatusBadRequest, res.status, "limit=%s: %s", bad, res)
			code, param := errorOf(res)
			require.Equal(t, "invalid_request", code)
			require.Equal(t, "limit", param)
		}
		res := a.get(base+"/api-keys?cursor=not-a-cursor", token)
		require.Equal(t, http.StatusBadRequest, res.status, res.String())
		_, param := errorOf(res)
		require.Equal(t, "cursor", param)

		for _, name := range []string{"one", "two"} {
			res := a.post(base+"/api-keys", token, map[string]any{"name": name, "role": reader.String()})
			require.Equal(t, http.StatusCreated, res.status, res.String())
		}
		var seen []string
		cursor := ""
		for range 3 {
			res := a.get(base+"/api-keys?limit=1"+cursor, token)
			require.Equal(t, http.StatusOK, res.status, res.String())
			var page iam.ListPage[iam.APIKey]
			res.decode(t, &page)
			require.Len(t, page.Items, 1)
			seen = append(seen, page.Items[0].Name)
			if page.Next == "" {
				break
			}
			require.NotContains(t, page.Next, page.Items[0].ID, "the cursor is opaque")
			cursor = "&cursor=" + page.Next
		}
		require.Equal(t, []string{"two", "one"}, seen, "newest first, then the end of the list: next_cursor null")
	})

	t.Run("DELETE is idempotent", func(t *testing.T) {
		res := a.post(base+"/api-keys", token, map[string]any{"name": "gone", "role": reader.String()})
		require.Equal(t, http.StatusCreated, res.status, res.String())
		var created iam.APIKeyCreated
		res.decode(t, &created)
		require.NotEmpty(t, created.Secret)
		for _, id := range []string{created.APIKey.ID, created.APIKey.ID, uuid.NewString()} {
			res := a.do(request{method: http.MethodDelete, path: base + "/api-keys/" + id, token: token})
			require.Equal(t, http.StatusNoContent, res.status, res.String())
		}
		res = a.post(base+"/invitations", token, map[string]any{"role": reader.String()})
		require.Equal(t, http.StatusCreated, res.status, res.String())
		var link iam.InvitationCreated
		res.decode(t, &link)
		require.NotEmpty(t, link.Code)
		for _, id := range []string{link.Invitation.ID, link.Invitation.ID, uuid.NewString()} {
			res := a.do(request{method: http.MethodDelete, path: base + "/invitations/" + id, token: token})
			require.Equal(t, http.StatusNoContent, res.status, res.String())
		}
		for range 2 {
			res := a.do(request{method: http.MethodDelete, path: base + "/members/users/" + uuid.NewString(), token: token})
			require.Equal(t, http.StatusNoContent, res.status, res.String())
		}
	})

	t.Run("anti-enumeration before authorization, the specific code after", func(t *testing.T) {
		// An unknown group is refused like a foreign one.
		res := a.get("/groups/"+uuid.NewString()+"/members", token)
		require.Equal(t, http.StatusForbidden, res.status, res.String())
		require.Equal(t, "forbidden", res.code())
		// Authorized in the group, the operation's own refusal reaches the wire.
		put := func(bearer, subject, role string) response {
			return a.do(request{method: http.MethodPut, path: base + "/members/users/" + subject, body: map[string]string{"role": role}, token: bearer})
		}
		res = put(token, member.ID, "root:owner")
		require.Equal(t, http.StatusBadRequest, res.status, res.String())
		require.Equal(t, "role_not_assignable", res.code(), "a role of another persona")
		res = put(managerToken, member.ID, team.Owner.String())
		require.Equal(t, http.StatusForbidden, res.status, res.String())
		require.Contains(t, []string{"insufficient_authority", "role_assignment_escalation"}, res.code(), "a role above the caller's")
		res = put(token, member.ID, manager.String())
		require.Equal(t, http.StatusOK, res.status, res.String())
		var m iam.GroupMember
		res.decode(t, &m)
		require.Equal(t, iam.UserSubject(member.ID), m.Subject)
		require.Equal(t, manager, m.Role)
	})

	t.Run("times are UTC and unset values null", func(t *testing.T) {
		res := a.get("/me", token)
		require.Equal(t, http.StatusOK, res.status, res.String())
		var me map[string]any
		require.NoError(t, json.Unmarshal(res.body, &me))
		require.True(t, strings.HasSuffix(me["created_at"].(string), "Z"), me["created_at"])
		require.Contains(t, me, "avatar_url")
		require.Nil(t, me["avatar_url"])
		require.Equal(t, []any{}, me["providers"])
		require.Nil(t, me["solana_wallet"])
	})
}
