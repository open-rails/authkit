package apitest_test

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
)

// Staff edit and ban other accounts over HTTP, after a recent sign-in and
// within their authority (rule ACCT); never their own account.
func TestAdminAccountRoutes(t *testing.T) {
	rbac := authkit.NewRoles()
	staffRole := rbac.Root.Role("staff", rbac.Root.Users.Read, rbac.Root.Users.Manage, rbac.Root.Users.Ban)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Roles = rbac
		// root:users:manage needs MFA while 2FA is on; this test is about the routes.
		c.TwoFactor.Mode = iam.TwoFactorDisabled
		// Self-renames stay off: staff rename others regardless.
	}))
	a := newAPI(t, auth)
	staff, target, plain := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), staffRole)
	token, plainToken := authtest.SignIn(t, auth, staff).AccessToken, authtest.SignIn(t, auth, plain).AccessToken
	user := "/admin/users/" + target.ID
	entry := func() iam.UserEntry {
		t.Helper()
		var e iam.UserEntry
		expect(t, http.StatusOK, a.get(user, token)).decode(t, &e)
		return e
	}

	t.Run("PATCH edits the account", func(t *testing.T) {
		patch := func(bearer, path string, body any) response {
			return a.do(request{method: http.MethodPatch, path: path, body: body, token: bearer})
		}
		email, phone := uniqueEmail("adminpatch"), uniquePhone()
		res := expect(t, http.StatusOK, patch(token, user, map[string]any{"email": email, "phone_number": phone, "username": "patched" + target.ID[:8],
			"preferred_language": "fr"}))
		var got iam.UserEntry
		res.decode(t, &got)
		require.Equal(t, target.ID, got.ID)
		require.Equal(t, email, *got.Email)
		require.Equal(t, phone, *got.Phone)
		require.Equal(t, "patched"+target.ID[:8], got.Username)
		require.Equal(t, "fr", *got.PreferredLanguage)
		require.Equal(t, got, entry())
		// An absent field is unchanged; an empty one clears it.
		res = expect(t, http.StatusOK, patch(token, user, map[string]any{"preferred_language": ""}))
		res.decode(t, &got)
		require.Nil(t, got.PreferredLanguage)
		require.Equal(t, email, *got.Email)
		expect(t, http.StatusOK, patch(token, user, map[string]any{}))

		for name, tc := range map[string]struct {
			bearer, path string
			body         any
			status       int
			code         string
		}{
			"the verified flags are the system's": {token, user, map[string]any{"email_verified": true}, http.StatusBadRequest, "invalid_request"},
			"public metadata is the host's":       {token, user, map[string]any{"public_metadata": map[string]any{"badge": "staff"}}, http.StatusBadRequest, "invalid_request"},
			"a contact of one's own":              {token, "/admin/users/" + staff.ID, map[string]any{"email": uniqueEmail("self")}, http.StatusForbidden, "cannot_target_self"},
			"no root:users:manage":                {plainToken, user, map[string]any{"username": "hijack"}, http.StatusForbidden, ""},
			"an unknown account":                  {token, "/admin/users/0190a0a0-0000-7000-8000-000000000000", map[string]any{"username": "ghost"}, http.StatusNotFound, "user_not_found"},
			"signed out":                          {"", user, map[string]any{"username": "anon"}, http.StatusUnauthorized, ""},
			"a stale session":                     {authtest.StaleSession(t, auth, token), user, map[string]any{"username": "stale"}, http.StatusForbidden, "step_up_required"},
		} {
			res := patch(tc.bearer, tc.path, tc.body)
			require.Equal(t, tc.status, res.status, "%s: %s", name, res)
			if tc.code != "" {
				require.Equal(t, tc.code, res.code(), name)
			}
		}
		require.Equal(t, email, *entry().Email)
	})

	t.Run("PUT and DELETE ban are idempotent", func(t *testing.T) {
		ban := func(body string) response {
			return a.do(request{method: http.MethodPut, path: user + "/ban", body: body, token: token})
		}
		unban := func() response { return a.do(request{method: http.MethodDelete, path: user + "/ban", token: token}) }
		expect(t, http.StatusNoContent, ban(`{"reason":"spam","until":null}`))
		state := entry().Ban
		require.NotNil(t, state)
		require.Nil(t, state.Until, "a null until bans indefinitely")
		require.Equal(t, "spam", *state.Reason)
		require.Equal(t, staff.ID, *state.By)
		until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
		expect(t, http.StatusNoContent, ban(`{"reason":"cooling off","until":"`+until.Format(time.RFC3339)+`"}`))
		state = entry().Ban
		require.True(t, until.Equal(*state.Until), "the new ban replaces the one in force")
		require.Equal(t, "cooling off", *state.Reason)
		expect(t, http.StatusNoContent, ban(`{"reason":"cooling off","until":"`+until.Format(time.RFC3339)+`"}`))
		res := expect(t, http.StatusBadRequest, ban(`{"reason":null,"until":"`+time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)+`"}`))
		require.Equal(t, "invalid_until", res.code())
		expect(t, http.StatusBadRequest, ban(`{"until":"infinite"}`))
		res = expect(t, http.StatusForbidden, a.do(request{method: http.MethodPut, path: "/admin/users/" + staff.ID + "/ban", body: `{}`, token: token}))
		require.Equal(t, "cannot_target_self", res.code())
		expect(t, http.StatusForbidden, a.do(request{method: http.MethodPut, path: user + "/ban", body: `{}`, token: plainToken}))
		require.True(t, until.Equal(*entry().Ban.Until), "refusals change nothing")

		expect(t, http.StatusNoContent, unban())
		require.Nil(t, entry().Ban)
		expect(t, http.StatusNoContent, unban())
		expect(t, http.StatusNoContent, ban(`{}`))
		require.Nil(t, entry().Ban.Until, "an empty body bans indefinitely")
		expect(t, http.StatusNoContent, unban())
	})

	// A ban that ran out is no ban, but stays readable as ExpiredBan until an
	// unban clears it.
	t.Run("an expired ban is ExpiredBan", func(t *testing.T) {
		until := time.Now().Add(3 * time.Second).UTC().Truncate(time.Second)
		expect(t, http.StatusNoContent, a.do(request{method: http.MethodPut, path: user + "/ban", token: token,
			body: `{"reason":"cooling off","until":"` + until.Format(time.RFC3339) + `"}`}))
		require.NotNil(t, entry().Ban)
		require.Nil(t, entry().ExpiredBan)
		require.Eventually(t, func() bool { return entry().Ban == nil }, 10*time.Second, 200*time.Millisecond, "the ban runs out")

		got := entry()
		require.Nil(t, got.Ban)
		require.NotNil(t, got.ExpiredBan)
		require.True(t, until.Equal(*got.ExpiredBan.Until))
		require.Equal(t, "cooling off", *got.ExpiredBan.Reason)
		require.Equal(t, staff.ID, *got.ExpiredBan.By)
		require.False(t, got.ExpiredBan.At.IsZero())
		sameBan := func(b *iam.BanState) {
			t.Helper()
			require.NotNil(t, b)
			require.True(t, got.ExpiredBan.At.Equal(b.At) && until.Equal(*b.Until))
			require.Equal(t, []string{"cooling off", staff.ID}, []string{*b.Reason, *b.By})
		}
		viaClient, err := auth.User(t.Context(), iam.UserByID(target.ID))
		require.NoError(t, err)
		require.Nil(t, viaClient.Ban)
		sameBan(viaClient.ExpiredBan)
		bulk, err := auth.Users(t.Context(), []string{target.ID})
		require.NoError(t, err)
		require.Nil(t, bulk[target.ID].Ban)
		sameBan(bulk[target.ID].ExpiredBan)

		expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: user + "/ban", token: token}))
		got = entry()
		require.Nil(t, got.Ban)
		require.Nil(t, got.ExpiredBan, "an unban clears an expired ban too")
	})

	t.Run("sessions of an unknown id", func(t *testing.T) {
		res := expect(t, http.StatusNotFound, a.get("/admin/users/not-a-uuid/sessions", token))
		require.Equal(t, "user_not_found", res.code())
		expect(t, http.StatusForbidden, a.get(user+"/sessions", plainToken))
	})
}
