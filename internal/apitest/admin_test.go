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

	t.Run("sessions of an unknown id", func(t *testing.T) {
		res := expect(t, http.StatusNotFound, a.get("/admin/users/not-a-uuid/sessions", token))
		require.Equal(t, "user_not_found", res.code())
		expect(t, http.StatusForbidden, a.get(user+"/sessions", plainToken))
	})
}

// The ban history is AuthKit's own record: every ban and unban with who did
// it, newest first and paged, including the ban an imported or seeded account
// arrives with. Reading it takes root:users:read.
func TestAdminBanHistory(t *testing.T) {
	rbac := authkit.NewRoles()
	staffRole := rbac.Root.Role("staff", rbac.Root.Users.Read, rbac.Root.Users.Ban)
	auditorRole := rbac.Root.Role("auditor", rbac.Root.Users.Read)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }))
	ctx := t.Context()
	a := newAPI(t, auth)
	staff, auditor, target, plain := authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth), authtest.NewUser(t, auth)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(staff.ID), staffRole)
	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(auditor.ID), auditorRole)
	token, auditorToken, plainToken := authtest.SignIn(t, auth, staff).AccessToken, authtest.SignIn(t, auth, auditor).AccessToken, authtest.SignIn(t, auth, plain).AccessToken
	history := func(userID, query string) iam.ListPage[iam.BanEvent] {
		t.Helper()
		var page iam.ListPage[iam.BanEvent]
		expect(t, http.StatusOK, a.get("/admin/users/"+userID+"/ban-history"+query, auditorToken)).decode(t, &page)
		return page
	}
	require.Empty(t, history(target.ID, "").Items, "a never-banned account has no history")

	ban := "/admin/users/" + target.ID + "/ban"
	until := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second)
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodPut, path: ban, token: token, body: map[string]any{"reason": "spam", "until": until}}))
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodPut, path: ban, token: token, body: `{}`}))
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: ban, token: token}))
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: ban, token: token}))
	require.NoError(t, auth.Ban(ctx, iam.SystemActor(), target.ID, iam.Ban{Reason: "legacy"}))

	type entry struct {
		kind   iam.BanEventKind
		reason string
		by     string
		until  bool
	}
	summary := func(events []iam.BanEvent) []entry {
		out := make([]entry, len(events))
		for i, e := range events {
			require.NotEmpty(t, e.ID)
			require.WithinDuration(t, time.Now(), e.OccurredAt, time.Minute)
			out[i] = entry{kind: e.Kind, until: e.Until != nil}
			if e.Reason != nil {
				out[i].reason = *e.Reason
			}
			if e.By != nil {
				out[i].by = *e.By
			}
		}
		return out
	}
	want := []entry{
		{kind: iam.BanEventBanned, reason: "legacy"},
		{kind: iam.BanEventUnbanned, by: staff.ID},
		{kind: iam.BanEventBanned, by: staff.ID},
		{kind: iam.BanEventBanned, reason: "spam", by: staff.ID, until: true},
	}
	all := history(target.ID, "")
	require.Equal(t, want, summary(all.Items), "a repeated unban adds nothing")
	require.Empty(t, all.Next)
	require.True(t, until.Equal(*all.Items[3].Until))

	first := history(target.ID, "?limit=3")
	require.Equal(t, want[:3], summary(first.Items))
	require.NotEmpty(t, first.Next)
	rest := history(target.ID, "?limit=3&cursor="+first.Next)
	require.Equal(t, want[3:], summary(rest.Items))
	require.Empty(t, rest.Next)
	fromClient, err := auth.ListBanEvents(ctx, target.ID, iam.PageRequest{})
	require.NoError(t, err)
	require.Equal(t, want, summary(fromClient.Items))

	// An imported ban keeps its date and its banner; a seeded one starts now.
	bannedAt := time.Now().Add(-90 * 24 * time.Hour).UTC().Truncate(time.Second)
	reason := "imported"
	imported, err := auth.ImportUsers(ctx, []iam.ImportUser{{Username: unique("banimport"), Email: uniqueEmail("banimport"),
		Ban: &iam.BanState{At: bannedAt, Reason: &reason, By: &staff.ID}}}, iam.ImportOptions{})
	require.NoError(t, err)
	require.Equal(t, iam.ImportInserted, imported.Rows[0].Status, "%+v", imported.Rows[0])
	old := history(imported.Rows[0].UserID, "").Items
	require.Len(t, old, 1)
	require.True(t, bannedAt.Equal(old[0].OccurredAt), "%s", old[0].OccurredAt)
	require.Equal(t, []any{iam.BanEventBanned, reason, staff.ID}, []any{old[0].Kind, *old[0].Reason, *old[0].By})
	require.Nil(t, old[0].Until)
	seededEmail := uniqueEmail("banseed")
	_, err = auth.ApplyBootstrapManifest(ctx, iam.BootstrapManifest{Users: []iam.BootstrapManifestUser{{Username: unique("banseed"), Email: seededEmail,
		Ban: &iam.BanState{Reason: &reason}}}}, iam.BootstrapOptions{})
	require.NoError(t, err)
	seeded, err := auth.User(ctx, iam.UserByEmail(seededEmail))
	require.NoError(t, err)
	require.Equal(t, []entry{{kind: iam.BanEventBanned, reason: reason}}, summary(history(seeded.ID, "").Items))

	path := "/admin/users/" + target.ID + "/ban-history"
	expect(t, http.StatusForbidden, a.get(path, plainToken))
	expect(t, http.StatusUnauthorized, a.get(path, ""))
	expect(t, http.StatusOK, a.get(path, token))
	res := expect(t, http.StatusNotFound, a.get("/admin/users/not-a-uuid/ban-history", auditorToken))
	require.Equal(t, "user_not_found", res.code())
	res = expect(t, http.StatusBadRequest, a.get(path+"?cursor=bogus", auditorToken))
	require.Equal(t, "invalid_request", res.code())
}
