package apitest_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/open-rails/authkit"
	"github.com/open-rails/authkit/authtest"
	"github.com/open-rails/authkit/iam"
	"github.com/open-rails/authkit/internal/httpapi"
	"github.com/open-rails/authkit/internal/passkeytest"
)

// PATCH /me changes the username and preferred language in one call and
// answers the profile; a refused field changes nothing, and a second
// rename inside the cooldown is rename_rate_limited with its availability.
func TestMeProfileUpdate(t *testing.T) {
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.Username.Renames = true
		c.Languages = authkit.LanguageConfig{Supported: []string{"en", "es"}}
	}))
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, u).AccessToken
	patch := func(body any) response {
		return a.do(request{method: http.MethodPatch, path: "/me", token: token, body: body})
	}
	var profile struct {
		ID                string  `json:"id"`
		Username          string  `json:"username"`
		PreferredLanguage *string `json:"preferred_language"`
		HasPassword       bool    `json:"has_password"`
		Naming            struct {
			Allowed      bool       `json:"allowed"`
			NextRenameAt *time.Time `json:"next_rename_at"`
		} `json:"naming"`
	}

	refused := expect(t, http.StatusBadRequest, patch(map[string]any{"username": unique("never"), "preferred_language": "xx"}))
	require.Equal(t, "invalid_preferred_language", refused.code())
	require.Equal(t, u.Username, a.me(t, token).Username, "a refused field changes nothing")

	name := unique("renamed")
	res := expect(t, http.StatusOK, patch(map[string]any{"username": name, "preferred_language": "es"}))
	res.decode(t, &profile)
	require.Equal(t, u.ID, profile.ID)
	require.Equal(t, name, profile.Username)
	require.Equal(t, "es", *profile.PreferredLanguage)
	require.True(t, profile.HasPassword)
	require.False(t, profile.Naming.Allowed)
	require.NotNil(t, profile.Naming.NextRenameAt)
	stored, err := auth.User(t.Context(), iam.UserByID(u.ID))
	require.NoError(t, err)
	require.Equal(t, name, stored.Username)

	// An absent field stays.
	res = expect(t, http.StatusOK, patch(map[string]any{}))
	res.decode(t, &profile)
	require.Equal(t, "es", *profile.PreferredLanguage)

	limited := expect(t, http.StatusTooManyRequests, patch(map[string]any{"username": unique("again")}))
	var env struct {
		Error struct {
			Code     string `json:"code"`
			Metadata struct {
				Action        string     `json:"action"`
				NextAllowedAt *time.Time `json:"next_allowed_at"`
			} `json:"metadata"`
		} `json:"error"`
	}
	limited.decode(t, &env)
	require.Equal(t, "rename_rate_limited", env.Error.Code)
	require.Equal(t, "update_username", env.Error.Metadata.Action)
	require.NotNil(t, env.Error.Metadata.NextAllowedAt)

	expect(t, http.StatusBadRequest, patch(map[string]any{"email": "not@editable.example"}))
}

// Public metadata is the host's to write and anyone's to read: GET /me and
// GET /users carry it whole, signed in or not. No route takes it, so neither
// the account nor staff writes it over HTTP, and the account can't through the
// Client either.
func TestPublicMetadataOverHTTP(t *testing.T) {
	auth, _ := authtest.New(t)
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, u).AccessToken
	profile := map[string]any{"avatar": "https://media.example.test/u/1.webp", "biography": "hi", "links": map[string]any{"site": "https://u.example"}}
	require.NoError(t, auth.PatchPublicMetadata(t.Context(), iam.SystemIdentity(), u.ID, profile))

	var me struct {
		PublicMetadata map[string]any `json:"public_metadata"`
	}
	expect(t, http.StatusOK, a.get("/me", token)).decode(t, &me)
	require.Equal(t, profile, me.PublicMetadata)
	var page iam.ListPage[iam.PublicUser]
	expect(t, http.StatusOK, a.get("/users?ids="+u.ID, "")).decode(t, &page)
	require.Len(t, page.Items, 1)
	require.Equal(t, profile, page.Items[0].PublicMetadata)

	for _, body := range []map[string]any{
		{"public_metadata": map[string]any{"biography": "mine now"}},
		{"metadata": map[string]any{"badge": "admin"}},
		{"avatar_url": "https://tracker.example.test/pixel.png"},
	} {
		res := expect(t, http.StatusBadRequest, a.do(request{method: http.MethodPatch, path: "/me", token: token, body: body}))
		require.Equal(t, "invalid_request", res.code())
	}
	require.ErrorIs(t, auth.PatchPublicMetadata(t.Context(), iam.UserIdentity(u.ID), u.ID, map[string]any{"biography": "x"}), iam.ErrCannotTargetSelf)
	stored, err := auth.User(t.Context(), iam.UserByID(u.ID))
	require.NoError(t, err)
	require.Equal(t, profile, stored.PublicMetadata)
	for _, r := range httpapi.Catalog() {
		for _, in := range []any{r.Request, r.Query} {
			require.False(t, in != nil && namesMember(reflect.TypeOf(in), "public_metadata", map[reflect.Type]bool{}), "%s %s takes public metadata", r.Method, r.Path)
		}
	}
}

// namesMember reports whether t, or a type it holds, has a JSON member name.
func namesMember(t reflect.Type, name string, seen map[reflect.Type]bool) bool {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || seen[t] {
		return false
	}
	seen[t] = true
	for _, f := range reflect.VisibleFields(t) {
		if tag, _, _ := strings.Cut(f.Tag.Get("json"), ","); tag == name || namesMember(f.Type, name, seen) {
			return true
		}
	}
	return false
}

// DELETE /me/sessions signs out every other session and keeps the caller's;
// device keys stay. One session ends by id, and the history lists the
// revocations by kind.
func TestMeSessions(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.DeviceKeys.Enabled = true }))
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	device := authtest.EnrollDeviceKey(t, auth, outbox, u)
	caller, other := authtest.SignIn(t, auth, u), authtest.SignIn(t, auth, u)
	listSessions := func(token string) []iam.Session {
		t.Helper()
		var page struct {
			Data []iam.Session `json:"data"`
		}
		expect(t, http.StatusOK, a.get("/me/sessions", token)).decode(t, &page)
		return page.Data
	}
	listed := listSessions(caller.AccessToken)
	require.Len(t, listed, 2)
	current := 0
	for _, s := range listed {
		if s.Current {
			current++
		}
	}
	require.Equal(t, 1, current, "the caller's own session is marked")

	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: "/me/sessions", token: caller.AccessToken}))
	listed = listSessions(caller.AccessToken)
	require.Len(t, listed, 1)
	require.True(t, listed[0].Current)
	status, _, err := refreshSession(a, *other.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status, "the other session ended")
	expect(t, http.StatusOK, a.get("/me/sign-in-keys", caller.AccessToken))
	keys, err := auth.DeviceKeys(t.Context(), u.ID)
	require.NoError(t, err)
	require.Len(t, keys, 1)
	require.Nil(t, keys[0].RevokedAt, "signing out other sessions leaves device keys")
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: "/me/sessions", token: device.AccessToken}))
	status, _, err = refreshSession(a, *caller.RefreshToken)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, status, "a device key signs out every session")

	third := authtest.SignIn(t, auth, u)
	fourth := authtest.SignIn(t, auth, u)
	fourthID, _ := accessClaims(t, fourth.AccessToken)["sid"].(string)
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: "/me/sessions/" + fourthID, token: third.AccessToken}))
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: "/me/sessions/" + fourthID, token: third.AccessToken}))
	expect(t, http.StatusNoContent, a.do(request{method: http.MethodDelete, path: "/me/sessions/not-a-session", token: third.AccessToken}))
	require.Len(t, listSessions(third.AccessToken), 1)

	var events struct {
		Data []iam.SessionEvent `json:"data"`
	}
	expect(t, http.StatusOK, a.get("/me/session-events?kind=session_revoked", third.AccessToken)).decode(t, &events)
	require.NotEmpty(t, events.Data)
	for _, e := range events.Data {
		require.Equal(t, iam.SessionEventRevoked, e.Kind)
	}
	expect(t, http.StatusOK, a.get("/me/session-events?kind=session_created&kind=session_revoked&limit=2", third.AccessToken)).decode(t, &events)
	require.Len(t, events.Data, 2)
	bad := expect(t, http.StatusBadRequest, a.get("/me/session-events?kind=bogus", third.AccessToken))
	require.Contains(t, bad.String(), `"param":"kind"`)
	expect(t, http.StatusBadRequest, a.get("/me/session-events?limit=0", third.AccessToken))
}

// GET /me/sign-in-keys lists the caller's passkeys and live device keys
// together; a browser session relabels and revokes either kind, another
// account's key is not found, and a revoked device key's token acts on
// nothing.
func TestSignInKeysView(t *testing.T) {
	auth, outbox := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) {
		c.DeviceKeys.Enabled = true
		c.Passkeys = authkit.PasskeyConfig{RPID: "example.com", RPDisplayName: "Example", Origins: []string{"https://example.com"}}
	}))
	f := newFactorFlow(t, auth, outbox)
	u := authtest.NewUser(t, auth)
	browser := authtest.SignIn(t, auth, u).AccessToken
	begun := f.expect(http.StatusOK, f.request(http.MethodPost, "/me/passkeys/register/begin", browser, nil))
	var creation protocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(begun.raw), &creation))
	var passkey httpapi.SignInKey
	created := f.expect(http.StatusCreated, f.request(http.MethodPost, "/me/passkeys/register/finish", browser, passkeytest.New(t, "https://example.com").Register(t, &creation)))
	require.NoError(t, json.Unmarshal([]byte(created.raw), &passkey))
	require.Equal(t, httpapi.SignInKeyPasskey, passkey.Kind)
	device := authtest.EnrollDeviceKey(t, auth, outbox, u)

	keys := f.signInKeys(browser, "")
	require.Len(t, keys, 2)
	kinds := map[httpapi.SignInKeyKind]httpapi.SignInKey{}
	for _, k := range keys {
		kinds[k.Kind] = k
		require.False(t, k.Current, "a browser session holds no key")
	}
	require.Equal(t, passkey.ID, kinds[httpapi.SignInKeyPasskey].ID)
	require.Equal(t, device.ID, kinds[httpapi.SignInKeyDeviceKey].ID)
	for _, k := range f.signInKeys(device.AccessToken, "") {
		require.Equal(t, k.Kind == httpapi.SignInKeyDeviceKey, k.Current, "the device key behind the token is current")
	}

	relabel := func(token, id, label string) authAnswer {
		return f.request(http.MethodPatch, "/me/sign-in-keys/"+id, token, map[string]any{"label": label})
	}
	for _, id := range []string{passkey.ID, device.ID} {
		var renamed httpapi.SignInKey
		require.NoError(t, json.Unmarshal([]byte(f.expect(http.StatusOK, relabel(browser, id, "work")).raw), &renamed))
		require.Equal(t, id, renamed.ID)
		require.Equal(t, "work", *renamed.Label)
	}
	f.expect(http.StatusBadRequest, relabel(browser, device.ID, strings.Repeat("x", 129)))
	f.expect(http.StatusNotFound, relabel(browser, uuid.NewString(), "missing"))
	f.expect(http.StatusNotFound, relabel(browser, "not-a-key", "missing"))

	// Another account neither sees nor touches these keys.
	stranger := authtest.SignIn(t, auth, authtest.NewUser(t, auth)).AccessToken
	require.Empty(t, f.signInKeys(stranger, ""))
	for _, id := range []string{passkey.ID, device.ID} {
		f.expect(http.StatusNotFound, relabel(stranger, id, "mine"))
		f.expect(http.StatusNotFound, f.request(http.MethodDelete, "/me/sign-in-keys/"+id, stranger, nil))
	}

	// Management needs a recent sign-in.
	stale := authtest.StaleSession(t, auth, browser)
	denied := f.expect(http.StatusUnauthorized, f.request(http.MethodDelete, "/me/sign-in-keys/"+device.ID, stale, nil))
	require.Equal(t, "step_up_required", denied.Error.Code)

	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/sign-in-keys/"+device.ID, browser, nil))
	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/sign-in-keys/"+device.ID, browser, nil))
	revoked := f.expect(http.StatusUnauthorized, f.request(http.MethodDelete, "/me/sign-in-keys/"+passkey.ID, device.AccessToken, nil))
	require.Equal(t, "session_revoked", revoked.Error.Code)
	f.expect(http.StatusNotFound, relabel(browser, device.ID, "gone"))
	require.Equal(t, []string{passkey.ID}, keyIDs(f.signInKeys(browser, "")))

	f.expect(http.StatusNoContent, f.request(http.MethodDelete, "/me/sign-in-keys/"+passkey.ID, browser, nil))
	f.expect(http.StatusNotFound, f.request(http.MethodDelete, "/me/sign-in-keys/"+passkey.ID, browser, nil)) // a deleted passkey is gone
	f.expect(http.StatusNotFound, f.request(http.MethodDelete, "/me/sign-in-keys/"+uuid.NewString(), browser, nil))
	require.Empty(t, f.signInKeys(browser, ""))
}

func keyIDs(keys []httpapi.SignInKey) []string {
	out := []string{}
	for _, k := range keys {
		out = append(out, k.ID)
	}
	return out
}

// DELETE /me/phone removes the phone only while a proven email remains: never
// the last way to sign in or recover, never an MFA holder's last proven
// address. It needs a recent sign-in, and no phone is already removed.
func TestMePhoneRemoval(t *testing.T) {
	auth, _ := authtest.New(t)
	a := newAPI(t, auth)
	ctx := t.Context()
	newAccount := func(email string, emailProven bool) authtest.User {
		t.Helper()
		name := unique("phone")
		created, err := auth.CreateUser(ctx, iam.NewUser{Email: email, Phone: uniquePhone(), Username: name, Password: authtest.Password,
			EmailVerified: emailProven, PhoneVerified: true})
		require.NoError(t, err)
		return authtest.User{User: created, Password: authtest.Password}
	}
	remove := func(token string) response {
		return a.do(request{method: http.MethodDelete, path: "/me/phone", token: token})
	}
	phoneOf := func(id string) *string {
		t.Helper()
		u, err := auth.User(ctx, iam.UserByID(id))
		require.NoError(t, err)
		return u.Phone
	}

	proven := newAccount(uniqueEmail("phone-proven"), true)
	token := authtest.SignIn(t, auth, proven).AccessToken
	denied := expect(t, http.StatusUnauthorized, remove(authtest.StaleSession(t, auth, token)))
	require.Equal(t, "step_up_required", denied.code())
	expect(t, http.StatusNoContent, remove(token))
	require.Nil(t, phoneOf(proven.ID))
	expect(t, http.StatusNoContent, remove(token))

	for name, u := range map[string]authtest.User{
		"no email":       newAccount("", false),
		"unproven email": newAccount(uniqueEmail("phone-unproven"), false),
	} {
		t.Run(name, func(t *testing.T) {
			res := expect(t, http.StatusConflict, remove(authtest.SignIn(t, auth, u).AccessToken))
			require.Equal(t, "cannot_remove_last_contact", res.code())
			require.NotNil(t, phoneOf(u.ID))
		})
	}

	// An MFA holder keeps a proven address.
	holder := newAccount(uniqueEmail("phone-mfa"), false)
	holder.TOTP = authtest.EnrollTOTP(t, auth, holder)
	res := expect(t, http.StatusConflict, remove(authtest.SignIn(t, auth, holder).AccessToken))
	require.Equal(t, "cannot_remove_last_contact", res.code())
	require.NotNil(t, phoneOf(holder.ID))
}

// PUT /me/email and /me/phone need a recent sign-in, send a code to the new
// address and change nothing until the caller confirms it signed in.
func TestMeContactChange(t *testing.T) {
	auth, outbox := authtest.New(t)
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, u).AccessToken
	put := func(path, token string, body any) response {
		return a.do(request{method: http.MethodPut, path: path, token: token, body: body})
	}
	next := uniqueEmail("changed")
	denied := expect(t, http.StatusUnauthorized, put("/me/email", authtest.StaleSession(t, auth, token), map[string]any{"email": next}))
	require.Equal(t, "step_up_required", denied.code())
	require.Empty(t, outbox.Messages(iam.MessageVerification, next), "a stale session sends nothing")

	expect(t, http.StatusBadRequest, put("/me/email", token, map[string]any{"email": "not-an-email"}))
	expect(t, http.StatusBadRequest, put("/me/email", token, map[string]any{"email": ""}))
	taken := authtest.NewUser(t, auth)
	expect(t, http.StatusBadRequest, put("/me/email", token, map[string]any{"email": taken.Email}))

	expect(t, http.StatusAccepted, put("/me/email", token, map[string]any{"email": next}))
	require.Equal(t, u.Email, *a.meUser(t, token).Email, "nothing changes before the proof")
	expect(t, http.StatusNoContent, a.post("/verify/confirm", token, map[string]any{"identifier": next, "code": outbox.Last(t, iam.MessageVerification, next).Code}))
	changed := a.meUser(t, token)
	require.Equal(t, next, *changed.Email)
	require.True(t, changed.EmailVerified)

	phone := uniquePhone()
	expect(t, http.StatusBadRequest, put("/me/phone", token, map[string]any{"phone_number": "12"}))
	expect(t, http.StatusAccepted, put("/me/phone", token, map[string]any{"phone_number": phone}))
	require.Nil(t, a.meUser(t, token).Phone)
	expect(t, http.StatusNoContent, a.post("/verify/confirm", token, map[string]any{"identifier": phone, "code": outbox.Last(t, iam.MessageVerification, phone).Code}))
	changed = a.meUser(t, token)
	require.Equal(t, phone, *changed.Phone)
	require.True(t, changed.PhoneVerified)
}

// meUser is GET /me's account.
func (a *api) meUser(t *testing.T, token string) iam.User {
	t.Helper()
	var u iam.User
	expect(t, http.StatusOK, a.get("/me", token)).decode(t, &u)
	return u
}

// PUT /me/password is a plain step-up route: a recent sign-in sets the new
// password (204) and ends the other sessions; a stale one steps up first. A
// wrong password at the step-up is invalid_password on fresh and stale
// sessions alike, and a password never re-proves an account with a second
// factor (M5).
func TestMePasswordChange(t *testing.T) {
	auth, _ := authtest.New(t)
	a := newAPI(t, auth)
	put := func(token string, body map[string]any) response {
		return a.do(request{method: http.MethodPut, path: "/me/password", token: token, body: body})
	}
	stepUp := func(token, password string) response {
		return a.post("/me/step-up/password", token, map[string]any{"password": password})
	}
	u := authtest.NewUser(t, auth)
	current, other := authtest.SignIn(t, auth, u), authtest.SignIn(t, auth, u)
	refused := expect(t, http.StatusBadRequest, put(current.AccessToken, map[string]any{"current_password": u.Password, "new_password": "Second-horse-battery-2"}))
	require.Equal(t, "invalid_request", refused.code(), "the current password is a step-up's, never the change's")
	stale := authtest.StaleSession(t, auth, authtest.SignIn(t, auth, u).AccessToken)
	for _, token := range []string{current.AccessToken, stale} {
		wrong := expect(t, http.StatusUnauthorized, stepUp(token, "wrong-password"))
		require.Equal(t, "invalid_password", wrong.code())
	}

	expect(t, http.StatusNoContent, put(current.AccessToken, map[string]any{"new_password": "Second-horse-battery-2"}))
	refresh := func(ts iam.TokenSet) response {
		return a.post("/token", "", map[string]any{"grant_type": "refresh_token", "refresh_token": ts.RefreshToken})
	}
	expect(t, http.StatusUnauthorized, refresh(other))
	expect(t, http.StatusOK, refresh(current))
	u.Password = "Second-horse-battery-2"

	stale = authtest.StaleSession(t, auth, authtest.SignIn(t, auth, u).AccessToken)
	required := expect(t, http.StatusUnauthorized, put(stale, map[string]any{"new_password": "Third-horse-battery-3"}))
	require.Equal(t, "step_up_required", required.code())
	fresh := expectAnswer(t, stepUp(stale, u.Password), http.StatusOK).tokens().AccessToken
	expect(t, http.StatusNoContent, put(fresh, map[string]any{"new_password": "Third-horse-battery-3"}))
	u.Password = "Third-horse-battery-3"
	authtest.SignIn(t, auth, u)

	holder := authtest.NewUser(t, auth)
	holder.TOTP = authtest.EnrollTOTP(t, auth, holder)
	staleMFA := authtest.StaleSession(t, auth, authtest.SignIn(t, auth, holder).AccessToken)
	refused = expect(t, http.StatusUnauthorized, stepUp(staleMFA, holder.Password))
	require.Equal(t, "step_up_required", refused.code(), "a password never re-proves an account with a second factor")
	refused = expect(t, http.StatusUnauthorized, put(staleMFA, map[string]any{"new_password": "Fourth-horse-battery-4"}))
	require.Equal(t, "step_up_required", refused.code())
}

// GET /me/permissions: the caller's role in a group and the permissions it
// grants, expanded; root by default, and nothing in an unknown group.
func TestMePermissions(t *testing.T) {
	rbac := authkit.NewRoles()
	reader := rbac.Root.Role("reader", rbac.Root.Users.Read)
	auth, _ := authtest.New(t, authtest.WithConfig(func(c *authkit.Config) { c.Roles = rbac }))
	a := newAPI(t, auth)
	u := authtest.NewUser(t, auth)
	token := authtest.SignIn(t, auth, u).AccessToken
	var set struct {
		GroupID     string   `json:"group_id"`
		Role        *string  `json:"role"`
		Permissions []string `json:"permissions"`
	}
	expect(t, http.StatusOK, a.get("/me/permissions", token)).decode(t, &set)
	require.NotEmpty(t, set.GroupID)
	require.Nil(t, set.Role)
	require.Empty(t, set.Permissions)
	root := set.GroupID

	authtest.GrantRole(t, auth, iam.RootGroup(), iam.UserSubject(u.ID), reader)
	expect(t, http.StatusOK, a.get("/me/permissions?group_id=root", token)).decode(t, &set)
	require.Equal(t, root, set.GroupID)
	require.Equal(t, "root:reader", *set.Role)
	require.Equal(t, []string{"root:users:read"}, set.Permissions)

	unknown := uuid.NewString()
	expect(t, http.StatusOK, a.get("/me/permissions?group_id="+unknown, token)).decode(t, &set)
	require.Equal(t, unknown, set.GroupID)
	require.Nil(t, set.Role)
	require.Empty(t, set.Permissions)
}
